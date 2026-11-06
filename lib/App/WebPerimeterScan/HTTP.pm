package App::WebPerimeterScan::HTTP;

use strict;
use warnings;

use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL;
use Time::HiRes qw(time sleep);

use URI;

our $VERSION = '0.001.0';

my %DEFAULT_HEADERS = (
	'Accept'          => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
	'Accept-Language' => 'en-GB,en;q=0.9',
	'Accept-Encoding' => 'identity',
	'Connection'      => 'close',
);

# Deliberately hand-rolled rather than LWP, for two reasons:
#   * we need every Set-Cookie header separately (LWP/HTTP::Tiny join them,
#     and Expires contains commas so the join is not reversible);
#   * we want the raw status line and no automatic redirects, so the caller
#     can decide which hops are in scope before following them.
sub new
{
	my ($class, %args) = @_;

	return bless {
		timeout  => $args{timeout}  // 10,
		delay    => $args{delay}    // 0.5,
		max_size => $args{max_size} // 2_000_000,
		agent    => $args{agent}    // 'webperimeter/0.01 (authorised perimeter check)',
		last     => {},
		requests => 0,
	}, $class;
}

sub requests
{
	my ($self) = @_;

	return $self->{requests};
}

sub fetch
{
	my ($self, $url, %opt) = @_;

	my $method = $opt{method} || 'GET';
	my $uri = eval { URI->new($url) };
	return { url => $url, error => 'invalid URL' }
		unless $uri && $uri->scheme;

	my $scheme = lc $uri->scheme;
	return { url => $url, error => "unsupported scheme '$scheme'" }
		unless $scheme eq 'http' || $scheme eq 'https';

	my $host = $uri->host or return { url => $url, error => 'URL has no host' };
	my $port = $uri->port || ($scheme eq 'https' ? 443 : 80);
	my $path = $uri->path_query;
	$path = '/' unless length $path;
	$path = "/$path" unless $path =~ m{^/};

	$self->_throttle($host);

	my $started = time;
	my $sock = $self->_connect($scheme, $host, $port);
	return {
		url   => $url,
		host  => $host,
		port  => $port,
		error => 'connect failed: ' . ($IO::Socket::SSL::SSL_ERROR || "$!"),
	} unless $sock;

	$self->{requests}++;

	my $default_port = $scheme eq 'https' ? 443 : 80;
	my $host_header = $port == $default_port ? $host : "$host:$port";

	my $request = "$method $path HTTP/1.1\r\n";
	$request .= "Host: $host_header\r\n";
	$request .= "User-Agent: $self->{agent}\r\n";
	for my $name (sort keys %DEFAULT_HEADERS) {
		$request .= "$name: $DEFAULT_HEADERS{$name}\r\n";
	}
	for my $extra (@{ $opt{headers} || [] }) {
		next if $extra =~ /[\r\n]/;
		$request .= "$extra\r\n";
	}
	$request .= "\r\n";

	my $deadline = time + $self->{timeout};

	unless($self->_write_all($sock, $request, $deadline)) {
		close $sock;
		return { url => $url, host => $host, port => $port, error => 'request write failed' };
	}

	my $buffer = '';
	my $head;
	while(1) {
		if($buffer =~ /\r?\n\r?\n/) {
			($head, $buffer) = split /\r?\n\r?\n/, $buffer, 2;
			last;
		}
		last if length($buffer) > 65_536;

		my $chunk = $self->_read($sock, $deadline);
		last unless defined $chunk && length $chunk;
		$buffer .= $chunk;
	}

	unless(defined $head) {
		close $sock;
		return { url => $url, host => $host, port => $port, error => 'no response headers' };
	}

	my @lines = split /\r?\n/, $head;
	my $status_line = shift @lines;
	my ($http_version, $status, $reason) = ($status_line // '') =~ m{^(HTTP/\d\.\d)\s+(\d{3})\s*(.*)$};
	unless(defined $status) {
		close $sock;
		return { url => $url, host => $host, port => $port, error => 'malformed status line' };
	}

	my (%headers, $last_name);
	for my $line (@lines) {
		if($line =~ /^[ \t]+(.+)$/ && defined $last_name) {
			$headers{$last_name}[-1] .= ' ' . $1;
			next;
		}
		next unless $line =~ /^([^:]+):[ \t]*(.*)$/;
		my $name = lc $1;
		$name =~ s/[ \t]+$//;
		push @{ $headers{$name} }, $2;
		$last_name = $name;
	}

	my $content_length = $headers{'content-length'} ? $headers{'content-length'}[0] : undef;
	my $transfer_encoding = $headers{'transfer-encoding'}
		? lc join(',', @{ $headers{'transfer-encoding'} })
		: '';

	my $body = '';
	my $truncated = 0;
	if($method eq 'HEAD' || $status == 204 || $status == 304 || $status =~ /^1/) {
		$body = '';
	} elsif($transfer_encoding =~ /chunked/) {
		($body, $truncated) = $self->_read_chunked($sock, $deadline, \$buffer);
	} elsif(defined $content_length && $content_length =~ /^\d+$/) {
		($body, $truncated) = $self->_read_length($sock, $deadline, \$buffer, $content_length);
	} else {
		($body, $truncated) = $self->_read_to_eof($sock, $deadline, \$buffer);
	}

	close $sock;

	return {
		url           => $url,
		host          => lc $host,
		port          => $port + 0,
		scheme        => $scheme,
		status        => $status + 0,
		reason        => $reason,
		http_version  => $http_version,
		headers       => \%headers,
		set_cookie    => $headers{'set-cookie'} || [],
		body          => $body,
		truncated     => $truncated,
		content_type  => ($headers{'content-type'} ? $headers{'content-type'}[0] : ''),
		# The header block as it arrived, for reports that have to show it.
		raw_headers   => $head,
		elapsed       => time - $started,
	};
}

# Convenience accessor so callers do not have to remember the arrayrefs.
sub header
{
	my ($self, $response, $name) = @_;

	my $values = $response->{headers}{ lc $name } or return undef;
	return $values->[-1];
}

sub _connect
{
	my ($self, $scheme, $host, $port) = @_;

	if($scheme eq 'https') {
		# Verification failures are reported by App::WebPerimeterScan::TLS;
		# here we still want the response so the rest of the checks can run.
		return IO::Socket::SSL->new(
			PeerHost        => $host,
			PeerPort        => $port,
			Timeout         => $self->{timeout},
			SSL_hostname    => $host,
			SSL_verify_mode => 0,
		);
	}

	return IO::Socket::INET->new(
		PeerAddr => $host,
		PeerPort => $port,
		Proto    => 'tcp',
		Timeout  => $self->{timeout},
	);
}

sub _throttle
{
	my ($self, $host) = @_;

	my $delay = $self->{delay};
	return unless $delay > 0;

	my $last = $self->{last}{$host};
	if(defined $last) {
		my $wait = $last + $delay - time;
		sleep($wait) if $wait > 0;
	}

	$self->{last}{$host} = time;
}

sub _read
{
	my ($self, $sock, $deadline) = @_;

	my $wait = $deadline - time;
	return undef if $wait <= 0;

	my $select = IO::Select->new($sock);
	return undef unless $select->can_read($wait);

	my $buffer = '';
	my $read = sysread($sock, $buffer, 16_384);
	return undef unless defined $read;

	return $buffer;
}

sub _write_all
{
	my ($self, $sock, $data, $deadline) = @_;

	my $offset = 0;
	my $length = length $data;
	my $select = IO::Select->new($sock);

	while($offset < $length) {
		my $wait = $deadline - time;
		return 0 if $wait <= 0;
		return 0 unless $select->can_write($wait);

		my $written = syswrite($sock, $data, $length - $offset, $offset);
		return 0 unless defined $written;
		$offset += $written;
	}

	return 1;
}

sub _read_length
{
	my ($self, $sock, $deadline, $buffer_ref, $length) = @_;

	my $want = $length;
	my $truncated = 0;
	if($want > $self->{max_size}) {
		$want = $self->{max_size};
		$truncated = 1;
	}

	while(length($$buffer_ref) < $want) {
		my $chunk = $self->_read($sock, $deadline);
		last unless defined $chunk && length $chunk;
		$$buffer_ref .= $chunk;
	}

	return (substr($$buffer_ref, 0, $want), $truncated);
}

sub _read_to_eof
{
	my ($self, $sock, $deadline, $buffer_ref) = @_;

	while(length($$buffer_ref) < $self->{max_size}) {
		my $chunk = $self->_read($sock, $deadline);
		last unless defined $chunk && length $chunk;
		$$buffer_ref .= $chunk;
	}

	my $body = $$buffer_ref;
	my $truncated = length($body) >= $self->{max_size} ? 1 : 0;

	return (substr($body, 0, $self->{max_size}), $truncated);
}

sub _read_line
{
	my ($self, $sock, $deadline, $buffer_ref) = @_;

	while($$buffer_ref !~ /\r?\n/) {
		my $chunk = $self->_read($sock, $deadline);
		return undef unless defined $chunk && length $chunk;
		$$buffer_ref .= $chunk;
	}

	$$buffer_ref =~ s/\A(.*?)\r?\n//s or return undef;

	return $1;
}

sub _read_chunked
{
	my ($self, $sock, $deadline, $buffer_ref) = @_;

	my $body = '';
	my $truncated = 0;

	while(1) {
		my $line = $self->_read_line($sock, $deadline, $buffer_ref);
		last unless defined $line;

		$line =~ s/;.*//;
		$line =~ s/\s+//g;
		last unless $line =~ /^[0-9a-fA-F]+$/;

		my $size = hex $line;
		if($size == 0) {
			# Consume trailers up to the blank line.
			while(1) {
				my $trailer = $self->_read_line($sock, $deadline, $buffer_ref);
				last unless defined $trailer && length $trailer;
			}
			last;
		}

		while(length($$buffer_ref) < $size + 2) {
			my $chunk = $self->_read($sock, $deadline);
			last unless defined $chunk && length $chunk;
			$$buffer_ref .= $chunk;
		}
		last if length($$buffer_ref) < $size;

		$body .= substr($$buffer_ref, 0, $size);
		substr($$buffer_ref, 0, $size) = '';
		$$buffer_ref =~ s/\A\r?\n//;

		if(length($body) > $self->{max_size}) {
			$body = substr($body, 0, $self->{max_size});
			$truncated = 1;
			last;
		}
	}

	return ($body, $truncated);
}

1;

__END__

=head1 NAME

App::WebPerimeterScan::HTTP - minimal HTTP/1.1 client for perimeter scanning

=head1 SYNOPSIS

	my $http = App::WebPerimeterScan::HTTP->new(delay => 0.5);
	my $res = $http->fetch('https://example.com/');
	print $res->{status}, "\n" unless $res->{error};
	print $http->header($res, 'server'), "\n";

=head1 DESCRIPTION

A deliberately small HTTP client.  It does not follow redirects, it returns
every C<Set-Cookie> header separately, and it throttles per host so a scan
does not look like a denial of service.

TLS certificates are not verified at this layer so that a site with an
expired or mismatched certificate can still be inspected; the verification
result is reported separately by L<App::WebPerimeterScan::TLS>.

=head1 LICENSE

GPL2

=cut
