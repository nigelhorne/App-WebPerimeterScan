package App::WebPerimeterScan::HTTP;

use strict;
use warnings;
use autodie qw(:all);

# Network failures are results, not exceptions: a refused or reset
# connection is what a perimeter scan is looking for.  These builtins keep
# their ordinary return-value behaviour so the code below can report them.
no autodie qw(close sysread syswrite);

use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL;
use Params::Get qw(get_params);
use Params::Validate::Strict qw(validate_strict);
use Readonly;
use Sub::Private { mode => 'enforce' };
use Time::HiRes qw(time sleep);
use URI;

use App::WebPerimeterScan::I18N ();
use parent -norequire, 'App::WebPerimeterScan::I18N';

our $VERSION = '0.001.0';

# Defaults for new(); a plain hash so Object::Configure, or a caller, can
# change them for every client created afterwards.
our %config = (
	timeout  => 10,		# seconds for one whole request and response
	delay    => 0.5,	# minimum seconds between requests to one host
	max_size => 2_000_000,	# bytes of body kept; the rest is discarded
);

# Sent on every request.  identity: the body is inspected, so no gzip.
Readonly::Hash my %DEFAULT_HEADERS => (
	'Accept'          => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
	'Accept-Language' => 'en-GB,en;q=0.9',
	'Accept-Encoding' => 'identity',
	'Connection'      => 'close',
);

# The User-Agent names the release, so a site operator reading their logs
# can tell which version of the tool sent a request.
Readonly::Scalar my $AGENT => "webperimeter/$VERSION (authorised perimeter check)";

Readonly::Scalar my $DEFAULT_METHOD => 'GET';
Readonly::Hash my %DEFAULT_PORT => (http => 80, https => 443);

# A request method is a token; anything else could split the request line.
Readonly::Scalar my $METHOD_RE => qr/\A[A-Z]+\z/;

# Statuses whose responses never carry a body (RFC 9110 6.4.1).
Readonly::Hash my %NO_BODY_STATUS => (204 => 1, 304 => 1);

# A header block larger than this is not a web server we want to parse.
Readonly::Scalar my $MAX_HEADER_BYTES => 65_536;

# One sysread at a time.
Readonly::Scalar my $READ_SIZE => 16_384;

# End of the header block, and one line ending, tolerating bare LF.
Readonly::Scalar my $HEADER_END => qr/\r?\n\r?\n/;
Readonly::Scalar my $LINE_END   => qr/\r?\n/;

=encoding utf8

=head1 NAME

App::WebPerimeterScan::HTTP - minimal HTTP/1.1 client for perimeter scanning

=head1 VERSION

Version 0.001.0

=head1 SYNOPSIS

	my $http = App::WebPerimeterScan::HTTP->new(delay => 0.5);
	my $res = $http->fetch('https://example.com/');
	print $res->{status}, "\n" unless $res->{error};
	print $http->header($res, 'server') // '', "\n";

=head1 DESCRIPTION

A deliberately small HTTP client, hand-rolled rather than L<LWP> or
L<HTTP::Tiny> for two reasons: every C<Set-Cookie> header is needed
separately (those modules join them, and C<Expires> contains commas so the
join cannot be undone), and the raw status line is wanted with no automatic
redirects, so the caller decides which hops are in scope.

It throttles per host so a scan does not look like a denial of service.

TLS certificates are not verified at this layer so that a site with an
expired or mismatched certificate can still be inspected; the verification
result is reported separately by L<App::WebPerimeterScan::TLS>.

=head1 REQUIREMENTS

C<IO::Socket::INET> 1.31 and C<IO::Select> 1.17.  HTTPS requests also need
C<IO::Socket::SSL> 2.000, whose installation needs the OpenSSL headers.

=head1 SUBROUTINES/METHODS

=head2 new

Purpose: create a client.

Args: named C<timeout> (seconds per request), C<delay> (seconds between
requests to one host), C<max_size> (bytes of body kept), C<agent>
(User-Agent).  Defaults come from C<%App::WebPerimeterScan::HTTP::config>.

Returns: the new object.

Side Effects: none; no connection is made until C<fetch>.

Usage: C<< my $http = App::WebPerimeterScan::HTTP->new(timeout => 5); >>

=head3 EXAMPLE

	my $http = App::WebPerimeterScan::HTTP->new(delay => 0);	# no throttle, for tests

=head3 API SPECIFICATION

=head4 INPUT

	{
		timeout  => { type => 'number', min => 0, optional => 1 },
		delay    => { type => 'number', min => 0, optional => 1 },
		max_size => { type => 'integer', min => 1, optional => 1 },
		agent    => { type => 'string', min => 1, optional => 1 },
	}

=head4 OUTPUT

	{ type => 'object', isa => 'App::WebPerimeterScan::HTTP' }

=head3 MESSAGES

	Message                          Meaning / resolution
	-------------------------------  -----------------------------------
	Parameter 'X' ... (fatal)        A value is negative or not a number.
	Unknown parameter 'X' (fatal)    A misspelt argument name.

=head3 FORMAL SPECIFICATION

	┌─ InitHTTP ──────────────────────────────────────────
	│ HTTP'; timeout?, delay? : ℝ; max_size? : ℕ₁
	├─────────────────────────────────────────────────────
	│ timeout? ≥ 0 ∧ delay? ≥ 0
	│ requests' = 0 ∧ last' = ∅
	└─────────────────────────────────────────────────────

=cut

sub new
{
	my $class = shift;

	my $args = validate_strict(
		schema => {
			timeout  => { type => 'number', min => 0, optional => 1 },
			delay    => { type => 'number', min => 0, optional => 1 },
			max_size => { type => 'integer', min => 1, optional => 1 },
			agent    => { type => 'string', min => 1, optional => 1 },
		},
		input => get_params(undef, \@_) // {},
	);

	return bless {
		timeout  => $args->{timeout}  // $config{timeout},
		delay    => $args->{delay}    // $config{delay},
		max_size => $args->{max_size} // $config{max_size},
		agent    => $args->{agent}    // $AGENT,
		last     => {},	# host => time of the last request
		requests => 0,
	}, $class;
}

=head2 requests

Purpose: the number of requests actually sent (connections that opened).

Args: none.

Returns: a non-negative integer.

Side Effects: none.

Usage: C<< printf "Requests: %d\n", $http->requests; >>

=head3 EXAMPLE

	$http->fetch($url);
	print $http->requests, "\n";

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'integer', min => 0 }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	┌─ Requests ──────────────────────────────────────────
	│ ΞHTTP; result! : ℕ
	├─────────────────────────────────────────────────────
	│ result! = requests
	└─────────────────────────────────────────────────────

=cut

sub requests
{
	my ($self) = @_;

	return $self->{requests};
}

=head2 fetch

Purpose: send one request and read the response.

Args: C<$url>, then named C<method> (an upper-case token, default C<GET>)
and C<headers> (an array reference of C<Name: value> strings; any
containing CR or LF are dropped so they cannot inject headers).

Returns: a hash reference.  On failure it has C<url> and C<error> (a
translated message), plus C<host> and C<port> when the URL was usable.  On
success: C<url>, C<host>, C<port>, C<scheme>, C<status>, C<reason>,
C<http_version>, C<headers> (lower-case name =E<gt> array of values, in
order), C<set_cookie>, C<body>, C<truncated>, C<content_type>,
C<raw_headers> and C<elapsed>.

Side Effects: network traffic; may sleep to honour C<delay>; increments
C<requests> when a connection opens.

Usage: C<< my $res = $http->fetch($url, method => 'OPTIONS'); >>

=head3 EXAMPLE

	my $res = $http->fetch('https://example.com/',
		headers => [ 'Origin: https://ws-probe.invalid' ]);
	if($res->{error}) {
		print "failed: $res->{error}\n";
	} else {
		print "$res->{status} ", scalar @{ $res->{set_cookie} }, " cookie(s)\n";
	}

=head3 API SPECIFICATION

=head4 INPUT

	{
		url     => { type => 'string', min => 1, position => 0 },
		method  => { type => 'string', matches => qr/\A[A-Z]+\z/, optional => 1 },
		headers => { type => 'arrayref', optional => 1 },
	}

=head4 OUTPUT

	{ type => 'hashref' }	# see Returns; 'error' present on failure

=head3 MESSAGES

These are returned in C<error>, not thrown:

	Message                       Meaning / resolution
	----------------------------  ---------------------------------------
	invalid URL                   The URL did not parse.
	unsupported scheme 'S'        Only http and https are fetched.
	URL has no host               The URL has no authority part.
	connect failed: E             TCP or TLS connect failed; E says why.
	request write failed          The connection closed or timed out
	                              while sending.
	no response headers           Nothing usable arrived before timeout.
	malformed status line         The reply was not HTTP/1.x.

=head3 FORMAL SPECIFICATION

	┌─ Fetch ─────────────────────────────────────────────
	│ ΔHTTP; url? : URL; method? : TOKEN; res! : RESPONSE
	├─────────────────────────────────────────────────────
	│ scheme(url?) ∈ {http, https} ∧ host(url?) ≠ ∅
	│ now − last(host(url?)) ≥ delay        (after any sleep)
	│ connected ⇒ requests' = requests + 1
	│ ¬ connected ⇒ requests' = requests ∧ error ∈ dom res!
	│ #res!.body ≤ max_size
	└─────────────────────────────────────────────────────

=head3 PSEUDOCODE

	parse the URL; return an error for anything but http(s) with a host
	wait until the per-host delay has passed
	connect (TLS without verification for https); return an error on failure
	write the request line, Host, User-Agent, fixed and extra headers
	read until the blank line; parse the status line and headers
	read the body by Content-Length, chunked encoding or to EOF
	return the parsed response

=cut

sub fetch
{
	my ($self, $url, @rest) = @_;

	my $opt = validate_strict(
		schema => {
			method  => { type => 'string', matches => $METHOD_RE, optional => 1 },
			headers => { type => 'arrayref', optional => 1 },
		},
		input => get_params(undef, \@rest) // {},
	);
	my $method = $opt->{method} // $DEFAULT_METHOD;

	my $target = _target($url);
	return $target if $target->{error};

	$self->_throttle($target->{host});

	my $started = time;
	my $sock = $self->_connect($target);
	return _failure($target, 'http.connect_failed', { error => _connect_error($target) })
		unless $sock;

	# The timeout covers the exchange; the connect had its own.
	$self->{requests}++;
	my $deadline = time + $self->{timeout};

	my $response = $self->_exchange($sock, $target, $method, $opt->{headers}, $deadline);
	close $sock;

	$response->{elapsed} = time - $started;

	return $response;
}

=head2 header

Purpose: the last value of a response header, without dealing in array
references.

Args: C<$response> (from C<fetch>) and C<$name> (any case).

Returns: the value, or C<undef> if the header is absent.

Side Effects: none.

Usage: C<< my $server = $http->header($res, 'Server'); >>

=head3 EXAMPLE

	my $type = $http->header($res, 'Content-Type') // 'none';

=head3 API SPECIFICATION

=head4 INPUT

	{
		response => { type => 'hashref', position => 0 },
		name     => { type => 'string', min => 1, position => 1 },
	}

=head4 OUTPUT

	{ type => 'string', optional => 1 }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	┌─ Header ────────────────────────────────────────────
	│ response? : RESPONSE; name? : STRING; result! : STRING ∪ {⊥}
	├─────────────────────────────────────────────────────
	│ n = lower(name?)
	│ n ∈ dom response?.headers ⇒ result! = last(response?.headers(n))
	│ n ∉ dom response?.headers ⇒ result! = ⊥
	└─────────────────────────────────────────────────────

=cut

sub header
{
	my ($self, $response, $name) = @_;

	my $values = $response->{headers}{ lc $name };

	return $values ? $values->[-1] : undef;
}

# _target
# Purpose:     split a URL into what a request needs.
# Entry:       $url is any string.
# Exit:        hashref of url, scheme, host, port, path, host_header; or a
#              failure hashref with 'error'.
# Side effects: none.
sub _target :Private
{
	my ($url) = @_;

	my $uri = eval { URI->new($url) };
	return _failure({ url => $url }, 'http.invalid_url') unless $uri && $uri->scheme;

	my $scheme = lc $uri->scheme;
	return _failure({ url => $url }, 'http.unsupported_scheme', { scheme => $scheme })
		unless exists $DEFAULT_PORT{$scheme};

	my $host = $uri->host;
	return _failure({ url => $url }, 'http.no_host') unless defined $host && length $host;

	my $port = $uri->port || $DEFAULT_PORT{$scheme};

	# path_query is empty for "http://host"; the request line needs "/".
	my $path = $uri->path_query;
	$path = "/$path" unless $path =~ m{\A/};

	return {
		url         => $url,
		scheme      => $scheme,
		host        => $host,
		port        => $port + 0,
		path        => $path,
		host_header => $port == $DEFAULT_PORT{$scheme} ? $host : "$host:$port",
	};
}

# _failure
# Purpose:     a response hash describing an error.
# Entry:       $context has at least 'url'; $key is a catalogue key.
# Exit:        hashref with url, error and host/port when known.
# Side effects: none.
sub _failure :Private
{
	my ($context, $key, $args) = @_;

	my %failure = (url => $context->{url}, error => __PACKAGE__->i18n($key, $args));
	$failure{$_} = $context->{$_} for grep { defined $context->{$_} } qw(host port);

	return \%failure;
}

# _connect_error
# Purpose:     why a connect failed.
# Entry:       called straight after a failed _connect for $target.
# Exit:        a non-empty string.
# Side effects: none.
sub _connect_error :Private
{
	my ($target) = @_;

	# Only an https connect can have a TLS error.  For plain http,
	# SSL_ERROR still holds whatever the last TLS failure was - on another
	# host, minutes ago - and reporting it here was misleading.
	my $tls_error = $target->{scheme} eq 'https' ? $IO::Socket::SSL::SSL_ERROR : undef;

	return (defined $tls_error && length $tls_error) ? $tls_error : "$!";
}

# _exchange
# Purpose:     send the request on an open socket and parse the reply.
# Entry:       $sock is connected; $deadline is an absolute time.
# Exit:        a response hashref (with 'error' on failure).
# Side effects: socket I/O.  Does not close the socket.
sub _exchange :Private
{
	my ($self, $sock, $target, $method, $extra, $deadline) = @_;

	my $request = $self->_request_text($target, $method, $extra);
	return _failure($target, 'http.write_failed')
		unless _write_all($sock, $request, $deadline);

	my ($head, $buffer) = $self->_read_head($sock, $deadline);
	return _failure($target, 'http.no_headers') unless defined $head;

	my $parsed = _parse_head($head);
	return _failure($target, 'http.malformed_status') unless $parsed;

	my ($body, $truncated) = @{ $self->_read_body($sock, $deadline, \$buffer, $method, $parsed) };
	my $headers = $parsed->{headers};

	return {
		url          => $target->{url},
		host         => lc $target->{host},
		port         => $target->{port},
		scheme       => $target->{scheme},
		status       => $parsed->{status},
		reason       => $parsed->{reason},
		http_version => $parsed->{http_version},
		headers      => $headers,
		set_cookie   => $headers->{'set-cookie'} || [],
		body         => $body,
		truncated    => $truncated,
		content_type => $headers->{'content-type'} ? $headers->{'content-type'}[0] : '',
		# The header block as it arrived, for reports that have to show it.
		raw_headers  => $head,
	};
}

# _request_text
# Purpose:     the bytes of one HTTP/1.1 request.
# Entry:       $method matches $METHOD_RE; $extra is an arrayref or undef.
# Exit:        the request string, ending in a blank line.
# Side effects: none.
sub _request_text :Private
{
	my ($self, $target, $method, $extra) = @_;

	my @lines = (
		"$method $target->{path} HTTP/1.1",
		"Host: $target->{host_header}",
		"User-Agent: $self->{agent}",
		map({ "$_: $DEFAULT_HEADERS{$_}" } sort keys %DEFAULT_HEADERS),
		# A caller-supplied header with a line break could smuggle a
		# second header or a second request, so it is dropped.
		grep({ defined && !/[\r\n]/ } @{ $extra || [] }),
	);

	return join("\r\n", @lines) . "\r\n\r\n";
}

# _read_head
# Purpose:     read up to the end of the header block.
# Entry:       $sock is readable; $deadline is absolute.
# Exit:        (head, rest-of-buffer); head is undef on timeout, EOF or an
#              oversized block.
# Side effects: socket reads.
sub _read_head :Private
{
	my ($self, $sock, $deadline) = @_;

	my $buffer = '';
	while($buffer !~ $HEADER_END) {
		return (undef, $buffer) if length($buffer) > $MAX_HEADER_BYTES;

		my $chunk = _read($sock, $deadline);
		return (undef, $buffer) unless defined $chunk && length $chunk;
		$buffer .= $chunk;
	}

	return split $HEADER_END, $buffer, 2;
}

# _parse_head
# Purpose:     parse a status line and header fields.
# Entry:       $head is the header block without the terminating blank line.
# Exit:        hashref of http_version, status, reason, headers; undef if
#              the status line is not HTTP/1.x.
# Side effects: none.
sub _parse_head :Private
{
	my ($head) = @_;

	my @lines = split $LINE_END, $head;
	my $status_line = shift(@lines) // '';
	my ($http_version, $status, $reason) = $status_line =~ m{\A(HTTP/\d\.\d)\s+(\d{3})\s*(.*)\z};
	return unless defined $status;

	my (%headers, $last_name);
	for my $line (@lines) {
		# obs-fold: a continuation line belongs to the previous header.
		if($line =~ /\A[ \t]+(.+)\z/ && defined $last_name) {
			$headers{$last_name}[-1] .= " $1";
			next;
		}
		# Copy the captures before the substitution below: a successful s///
		# resets $2, which once lost the value of "Name : value" headers.
		my ($name, $value) = $line =~ /\A([^:]+):[ \t]*(.*)\z/ or next;
		($name = lc $name) =~ s/[ \t]+\z//;
		push @{ $headers{$name} }, $value;
		$last_name = $name;
	}

	return {
		http_version => $http_version,
		status       => $status + 0,
		reason       => $reason,
		headers      => \%headers,
	};
}

# _read_body
# Purpose:     read the body the way the headers describe it.
# Entry:       $buffer_ref holds bytes already read past the header block.
# Exit:        arrayref [body, truncated flag].
# Side effects: socket reads; consumes $$buffer_ref.
sub _read_body :Private
{
	my ($self, $sock, $deadline, $buffer_ref, $method, $parsed) = @_;

	my $status  = $parsed->{status};
	my $headers = $parsed->{headers};

	# HEAD, 1xx, 204 and 304 never have a body, whatever the headers say.
	return [ '', 0 ] if $method eq 'HEAD' || $status < 200 || $NO_BODY_STATUS{$status};

	my $encoding = lc join ',', @{ $headers->{'transfer-encoding'} || [] };
	return $self->_read_chunked($sock, $deadline, $buffer_ref) if $encoding =~ /chunked/;

	my $length = $headers->{'content-length'} ? $headers->{'content-length'}[0] : undef;
	return $self->_read_until($sock, $deadline, $buffer_ref, $length)
		if defined $length && $length =~ /\A\d+\z/;

	return $self->_read_until($sock, $deadline, $buffer_ref, undef);
}

# _connect
# Purpose:     open a TCP or TLS connection.
# Entry:       $target from _target.
# Exit:        the socket, or undef on failure ($! / SSL_ERROR set).
# Side effects: network connection.
sub _connect :Private
{
	my ($self, $target) = @_;

	my %common = (
		PeerPort => $target->{port},
		Timeout  => $self->{timeout},
	);

	# Verification failures are reported by App::WebPerimeterScan::TLS;
	# here the response is still wanted so the other checks can run.
	return IO::Socket::SSL->new(
		%common,
		PeerHost        => $target->{host},
		SSL_hostname    => $target->{host},
		SSL_verify_mode => SSL_VERIFY_NONE,
	) if $target->{scheme} eq 'https';

	return IO::Socket::INET->new(%common, PeerAddr => $target->{host}, Proto => 'tcp');
}

# _throttle
# Purpose:     keep at least 'delay' seconds between requests to one host.
# Entry:       $host is the request's host.
# Exit:        $self.
# Side effects: may sleep; records the time of this request.
sub _throttle :Private
{
	my ($self, $host) = @_;

	my $last = $self->{last}{$host};
	if($self->{delay} > 0 && defined $last) {
		my $wait = $last + $self->{delay} - time;
		sleep($wait) if $wait > 0;
	}
	$self->{last}{$host} = time;

	return $self;
}

# _read
# Purpose:     one bounded read.
# Entry:       $sock open; $deadline absolute.
# Exit:        the bytes read ('' at EOF), or undef on timeout or error.
# Side effects: socket read.
sub _read :Private
{
	my ($sock, $deadline) = @_;

	my $wait = $deadline - time;
	my $buffer;

	# undef stands for "nothing more will come": timed out or failed.
	if($wait > 0 && IO::Select->new($sock)->can_read($wait)) {
		$buffer = '';
		$buffer = undef unless defined sysread($sock, $buffer, $READ_SIZE);
	}

	return $buffer;
}

# _write_all
# Purpose:     write a whole string, waiting for the socket as needed.
# Entry:       $sock open; $deadline absolute.
# Exit:        1 when everything was written, 0 on timeout or error.
# Side effects: socket writes.
sub _write_all :Private
{
	my ($sock, $data, $deadline) = @_;

	my $offset = 0;
	my $select = IO::Select->new($sock);

	while($offset < length $data) {
		my $wait = $deadline - time;
		return 0 if $wait <= 0 || !$select->can_write($wait);

		my $written = syswrite($sock, $data, length($data) - $offset, $offset);
		return 0 unless defined $written;
		$offset += $written;
	}

	return 1;
}

# _read_until
# Purpose:     read a body of known length, or to EOF when $length is undef,
#              keeping at most max_size bytes.
# Entry:       $buffer_ref holds bytes already read.
# Exit:        arrayref [body, truncated flag].
# Side effects: socket reads; grows $$buffer_ref.
sub _read_until :Private
{
	my ($self, $sock, $deadline, $buffer_ref, $length) = @_;

	my $max = $self->{max_size};
	my $want = defined $length && $length < $max ? $length : $max;

	while(length($$buffer_ref) < $want) {
		my $chunk = _read($sock, $deadline);
		last unless defined $chunk && length $chunk;
		$$buffer_ref .= $chunk;
	}

	# Truncated means bytes were left behind: a declared length beyond the
	# cap, or an unbounded body that reached it.
	my $truncated = defined $length ? ($length > $max ? 1 : 0) : (length($$buffer_ref) >= $max ? 1 : 0);

	return [ substr($$buffer_ref, 0, $want), $truncated ];
}

# _read_line
# Purpose:     one CRLF- or LF-terminated line, for chunked framing.
# Entry:       $buffer_ref holds bytes already read.
# Exit:        the line without its terminator, or undef on EOF/timeout.
# Side effects: socket reads; removes the line from $$buffer_ref.
sub _read_line :Private
{
	my ($sock, $deadline, $buffer_ref) = @_;

	# Keep reading until a line ending arrives or the peer stops sending;
	# a partial line at EOF does not match below and so yields undef.
	my $chunk = '';
	$$buffer_ref .= $chunk
		while $$buffer_ref !~ $LINE_END
			&& defined($chunk = _read($sock, $deadline)) && length $chunk;

	return $$buffer_ref =~ s/\A(.*?)$LINE_END//s ? $1 : undef;
}

# _read_chunked
# Purpose:     decode a chunked body (RFC 9112 7.1), keeping max_size bytes.
# Entry:       $buffer_ref holds bytes already read past the headers.
# Exit:        arrayref [body, truncated flag].
# Side effects: socket reads; consumes $$buffer_ref.
#
# Each chunk is "<hex size>[;ext]\r\n<data>\r\n"; a zero size ends the body
# and is followed by optional trailers and a blank line.  Anything that does
# not parse ends the body early rather than guessing.
sub _read_chunked :Private
{
	my ($self, $sock, $deadline, $buffer_ref) = @_;

	my $body = '';
	while(defined(my $line = _read_line($sock, $deadline, $buffer_ref))) {
		$line =~ s/;.*//;	# chunk extensions are ignored
		$line =~ s/\s+//g;
		last unless $line =~ /\A[0-9a-fA-F]+\z/;

		my $size = hex $line;
		if($size == 0) {
			# Trailers, up to the blank line, are read and discarded.
			1 while length(_read_line($sock, $deadline, $buffer_ref) // '');
			last;
		}

		# The data plus its CRLF.
		while(length($$buffer_ref) < $size + 2) {
			my $chunk = _read($sock, $deadline);
			last unless defined $chunk && length $chunk;
			$$buffer_ref .= $chunk;
		}
		last if length($$buffer_ref) < $size;

		$body .= substr($$buffer_ref, 0, $size, '');
		$$buffer_ref =~ s/\A$LINE_END//;

		return [ substr($body, 0, $self->{max_size}), 1 ] if length($body) > $self->{max_size};
	}

	return [ $body, 0 ];
}

1;

__END__

=head1 LIMITATIONS

=over 4

=item * HTTP/1.1 only, one request per connection, no redirects, no
compression, no proxy support.  An interim C<100 Continue> response is
returned as if it were the final one.

=item * The host name is resolved again for each connection; see
L<App::WebPerimeterScan::Scope/LIMITATIONS> for why that matters.

=item * An IPv6 literal host is passed to the socket layer as given but the
C<Host> header does not bracket it.

=back

=head1 LICENSE

GPL2

=cut
