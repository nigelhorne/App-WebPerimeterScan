package App::WebPerimeterScan::TLS;

use strict;
use warnings;

use IO::Socket::SSL;
use Net::SSLeay ();
use Time::HiRes qw(time);
use Time::Local qw(timegm);

our $VERSION = '0.01';

my %MONTH = (
	Jan => 0, Feb => 1, Mar => 2,  Apr => 3,  May => 4,  Jun => 5,
	Jul => 6, Aug => 7, Sep => 8,  Oct => 9,  Nov => 10, Dec => 11,
);

# Which protocol versions the server will still negotiate.  Anything below
# TLS 1.2 is deprecated by RFC 8996.
my @PROBE_VERSIONS = qw(TLSv1 TLSv1_1 TLSv1_2 TLSv1_3);

sub inspect
{
	my ($class, %args) = @_;

	my $host    = $args{host};
	my $port    = $args{port} || 443;
	my $timeout = $args{timeout} || 10;

	my $result = { host => $host, port => $port, protocols => [] };

	my $sock = _connect($host, $port, $timeout);
	unless($sock) {
		$result->{error} = $IO::Socket::SSL::SSL_ERROR || "$!";
		return $result;
	}

	$result->{ok}         = 1;
	$result->{protocol}   = $sock->get_sslversion // '';
	$result->{cipher}     = $sock->get_cipher // '';
	$result->{self_signed} = _self_signed($sock);

	if(my $subject = eval { $sock->peer_certificate('subject') }) {
		$result->{subject} = _name($subject);
	}
	if(my $issuer = eval { $sock->peer_certificate('issuer') }) {
		$result->{issuer} = _name($issuer);
	}
	if(defined(my $not_after = _not_after($sock))) {
		$result->{not_after} = $not_after;
		if(defined(my $epoch = _parse_asn1_time($not_after))) {
			$result->{expires_at} = $epoch;
			$result->{days_left}  = int(( $epoch - time ) / 86_400);
		}
	}
	if(my $fingerprint = eval { $sock->peer_certificate('fingerprint') }) {
		$result->{fingerprint} = $fingerprint;
	}

	close $sock;

	# Verification is a separate handshake: the inspection socket above
	# deliberately does not verify, so a broken chain cannot hide a site.
	$result->{verify_error} = _verify($host, $port, $timeout);

	for my $version (@PROBE_VERSIONS) {
		my $probe = _connect($host, $port, $timeout, $version) or next;
		push @{ $result->{protocols} }, $version;
		close $probe;
	}

	return $result;
}

sub _connect
{
	my ($host, $port, $timeout, $version) = @_;

	my %args = (
		PeerHost        => $host,
		PeerPort        => $port,
		Timeout         => $timeout,
		SSL_hostname    => $host,
		SSL_verify_mode => 0,
	);
	$args{SSL_version} = $version if $version;

	return IO::Socket::SSL->new(%args);
}

sub _verify
{
	my ($host, $port, $timeout) = @_;

	my $sock = IO::Socket::SSL->new(
		PeerHost           => $host,
		PeerPort           => $port,
		Timeout            => $timeout,
		SSL_hostname       => $host,
		SSL_verify_mode    => 1,
		SSL_verifycn_name  => $host,
		SSL_verifycn_scheme => 'http',
	);

	if($sock) {
		close $sock;
		return undef;
	}

	my $error = $IO::Socket::SSL::SSL_ERROR;
	return defined $error && length $error ? $error : 'certificate verification failed';
}

sub _self_signed
{
	my ($sock) = @_;

	my $subject = eval { $sock->peer_certificate('subject') } or return 0;
	my $issuer  = eval { $sock->peer_certificate('issuer') }  or return 0;

	return _name($subject) eq _name($issuer) ? 1 : 0;
}

sub _name
{
	my ($name) = @_;

	# Some IO::Socket::SSL builds return the whole name as one string,
	# others as a hash of fields whose values are array references.  Both
	# shapes are accepted: reporting an empty name for one of them made
	# subject and issuer compare equal, which turned every certificate into
	# a self-signed one.
	return '' unless defined $name;
	return $name if !ref $name;
	return '' unless ref $name eq 'HASH';

	my @parts;
	for my $key (qw(commonName organizationName organizationalUnitName countryName)) {
		my $value = $name->{$key};
		next unless defined $value;
		$value = $value->[0] if ref $value eq 'ARRAY';
		push @parts, $value if defined $value && !ref $value && length $value;
	}

	return join(', ', @parts) || 'unknown';
}

# notAfter as a date string.  peer_certificate() exposes only a handful of
# fields, and where not_after is not one of them the expiry checks used to be
# skipped; the certificate itself is still reachable through Net::SSLeay.
sub _not_after
{
	my ($sock) = @_;

	my $not_after = eval { $sock->peer_certificate('not_after') };
	return $not_after if defined $not_after && !ref $not_after && length $not_after;

	my $ssl = eval { $sock->_get_ssl_object } or return undef;
	my $x509 = eval { Net::SSLeay::get_peer_certificate($ssl) } or return undef;
	my $asn1 = eval { Net::SSLeay::X509_get_notAfter($x509) };
	return undef unless defined $asn1;

	my $string = eval { Net::SSLeay::P_ASN1_TIME_put2string($asn1) };
	if(!defined $string || !defined _parse_asn1_time($string)) {
		$string = eval { Net::SSLeay::P_ASN1_TIME_get_isotime($asn1) };
	}
	eval { Net::SSLeay::X509_free($x509) };

	return undef unless defined $string;
	$string =~ s/\A\s+//;

	return defined _parse_asn1_time($string) ? $string : undef;
}

# "Jun  1 12:00:00 2027 GMT" -> epoch.  ASN.1 times are always UTC.
sub _parse_asn1_time
{
	my ($string) = @_;

	return undef unless defined $string;

	# Net::SSLeay can also hand back ISO 8601: 2026-12-25T22:56:35Z
	if($string =~ /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/) {
		return eval { timegm($6, $5, $4, $3, $2 - 1, $1) };
	}

	return undef unless $string =~ /^\s*([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})/;

	my ($mon, $day, $hour, $min, $sec, $year) = ($1, $2, $3, $4, $5, $6);
	return undef unless exists $MONTH{$mon};

	my $epoch = eval { timegm($sec, $min, $hour, $day, $MONTH{$mon}, $year) };

	return $epoch;
}

1;

__END__

=head1 NAME

App::WebPerimeterScan::TLS - certificate and protocol inspection

=head1 SYNOPSIS

	my $tls = App::WebPerimeterScan::TLS->inspect(host => 'example.com', port => 443);
	printf "expires in %d days using %s\n", $tls->{days_left}, $tls->{protocol};

=head1 DESCRIPTION

Performs four independent handshakes: one to read the certificate and the
negotiated cipher, one with verification enabled to see whether a browser
would trust the chain, and one per protocol version to see which of TLS 1.0,
1.1, 1.2 and 1.3 the server still accepts.

=head1 LICENSE

GPL2

=cut
