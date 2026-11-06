package App::WebPerimeterScan::Ports;

use strict;
use warnings;
use autodie qw(:all);

# A refused or filtered port is the answer the scan is looking for, not an
# error, and a non-blocking connect() "fails" with EINPROGRESS by design.
# These builtins therefore keep their ordinary return values.
no autodie qw(socket connect fcntl getsockopt close sysread);

use Errno qw(EINPROGRESS EWOULDBLOCK);
use Fcntl ();
use IO::Select;
use IO::Socket::INET ();
use Params::Get qw(get_params);
use Params::Validate::Strict qw(validate_strict);
use Readonly;
use Socket qw(AF_INET SOCK_STREAM SOL_SOCKET SO_ERROR inet_aton sockaddr_in);
use Sub::Private { mode => 'enforce' };
use Time::HiRes qw(time);

use App::WebPerimeterScan::I18N ();
use parent -norequire, 'App::WebPerimeterScan::I18N';

our $VERSION = '0.001.0';

# Defaults for scan(); a plain hash so Object::Configure or a caller can
# change them.
our %config = (
	timeout        => 3,	# seconds for the whole connect batch
	banner_timeout => 0.6,	# seconds to wait for a service greeting
	banner_bytes   => 200,	# bytes of greeting read
	banner_length  => 120,	# characters of greeting kept after cleaning
);

# F_GETFL and friends are not defined on Windows, where Fcntl dies with "Your
# vendor has not defined Fcntl macro" as soon as the constant is reached.  The
# flags are probed once here, and the parallel batch is only used where they
# exist; everywhere else the scan connects one port at a time instead.  Not
# Readonly: the tests force the serial path with local().
our $NONBLOCKING = eval {
	Fcntl::F_GETFL() + Fcntl::F_SETFL() + Fcntl::O_NONBLOCK() >= 0;
} ? 1 : 0;

# Published services worth knowing about.  Keep this list short: a long list
# is slow and noisy, and this is an attack-surface summary, not nmap.
Readonly::Array our @DEFAULT_PORTS => (
	21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
	1433, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
	8888, 9200, 11211, 27017,
);

# How bad it is for each port to be reachable from the internet.  The reason
# is text, so it lives in the message catalogue under port-open.detail.
Readonly::Hash our %RISKY => (
	21    => 'critical',	# FTP
	23    => 'critical',	# Telnet
	445   => 'high',	# SMB
	1433  => 'high',	# MS SQL
	3306  => 'high',	# MySQL
	3389  => 'high',	# RDP
	5432  => 'high',	# PostgreSQL
	5900  => 'medium',	# VNC
	6379  => 'high',	# Redis
	9200  => 'high',	# Elasticsearch
	11211 => 'high',	# memcached
	27017 => 'high',	# MongoDB
	993   => 'info',	# IMAPS
	995   => 'info',	# POP3S
	587   => 'info',	# submission
	25    => 'low',		# SMTP
	22    => 'low',		# SSH
	3000  => 'low',		# development servers
	8000  => 'low',		# alternate HTTP
	8080  => 'low',
	8443  => 'low',		# alternate HTTPS
	8888  => 'low',
);

Readonly::Scalar my $MIN_PORT => 1;
Readonly::Scalar my $MAX_PORT => 65_535;

# SO_ERROR is an int; 0 means the handshake completed.
Readonly::Scalar my $SO_ERROR_FORMAT => 'i';
Readonly::Scalar my $CONNECTED       => 0;

# Printable ASCII, for cleaning a banner before it reaches a report.
Readonly::Scalar my $UNPRINTABLE => qr/[^\x20-\x7e]/;

=encoding utf8

=head1 NAME

App::WebPerimeterScan::Ports - parallel TCP connect scan

=head1 VERSION

Version 0.001.0

=head1 SYNOPSIS

	my $scan = App::WebPerimeterScan::Ports->scan(host => 'example.com');
	for my $open (@{ $scan->{open} }) {
		print "$open->{port} $open->{banner}\n";
	}

=head1 DESCRIPTION

Opens every socket in one non-blocking batch and waits on a single select,
so a full pass over the default port list costs one timeout rather than one
timeout per port.  A short banner read follows, because an SSH or SMTP
greeting is often the difference between "a port is open" and "this is a
seven-year-old OpenSSH".

=head1 REQUIREMENTS

C<Socket> 2.020: the core of 5.10.1 ships 2.018, and C<SO_ERROR> is what
separates a refused connection from an open one.  C<IO::Select> 1.17 and
C<IO::Socket::INET> 1.31 are the versions this is tested against.

The parallel path needs a working C<fcntl(F_SETFL)> and C<O_NONBLOCK>.  Where
they are missing, as on Windows, the scan connects one port at a time
instead.

=head1 SUBROUTINES/METHODS

=head2 scan

Purpose: find which of a list of TCP ports accept a connection.

Args: named C<host> (required), C<ports> (array reference; default
C<@DEFAULT_PORTS>), C<timeout> (seconds for the whole batch; default 3) and
C<banner> (boolean, read a greeting from each open port; default 1).  A
class method.

Returns: a hash reference: C<host>, C<open> (array reference of
C<< { port => N, banner => TEXT } >>, sorted by port) and C<error> (C<undef>,
or why the scan could not run).  Port numbers outside 1-65535 are ignored.

Side Effects: TCP connections to the host; a second short connection to each
open port when C<banner> is set.

Usage: C<< my $scan = App::WebPerimeterScan::Ports->scan(host => $h, ports => [22, 443]); >>

=head3 EXAMPLE

	my $scan = App::WebPerimeterScan::Ports->scan(
		host => 'example.com', ports => [ 22, 80, 443 ], timeout => 2,
	);
	die "$scan->{error}\n" if $scan->{error};
	print join(', ', map { $_->{port} } @{ $scan->{open} }), "\n";

=head3 API SPECIFICATION

=head4 INPUT

	{
		host    => { type => 'string', min => 1 },
		ports   => { type => 'arrayref', element_type => 'integer', optional => 1 },
		timeout => { type => 'number', min => 0, optional => 1 },
		banner  => { type => 'boolean', optional => 1 },
	}

=head4 OUTPUT

	{
		type => 'hashref',
		schema => {
			host  => { type => 'string' },
			open  => { type => 'arrayref' },
			error => { type => 'string', optional => 1 },
		},
	}

=head3 MESSAGES

Returned in C<error>, not thrown:

	Message                   Meaning / resolution
	------------------------  -------------------------------------------
	cannot resolve 'H'        H has no IPv4 address; check the name.
	no tcp protocol           The system has no "tcp" protocol entry.

=head3 FORMAL SPECIFICATION

	┌─ Scan ──────────────────────────────────────────────
	│ host? : HOST; ports? : ℙ PORT; result! : SCANRESULT
	├─────────────────────────────────────────────────────
	│ resolve(host?) = ∅ ⇒ result!.error ≠ ⊥ ∧ result!.open = ⟨⟩
	│ resolve(host?) ≠ ∅ ⇒
	│   ran(port ∘ result!.open) =
	│       { p : ports? ∩ 1 .. 65535 | handshake(host?, p) completes
	│                                   within timeout }
	│   ∧ result!.open is sorted by port
	└─────────────────────────────────────────────────────

=head3 PSEUDOCODE

	validate the arguments; apply defaults from %config
	resolve the host to an IPv4 address, or return an error
	keep only port numbers in 1..65535
	connect to them all in parallel where fcntl allows, else one at a time
	sort the open ports
	read a greeting from each open port if banners were asked for

=cut

sub scan
{
	my $class = shift;

	my $args = validate_strict(
		schema => {
			host    => { type => 'string', min => 1 },
			ports   => { type => 'arrayref', element_type => 'integer', optional => 1 },
			timeout => { type => 'number', min => 0, optional => 1 },
			banner  => { type => 'boolean', optional => 1, default => 1 },
		},
		input => get_params(undef, \@_) // {},
	);

	my $host    = $args->{host};
	my $timeout = $args->{timeout} || $config{timeout};
	my @ports   = grep { $_ >= $MIN_PORT && $_ <= $MAX_PORT } @{ $args->{ports} || \@DEFAULT_PORTS };

	# inet_aton resolves names as well as parsing dotted quads.
	my $ip = inet_aton($host);
	return _result($host, [], $class->i18n('ports.unresolvable', { host => $host })) unless defined $ip;

	my $proto = getprotobyname('tcp');
	return _result($host, [], $class->i18n('ports.no_tcp')) unless $proto;

	my $open = $NONBLOCKING
		? _connect_parallel($ip, $proto, \@ports, $timeout)
		: _connect_serial($host, \@ports, $timeout);
	my @sorted = sort { $a->{port} <=> $b->{port} } @{$open};

	$_->{banner} = _banner($host, $_->{port}) for $args->{banner} ? @sorted : ();

	return _result($host, \@sorted, undef);
}

# _result
# Purpose:     the hash scan() returns, built in one place.
# Entry:       $open is an arrayref; $error is a string or undef.
# Exit:        hashref of host, open, error.
# Side effects: none.
sub _result :Private
{
	my ($host, $open, $error) = @_;

	return { host => $host, open => $open, error => $error };
}

# _open_port
# Purpose:     the record for one open port, built in one place.
# Entry:       $port is numeric.
# Exit:        hashref of port and an empty banner.
# Side effects: none.
sub _open_port :Private
{
	my ($port) = @_;

	return { port => $port + 0, banner => '' };
}

# _handshake_ok
# Purpose:     did the connect on this socket complete?
# Entry:       $sock has had connect() called on it and is writable.
# Exit:        1 if SO_ERROR is 0, else 0.
# Side effects: none.
#
# SO_ERROR holds the result of a connect: 0 means the handshake completed.
# connect() returning true only means it started, which is how a refused
# port was once reported as open on macOS, so both connect paths ask here.
sub _handshake_ok :Private
{
	my ($sock) = @_;

	my $error = getsockopt($sock, SOL_SOCKET, SO_ERROR);

	return (defined $error && unpack($SO_ERROR_FORMAT, $error) == $CONNECTED) ? 1 : 0;
}

# _connect_parallel
# Purpose:     connect to every port in one non-blocking batch.
# Entry:       $ip is a packed IPv4 address; $NONBLOCKING is true.
# Exit:        arrayref of open-port records, unsorted.
# Side effects: opens and closes one socket per port.
sub _connect_parallel :Private
{
	my ($ip, $proto, $ports, $timeout) = @_;

	my (%pending, @open);
	my $select = IO::Select->new;

	# Start every connect.  Most return EINPROGRESS and are resolved by
	# the select loop below; a loopback connect may finish at once.
	for my $port (@{$ports}) {
		socket(my $sock, AF_INET, SOCK_STREAM, $proto) or next;
		my $flags = fcntl($sock, Fcntl::F_GETFL(), 0) // 0;
		fcntl($sock, Fcntl::F_SETFL(), $flags | Fcntl::O_NONBLOCK());

		if(connect($sock, sockaddr_in($port, $ip))) {
			push @open, _open_port($port);
			close $sock;
		} elsif($! == EINPROGRESS || $! == EWOULDBLOCK) {
			$pending{ fileno $sock } = { sock => $sock, port => $port };
			$select->add($sock);
		} else {
			close $sock;	# refused outright
		}
	}

	# A socket becomes writable when its connect finishes either way;
	# SO_ERROR says which way.
	my $deadline = time + $timeout;
	while($select->count && (my $wait = $deadline - time) > 0) {
		for my $sock ($select->can_write($wait)) {
			my $entry = delete $pending{ fileno $sock } or next;
			$select->remove($sock);
			push @open, _open_port($entry->{port}) if _handshake_ok($sock);
			close $sock;
		}
	}

	# Whatever is still pending was filtered: no answer within the timeout.
	close $_->{sock} for values %pending;

	return \@open;
}

# _connect_serial
# Purpose:     connect to one port at a time, for platforms without fcntl
#              flags (Windows).  Slower against a firewall, but correct.
# Entry:       $host is a name or address.
# Exit:        arrayref of open-port records.
# Side effects: opens and closes one socket per port.
sub _connect_serial :Private
{
	my ($host, $ports, $timeout) = @_;

	my @open;
	for my $port (@{$ports}) {
		my $sock = IO::Socket::INET->new(
			PeerAddr => $host,
			PeerPort => $port,
			Proto    => 'tcp',
			Timeout  => $timeout,
		) or next;

		# IO::Socket::INET can hand back a socket whose connect is still in
		# progress, so a refused port looks open; wait for it to become
		# writable before asking how the handshake ended.
		push @open, _open_port($port)
			if IO::Select->new($sock)->can_write($timeout) && _handshake_ok($sock);
		close $sock;
	}

	return \@open;
}

# _banner
# Purpose:     read whatever a service says first (SSH, SMTP, FTP, MySQL).
# Entry:       $port is known to be open.
# Exit:        printable, single-line text; '' when the service is silent.
# Side effects: one short TCP connection.  Read-only: nothing is sent.
sub _banner :Private
{
	my ($host, $port) = @_;

	my $sock = IO::Socket::INET->new(
		PeerAddr => $host,
		PeerPort => $port,
		Proto    => 'tcp',
		Timeout  => $config{banner_timeout},
	) or return '';

	# Silence is a valid answer: many services wait for the client.
	my $buffer = '';
	sysread($sock, $buffer, $config{banner_bytes})
		if IO::Select->new($sock)->can_read($config{banner_timeout});
	close $sock;

	# One line of printable ASCII, so a banner cannot corrupt a report.
	$buffer =~ s/[\r\n]+/ /g;
	$buffer =~ s/$UNPRINTABLE//g;
	$buffer =~ s/\s+/ /g;
	$buffer =~ s/\A\s+|\s+\z//g;

	return substr($buffer, 0, $config{banner_length});
}

1;

__END__

=head1 LIMITATIONS

=over 4

=item * IPv4 only: the host is resolved with C<inet_aton>, so a host that
is reachable only over IPv6 reports an error and a dual-stack host is only
scanned on its IPv4 address.

=item * A connect scan cannot tell "filtered" from "closed": both are simply
absent from C<open>.

=item * The banner is read on a second connection, so a service that only
answers the first connection, or rate-limits connections, may show none.

=item * The whole batch shares one timeout, so a very long port list on a
slow link can time out ports that a longer wait would have found open.

=back

=head1 LICENSE

GPL2

=cut
