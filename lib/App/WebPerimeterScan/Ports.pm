package App::WebPerimeterScan::Ports;

use strict;
use warnings;

use Errno qw(EINPROGRESS EWOULDBLOCK);
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use IO::Select;
use IO::Socket::INET ();
use Socket qw(AF_INET SOCK_STREAM SOL_SOCKET SO_ERROR inet_aton sockaddr_in);
use Time::HiRes qw(time);

our $VERSION = '0.001.0';

# F_GETFL and friends are not defined on Windows, where Fcntl dies with "Your
# vendor has not defined Fcntl macro" as soon as the constant is reached.  The
# flags are probed once here, and the parallel batch is only used where they
# exist; everywhere else the scan connects one port at a time instead.
our $NONBLOCKING = eval {
	Fcntl::F_GETFL() + Fcntl::F_SETFL() + Fcntl::O_NONBLOCK() >= 0;
} ? 1 : 0;

# Published services worth knowing about.  Keep this list short: a long list
# is slow and noisy, and this is an attack-surface summary, not nmap.
our @DEFAULT_PORTS = (
	21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
	1433, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
	8888, 9200, 11211, 27017,
);

# Ports that should almost never be reachable from the public internet.
our %RISKY = (
	21    => [ 'critical', 'FTP is unencrypted and frequently allows anonymous access' ],
	23    => [ 'critical', 'Telnet is unencrypted' ],
	445   => [ 'high',     'SMB should never be exposed to the internet' ],
	1433  => [ 'high',     'Microsoft SQL Server should not be internet-facing' ],
	3306  => [ 'high',     'MySQL should not be internet-facing' ],
	3389  => [ 'high',     'RDP is a common ransomware entry point' ],
	5432  => [ 'high',     'PostgreSQL should not be internet-facing' ],
	5900  => [ 'medium',   'VNC is unencrypted and often unauthenticated' ],
	6379  => [ 'high',     'Redis is unauthenticated by default' ],
	9200  => [ 'high',     'Elasticsearch has no authentication by default' ],
	11211 => [ 'high',     'memcached has no authentication at all' ],
	27017 => [ 'high',     'MongoDB has historically shipped without authentication' ],
	993   => [ 'info',     'IMAPS is reachable' ],
	995   => [ 'info',     'POP3S is reachable' ],
	587   => [ 'info',     'Message submission is reachable' ],
	25    => [ 'low',      'SMTP is reachable from the internet' ],
	22    => [ 'low',      'SSH is reachable; confirm it only allows keys and is patched' ],
	3000  => [ 'low',      'A development application server appears to be exposed' ],
	8000  => [ 'low',      'An alternate HTTP port is exposed' ],
	8080  => [ 'low',      'An alternate HTTP port is exposed' ],
	8443  => [ 'low',      'An alternate HTTPS port is exposed' ],
	8888  => [ 'low',      'An alternate HTTP port is exposed' ],
);

sub scan
{
	my ($class, %args) = @_;

	my $host    = $args{host};
	my $ports   = $args{ports} || \@DEFAULT_PORTS;
	my $timeout = $args{timeout} || 3;
	my $banner  = exists $args{banner} ? $args{banner} : 1;

	my $ip = inet_aton($host);
	if(!defined $ip) {
		my @resolved = gethostbyname($host);
		$ip = $resolved[4] if @resolved > 4;
	}
	return { host => $host, open => [], error => "cannot resolve '$host'" }
		unless defined $ip;

	my $proto = getprotobyname('tcp');
	return { host => $host, open => [], error => 'no tcp protocol' } unless $proto;

	my @open = $NONBLOCKING
		? _connect_parallel($ip, $proto, $ports, $timeout)
		: _connect_serial($host, $ports, $timeout);

	@open = sort { $a->{port} <=> $b->{port} } @open;

	if($banner) {
		for my $entry (@open) {
			$entry->{banner} = _banner($host, $entry->{port}, 0.6);
		}
	}

	return {
		host => $host,
		open => \@open,
		error => undef,
	};
}

# SO_ERROR holds the result of a connect: 0 means the handshake completed.
# connect() returning true only means it started, which is how a refused port
# was once reported as open on macOS, so both connect paths ask here.
sub _handshake_ok
{
	my ($sock) = @_;

	my $error = getsockopt($sock, SOL_SOCKET, SO_ERROR);
	my $errno = defined $error ? unpack('i', $error) : 1;

	return $errno == 0 ? 1 : 0;
}

# One non-blocking batch, resolved through a single select.
sub _connect_parallel
{
	my ($ip, $proto, $ports, $timeout) = @_;

	my %by_fd;
	my $select = IO::Select->new;
	my @open;

	for my $port (@{ $ports }) {
		next unless $port =~ /^\d+$/ && $port > 0 && $port < 65_536;

		socket(my $sock, AF_INET, SOCK_STREAM, $proto) or next;
		my $flags = fcntl($sock, F_GETFL, 0);
		fcntl($sock, F_SETFL, $flags | O_NONBLOCK);

		my $address = sockaddr_in($port, $ip);
		my $connected = connect($sock, $address);

		if($connected) {
			push @open, { port => $port + 0, banner => '' };
			close $sock;
			next;
		}

		my $errno = 0 + $!;
		if($errno == EINPROGRESS || $errno == EWOULDBLOCK) {
			my $fd = fileno $sock;
			$by_fd{$fd} = { sock => $sock, port => $port + 0, started => time };
			$select->add($sock);
		} else {
			close $sock;	# refused outright
		}
	}

	my $deadline = time + $timeout;
	while($select->count) {
		my $wait = $deadline - time;
		last if $wait <= 0;

		for my $sock ($select->can_write($wait)) {
			my $fd = fileno $sock;
			my $entry = $by_fd{$fd} or next;

			$select->remove($sock);
			delete $by_fd{$fd};

			if(_handshake_ok($sock)) {
				push @open, { port => $entry->{port}, banner => '' };
				close $sock;
			} else {
				close $sock;
			}
		}
	}

	for my $entry (values %by_fd) {
		close $entry->{sock};
	}

	return @open;
}

# Where the socket flags cannot be set, a batch would simply block on the
# first filtered port, so connect one at a time with a socket timeout.  Slower
# against a firewall, but correct on Windows and on any other platform whose
# fcntl() has no file-status flags.
sub _connect_serial
{
	my ($host, $ports, $timeout) = @_;

	my @open;
	for my $port (@{ $ports }) {
		next unless $port =~ /^\d+$/ && $port > 0 && $port < 65_536;

		my $sock = IO::Socket::INET->new(
			PeerAddr => $host,
			PeerPort => $port,
			Proto    => 'tcp',
			Timeout  => $timeout,
		) or next;

		# IO::Socket::INET can hand back a socket whose connect is still in
		# progress, so a refused port looks open; wait for it to become
		# writable before asking how the handshake ended.
		my $select = IO::Select->new($sock);
		if($select->can_write($timeout) && _handshake_ok($sock)) {
			push @open, { port => $port + 0, banner => '' };
		}
		close $sock;
	}

	return @open;
}

# Best-effort, read-only: many services announce themselves before the
# client says anything (SSH, SMTP, FTP, MySQL).  Silence is a valid answer.
sub _banner
{
	my ($host, $port, $timeout) = @_;

	my $sock = IO::Socket::INET->new(
		PeerAddr => $host,
		PeerPort => $port,
		Proto    => 'tcp',
		Timeout  => $timeout,
	) or return '';

	my $select = IO::Select->new($sock);
	unless($select->can_read($timeout)) {
		close $sock;
		return '';
	}

	my $buffer = '';
	my $read = sysread($sock, $buffer, 200);
	close $sock;

	return '' unless defined $read && $read;
	$buffer =~ s/[\r\n]+/ /g;
	$buffer =~ s/[^\x20-\x7e]//g;
	$buffer =~ s/\s+/ /g;
	$buffer =~ s/^\s+|\s+$//g;

	return substr($buffer, 0, 120);
}

1;

__END__

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

Perl 5.10 or later, with C<Socket> 2.020: the core of 5.10.1 ships 2.018, and
C<SO_ERROR> is what separates a refused connection from an open one.
C<IO::Select> 1.17 and C<IO::Socket::INET> 1.31 are the versions this is
tested against.

The parallel path needs a working C<fcntl(F_SETFL)> and C<O_NONBLOCK>.  Where
they are missing, as on Windows, the scan connects one port at a time
instead.

=head1 LICENSE

GPL2

=cut
