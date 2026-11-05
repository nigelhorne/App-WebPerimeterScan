package App::WebPerimeterScan::Ports;

use strict;
use warnings;

use Errno qw(EINPROGRESS EWOULDBLOCK);
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use IO::Select;
use Socket qw(AF_INET SOCK_STREAM SOL_SOCKET SO_ERROR inet_aton sockaddr_in);
use Time::HiRes qw(time);

our $VERSION = '0.01';

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

			my $error = getsockopt($sock, SOL_SOCKET, SO_ERROR);
			my $errno = defined $error ? unpack('i', $error) : 1;

			$select->remove($sock);
			delete $by_fd{$fd};

			if($errno == 0) {
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

=head1 LICENSE

GPL2

=cut
