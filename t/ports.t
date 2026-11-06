use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use IO::Socket::INET;
use Test::More;

use App::WebPerimeterScan::Ports;

my $listener = IO::Socket::INET->new(
	LocalAddr => '127.0.0.1',
	LocalPort => 0,
	Listen    => 5,
	ReuseAddr => 1,
	Proto     => 'tcp',
);
plan skip_all => 'cannot bind a loopback listener' unless $listener;

my $open_port = $listener->sockport;

# Bind a port without listening on it: nothing answers there, and because the
# port stays bound the kernel cannot hand it out as the local port of the
# scan's own connection.  Releasing it instead let macOS reuse it that way, so
# the scan connected to itself and the port looked open.
my $closed_socket = IO::Socket::INET->new(
	LocalAddr => '127.0.0.1',
	LocalPort => 0,
	Proto     => 'tcp',
);
plan skip_all => 'could not bind a closed port' unless $closed_socket;

my $closed_port = $closed_socket->sockport;

my $scan = App::WebPerimeterScan::Ports->scan(
	host    => '127.0.0.1',
	ports   => [ $open_port, $closed_port ],
	timeout => 2,
	banner  => 0,
);

is($scan->{error}, undef, 'scan completed');
is_deeply(
	[ map { $_->{port} } @{ $scan->{open} } ],
	[ $open_port ],
	'only the listening port reports as open',
);

my $unresolvable = App::WebPerimeterScan::Ports->scan(
	host => 'this-host-should-not-exist.invalid',
	ports => [80],
	timeout => 1,
	banner => 0,
);
ok($unresolvable->{error}, 'unresolvable host reports an error');

# The serial path is what Windows uses, since it has no fcntl(F_SETFL);
# exercise it here so the fallback cannot rot on the platforms that have it.
{
	local $App::WebPerimeterScan::Ports::NONBLOCKING = 0;

	my $serial = App::WebPerimeterScan::Ports->scan(
		host    => '127.0.0.1',
		ports   => [ $open_port, $closed_port ],
		timeout => 2,
		banner  => 0,
	);

	is($serial->{error}, undef, 'serial fallback completes');
	is_deeply(
		[ map { $_->{port} } @{ $serial->{open} } ],
		[ $open_port ],
		'serial fallback finds only the listening port',
	);
}

close $listener;
close $closed_socket;

ok(scalar @App::WebPerimeterScan::Ports::DEFAULT_PORTS > 0,
	'default port list is populated');

done_testing();
