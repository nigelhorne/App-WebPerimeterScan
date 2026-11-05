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

# Reserve a port, then release it, so we have an address nothing listens on.
my $closed_port;
for (1 .. 10) {
	my $temp = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => 0,
		Listen    => 5,
		ReuseAddr => 1,
		Proto     => 'tcp',
	) or next;

	my $candidate = $temp->sockport;
	close $temp;
	next if $candidate == $open_port;
	$closed_port = $candidate;
	last;
}
plan skip_all => 'could not reserve a closed port' unless defined $closed_port;

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

close $listener;

ok(scalar @App::WebPerimeterScan::Ports::DEFAULT_PORTS > 0,
	'default port list is populated');

done_testing();
