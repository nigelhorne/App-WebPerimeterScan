use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use File::Temp qw(tempfile);
use Test::More;
use Test::Fatal;

use App::WebPerimeterScan::Scope;

my ($fh, $filename) = tempfile(UNLINK => 1);
print $fh <<'SCOPE';
# a comment
example.com
www.example.com:8443
https://shop.example.com/
*.wild.example
this is not a host!!
SCOPE
close $fh;

my $scope = App::WebPerimeterScan::Scope->new;

{
	local $SIG{__WARN__} = sub { };
	$scope->load_file($filename);
}

ok($scope->covers('example.com'), 'exact host is covered');
ok($scope->covers('EXAMPLE.COM.'), 'case and trailing dot are normalised');
ok($scope->covers('sub.wild.example'), 'wildcard covers a sub-domain');
ok($scope->covers('wild.example'), 'wildcard covers the domain itself');
ok(!$scope->covers('evil.com'), 'unrelated host is not covered');
ok(!$scope->covers('notexample.com'), 'suffix match is on label boundary');

my @hosts = $scope->hosts;
is(scalar @hosts, 3, 'wildcard is not a concrete scan target');
is_deeply([ sort map { $_->{host} } @hosts ],
	[qw(example.com shop.example.com www.example.com)], 'concrete hosts parsed');

my $port_entry = (grep { $_->{host} eq 'www.example.com' } @hosts)[0];
is($port_entry->{port}, 8443, 'explicit port kept');

my $https_entry = (grep { $_->{host} eq 'shop.example.com' } @hosts)[0];
is($https_entry->{scheme}, 'https', 'scheme kept from URL form');

like(exception { $scope->assert_target_allowed('evil.com') },
	qr/not listed in/, 'out-of-scope host is refused');

is($scope->assert_target_allowed('example.com'), 1, 'in-scope host is allowed');

ok($scope->is_private_target('127.0.0.1'), 'loopback detected');
ok($scope->is_private_target('10.1.2.3'), 'RFC1918 10/8 detected');
ok($scope->is_private_target('192.168.0.5'), 'RFC1918 192.168/16 detected');
ok(!$scope->is_private_target('8.8.8.8'), 'public address not treated as private');

my $private_scope = App::WebPerimeterScan::Scope->new;
my ($pfh, $pfile) = tempfile(UNLINK => 1);
print $pfh "127.0.0.1\n";
close $pfh;
$private_scope->load_file($pfile);

like(exception { $private_scope->assert_target_allowed('127.0.0.1') },
	qr/private address space/, 'private target refused by default');

my $permitted = App::WebPerimeterScan::Scope->new(allow_private => 1);
$permitted->load_file($pfile);
is($permitted->assert_target_allowed('127.0.0.1'), 1, 'private target allowed with allow_private');

done_testing();
