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

my @hosts = @{ $scope->hosts };
is(scalar @hosts, 3, 'wildcard is not a concrete scan target');
is_deeply([ sort map { $_->{host} } @hosts ],
	[qw(example.com shop.example.com www.example.com)], 'concrete hosts parsed');

my $port_entry = (grep { $_->{host} eq 'www.example.com' } @hosts)[0];
is($port_entry->{port}, 8443, 'explicit port kept');

my $https_entry = (grep { $_->{host} eq 'shop.example.com' } @hosts)[0];
is($https_entry->{scheme}, 'https', 'scheme kept from URL form');

like(exception { $scope->assert_target_allowed('evil.com') },
	qr/not listed in/, 'out-of-scope host is refused');

is($scope->assert_target_allowed('example.com'), $scope, 'in-scope host is allowed, and the scope returned');

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
is($permitted->assert_target_allowed('127.0.0.1'), $permitted, 'private target allowed with allow_private');

is($https_entry->{port}, undef, 'a URL without a port records no port, so the HTTP-to-HTTPS check runs');

subtest 'URL entries and ports' => sub {
	my ($fh, $file) = tempfile(UNLINK => 1);
	print $fh "https://a.example:8443/\nhttp://b.example/\nc.example:0\nd.example:70000\n";
	close $fh;

	my @warnings;
	local $SIG{__WARN__} = sub { push @warnings, @_ };
	my $s = App::WebPerimeterScan::Scope->new->load_file($file);
	my %by_host = map { $_->{host} => $_ } @{ $s->hosts };

	is($by_host{'a.example'}{port}, 8443, 'an explicit port in a URL is kept');
	is($by_host{'b.example'}{scheme}, 'http', 'the scheme is kept');
	ok(!$by_host{'c.example'} && !$by_host{'d.example'}, 'ports outside 1-65535 are rejected');
	is(scalar @warnings, 2, 'one warning per rejected line');
};

subtest 'private address space' => sub {
	# Literal addresses only, so no test depends on DNS.
	ok(!$scope->is_private_target('192.30.252.1'), '192.30/16 is public (the old mask covered 192/8)');
	ok(!$scope->is_private_target('223.5.5.5'), '223/8 is public unicast, not multicast');
	ok($scope->is_private_target('224.0.0.1'), 'multicast is not a public target');
	ok($scope->is_private_target('192.0.2.7'), 'TEST-NET-1 is refused');
	ok($scope->is_private_target('198.51.100.7'), 'TEST-NET-2 is refused');
	ok($scope->is_private_target('203.0.113.7'), 'TEST-NET-3 is refused');
	ok($scope->is_private_target('198.18.0.1'), 'the benchmarking range is refused');
	ok($scope->is_private_target('100.64.0.1'), 'CGNAT is refused');
	ok($scope->is_private_target('::1'), 'IPv6 loopback is refused');
	ok($scope->is_private_target('fd00::1'), 'IPv6 unique-local is refused');
	ok($scope->is_private_target('fe80::1'), 'IPv6 link-local is refused');
	ok(!$scope->is_private_target('2606:4700::1'), 'a public IPv6 address is allowed');
	ok(!$scope->is_private_target('name.invalid'), 'a name that does not resolve is not private');
};

subtest 'allows' => sub {
	my $wild = App::WebPerimeterScan::Scope->new;
	my ($fh, $file) = tempfile(UNLINK => 1);
	print $fh "127.0.0.1\n8.8.8.8\n";
	close $fh;
	$wild->load_file($file);

	ok(!$wild->allows('127.0.0.1'), 'covered but private is not allowed');
	ok($wild->allows('8.8.8.8'), 'covered and public is allowed');
	ok(!$wild->allows('9.9.9.9'), 'public but not covered is not allowed');
	ok(!$wild->allows(undef), 'undef is not allowed');
};

subtest 'errors' => sub {
	my $missing = '/nonexistent-' . $$ . '/scope.txt';
	my $error = exception { App::WebPerimeterScan::Scope->new->load_file($missing) };
	like($error, qr/Cannot read scope file '\Q$missing\E'/, 'an unreadable file is reported by name');
	like($error, qr/ at \S*scope\.t line/, "the error is reported from the caller's line");

	my ($fh, $empty) = tempfile(UNLINK => 1);
	print $fh "# nothing\n\n";
	close $fh;
	like(exception { App::WebPerimeterScan::Scope->new->load_file($empty) }, qr/no usable hosts/, 'an empty scope is refused');
	ok(!eval { App::WebPerimeterScan::Scope->new(bogus => 1); 1 }, 'an unknown argument is refused');
	is(App::WebPerimeterScan::Scope->new->source, '(none)', 'a new scope has no source');
};

done_testing();
