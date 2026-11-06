use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Test::More;

use Time::Local qw(timegm);

use App::WebPerimeterScan::TLS;

# IO::Socket::SSL has returned certificate names both ways: as a single
# string, and as a hash of fields whose values are array references.  Reading
# either shape as an empty name made subject and issuer compare equal, so
# every certificate was reported as self-signed.
is(App::WebPerimeterScan::TLS::_name('/CN=example.com'), '/CN=example.com',
	'a name given as one string is kept as it is');
is(App::WebPerimeterScan::TLS::_name({ commonName => ['example.com'] }), 'example.com',
	'a name given as a hash of array references is joined');
is(App::WebPerimeterScan::TLS::_name({ commonName => 'example.com' }), 'example.com',
	'a plain scalar field is accepted too');
is(App::WebPerimeterScan::TLS::_name({}), 'unknown',
	'a name with no usable fields says so');
is(App::WebPerimeterScan::TLS::_name(undef), '',
	'a missing name is empty, not unknown');

my $subject = App::WebPerimeterScan::TLS::_name('/CN=example.com');
my $issuer  = App::WebPerimeterScan::TLS::_name('/C=US/O=SSL Corporation/CN=Cloudflare TLS Issuing ECC CA 3');
isnt($subject, $issuer, 'a certificate with a separate issuer does not look self-signed');

is(App::WebPerimeterScan::TLS::_parse_asn1_time('Dec 25 22:56:35 2026 GMT'),
	timegm(35, 56, 22, 25, 11, 2026), 'notAfter is parsed as UTC');
is(App::WebPerimeterScan::TLS::_parse_asn1_time('garbage'), undef,
	'unparsable dates are rejected');
is(App::WebPerimeterScan::TLS::_parse_asn1_time('Xyz  1 00:00:00 2027 GMT'), undef,
	'an unknown month is rejected');
is(App::WebPerimeterScan::TLS::_parse_asn1_time(' Dec 25 22:56:35 2026 GMT'),
	timegm(35, 56, 22, 25, 11, 2026), 'leading white space is tolerated');
is(App::WebPerimeterScan::TLS::_parse_asn1_time('2026-12-25T22:56:35Z'),
	timegm(35, 56, 22, 25, 11, 2026), 'the ISO 8601 form is parsed too');

# This machine's IO::Socket::SSL has no not_after field, and skipping the
# expiry checks there would have hidden an expired certificate.
{
	package Fake::TLS;

	sub new { bless {}, shift }
	sub peer_certificate { die "invalid argument for peer_certificate\n" }
	sub _get_ssl_object { undef }
}
{
	package Fake::TLS::Dated;

	our @ISA = ('Fake::TLS');
	sub peer_certificate { 'Dec 25 22:56:35 2026 GMT' }
}

is(App::WebPerimeterScan::TLS::_not_after(Fake::TLS->new()), undef,
	'an unreadable expiry stays unknown instead of being fatal');
is(App::WebPerimeterScan::TLS::_not_after(Fake::TLS::Dated->new()),
	'Dec 25 22:56:35 2026 GMT', 'a build that does offer not_after is used as it is');

done_testing();
