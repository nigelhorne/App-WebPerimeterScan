use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Test::More;

my @modules = qw(
	App::WebPerimeterScan
	App::WebPerimeterScan::Checks
	App::WebPerimeterScan::Findings
	App::WebPerimeterScan::HTTP
	App::WebPerimeterScan::Ports
	App::WebPerimeterScan::Report
	App::WebPerimeterScan::Scope
	App::WebPerimeterScan::TLS
);

for my $module (@modules) {
	use_ok($module) or BAIL_OUT("Cannot load $module");
}

done_testing();
