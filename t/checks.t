use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Test::More;

use App::WebPerimeterScan::Checks;
use App::WebPerimeterScan::Findings;

sub response
{
	my (%args) = @_;

	return {
		status      => $args{status} // 200,
		headers     => $args{headers} // {},
		body        => $args{body} // '',
		set_cookie  => $args{set_cookie} // [],
		content_type => 'text/html',
	};
}

sub ids
{
	my ($findings) = @_;

	return map { $_->{id} => 1 } $findings->all;
}

sub run_page
{
	my (%args) = @_;

	my $findings = App::WebPerimeterScan::Findings->new;
	App::WebPerimeterScan::Checks::check_page(
		$findings,
		host => $args{host} // 'example.com',
		url  => $args{url}  // 'https://example.com/',
		res  => $args{res},
	);

	return $findings;
}

{
	my $findings = run_page(res => response());
	my %ids = ids($findings);

	ok($ids{'hsts-missing'}, 'missing HSTS reported');
	ok($ids{'csp-missing'}, 'missing CSP reported');
	ok($ids{'clickjacking'}, 'missing frame protection reported');
	ok($ids{'nosniff-missing'}, 'missing nosniff reported');
	ok($ids{'referrer-policy-missing'}, 'missing Referrer-Policy reported');
	ok($ids{'permissions-policy-missing'}, 'missing Permissions-Policy reported');
	is($findings->count, 6, 'six header findings on a bare HTTPS page');
}

{
	my $findings = run_page(res => response(
		headers => {
			'strict-transport-security' => ['max-age=31536000; includeSubDomains'],
			'content-security-policy'   => ["default-src 'self'; frame-ancestors 'none'"],
			'x-content-type-options'    => ['nosniff'],
			'referrer-policy'           => ['strict-origin-when-cross-origin'],
			'permissions-policy'        => ['camera=()'],
			'server'                    => ['nginx'],
		},
		body => '<html><head><title>ok</title></head><body>hello</body></html>',
	));

	is($findings->count, 0, 'hardened page produces no findings');
}

{
	my $findings = run_page(url => 'http://example.com/', res => response());
	my %ids = ids($findings);
	ok(!$ids{'hsts-missing'}, 'HSTS not required on a plain HTTP page');
	ok($ids{'csp-missing'}, 'CSP still checked on plain HTTP');
}

{
	my $findings = run_page(res => response(
		headers => { 'x-powered-by' => ['PHP/8.2.20'] },
	));
	my %ids = ids($findings);
	ok($ids{'php2shell'}, 'vulnerable PHP version flagged');
	my ($php) = grep { $_->{id} eq 'php2shell' } $findings->all;
	is($php->{severity}, 'critical', 'PHP2Shell is critical');
	like($php->{detail}, qr/8\.2\.35/, 'detail names the fix level');
}

{
	my $findings = run_page(res => response(
		headers => { 'x-powered-by' => ['PHP/8.4.27'] },
	));
	my %ids = ids($findings);
	ok(!$ids{'php2shell'}, 'patched PHP version not flagged');
}

{
	my $findings = run_page(res => response(
		headers => { 'x-powered-by' => ['PHP/5.6.40'] },
	));
	my %ids = ids($findings);
	ok($ids{'php2shell'}, 'end-of-life PHP flagged');
}

{
	my $findings = run_page(res => response(
		set_cookie => ['PHPSESSID=abc123; path=/; HttpOnly'],
	));
	my ($cookie) = grep { $_->{id} eq 'cookie-flags' } $findings->all;
	ok($cookie, 'cookie flags reported');
	like($cookie->{title}, qr/Secure/, 'missing Secure reported');
	is($cookie->{severity}, 'medium', 'missing Secure is medium');
}

{
	my $findings = run_page(res => response(
		set_cookie => ['pref=dark; Path=/; Secure; HttpOnly; SameSite=Lax'],
	));
	my %ids = ids($findings);
	ok(!$ids{'cookie-flags'}, 'fully flagged cookie not reported');
}

{
	my $findings = run_page(res => response(
		body => '<script src="http://cdn.example.net/app.js"></script>',
	));
	my %ids = ids($findings);
	ok($ids{'mixed-content-active'}, 'active mixed content reported');
}

{
	my $findings = run_page(res => response(
		body => '<img src="http://cdn.example.net/logo.png">',
	));
	my %ids = ids($findings);
	ok($ids{'mixed-content-passive'}, 'passive mixed content reported');
	ok(!$ids{'mixed-content-active'}, 'passive content is not called active');
}

{
	my $findings = run_page(res => response(
		status => 500,
		body   => 'Warning: mysql_fetch_assoc() expects parameter 1 to be resource in /var/www/app.php on line 12',
	));
	my %ids = ids($findings);
	ok($ids{'error-disclosure'}, 'verbose error output reported');
}

{
	my $findings = run_page(res => response(
		body => '<title>Index of /backup</title>',
	));
	my %ids = ids($findings);
	ok($ids{'directory-listing'}, 'directory listing reported');
}

{
	my $findings = App::WebPerimeterScan::Findings->new;
	App::WebPerimeterScan::Checks::check_ports($findings,
		host => 'example.com',
		scan => {
			open => [
				{ port => 80,   banner => '' },
				{ port => 22,   banner => 'SSH-2.0-OpenSSH_7.4' },
				{ port => 3306, banner => '' },
			],
		},
	);
	my %ids = ids($findings);
	ok($ids{'port-open-3306'}, 'internet-facing database port reported');
	ok($ids{'port-open-22'}, 'SSH reported as low');
	ok($ids{'outdated-ssh-banner'}, 'old OpenSSH banner reported');
	ok(!$ids{'port-open-80'}, 'HTTP port not reported as a finding');
	ok(!$ids{'ports-other-open'}, 'no unexpected-port finding');

	my ($mysql) = grep { $_->{id} eq 'port-open-3306' } $findings->all;
	is($mysql->{severity}, 'high', 'database port is high');
}

{
	my $findings = App::WebPerimeterScan::Findings->new;
	App::WebPerimeterScan::Checks::check_tls($findings,
		host => 'example.com',
		tls  => {
			ok        => 1,
			protocol  => 'TLSv1_2',
			cipher    => 'ECDHE-RSA-AES128-GCM-SHA256',
			protocols => ['TLSv1', 'TLSv1_2'],
			days_left => 10,
		},
	);
	my %ids = ids($findings);
	ok($ids{'tls-legacy-protocol'}, 'deprecated protocol reported');
	ok($ids{'tls-expiring'}, 'expiring certificate reported');

	my ($expiring) = grep { $_->{id} eq 'tls-expiring' } $findings->all;
	is($expiring->{severity}, 'high', 'under 14 days is high');
}

{
	my $findings = App::WebPerimeterScan::Findings->new;
	App::WebPerimeterScan::Checks::check_tls($findings,
		host => 'example.com',
		tls  => { ok => 0, error => 'connect failed: timeout' },
	);
	my %ids = ids($findings);
	ok($ids{'tls-unavailable'}, 'failed handshake reported');
}

{
	my $findings = App::WebPerimeterScan::Findings->new;
	App::WebPerimeterScan::Checks::check_cors($findings,
		host => 'example.com',
		url  => 'https://example.com/',
		res  => {
			headers => {
				'access-control-allow-origin'      => ['*'],
				'access-control-allow-credentials' => ['true'],
			},
		},
	);
	my ($cors) = grep { $_->{id} eq 'cors-misconfiguration' } $findings->all;
	ok($cors, 'permissive CORS reported');
	is($cors->{severity}, 'high', 'wildcard with credentials is high');
}

{
	my $findings = App::WebPerimeterScan::Findings->new;
	App::WebPerimeterScan::Checks::check_cors($findings,
		host => 'example.com',
		url  => 'https://example.com/',
		res  => { headers => { 'access-control-allow-origin' => ['https://other.example'] } },
	);
	is($findings->count, 0, 'a fixed allowlist origin is not reported');
}

{
	my $findings = App::WebPerimeterScan::Findings->new;
	App::WebPerimeterScan::Checks::check_methods($findings,
		host => 'example.com',
		url  => 'https://example.com/',
		res  => { headers => { allow => ['GET,HEAD,POST,TRACE'] } },
	);
	my %ids = ids($findings);
	ok($ids{'trace-enabled'}, 'TRACE reported');
}

{
	my $fingerprint = App::WebPerimeterScan::Checks::fingerprint(
		response(body => 'not found'),
	);
	is($fingerprint, App::WebPerimeterScan::Checks::fingerprint(response(body => 'not found')),
		'fingerprint is stable for identical responses');
	isnt($fingerprint, App::WebPerimeterScan::Checks::fingerprint(response(body => 'something else')),
		'fingerprint differs for different bodies');
}

done_testing();
