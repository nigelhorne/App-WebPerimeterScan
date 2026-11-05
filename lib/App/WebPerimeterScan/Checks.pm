package App::WebPerimeterScan::Checks;

use strict;
use warnings;

use Digest::MD5 qw(md5_hex);

use App::WebPerimeterScan::Ports ();

our $VERSION = '0.01';

# A reserved TLD (RFC 2606) so the CORS probe can never be mistaken for a
# real origin, and can never resolve to anything.
my $PROBE_ORIGIN = 'https://ws-probe.invalid';

# PHP versions at or above these are fixed for PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619).
my %PHP2SHELL_FIXED = (
	'8.5' => '8.5.12',
	'8.4' => '8.4.27',
	'8.3' => '8.3.36',
	'8.2' => '8.2.35',
);

# Well-known paths that should never be served.  The match regexp is what
# turns "the server returned 200" into "the file is really there": a SPA that
# answers 200 to everything must not produce twenty findings.
my @PROBES = (
	{
		id       => 'git-exposed',
		path     => '/.git/config',
		severity => 'critical',
		title    => 'Exposed Git repository metadata',
		match    => qr/\[core\]|repositoryformatversion/,
		detail   => 'The .git directory is being served. Source code, commit history and any credentials ever committed can be reconstructed from it.',
		fix      => 'Deny requests to /.git/ at the web server, and deploy with the repository outside the document root.',
		reference => 'https://cwe.mitre.org/data/definitions/538.html',
	},
	{
		id       => 'git-head',
		path     => '/.git/HEAD',
		severity => 'high',
		title    => 'Exposed Git HEAD',
		match    => qr/\Aref:\s+refs\//,
		detail   => 'A Git ref file is readable, which confirms the repository is exposed.',
		fix      => 'Deny requests to /.git/ at the web server.',
	},
	{
		id       => 'svn-exposed',
		path     => '/.svn/entries',
		severity => 'high',
		title    => 'Exposed Subversion metadata',
		match    => qr/^\d+\s*$/m,
		detail   => 'Subversion administrative files are readable.',
		fix      => 'Deny requests to /.svn/ at the web server.',
	},
	{
		id       => 'env-exposed',
		path     => '/.env',
		severity => 'critical',
		title    => 'Exposed environment file',
		match    => qr/^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S/m,
		detail   => 'A dotenv file is downloadable. These usually hold database passwords, API keys and application secrets.',
		fix      => 'Serve only the application entry point: deny dotfiles at the web server and keep configuration above the document root.',
		reference => 'https://cwe.mitre.org/data/definitions/200.html',
	},
	{
		id       => 'htpasswd-exposed',
		path     => '/.htpasswd',
		severity => 'critical',
		title    => 'Exposed password file',
		match    => qr/^[^:\s]+:\$?(?:apr1|2y|1|5|6|\{SHA\})/m,
		detail   => 'An htpasswd file is downloadable, so password hashes can be taken offline and cracked.',
		fix      => 'Store password files outside the document root and deny access to dotfiles.',
	},
	{
		id       => 'htaccess-exposed',
		path     => '/.htaccess',
		severity => 'medium',
		title    => 'Exposed .htaccess',
		match    => qr/<IfModule|RewriteEngine|Options\s+[-+]/i,
		detail   => 'Server configuration is readable and reveals internal rewrite targets and module versions.',
		fix      => 'Deny access to dotfiles at the web server.',
	},
	{
		id       => 'web-config-exposed',
		path     => '/web.config',
		severity => 'high',
		title    => 'Exposed web.config',
		match    => qr/<configuration/i,
		detail   => 'An IIS configuration file is readable and may contain connection strings.',
		fix      => 'Deny access to web.config.',
	},
	{
		id       => 'php-config-backup',
		path     => '/wp-config.php.bak',
		severity => 'critical',
		title    => 'Exposed WordPress configuration backup',
		match    => qr/DB_PASSWORD|DB_NAME|AUTH_KEY/,
		detail   => 'A backup copy of wp-config.php is downloadable, exposing database credentials and salts.',
		fix      => 'Remove backup copies from the document root and deny requests for .bak/.old/.orig files.',
	},
	{
		id       => 'sql-dump-exposed',
		path     => '/backup.sql',
		severity => 'critical',
		title    => 'Exposed database dump',
		match    => qr/CREATE TABLE|INSERT INTO/i,
		detail   => 'A database dump is downloadable, which is usually a complete copy of the application data.',
		fix      => 'Remove dumps from the web root and store backups off the web server.',
		reference => 'https://cwe.mitre.org/data/definitions/538.html',
	},
	{
		id       => 'ds-store-exposed',
		path     => '/.DS_Store',
		severity => 'low',
		title    => 'Exposed .DS_Store',
		match    => qr/\x00\x00\x00\x01Bud1/,
		detail   => 'A macOS folder index is readable, which leaks the names of files (sometimes files that are otherwise unreachable) in that directory.',
		fix      => 'Deny dotfiles at the web server and stop deploying macOS metadata.',
	},
	{
		id       => 'server-status-exposed',
		path     => '/server-status',
		severity => 'high',
		title    => 'Apache server-status is public',
		match    => qr/Apache Server Status|requests currently being processed/i,
		detail   => 'mod_status is reachable, exposing internal URLs, client addresses and server load.',
		fix      => 'Restrict /server-status with Require ip on localhost, or disable mod_status.',
	},
	{
		id       => 'server-info-exposed',
		path     => '/server-info',
		severity => 'medium',
		title    => 'Apache server-info is public',
		match    => qr/Apache Server Information|Server Settings/i,
		detail   => 'mod_info is reachable and publishes the full module configuration.',
		fix      => 'Restrict /server-info with Require ip on localhost, or disable mod_info.',
	},
	{
		id       => 'phpinfo-exposed',
		path     => '/phpinfo.php',
		severity => 'high',
		title    => 'phpinfo() is public',
		match    => qr/PHP Version|phpinfo\(\)|Configuration File \(php\.ini\)/i,
		detail   => 'A phpinfo page leaks absolute paths, loaded extensions, environment variables and sometimes credentials.',
		fix      => 'Delete phpinfo scripts from production.',
	},
	{
		id       => 'spring-actuator-exposed',
		path     => '/actuator/env',
		severity => 'critical',
		title    => 'Spring Boot actuator environment is public',
		match    => qr/"propertySources"|"activeProfiles"/,
		detail   => 'The actuator env endpoint is reachable and commonly exposes datasource credentials and API keys.',
		fix      => 'Require authentication on /actuator/**, and only expose health and info.',
	},
	{
		id       => 'spring-health-exposed',
		path     => '/actuator/health',
		severity => 'low',
		title    => 'Spring Boot actuator health is public',
		match    => qr/"status"\s*:\s*"(?:UP|DOWN)"/,
		detail   => 'Health detail is public. This is minor on its own but confirms a Spring Boot management surface.',
		fix      => 'Expose only the health endpoint, and set management.endpoint.health.show-details=never.',
	},
	{
		id       => 'composer-json-exposed',
		path     => '/composer.json',
		severity => 'low',
		title    => 'composer.json is public',
		match    => qr/"require"\s*:|"autoload"\s*:/,
		detail   => 'Dependency pins are readable, which tells an attacker exactly which versions to try.',
		fix      => 'Deny access to composer.json and composer.lock.',
	},
	{
		id       => 'package-json-exposed',
		path     => '/package.json',
		severity => 'low',
		title    => 'package.json is public',
		match    => qr/"dependencies"\s*:|"devDependencies"\s*:/,
		detail   => 'Dependency pins are readable, which tells an attacker exactly which versions to try.',
		fix      => 'Deny access to package.json and package-lock.json.',
	},
	{
		id       => 'crossdomain-xml',
		path     => '/crossdomain.xml',
		severity => 'medium',
		title    => 'Permissive crossdomain.xml',
		match    => qr/allow-access-from\s+domain\s*=\s*"\*"/,
		detail   => 'A wildcard Flash cross-domain policy lets any site read responses from this origin (still honoured by some legacy clients).',
		fix      => 'Remove crossdomain.xml, or restrict allow-access-from to specific trusted domains.',
	},
);

sub check_page
{
	my ($findings, %args) = @_;

	my $host = $args{host};
	my $url  = $args{url};
	my $res  = $args{res};

	return unless $res && !$res->{error};

	my $headers   = $res->{headers} || {};
	my $is_https  = $url =~ m{^https://}i ? 1 : 0;
	my $body      = $res->{body} // '';

	my $get = sub {
		my $name = lc $_[0];
		return $headers->{$name} ? $headers->{$name}[-1] : undef;
	};

	my $hsts = $get->('strict-transport-security');
	my $csp  = $headers->{'content-security-policy'}
		? join('; ', @{ $headers->{'content-security-policy'} })
		: undef;
	my $xfo  = $get->('x-frame-options');
	my $xcto = $get->('x-content-type-options');

	# HSTS is only meaningful over HTTPS.
	if($is_https) {
		if(!defined $hsts) {
			$findings->add(
				id => 'hsts-missing', severity => 'medium',
				host => $host, url => '',
				title => 'Strict-Transport-Security header is missing',
				detail => 'Without HSTS a user who types the bare hostname makes one plaintext request, which is enough for a network attacker to intercept the session.',
				evidence => 'No Strict-Transport-Security header on ' . $url,
				fix => 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains on all HTTPS responses.',
				reference => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
			);
		} elsif($hsts =~ /max-age\s*=\s*"?(\d+)/i) {
			my $max_age = $1;
			if($max_age < 15_552_000) {
				$findings->add(
					id => 'hsts-short-max-age', severity => 'low',
					host => $host, url => '',
					title => 'HSTS max-age is shorter than six months',
					detail => 'A short max-age gives an attacker a window to downgrade the connection once the policy expires.',
					evidence => "Strict-Transport-Security: $hsts",
					fix => 'Raise max-age to at least 15552000, ideally 31536000.',
				);
			} elsif($hsts !~ /includeSubDomains/i) {
				$findings->add(
					id => 'hsts-no-subdomains', severity => 'info',
					host => $host, url => '',
					title => 'HSTS does not cover sub-domains',
					detail => 'Sub-domains remain downgradable, which matters if any of them serves the same cookies.',
					evidence => "Strict-Transport-Security: $hsts",
					fix => 'Add includeSubDomains once every sub-domain is HTTPS-only.',
				);
			}
		}
	}

	if(!defined $csp) {
		$findings->add(
			id => 'csp-missing', severity => 'medium',
			host => $host, url => '',
			title => 'Content-Security-Policy is missing',
			detail => 'CSP is the main defence-in-depth control against cross-site scripting; without it any injected script runs with full page privileges.',
			evidence => 'No Content-Security-Policy header on ' . $url,
			fix => 'Start with a report-only policy, then enforce it once the reports are clean.',
			reference => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
		);
	} else {
		if($csp =~ /(?:script-src|default-src)[^;]*\*/i) {
			$findings->add(
				id => 'csp-wildcard', severity => 'medium',
				host => $host, url => '',
				title => 'Content-Security-Policy allows scripts from any origin',
				detail => 'A wildcard source means the policy does not restrict script loading at all.',
				evidence => $csp,
				fix => 'List the specific origins that host scripts.',
			);
		}
		if($csp =~ /unsafe-inline|unsafe-eval/i) {
			$findings->add(
				id => 'csp-unsafe', severity => 'low',
				host => $host, url => '',
				title => 'Content-Security-Policy permits unsafe-inline or unsafe-eval',
				detail => 'Inline and eval are the two gaps most XSS payloads rely on.',
				evidence => $csp,
				fix => 'Move inline handlers into files and use a nonce or hash instead of unsafe-inline.',
			);
		}
	}

	if(!defined $xfo && !(defined $csp && $csp =~ /frame-ancestors/i)) {
		$findings->add(
			id => 'clickjacking', severity => 'medium',
			host => $host, url => '',
			title => 'No clickjacking protection',
			detail => 'The page can be framed by another site, so its buttons can be overlaid and used for clickjacking.',
			evidence => 'No X-Frame-Options header and no frame-ancestors directive',
			fix => "Send X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'self'.",
			reference => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
		);
	}

	if(!defined $xcto || $xcto !~ /nosniff/i) {
		$findings->add(
			id => 'nosniff-missing', severity => 'low',
			host => $host, url => '',
			title => 'X-Content-Type-Options is missing',
			detail => 'Without nosniff some browsers will sniff a text/plain upload as HTML, turning an upload into stored XSS.',
			evidence => defined $xcto ? "X-Content-Type-Options: $xcto" : 'Header absent',
			fix => 'Send X-Content-Type-Options: nosniff on every response.',
		);
	}

	if(!defined $get->('referrer-policy')) {
		$findings->add(
			id => 'referrer-policy-missing', severity => 'low',
			host => $host, url => '',
			title => 'Referrer-Policy is missing',
			detail => 'Full URLs, including tokens in query strings, leak to third parties through the Referer header.',
			evidence => 'No Referrer-Policy header',
			fix => 'Send Referrer-Policy: strict-origin-when-cross-origin.',
		);
	}

	if(!defined $get->('permissions-policy') && !defined $get->('feature-policy')) {
		$findings->add(
			id => 'permissions-policy-missing', severity => 'info',
			host => $host, url => '',
			title => 'Permissions-Policy is missing',
			detail => 'Camera, microphone and geolocation remain available to any embedded or injected frame.',
			evidence => 'No Permissions-Policy header',
			fix => 'Send Permissions-Policy denying the features the site does not use.',
		);
	}

	_check_disclosure($findings, $host, $url, $headers, $body);
	_check_cookies($findings, $host, $url, $res, $is_https);
	_check_body($findings, $host, $url, $body, $is_https, $res);
}

sub _check_disclosure
{
	my ($findings, $host, $url, $headers, $body) = @_;

	my $server = $headers->{server} ? $headers->{server}[-1] : '';
	if($server =~ m{([\w.-]+)/(\d+(?:\.\d+)+)}) {
		$findings->add(
			id => 'server-version-disclosed', severity => 'low',
			host => $host, url => '',
			title => "Server version disclosed: $server",
			detail => 'Publishing an exact version lets an attacker go straight to the matching exploit instead of probing.',
			evidence => "Server: $server",
			fix => 'Suppress the version token (ServerTokens Prod in Apache, server_tokens off in nginx).',
		);
	}

	my $powered_by = $headers->{'x-powered-by'} ? $headers->{'x-powered-by'}[-1] : '';
	if(length $powered_by) {
		$findings->add(
			id => 'x-powered-by', severity => 'low',
			host => $host, url => '',
			title => "X-Powered-By discloses the platform: $powered_by",
			detail => 'The header advertises the application stack and usually its version.',
			evidence => "X-Powered-By: $powered_by",
			fix => 'unset X-Powered-By (expose_php = Off, or Header unset).',
		);

		if($powered_by =~ m{PHP/(\d+\.\d+\.\d+)}) {
			_check_php($findings, $host, $1);
		}
	}

	my $generator = '';
	if($body =~ /<meta[^>]+name\s*=\s*["']generator["'][^>]*content\s*=\s*["']([^"']+)["']/i) {
		$generator = $1;
	} elsif($body =~ /<meta[^>]+content\s*=\s*["']([^"']+)["'][^>]*name\s*=\s*["']generator["']/i) {
		$generator = $1;
	}
	if(length $generator) {
		$findings->add(
			id => 'generator-disclosed', severity => 'info',
			host => $host, url => $url,
			title => "Generator meta tag discloses: $generator",
			detail => 'The CMS and its version are advertised in the markup.',
			evidence => "<meta name=\"generator\" content=\"$generator\">",
			fix => 'Remove the generator meta tag.',
		);
	}
}

sub _check_php
{
	my ($findings, $host, $version) = @_;

	my ($major, $minor, $patch) = split /\./, $version;
	return unless defined $patch;

	my ($vulnerable, $why);
	if($major < 8 || ($major == 8 && $minor < 2)) {
		$vulnerable = 1;
		$why = "PHP $version has no upstream fix for PHP2Shell";
	} elsif(exists $PHP2SHELL_FIXED{"$major.$minor"}) {
		my $fixed = $PHP2SHELL_FIXED{"$major.$minor"};
		my (undef, undef, $fixed_patch) = split /\./, $fixed;
		if($patch + 0 < $fixed_patch + 0) {
			$vulnerable = 1;
			$why = "PHP $version is below the PHP2Shell fix level $fixed";
		}
	}

	return unless $vulnerable;

	$findings->add(
		id => 'php2shell', severity => 'critical',
		host => $host, url => '',
		title => "PHP version vulnerable to PHP2Shell ($version)",
		detail => "$why. CVE-2026-109618 and CVE-2026-109619 are remote code execution flaws that moved from disclosure to active exploitation within hours.",
		evidence => "X-Powered-By reports PHP/$version",
		fix => "Upgrade to the fixed release for this branch ($PHP2SHELL_FIXED{'8.5'} / $PHP2SHELL_FIXED{'8.4'} / $PHP2SHELL_FIXED{'8.3'} / $PHP2SHELL_FIXED{'8.2'}) and restart the SAPI. If you cannot patch yet, apply the compensating controls in php2shell/ in this repository.",
		reference => 'https://www.cve.org/CVERecord?id=CVE-2026-109618',
	);
}

sub _check_cookies
{
	my ($findings, $host, $url, $res, $is_https) = @_;

	for my $cookie (@{ $res->{set_cookie} || [] }) {
		my ($pair) = split /;/, $cookie;
		next unless defined $pair && $pair =~ /=/;

		my ($name) = split /=/, $pair, 2;
		next unless defined $name;
		$name =~ s/^\s+|\s+$//g;
		next unless length $name;

		my @missing;
		push @missing, 'Secure'   if $is_https && $cookie !~ /;\s*Secure\b/i;
		push @missing, 'HttpOnly' if $cookie !~ /;\s*HttpOnly\b/i;
		push @missing, 'SameSite' if $cookie !~ /;\s*SameSite\s*=/i;
		next unless @missing;

		my $severity = (grep { $_ eq 'Secure' } @missing) ? 'medium' : 'low';
		my $evidence = $cookie;
		$evidence = substr($evidence, 0, 200) . '...' if length $evidence > 200;

		$findings->add(
			id => 'cookie-flags', severity => $severity,
			host => $host, url => '', key => $name,
			title => "Cookie '$name' is missing " . join(', ', @missing),
			detail => 'A cookie without HttpOnly can be read by injected script; without Secure it is sent over plaintext; without SameSite it is attached to cross-site requests.',
			evidence => "Set-Cookie: $evidence (seen on $url)",
			fix => 'Set Secure, HttpOnly and SameSite=Lax (or Strict) on session cookies.',
			reference => 'https://owasp.org/www-project-secure-headers/',
		);
	}
}

sub _check_body
{
	my ($findings, $host, $url, $body, $is_https, $res) = @_;

	return unless length $body;

	if($body =~ /<title>\s*Index of\s*\//i) {
		$findings->add(
			id => 'directory-listing', severity => 'medium',
			host => $host, url => $url,
			title => 'Directory listing is enabled',
			detail => 'The server returns an index of the directory, which reveals files that are not linked from anywhere.',
			evidence => 'Response title is "Index of /"',
			fix => 'Disable auto-indexing (Options -Indexes / autoindex off).',
		);
	}

	if($res->{status} && $res->{status} >= 500 || $body =~ /(?:Warning|Fatal error):\s+\S+/i) {
		my @markers;
		push @markers, 'PHP error' if $body =~ /(?:Fatal error|Parse error|Warning):\s+\S+ in \S+ on line \d+/i;
		push @markers, 'Perl error' if $body =~ /\bat \S+\.p[lm] line \d+/i;
		push @markers, 'Python traceback' if $body =~ /Traceback \(most recent call last\)/;
		push @markers, 'Java stack trace' if $body =~ /\bat [\w.$]+\([\w.]+\.java:\d+\)/;
		push @markers, 'SQL error' if $body =~ /(?:SQL syntax|mysql_fetch|ORA-\d{5}|unclosed quotation mark)/i;
		push @markers, 'stack trace' if $body =~ /Stack trace:/i;

		if(@markers) {
			$findings->add(
				id => 'error-disclosure', severity => 'medium',
				host => $host, url => $url,
				title => 'Verbose error output discloses internals (' . join(', ', @markers) . ')',
				detail => 'Error pages leak file paths, framework versions and sometimes query fragments, which shortens an attacker\'s reconnaissance.',
				evidence => _excerpt($body),
				fix => 'Log details server-side and return a generic error page with the correct status code.',
				reference => 'https://cwe.mitre.org/data/definitions/209.html',
			);
		}
	}

	return unless $is_https;

	my (%seen, @active, @passive);
	while($body =~ /<(script|iframe|embed|object|img|link|form)\b[^>]*?\b(?:src|href|action)\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi) {
		my ($tag, $resource) = (lc $1, $2);
		next if $seen{$resource}++;

		if($tag eq 'script' || $tag eq 'iframe' || $tag eq 'embed' || $tag eq 'object' || $tag eq 'form') {
			push @active, "$tag $resource";
		} else {
			push @passive, "$tag $resource";
		}
		last if @active + @passive >= 5;
	}

	if(@active) {
		$findings->add(
			id => 'mixed-content-active', severity => 'high',
			host => $host, url => $url,
			title => 'Active mixed content on an HTTPS page',
			detail => 'Script, frame or form targets are loaded over plaintext, so a network attacker can replace them wholesale. Form actions over HTTP also send their contents in the clear.',
			evidence => join('; ', @active),
			fix => 'Move every script, frame and form target to https:// (or a scheme-relative URL) and add upgrade-insecure-requests to the CSP.',
			reference => 'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content',
		);
	}

	if(@passive) {
		$findings->add(
			id => 'mixed-content-passive', severity => 'low',
			host => $host, url => $url,
			title => 'Passive mixed content on an HTTPS page',
			detail => 'Images or stylesheets are fetched over plaintext, so they can be modified in transit and can leak the page URL through the Referer header.',
			evidence => join('; ', @passive),
			fix => 'Reference these resources over https://.',
		);
	}
}

sub _excerpt
{
	my ($body) = @_;

	my $text = $body;
	$text =~ s/<[^>]+>/ /g;
	$text =~ s/\s+/ /g;
	$text =~ s/^\s+|\s+$//g;

	return substr($text, 0, 200);
}

# The probe response comes from a request carrying a foreign Origin header.
sub check_cors
{
	my ($findings, %args) = @_;

	my $res = $args{res} or return;
	return if $res->{error};

	my $headers = $res->{headers} || {};
	my $origin_allowed = $headers->{'access-control-allow-origin'}
		? $headers->{'access-control-allow-origin'}[-1]
		: undef;
	return unless defined $origin_allowed;

	my $credentials = $headers->{'access-control-allow-credentials'}
		&& lc($headers->{'access-control-allow-credentials'}[-1]) eq 'true';

	my $severity;
	my $detail;

	if($credentials && ($origin_allowed eq '*' || $origin_allowed eq $PROBE_ORIGIN)) {
		$severity = 'high';
		$detail = 'Any origin may read authenticated responses, so a malicious site can act as the logged-in user.';
	} elsif($origin_allowed eq $PROBE_ORIGIN) {
		$severity = 'medium';
		$detail = 'The server echoes back whatever Origin it is given, so any site can read these responses.';
	} elsif($origin_allowed eq '*') {
		$severity = 'low';
		$detail = 'Any origin may read these responses. Harmless for genuinely public data, dangerous for anything user-specific.';
	} else {
		return;
	}

	$findings->add(
		id => 'cors-misconfiguration', severity => $severity,
		host => $args{host}, url => $args{url},
		title => 'CORS policy allows untrusted origins',
		detail => $detail,
		evidence => "Access-Control-Allow-Origin: $origin_allowed"
			. ($credentials ? '; Access-Control-Allow-Credentials: true' : '')
			. " (request sent Origin: $PROBE_ORIGIN)",
		fix => 'Echo back only origins on an explicit allowlist, never a wildcard, and only with credentials when necessary.',
		reference => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
	);
}

sub check_methods
{
	my ($findings, %args) = @_;

	my $res = $args{res} or return;
	return if $res->{error};

	my $allow = $res->{headers}{allow} ? join(',', @{ $res->{headers}{allow} }) : undef;
	return unless defined $allow;

	if($allow =~ /\bTRACE\b/i) {
		$findings->add(
			id => 'trace-enabled', severity => 'medium',
			host => $args{host}, url => $args{url},
			title => 'HTTP TRACE is enabled',
			detail => 'TRACE echoes the request back, which can be combined with other flaws to read cookies and headers.',
			evidence => "Allow: $allow",
			fix => 'Disable TRACE (TraceEnable off in Apache).',
		);
	}

	if($allow =~ /\b(?:PUT|DELETE|PATCH)\b/i) {
		$findings->add(
			id => 'write-methods-enabled', severity => 'low',
			host => $args{host}, url => $args{url},
			title => 'Write methods advertised on a public URL',
			detail => 'PUT, DELETE or PATCH are allowed here. That may be intended for an API, but it is worth confirming the endpoint authenticates and authorises.',
			evidence => "Allow: $allow",
			fix => 'Restrict methods per route at the web server or application layer.',
		);
	}
}

sub check_tls
{
	my ($findings, %args) = @_;

	my $tls  = $args{tls}  or return;
	my $host = $args{host};

	unless($tls->{ok}) {
		$findings->add(
			id => 'tls-unavailable', severity => 'medium',
			host => $host, url => '',
			title => 'TLS handshake failed',
			detail => 'The host did not complete a TLS handshake on the scanned port, so either HTTPS is not served there or the TLS configuration is broken.',
			evidence => $tls->{error} // 'unknown handshake error',
			fix => 'Confirm the port serves HTTPS and that the certificate chain is complete.',
		);
		return;
	}

	if($tls->{verify_error}) {
		$findings->add(
			id => 'tls-invalid-certificate', severity => 'high',
			host => $host, url => '',
			title => 'TLS certificate does not verify',
			detail => 'Browsers will show a full-page warning, and users who click through are training themselves to ignore the warning that protects them.',
			evidence => $tls->{verify_error},
			fix => 'Serve the full chain including intermediates, and issue the certificate for the names actually in use.',
			reference => 'https://www.ssllabs.com/ssltest/',
		);
	}

	if($tls->{self_signed}) {
		$findings->add(
			id => 'tls-self-signed', severity => 'high',
			host => $host, url => '',
			title => 'TLS certificate is self-signed',
			detail => 'A self-signed certificate provides no identity guarantee, so it offers no protection against interception.',
			evidence => 'Subject and issuer are identical: ' . ($tls->{subject} // ''),
			fix => 'Use a certificate from a publicly trusted CA.',
		);
	}

	if(defined $tls->{days_left}) {
		my $days = $tls->{days_left};
		if($days < 0) {
			$findings->add(
				id => 'tls-expired', severity => 'high',
				host => $host, url => '',
				title => "TLS certificate expired ${\ abs $days} days ago",
				detail => 'Every visitor sees an interstitial warning, and API clients will reject the connection.',
				evidence => 'notAfter: ' . ($tls->{not_after} // 'unknown'),
				fix => 'Renew the certificate and automate renewal.',
			);
		} elsif($days < 30) {
			$findings->add(
				id => 'tls-expiring', severity => $days < 14 ? 'high' : 'medium',
				host => $host, url => '',
				title => "TLS certificate expires in $days days",
				detail => 'Certificate expiry is a self-inflicted outage, and automated clients fail closed.',
				evidence => 'notAfter: ' . ($tls->{not_after} // 'unknown'),
				fix => 'Renew now and automate renewal with ACME.',
			);
		}
	}

	my %accepted = map { $_ => 1 } @{ $tls->{protocols} || [] };
	if($accepted{TLSv1} || $accepted{TLSv1_1}) {
		my @legacy = grep { $accepted{$_} } qw(TLSv1 TLSv1_1);
		$findings->add(
			id => 'tls-legacy-protocol', severity => $accepted{TLSv1} ? 'high' : 'medium',
			host => $host, url => '',
			title => 'Deprecated TLS protocol version accepted (' . join(', ', @legacy) . ')',
			detail => 'TLS 1.0 and 1.1 are deprecated by RFC 8996 and are barred by PCI DSS. They only survive to support clients that should be retired.',
			evidence => 'Server completed a handshake with ' . join(', ', @legacy),
			fix => 'Require TLS 1.2 or newer (SSLProtocol -all +TLSv1.2 +TLSv1.3).',
		);
	}

	if(($tls->{cipher} // '') =~ /RC4|3DES|DES-CBC3|NULL|EXPORT|MD5|anon/i) {
		$findings->add(
			id => 'tls-weak-cipher', severity => 'high',
			host => $host, url => '',
			title => "Weak cipher negotiated: $tls->{cipher}",
			detail => 'The negotiated suite is broken or has no authentication, so the connection can be decrypted or impersonated.',
			evidence => "Cipher: $tls->{cipher}; protocol: " . ($tls->{protocol} // 'unknown'),
			fix => 'Restrict the cipher list to AEAD suites and disable anonymous and export ciphers.',
		);
	}
}

sub check_ports
{
	my ($findings, %args) = @_;

	my $scan = $args{scan} or return;
	my $host = $args{host};

	if($scan->{error}) {
		$findings->add(
			id => 'portscan-failed', severity => 'info',
			host => $host, url => '',
			title => 'Port scan could not run',
			detail => $scan->{error},
		);
		return;
	}

	my @other;
	for my $entry (@{ $scan->{open} }) {
		my $port = $entry->{port};
		my $banner = $entry->{banner} // '';

		if(exists $App::WebPerimeterScan::Ports::RISKY{$port}) {
			my ($severity, $detail) = @{ $App::WebPerimeterScan::Ports::RISKY{$port} };
			$findings->add(
				id => "port-open-$port", severity => $severity,
				host => $host, url => '',
				title => "Port $port accepts connections from outside the host",
				detail => $detail,
				evidence => $banner ? "Banner: $banner" : 'TCP connect succeeded, no banner',
				fix => 'Close the port at the firewall unless it must be public; if it must, restrict it by source address and require authentication.',
			);
		} elsif($port != 80 && $port != 443) {
			push @other, $port;
		}
	}

	if(@other) {
		$findings->add(
			id => 'ports-other-open', severity => 'info',
			host => $host, url => '',
			title => 'Other reachable ports: ' . join(', ', @other),
			detail => 'These are not inherently unsafe, but every open port is attack surface that has to be patched and monitored.',
			evidence => 'Open: ' . join(', ', @other),
			fix => 'Close anything not actively needed.',
		);
	}

	my @outdated_banners;
	for my $entry (@{ $scan->{open} }) {
		my $banner = $entry->{banner} // '';
		next unless $banner =~ /OpenSSH[_-]([\d.]+)/i;
		my $version = $1;
		push @outdated_banners, "port $entry->{port}: $banner"
			if _version_lt($version, '9.0');
	}

	if(@outdated_banners) {
		$findings->add(
			id => 'outdated-ssh-banner', severity => 'medium',
			host => $host, url => '',
			title => 'SSH announces an old version',
			detail => 'OpenSSH releases before 9.0 include versions with published remote flaws; the banner alone is not proof of a working exploit, but it is a strong hint.',
			evidence => join('; ', @outdated_banners),
			fix => 'Upgrade OpenSSH and restart sshd.',
		);
	}
}

sub _version_lt
{
	my ($left, $right) = @_;

	my @l = split /\./, $left;
	my @r = split /\./, $right;
	for my $i (0 .. 2) {
		my $l = $l[$i] // 0;
		my $r = $r[$i] // 0;
		return 1 if $l < $r;
		return 0 if $l > $r;
	}

	return 0;
}

# Compare a probe response against a deliberately non-existent path: if the
# application answers 200 for everything, no probe result can be trusted.
sub fingerprint
{
	my ($res) = @_;

	return '' unless $res && !$res->{error};
	my $body = $res->{body} // '';

	return join ':', $res->{status} // 0, length($body), md5_hex($body);
}

sub check_paths
{
	my ($findings, %args) = @_;

	my $http     = $args{http} or return;
	my $host     = $args{host};
	my $base     = $args{base};
	my $baseline = $args{baseline} // '';

	my $root = $base;
	$root =~ s{/+$}{};

	for my $probe (@PROBES) {
		my $url = $root . $probe->{path};
		my $res = $http->fetch($url);
		next if $res->{error};

		my $fingerprint = fingerprint($res);
		next if length $baseline && $fingerprint eq $baseline;

		next unless $res->{status} && $res->{status} == 200;
		my $body = $res->{body} // '';
		next unless $body =~ $probe->{match};

		my $evidence = $body;
		$evidence =~ s/\s+/ /g;
		$evidence = substr($evidence, 0, 200);

		$findings->add(
			id        => $probe->{id},
			severity  => $probe->{severity},
			host      => $host,
			url       => $url,
			title     => $probe->{title},
			detail    => $probe->{detail},
			evidence  => $evidence,
			fix       => $probe->{fix} // '',
			reference => $probe->{reference} // '',
		);
	}

	# security.txt is worth mentioning once, as a low-priority prompt.
	my $security_txt = $http->fetch($root . '/.well-known/security.txt');
	if(!$security_txt->{error}
		&& $security_txt->{status}
		&& $security_txt->{status} == 200
		&& ($security_txt->{body} // '') =~ /^\s*Contact\s*:/mi) {
		$findings->add(
			id => 'security-txt-present', severity => 'info',
			host => $host, url => $root . '/.well-known/security.txt',
			title => 'security.txt is published',
			detail => 'Good: this gives a researcher a route to report a finding to you privately.',
			evidence => 'Contact directive found',
		);
	}

	# robots.txt is not a vulnerability, but it often lists exactly the paths
	# an operator wanted to hide.
	my $robots = $http->fetch($root . '/robots.txt');
	if(!$robots->{error} && $robots->{status} && $robots->{status} == 200) {
		my @disallow = ($robots->{body} // '') =~ /^\s*Disallow:\s*(\S+)/gmi;
		if(@disallow) {
			$findings->add(
				id => 'robots-disclosure', severity => 'info',
				host => $host, url => $root . '/robots.txt',
				title => 'robots.txt names ' . scalar(@disallow) . ' path(s)',
				detail => 'robots.txt is public. Anything listed there is a map of what the operator considers sensitive; it must not be the only protection.',
				evidence => 'Disallow: ' . join(' ', @disallow[0 .. ($#disallow > 4 ? 4 : $#disallow)]),
				fix => 'Enforce access control on these paths rather than relying on robots.txt, and consider not listing them at all.',
			);
		}
	}

	return;
}

# The probe table is private, but the source-aware pass needs the same paths
# so that what it looks for on disk is what was probed over the wire.
sub sensitive_probes
{
	return @PROBES;
}

sub probe_origin
{
	return $PROBE_ORIGIN;
}

1;

__END__

=head1 NAME

App::WebPerimeterScan::Checks - the rule set

=head1 DESCRIPTION

Each C<check_*> function takes the findings collector plus the data it needs
and adds zero or more findings.  Nothing here sends an exploit: the checks are
header analysis, response-body analysis, certificate inspection and requests
for well-known paths that a correct deployment answers with 404.

=head1 LICENSE

GPL2

=cut
