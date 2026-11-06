package App::WebPerimeterScan::Checks;

use strict;
use warnings;
use autodie qw(:all);

use Digest::MD5 qw(md5_hex);
use HTML::Parser ();
use Params::Get qw(get_params);
use Params::Validate::Strict qw(validate_strict);
use Readonly;
use Sub::Private { mode => 'enforce' };
use version ();

use App::WebPerimeterScan::I18N ();
use App::WebPerimeterScan::Ports ();
use parent -norequire, 'App::WebPerimeterScan::I18N';

our $VERSION = '0.001.0';

# Thresholds a site owner might reasonably tune.  A plain hash so a caller,
# or Object::Configure, can change them.
our %config = (
	hsts_min_max_age     => 15_552_000,	# 180 days, in seconds
	tls_expiry_warn_days => 30,		# report a certificate this close to expiry
	tls_expiry_high_days => 14,		# ... as high severity below this
	ssh_min_version      => '9.0',		# OpenSSH older than this is reported
	excerpt_length       => 200,		# characters of body kept as evidence
	mixed_content_limit  => 5,		# resources listed per mixed-content finding
	robots_limit         => 5,		# Disallow paths listed as evidence
);

# A reserved TLD (RFC 2606) so the CORS probe can never be mistaken for a
# real origin, and can never resolve to anything.
Readonly::Scalar my $PROBE_ORIGIN => 'https://ws-probe.invalid';

Readonly::Scalar my $HTTP_OK          => 200;
Readonly::Scalar my $HTTP_SERVER_ERROR => 500;

# Ports whose being open is the point of a web server.
Readonly::Hash my %WEB_PORT => (80 => 1, 443 => 1);

# PHP versions at or above these are fixed for PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619); branches older than the oldest key
# have no fix at all.
Readonly::Hash my %PHP2SHELL_FIXED => (
	'8.5' => '8.5.12',
	'8.4' => '8.4.27',
	'8.3' => '8.3.36',
	'8.2' => '8.2.35',
);
Readonly::Scalar my $PHP2SHELL_OLDEST_BRANCH => '8.2';

# The default severity and the reference URL of each rule.  The text of a
# rule is in the message catalogue under the same id.
Readonly::Hash my %RULE => (
	'hsts-missing'               => { severity => 'medium', reference => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security' },
	'hsts-short-max-age'         => { severity => 'low' },
	'hsts-no-subdomains'         => { severity => 'info' },
	'csp-missing'                => { severity => 'medium', reference => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP' },
	'csp-wildcard'               => { severity => 'medium' },
	'csp-unsafe'                 => { severity => 'low' },
	'clickjacking'               => { severity => 'medium', reference => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options' },
	'nosniff-missing'            => { severity => 'low' },
	'referrer-policy-missing'    => { severity => 'low' },
	'permissions-policy-missing' => { severity => 'info' },
	'server-version-disclosed'   => { severity => 'low' },
	'x-powered-by'               => { severity => 'low' },
	'generator-disclosed'        => { severity => 'info' },
	'php2shell'                  => { severity => 'critical', reference => 'https://www.cve.org/CVERecord?id=CVE-2026-109618' },
	'cookie-flags'               => { severity => 'low', reference => 'https://owasp.org/www-project-secure-headers/' },
	'directory-listing'          => { severity => 'medium' },
	'error-disclosure'           => { severity => 'medium', reference => 'https://cwe.mitre.org/data/definitions/209.html' },
	'mixed-content-active'       => { severity => 'high', reference => 'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content' },
	'mixed-content-passive'      => { severity => 'low' },
	'cors-misconfiguration'      => { severity => 'low', reference => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS' },
	'trace-enabled'              => { severity => 'medium' },
	'write-methods-enabled'      => { severity => 'low' },
	'tls-unavailable'            => { severity => 'medium' },
	'tls-invalid-certificate'    => { severity => 'high', reference => 'https://www.ssllabs.com/ssltest/' },
	'tls-self-signed'            => { severity => 'high' },
	'tls-expired'                => { severity => 'high' },
	'tls-expiring'               => { severity => 'medium' },
	'tls-legacy-protocol'        => { severity => 'medium' },
	'tls-weak-cipher'            => { severity => 'high' },
	'portscan-failed'            => { severity => 'info' },
	'ports-other-open'           => { severity => 'info' },
	'outdated-ssh-banner'        => { severity => 'medium' },
	'security-txt-present'       => { severity => 'info' },
	'robots-disclosure'          => { severity => 'info' },
);

# CORS outcome => severity.
Readonly::Hash my %CORS_SEVERITY => (credentials => 'high', reflected => 'medium', wildcard => 'low');

# Script sources that allow any origin: a bare wildcard or a whole scheme.
Readonly::Hash my %ANY_SOURCE => map { $_ => 1 } ('*', 'http:', 'https:', 'data:');

# A nonce or hash makes CSP2+ browsers ignore 'unsafe-inline'.
Readonly::Scalar my $NONCE_OR_HASH => qr/\A'(?:nonce|sha256|sha384|sha512)-/i;

# Protocol versions deprecated by RFC 8996, worst first.
Readonly::Array my @LEGACY_PROTOCOLS => qw(TLSv1 TLSv1_1);

# Cipher suites that are broken or unauthenticated.
Readonly::Scalar my $WEAK_CIPHER => qr/RC4|3DES|DES-CBC3|NULL|EXPORT|MD5|anon/i;

# Error-page fingerprints, in the order they are listed in a title.
Readonly::Array my @ERROR_MARKERS => (
	[ php    => qr/(?:Fatal error|Parse error|Warning):\s+\S+ in \S+ on line \d+/i ],
	[ perl   => qr/\bat \S+\.p[lm] line \d+/i ],
	[ python => qr/Traceback \(most recent call last\)/ ],
	[ java   => qr/\bat [\w.\$]+\([\w.]+\.java:\d+\)/ ],
	[ sql    => qr/(?:SQL syntax|mysql_fetch|ORA-\d{5}|unclosed quotation mark)/i ],
	[ stack  => qr/Stack trace:/i ],
);
Readonly::Scalar my $ERROR_HINT => qr/(?:Warning|Fatal error):\s+\S+/i;

# Resources a page loads: tag => [ URL attribute, mixed-content class ].
# A link's class depends on its rel, so it is decided separately.
Readonly::Hash my %RESOURCE => (
	script => [ src    => 'active' ],
	iframe => [ src    => 'active' ],
	frame  => [ src    => 'active' ],
	embed  => [ src    => 'active' ],
	object => [ data   => 'active' ],
	form   => [ action => 'active' ],
	img    => [ src    => 'passive' ],
	audio  => [ src    => 'passive' ],
	video  => [ src    => 'passive' ],
	source => [ src    => 'passive' ],
	link   => [ href   => undef ],
);

# Only these link relations load anything.  A stylesheet is blockable
# ("active") mixed content; canonical, alternate and the like load nothing
# and are ignored.
Readonly::Hash my %LINK_REL => (stylesheet => 'active', icon => 'passive');

Readonly::Scalar my $PLAINTEXT_URL => qr{\Ahttp://}i;

# Well-known paths that should never be served.  The match regexp is what
# turns "the server returned 200" into "the file is really there": a SPA that
# answers 200 to everything must not produce twenty findings.  Titles and
# advice are in the message catalogue under each id.
Readonly::Array my @PROBES => (
	{ id => 'git-exposed',             path => '/.git/config',        severity => 'critical', match => qr/\[core\]|repositoryformatversion/, reference => 'https://cwe.mitre.org/data/definitions/538.html' },
	{ id => 'git-head',                path => '/.git/HEAD',          severity => 'high',     match => qr/\Aref:\s+refs\// },
	{ id => 'svn-exposed',             path => '/.svn/entries',       severity => 'high',     match => qr/^\d+\s*$/m },
	{ id => 'env-exposed',             path => '/.env',               severity => 'critical', match => qr/^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S/m, reference => 'https://cwe.mitre.org/data/definitions/200.html' },
	{ id => 'htpasswd-exposed',        path => '/.htpasswd',          severity => 'critical', match => qr/^[^:\s]+:\$?(?:apr1|2y|1|5|6|\{SHA\})/m },
	{ id => 'htaccess-exposed',        path => '/.htaccess',          severity => 'medium',   match => qr/<IfModule|RewriteEngine|Options\s+[-+]/i },
	{ id => 'web-config-exposed',      path => '/web.config',         severity => 'high',     match => qr/<configuration/i },
	{ id => 'php-config-backup',       path => '/wp-config.php.bak',  severity => 'critical', match => qr/DB_PASSWORD|DB_NAME|AUTH_KEY/ },
	{ id => 'sql-dump-exposed',        path => '/backup.sql',         severity => 'critical', match => qr/CREATE TABLE|INSERT INTO/i, reference => 'https://cwe.mitre.org/data/definitions/538.html' },
	{ id => 'ds-store-exposed',        path => '/.DS_Store',          severity => 'low',      match => qr/\x00\x00\x00\x01Bud1/ },
	{ id => 'server-status-exposed',   path => '/server-status',      severity => 'high',     match => qr/Apache Server Status|requests currently being processed/i },
	{ id => 'server-info-exposed',     path => '/server-info',        severity => 'medium',   match => qr/Apache Server Information|Server Settings/i },
	{ id => 'phpinfo-exposed',         path => '/phpinfo.php',        severity => 'high',     match => qr/PHP Version|phpinfo\(\)|Configuration File \(php\.ini\)/i },
	{ id => 'spring-actuator-exposed', path => '/actuator/env',       severity => 'critical', match => qr/"propertySources"|"activeProfiles"/ },
	{ id => 'spring-health-exposed',   path => '/actuator/health',    severity => 'low',      match => qr/"status"\s*:\s*"(?:UP|DOWN)"/ },
	{ id => 'composer-json-exposed',   path => '/composer.json',      severity => 'low',      match => qr/"require"\s*:|"autoload"\s*:/ },
	{ id => 'package-json-exposed',    path => '/package.json',       severity => 'low',      match => qr/"dependencies"\s*:|"devDependencies"\s*:/ },
	{ id => 'crossdomain-xml',         path => '/crossdomain.xml',    severity => 'medium',   match => qr/allow-access-from\s+domain\s*=\s*"\*"/ },
);

Readonly::Scalar my $SECURITY_TXT => '/.well-known/security.txt';
Readonly::Scalar my $ROBOTS_TXT   => '/robots.txt';

=encoding utf8

=head1 NAME

App::WebPerimeterScan::Checks - the rule set

=head1 VERSION

Version 0.001.0

=head1 SYNOPSIS

	use App::WebPerimeterScan::Findings;
	use App::WebPerimeterScan::Checks;

	my $findings = App::WebPerimeterScan::Findings->new;

	App::WebPerimeterScan::Checks::check_page($findings,
		host => 'example.com', url => 'https://example.com/', res => $res);
	App::WebPerimeterScan::Checks::check_tls($findings,
		host => 'example.com', tls => $tls);

	print "$_->{severity} $_->{title}\n" for @{ $findings->sorted };

=head1 DESCRIPTION

Each C<check_*> function takes the findings collector plus the data it needs
and adds zero or more findings.  Nothing here sends an exploit: the checks are
header analysis, response-body analysis, certificate inspection and requests
for well-known paths that a correct deployment answers with 404.

Every C<check_*> function returns the collector it was given, so calls can
be chained.  The text of each rule is in L<App::WebPerimeterScan::Messages>
under the rule id; this module holds only ids, severities and the logic.

=head1 SUBROUTINES/METHODS

=head2 check_page

Purpose: the per-page rules: security headers, cookies, information
disclosure, directory listings, error pages and mixed content.

Args: C<$findings>, then named C<host>, C<url> and C<res> (a response from
L<App::WebPerimeterScan::HTTP/fetch>).

Returns: C<$findings>.

Side Effects: adds findings.  A response with C<error> set is ignored.

Usage: C<< check_page($findings, host => $host, url => $url, res => $res); >>

=head3 EXAMPLE

	my $findings = App::WebPerimeterScan::Findings->new;
	App::WebPerimeterScan::Checks::check_page($findings,
		host => 'example.com',
		url  => 'https://example.com/',
		res  => { status => 200, headers => {}, body => '', set_cookie => [] },
	);
	# hsts-missing, csp-missing, clickjacking, nosniff-missing,
	# referrer-policy-missing, permissions-policy-missing

=head3 API SPECIFICATION

=head4 INPUT

	{
		findings => { type => 'object', isa => 'App::WebPerimeterScan::Findings', position => 0 },
		host     => { type => 'string', optional => 1 },
		url      => { type => 'string', optional => 1 },
		res      => { type => 'hashref', optional => 1 },
	}

=head4 OUTPUT

	{ type => 'object', isa => 'App::WebPerimeterScan::Findings' }

=head3 MESSAGES

	Message                                   Meaning / resolution
	----------------------------------------  -----------------------------
	Parameter 'findings' must be an object    The first argument must be an
	... (fatal)                               App::WebPerimeterScan::Findings.

The findings it can add are listed in L</RULES>.

=head3 FORMAL SPECIFICATION

	┌─ CheckPage ─────────────────────────────────────────
	│ ΔFindings; url? : URL; res? : RESPONSE
	├─────────────────────────────────────────────────────
	│ res?.error ≠ ⊥ ⇒ items' = items
	│ res?.error = ⊥ ⇒ items' = items ⁀ headers(res?) ⁀ cookies(res?)
	│                            ⁀ body(res?)
	│ scheme(url?) = https ⇔ HSTS rules ⊆ rules applied
	└─────────────────────────────────────────────────────

=head3 PSEUDOCODE

	validate; return unless there is a successful response
	parse the HTML once (title, generator meta tag, loaded resources)
	if the page is HTTPS, check HSTS
	check CSP, framing, nosniff, Referrer-Policy and Permissions-Policy
	check Server, X-Powered-By (and the PHP version in it), generator
	check every Set-Cookie for Secure, HttpOnly and SameSite
	check for a directory listing, a verbose error, and mixed content

=cut

sub check_page
{
	my $findings = shift;

	my $args = _check_args($findings, \@_, { res => { type => 'hashref', optional => 1 } });
	my $res  = $args->{res};
	return $findings unless $res && !$res->{error};

	# Everything the page rules need, gathered once and passed around, so
	# no helper has a seven-argument signature.
	my $url  = $args->{url} // '';
	my $body = $res->{body} // '';
	my $page = {
		findings   => $findings,
		host       => $args->{host} // '',
		url        => $url,
		headers    => $res->{headers} || {},
		status     => $res->{status} // 0,
		set_cookie => $res->{set_cookie} || [],
		body       => $body,
		html       => _parse_html($body),
		is_https   => $url =~ m{\Ahttps://}i ? 1 : 0,
	};

	# HSTS is only meaningful over HTTPS.
	_check_hsts($page) if $page->{is_https};
	_check_csp($page);
	_check_simple_headers($page);
	_check_disclosure($page);
	_check_cookies($page);
	_check_body($page);

	return $findings;
}

=head2 check_cors

Purpose: report a CORS policy that lets an untrusted origin read responses.
The response must come from a request that sent C<Origin:> set to
C<probe_origin()>.

Args: C<$findings>, then named C<host>, C<url> and C<res>.

Returns: C<$findings>.

Side Effects: adds at most one C<cors-misconfiguration> finding: high when
credentials are allowed with a wildcard or reflected origin, medium when the
probe origin is reflected, low for a plain wildcard.

Usage: C<< check_cors($findings, host => $h, url => $u, res => $res); >>

=head3 EXAMPLE

	App::WebPerimeterScan::Checks::check_cors($findings,
		host => 'example.com', url => 'https://example.com/',
		res  => { headers => { 'access-control-allow-origin' => ['*'] } },
	);

=head3 API SPECIFICATION

=head4 INPUT

	{
		findings => { type => 'object', isa => 'App::WebPerimeterScan::Findings', position => 0 },
		host     => { type => 'string', optional => 1 },
		url      => { type => 'string', optional => 1 },
		res      => { type => 'hashref', optional => 1 },
	}

=head4 OUTPUT

	{ type => 'object', isa => 'App::WebPerimeterScan::Findings' }

=head3 MESSAGES

As C<check_page>.

=head3 FORMAL SPECIFICATION

	┌─ CheckCors ─────────────────────────────────────────
	│ ΔFindings; res? : RESPONSE
	├─────────────────────────────────────────────────────
	│ a = last(res?.headers(access-control-allow-origin))
	│ c ⇔ last(res?.headers(access-control-allow-credentials)) = "true"
	│ c ∧ a ∈ {*, PROBE} ⇒ severity = high
	│ ¬c ∧ a = PROBE ⇒ severity = medium
	│ ¬c ∧ a = * ⇒ severity = low
	│ a ∉ {*, PROBE} ⇒ items' = items
	└─────────────────────────────────────────────────────

=cut

sub check_cors
{
	my $findings = shift;

	my $args = _check_args($findings, \@_, { res => { type => 'hashref', optional => 1 } });
	my $res  = $args->{res};
	my $headers = ($res && !$res->{error}) ? ($res->{headers} || {}) : {};

	my $allowed = _last($headers, 'access-control-allow-origin');
	my $credentials = lc(_last($headers, 'access-control-allow-credentials') // '') eq 'true';

	# Which of the three bad outcomes this is, if any.
	my $case = !defined $allowed ? undef
		: $credentials && ($allowed eq '*' || $allowed eq $PROBE_ORIGIN) ? 'credentials'
		: $allowed eq $PROBE_ORIGIN ? 'reflected'
		: $allowed eq '*' ? 'wildcard'
		: undef;

	_flag($findings, 'cors-misconfiguration',
		host     => $args->{host},
		url      => $args->{url},
		severity => $CORS_SEVERITY{$case},
		vars     => {
			case        => $case,
			allowed     => $allowed,
			origin      => $PROBE_ORIGIN,
			credentials => $credentials ? 'yes' : 'no',
		},
	) if defined $case;

	return $findings;
}

=head2 check_methods

Purpose: report TRACE and write methods advertised by an C<OPTIONS> response.

Args: C<$findings>, then named C<host>, C<url> and C<res> (the C<OPTIONS>
response).

Returns: C<$findings>.

Side Effects: adds C<trace-enabled> and/or C<write-methods-enabled>.

Usage: C<< check_methods($findings, host => $h, url => $u, res => $options); >>

=head3 EXAMPLE

	App::WebPerimeterScan::Checks::check_methods($findings,
		host => 'example.com', url => 'https://example.com/',
		res  => { headers => { allow => ['GET,HEAD,TRACE'] } },
	);

=head3 API SPECIFICATION

=head4 INPUT

	{
		findings => { type => 'object', isa => 'App::WebPerimeterScan::Findings', position => 0 },
		host     => { type => 'string', optional => 1 },
		url      => { type => 'string', optional => 1 },
		res      => { type => 'hashref', optional => 1 },
	}

=head4 OUTPUT

	{ type => 'object', isa => 'App::WebPerimeterScan::Findings' }

=head3 MESSAGES

As C<check_page>.

=head3 FORMAL SPECIFICATION

	┌─ CheckMethods ──────────────────────────────────────
	│ ΔFindings; res? : RESPONSE
	├─────────────────────────────────────────────────────
	│ M = tokens(res?.headers(allow))
	│ TRACE ∈ M ⇔ trace-enabled ∈ ids(items' \ items)
	│ M ∩ {PUT, DELETE, PATCH} ≠ ∅ ⇔ write-methods-enabled ∈ ids(items' \ items)
	└─────────────────────────────────────────────────────

=cut

sub check_methods
{
	my $findings = shift;

	my $args = _check_args($findings, \@_, { res => { type => 'hashref', optional => 1 } });
	my $res  = $args->{res};
	my $allow = ($res && !$res->{error} && $res->{headers}{allow}) ? join(',', @{ $res->{headers}{allow} }) : '';

	my %common = (host => $args->{host}, url => $args->{url}, vars => { allow => $allow });
	_flag($findings, 'trace-enabled', %common) if $allow =~ /\bTRACE\b/i;
	_flag($findings, 'write-methods-enabled', %common) if $allow =~ /\b(?:PUT|DELETE|PATCH)\b/i;

	return $findings;
}

=head2 check_tls

Purpose: the TLS rules: handshake, chain, self-signed, expiry, protocol
versions and cipher.

Args: C<$findings>, then named C<host> and C<tls> (from
L<App::WebPerimeterScan::TLS/inspect>).

Returns: C<$findings>.

Side Effects: adds findings.  A failed default handshake adds
C<tls-unavailable>, plus C<tls-legacy-protocol> if a pinned old-protocol
handshake still succeeded.

Usage: C<< check_tls($findings, host => $h, tls => $tls); >>

=head3 EXAMPLE

	App::WebPerimeterScan::Checks::check_tls($findings,
		host => 'example.com',
		tls  => { ok => 1, protocols => ['TLSv1', 'TLSv1_2'], days_left => 10 },
	);
	# tls-legacy-protocol (high), tls-expiring (high)

=head3 API SPECIFICATION

=head4 INPUT

	{
		findings => { type => 'object', isa => 'App::WebPerimeterScan::Findings', position => 0 },
		host     => { type => 'string', optional => 1 },
		tls      => { type => 'hashref', optional => 1 },
	}

=head4 OUTPUT

	{ type => 'object', isa => 'App::WebPerimeterScan::Findings' }

=head3 MESSAGES

As C<check_page>.

=head3 FORMAL SPECIFICATION

	┌─ CheckTls ──────────────────────────────────────────
	│ ΔFindings; tls? : TLSRESULT
	├─────────────────────────────────────────────────────
	│ ¬ tls?.ok ⇒ ids(items' \ items) ⊆ {tls-unavailable, tls-legacy-protocol}
	│ tls?.ok ⇒
	│   (tls?.verify_error ≠ ⊥ ⇔ tls-invalid-certificate ∈ new)
	│ ∧ (tls?.days_left < 0 ⇔ tls-expired ∈ new)
	│ ∧ (0 ≤ tls?.days_left < warn ⇔ tls-expiring ∈ new)
	│ ∧ (ran tls?.protocols ∩ LEGACY ≠ ∅ ⇔ tls-legacy-protocol ∈ new)
	│ where new = ids(items' \ items)
	└─────────────────────────────────────────────────────

=head3 PSEUDOCODE

	validate; return unless a TLS result was given
	if the default handshake failed, report tls-unavailable and any
	legacy protocol, and stop
	report a verification error and a self-signed certificate
	report an expired certificate, or one expiring within the warning window
	report TLS 1.0 / 1.1 acceptance (high if 1.0)
	report a weak negotiated cipher

=cut

sub check_tls
{
	my $findings = shift;

	my $args = _check_args($findings, \@_, { tls => { type => 'hashref', optional => 1 } });
	my $tls  = $args->{tls} or return $findings;
	my $host = $args->{host};

	# Without a default handshake there is no certificate to judge, but a
	# server that only completes a pinned TLS 1.0 handshake still has a
	# protocol problem worth naming.
	unless($tls->{ok}) {
		_flag($findings, 'tls-unavailable', host => $host,
			evidence => $tls->{error} // __PACKAGE__->i18n('tls.unknown_error'));
		return _check_protocols($findings, $host, $tls);
	}

	_flag($findings, 'tls-invalid-certificate', host => $host, evidence => $tls->{verify_error})
		if $tls->{verify_error};
	_flag($findings, 'tls-self-signed', host => $host, vars => { subject => $tls->{subject} // '' })
		if $tls->{self_signed};

	_check_expiry($findings, $host, $tls);
	_check_protocols($findings, $host, $tls);

	return $findings;
}

=head2 check_ports

Purpose: the port rules: risky services, other unexpected ports and old
OpenSSH banners.

Args: C<$findings>, then named C<host> and C<scan> (from
L<App::WebPerimeterScan::Ports/scan>).

Returns: C<$findings>.

Side Effects: adds one C<port-open-N> finding per risky open port (severity
from C<%App::WebPerimeterScan::Ports::RISKY>), one C<ports-other-open> for
the rest except 80 and 443, and C<outdated-ssh-banner>.

Usage: C<< check_ports($findings, host => $h, scan => $scan); >>

=head3 EXAMPLE

	App::WebPerimeterScan::Checks::check_ports($findings,
		host => 'example.com',
		scan => { open => [ { port => 3306, banner => '' } ] },
	);
	# port-open-3306 (high)

=head3 API SPECIFICATION

=head4 INPUT

	{
		findings => { type => 'object', isa => 'App::WebPerimeterScan::Findings', position => 0 },
		host     => { type => 'string', optional => 1 },
		scan     => { type => 'hashref', optional => 1 },
	}

=head4 OUTPUT

	{ type => 'object', isa => 'App::WebPerimeterScan::Findings' }

=head3 MESSAGES

As C<check_page>.

=head3 FORMAL SPECIFICATION

	┌─ CheckPorts ────────────────────────────────────────
	│ ΔFindings; scan? : SCANRESULT
	├─────────────────────────────────────────────────────
	│ scan?.error ≠ ⊥ ⇒ ids(items' \ items) = {portscan-failed}
	│ ∀ p ∈ open(scan?) ∩ dom RISKY • port-open-p ∈ ids(items')
	│ (open(scan?) \ dom RISKY \ {80, 443}) ≠ ∅ ⇔ ports-other-open ∈ ids(items')
	└─────────────────────────────────────────────────────

=head3 PSEUDOCODE

	validate; return unless a scan was given
	if the scan failed, report portscan-failed and stop
	for each open port
		report it if it is in the risky table
		otherwise remember it unless it is 80 or 443
	report the remembered ports together
	report any OpenSSH banner older than the configured minimum

=cut

sub check_ports
{
	my $findings = shift;

	my $args = _check_args($findings, \@_, { scan => { type => 'hashref', optional => 1 } });
	my $scan = $args->{scan} or return $findings;
	my $host = $args->{host};

	if($scan->{error}) {
		_flag($findings, 'portscan-failed', host => $host, vars => { error => $scan->{error} });
		return $findings;
	}

	my @other;
	for my $entry (@{ $scan->{open} || [] }) {
		my $port   = $entry->{port};
		my $banner = $entry->{banner} // '';

		if(my $severity = $App::WebPerimeterScan::Ports::RISKY{$port}) {
			# One finding per port, all sharing the port-open text.
			_flag($findings, "port-open-$port",
				message  => 'port-open',
				host     => $host,
				severity => $severity,
				vars     => { port => $port, banner => $banner, has_banner => length $banner ? 'yes' : 'no' },
			);
		} elsif(!$WEB_PORT{$port}) {
			push @other, $port;
		}
	}

	my $ports = join ', ', @other;
	_flag($findings, 'ports-other-open', host => $host, vars => { ports => $ports }) if @other;

	_check_ssh_banners($findings, $host, $scan->{open} || []);

	return $findings;
}

=head2 fingerprint

Purpose: a short identity for a response, so a probe can be compared with
the answer to a path that certainly does not exist.  If the application
answers 200 for everything, no probe result can be trusted on status alone.

Args: C<$res>, a response hash reference.

Returns: C<"status:length:md5">, or an empty string for a failed response.

Side Effects: none.

Usage: C<< next if fingerprint($res) eq $baseline; >>

=head3 EXAMPLE

	my $baseline = App::WebPerimeterScan::Checks::fingerprint(
		$http->fetch('https://example.com/does-not-exist-12345'),
	);

=head3 API SPECIFICATION

=head4 INPUT

	{ res => { type => 'hashref', optional => 1, position => 0 } }

=head4 OUTPUT

	{ type => 'string' }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	┌─ Fingerprint ───────────────────────────────────────
	│ res? : RESPONSE; result! : STRING
	├─────────────────────────────────────────────────────
	│ res? = ⊥ ∨ res?.error ≠ ⊥ ⇒ result! = ""
	│ otherwise result! = status(res?) ⁀ ":" ⁀ #body(res?) ⁀ ":" ⁀ md5(body(res?))
	└─────────────────────────────────────────────────────

=cut

sub fingerprint
{
	my ($res) = @_;

	my $ok = $res && !$res->{error};
	my $body = $ok ? ($res->{body} // '') : '';

	return $ok ? join(':', $res->{status} // 0, length($body), md5_hex($body)) : '';
}

=head2 check_paths

Purpose: request each well-known sensitive path and report the ones that
are really there, plus C<security.txt> and C<robots.txt>.

Args: C<$findings>, then named C<http> (an L<App::WebPerimeterScan::HTTP>),
C<host>, C<base> (the site's root URL) and C<baseline> (the C<fingerprint>
of a response to a path that does not exist).

Returns: C<$findings>.

Side Effects: one request per probe plus two; adds findings.  A probe is
only reported when the status is 200, the fingerprint differs from the
baseline, and the body matches what the real file would contain.

Usage: C<< check_paths($findings, http => $http, host => $h, base => $base, baseline => $fp); >>

=head3 EXAMPLE

	App::WebPerimeterScan::Checks::check_paths($findings,
		http     => App::WebPerimeterScan::HTTP->new,
		host     => 'example.com',
		base     => 'https://example.com/',
		baseline => '',
	);

=head3 API SPECIFICATION

=head4 INPUT

	{
		findings => { type => 'object', isa => 'App::WebPerimeterScan::Findings', position => 0 },
		http     => { type => 'object', can => 'fetch' },
		host     => { type => 'string', optional => 1 },
		base     => { type => 'string', min => 1 },
		baseline => { type => 'string', optional => 1 },
	}

=head4 OUTPUT

	{ type => 'object', isa => 'App::WebPerimeterScan::Findings' }

=head3 MESSAGES

	Message                                  Meaning / resolution
	---------------------------------------  ------------------------------
	Parameter 'http' must be an object that  Pass an HTTP client with a
	understands the fetch method (fatal)     fetch method.

=head3 FORMAL SPECIFICATION

	┌─ CheckPaths ────────────────────────────────────────
	│ ΔFindings; base? : URL; baseline? : STRING
	├─────────────────────────────────────────────────────
	│ ∀ p : PROBES • p.id ∈ ids(items' \ items) ⇔
	│     let r = fetch(base? ⁀ p.path) •
	│         r.status = 200 ∧ fingerprint(r) ≠ baseline?
	│       ∧ r.body matches p.match
	└─────────────────────────────────────────────────────

=cut

sub check_paths
{
	my $findings = shift;

	my $args = _check_args($findings, \@_, {
		http     => { type => 'object', can => 'fetch' },
		base     => { type => 'string', min => 1 },
		baseline => { type => 'string', optional => 1 },
	});
	my $root = $args->{base} =~ s{/+\z}{}r;

	_probe_path($findings, $args, $root, $_) for @PROBES;
	_check_security_txt($findings, $args, $root);
	_check_robots($findings, $args, $root);

	return $findings;
}

=head2 sensitive_probes

Purpose: the probe table, so the source-aware pass looks on disk for exactly
the paths that were requested over the wire.

Args: none.

Returns: an array reference of hash references: C<id>, C<path>,
C<severity>, C<match> and optionally C<reference>.  The entries are
read-only.

Side Effects: none.

Usage: C<< for my $probe (@{ sensitive_probes() }) { ... } >>

=head3 EXAMPLE

	print "$_->{path}\n" for @{ App::WebPerimeterScan::Checks::sensitive_probes() };

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'arrayref', element_type => 'hashref' }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	┌─ SensitiveProbes ───────────────────────────────────
	│ result! : seq PROBE
	├─────────────────────────────────────────────────────
	│ result! = PROBES
	└─────────────────────────────────────────────────────

=cut

sub sensitive_probes
{
	return [ @PROBES ];
}

=head2 probe_origin

Purpose: the C<Origin> the CORS probe sends.  It is in the reserved
C<.invalid> TLD, so it can never be mistaken for a real site.

Args: none.

Returns: C<https://ws-probe.invalid>.

Side Effects: none.

Usage: C<< $http->fetch($url, headers => [ 'Origin: ' . probe_origin() ]) >>

=head3 EXAMPLE

	my $origin = App::WebPerimeterScan::Checks::probe_origin();

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'string', matches => qr/\.invalid\z/ }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	┌─ ProbeOrigin ───────────────────────────────────────
	│ result! : URL
	├─────────────────────────────────────────────────────
	│ result! = PROBE ∧ tld(PROBE) = invalid
	└─────────────────────────────────────────────────────

=cut

sub probe_origin
{
	return $PROBE_ORIGIN;
}

# _check_args
# Purpose:     the shared validation of every check_* function.
# Entry:       $findings is the first argument; $rest the remaining @_ as
#              an arrayref; $extra the function's own schema entries.
# Exit:        the validated named arguments (findings included).
# Side effects: croaks on a bad argument.
sub _check_args :Private
{
	my ($findings, $rest, $extra) = @_;

	return validate_strict(
		schema => {
			findings => { type => 'object', isa => 'App::WebPerimeterScan::Findings' },
			host     => { type => 'string', optional => 1 },
			url      => { type => 'string', optional => 1 },
			%{$extra},
		},
		input => { %{ get_params(undef, $rest) // {} }, findings => $findings },
	);
}

# _flag
# Purpose:     record one rule's finding with the rule table's defaults.
# Entry:       $id has catalogue text (or 'message' names text that does).
# Exit:        what Findings::report returns.
# Side effects: adds a finding.
sub _flag :Private
{
	my ($findings, $id, %args) = @_;

	# Undefined arguments are dropped so the rule table's defaults apply.
	return $findings->report($id,
		rule => $RULE{ $args{message} // $id } || {},
		map { defined $args{$_} ? ($_ => $args{$_}) : () } keys %args,
	);
}

# _page_flag
# Purpose:     _flag for a page rule.  Header rules are about the host, so
#              the URL is left empty unless given, which makes the same
#              missing header on forty pages one finding.
# Entry:       $page from check_page.
# Exit:        as _flag.
# Side effects: adds a finding.
sub _page_flag :Private
{
	my ($page, $id, %args) = @_;

	return _flag($page->{findings}, $id, host => $page->{host}, url => '', %args);
}

# _last
# Purpose:     the last value of a header in a parsed-headers hash.
# Entry:       $headers is name => arrayref.
# Exit:        the value or undef.
# Side effects: none.
sub _last :Private
{
	my ($headers, $name) = @_;

	my $values = $headers->{$name};

	return ($values && @{$values}) ? $values->[-1] : undef;
}

# _check_hsts
# Purpose:     Strict-Transport-Security present, long enough, covering
#              sub-domains.
# Entry:       $page is HTTPS.
# Exit:        $page.
# Side effects: may add hsts-missing, hsts-short-max-age or
#              hsts-no-subdomains.
sub _check_hsts :Private
{
	my ($page) = @_;

	my $hsts = _last($page->{headers}, 'strict-transport-security');
	my $minimum = $config{hsts_min_max_age};

	if(!defined $hsts) {
		_page_flag($page, 'hsts-missing', vars => { url => $page->{url} });
	} elsif($hsts =~ /max-age\s*=\s*"?(\d+)/i && $1 < $minimum) {
		_page_flag($page, 'hsts-short-max-age', vars => { value => $hsts, minimum => $minimum });
	} elsif($hsts =~ /max-age/i && $hsts !~ /includeSubDomains/i) {
		_page_flag($page, 'hsts-no-subdomains', vars => { value => $hsts });
	}

	return $page;
}

# _check_csp
# Purpose:     Content-Security-Policy present; script sources not
#              wildcarded; no effective unsafe-inline or unsafe-eval; and
#              some form of framing protection.
# Entry:       $page from check_page.
# Exit:        $page.
# Side effects: may add csp-missing, csp-wildcard, csp-unsafe, clickjacking.
#
# Only the script directive is judged.  A style-src 'unsafe-inline' is
# common and far less dangerous, and reporting it as an XSS gap was wrong.
sub _check_csp :Private
{
	my ($page) = @_;

	my $policy = join '; ', @{ $page->{headers}{'content-security-policy'} || [] };
	my $directives = _csp_directives($policy);

	_page_flag($page, 'clickjacking')
		unless defined _last($page->{headers}, 'x-frame-options') || exists $directives->{'frame-ancestors'};

	unless(length $policy) {
		_page_flag($page, 'csp-missing', vars => { url => $page->{url} });
		return $page;
	}

	# script-src governs scripts; default-src only when script-src is absent.
	my ($name) = grep { exists $directives->{$_} } qw(script-src default-src);
	return $page unless defined $name;

	my @sources = @{ $directives->{$name} };
	my %has = map { lc($_) => 1 } @sources;
	my $vars = { directive => $name, sources => join(' ', @sources) };

	# 'strict-dynamic' makes CSP3 browsers ignore host and scheme sources.
	_page_flag($page, 'csp-wildcard', vars => $vars)
		if !$has{q{'strict-dynamic'}} && grep { $ANY_SOURCE{ lc $_ } } @sources;

	# A nonce or hash makes browsers ignore 'unsafe-inline'.
	my $inline_effective = $has{q{'unsafe-inline'}} && !grep { $_ =~ $NONCE_OR_HASH } @sources;
	_page_flag($page, 'csp-unsafe', vars => $vars)
		if $inline_effective || $has{q{'unsafe-eval'}};

	return $page;
}

# _csp_directives
# Purpose:     parse a policy into directive => [sources].
# Entry:       $policy is the header value(s), joined with "; ".
# Exit:        hashref; the first occurrence of a directive wins, as in CSP.
# Side effects: none.
sub _csp_directives :Private
{
	my ($policy) = @_;

	my %directives;
	for my $directive (split /[;,]/, $policy) {
		my ($name, @sources) = split ' ', $directive;
		$directives{ lc $name } //= \@sources if defined $name;
	}

	return \%directives;
}

# _check_simple_headers
# Purpose:     the presence-only header rules.
# Entry:       $page from check_page.
# Exit:        $page.
# Side effects: may add nosniff-missing, referrer-policy-missing,
#              permissions-policy-missing.
sub _check_simple_headers :Private
{
	my ($page) = @_;

	my $headers = $page->{headers};

	my $xcto = _last($headers, 'x-content-type-options');
	_page_flag($page, 'nosniff-missing', vars => { present => defined $xcto ? 'yes' : 'no', value => $xcto })
		unless defined $xcto && $xcto =~ /nosniff/i;

	_page_flag($page, 'referrer-policy-missing') unless defined _last($headers, 'referrer-policy');

	# Feature-Policy is the old name and still counts.
	_page_flag($page, 'permissions-policy-missing')
		unless grep { defined _last($headers, $_) } qw(permissions-policy feature-policy);

	return $page;
}

# _check_disclosure
# Purpose:     version and platform disclosure.
# Entry:       $page from check_page.
# Exit:        $page.
# Side effects: may add server-version-disclosed, x-powered-by, php2shell,
#              generator-disclosed.
sub _check_disclosure :Private
{
	my ($page) = @_;

	my $server = _last($page->{headers}, 'server') // '';
	_page_flag($page, 'server-version-disclosed', vars => { server => $server })
		if $server =~ m{[\w.-]+/\d+(?:\.\d+)+};

	my $powered_by = _last($page->{headers}, 'x-powered-by') // '';
	if(length $powered_by) {
		_page_flag($page, 'x-powered-by', vars => { value => $powered_by });
		_check_php($page, $1) if $powered_by =~ m{PHP/(\d+\.\d+\.\d+)};
	}

	my $generator = $page->{html}{generator};
	_page_flag($page, 'generator-disclosed', url => $page->{url}, vars => { generator => $generator })
		if defined $generator && length $generator;

	return $page;
}

# _check_php
# Purpose:     the PHP2Shell version rule.
# Entry:       $version is "major.minor.patch" from X-Powered-By.
# Exit:        $page.
# Side effects: may add php2shell.
sub _check_php :Private
{
	my ($page, $version) = @_;

	my ($branch) = $version =~ /\A(\d+\.\d+)\./;
	my $fixed = $PHP2SHELL_FIXED{$branch};

	# Older than every fixed branch: no fix exists.  A listed branch: below
	# its fix level.  Anything newer than the table is assumed fixed.
	my $reason = _version_lt($version, $PHP2SHELL_OLDEST_BRANCH) ? 'unsupported'
		: (defined $fixed && _version_lt($version, $fixed)) ? 'below'
		: undef;

	# Newest branch first, as an upgrade path reads best that way.
	my $fixed_list = join ' / ', map { $PHP2SHELL_FIXED{$_} }
		sort { _version_lt($b, $a) ? -1 : 1 } keys %PHP2SHELL_FIXED;

	_page_flag($page, 'php2shell', vars => {
		version => $version, fixed => $fixed // '', reason => $reason, fixed_list => $fixed_list,
	}) if defined $reason;

	return $page;
}

# _check_cookies
# Purpose:     Secure (on HTTPS), HttpOnly and SameSite on every cookie.
# Entry:       $page from check_page.
# Exit:        $page.
# Side effects: may add one cookie-flags finding per cookie name.
sub _check_cookies :Private
{
	my ($page) = @_;

	for my $cookie (@{ $page->{set_cookie} }) {
		my ($name) = $cookie =~ /\A\s*([^=;]+?)\s*=/;
		next unless defined $name && length $name;

		my @missing = grep { $cookie !~ _attribute_re($_) }
			$page->{is_https} ? qw(Secure HttpOnly SameSite) : qw(HttpOnly SameSite);
		next unless @missing;

		# Sent over plaintext is worse than readable by script.
		my $secure_missing = grep { $_ eq 'Secure' } @missing;

		_page_flag($page, 'cookie-flags',
			key      => $name,
			severity => $secure_missing ? 'medium' : 'low',
			vars     => {
				name    => $name,
				missing => join(', ', @missing),
				cookie  => _excerpt($cookie, 0),
				url     => $page->{url},
			},
		);
	}

	return $page;
}

# _attribute_re
# Purpose:     the regexp that finds one cookie attribute.
# Entry:       $attribute is Secure, HttpOnly or SameSite.
# Exit:        a qr//.  SameSite needs a value; the others are flags.
# Side effects: none.
sub _attribute_re :Private
{
	my ($attribute) = @_;

	return $attribute eq 'SameSite' ? qr/;\s*SameSite\s*=/i : qr/;\s*\Q$attribute\E\b/i;
}

# _check_body
# Purpose:     the response-body rules.
# Entry:       $page from check_page.
# Exit:        $page.
# Side effects: may add directory-listing, error-disclosure and the two
#              mixed-content findings.
sub _check_body :Private
{
	my ($page) = @_;

	my $body = $page->{body};
	return $page unless length $body;

	my $title = $page->{html}{title} // '';
	_page_flag($page, 'directory-listing', url => $page->{url}, vars => { title => _excerpt($title, 0) })
		if $title =~ m{\A\s*Index of\s*/}i;

	# Only look for error signatures in something that looks like an error.
	if($page->{status} >= $HTTP_SERVER_ERROR || $body =~ $ERROR_HINT) {
		my @markers = map { __PACKAGE__->i18n("error-marker.$_->[0]") } grep { $body =~ $_->[1] } @ERROR_MARKERS;
		_page_flag($page, 'error-disclosure',
			url      => $page->{url},
			evidence => _excerpt($body, 1),
			vars     => { markers => join(', ', @markers) },
		) if @markers;
	}

	_check_mixed_content($page) if $page->{is_https};

	return $page;
}

# _check_mixed_content
# Purpose:     resources loaded over http:// from an HTTPS page.
# Entry:       $page is HTTPS and has parsed HTML.
# Exit:        $page.
# Side effects: may add mixed-content-active and mixed-content-passive.
sub _check_mixed_content :Private
{
	my ($page) = @_;

	my (%seen, %by_class);
	for my $resource (@{ $page->{html}{resources} }) {
		my ($class, $tag, $url) = @{$resource};
		next if $seen{$url}++;
		push @{ $by_class{$class} }, "$tag $url";
		last if keys(%seen) >= $config{mixed_content_limit};
	}

	for my $class (sort keys %by_class) {
		_page_flag($page, "mixed-content-$class", url => $page->{url}, evidence => join('; ', @{ $by_class{$class} }));
	}

	return $page;
}

# _parse_html
# Purpose:     the facts the page rules need from the markup, in one pass.
# Entry:       $body is the response body (any content type).
# Exit:        hashref: title (first <title>, or undef), generator (or
#              undef), resources (arrayref of [class, tag, url] for each
#              plaintext http:// resource that is loaded).
# Side effects: none.
#
# HTML::Parser rather than regexps: attribute order, quoting and entities
# all vary, and the old regexps both missed resources and flagged
# <link rel="canonical"> as though a canonical URL were loaded.
sub _parse_html :Private
{
	my ($body) = @_;

	my %html = (title => undef, generator => undef, resources => []);
	my $in_title = 0;

	my $parser = HTML::Parser->new(
		api_version => 3,
		start_h     => [ sub {
			my ($tag, $attr) = @_;
			if($tag eq 'title') {
				$in_title = !defined $html{title};
				$html{title} //= '';
			} elsif($tag eq 'meta' && lc($attr->{name} // '') eq 'generator') {
				$html{generator} //= $attr->{content};
			} elsif(my $resource = _resource($tag, $attr)) {
				push @{ $html{resources} }, $resource;
			}
		}, 'tagname, attr' ],
		end_h  => [ sub { $in_title = 0 if $_[0] eq 'title' }, 'tagname' ],
		text_h => [ sub { $html{title} .= $_[0] if $in_title }, 'dtext' ],
	);
	$parser->parse($body);
	$parser->eof;

	return \%html;
}

# _resource
# Purpose:     classify one tag as a mixed-content resource.
# Entry:       $tag is lower case; $attr has lower-case keys.
# Exit:        [class, tag, url] when it loads an http:// URL, else undef.
# Side effects: none.
sub _resource :Private
{
	my ($tag, $attr) = @_;

	my ($name, $class) = @{ $RESOURCE{$tag} || [] };
	my $url = defined $name ? $attr->{$name} : undef;
	return undef unless defined $url && $url =~ $PLAINTEXT_URL;

	# A link loads something only for some relations.
	($class) = grep { defined } map { $LINK_REL{ lc $_ } } split ' ', $attr->{rel} // ''
		if $tag eq 'link';

	return defined $class ? [ $class, $tag, $url ] : undef;
}

# _excerpt
# Purpose:     a short, single-line piece of text for evidence.
# Entry:       $strip_tags removes markup first (for HTML bodies).
# Exit:        at most excerpt_length characters, with "..." if cut.
# Side effects: none.
sub _excerpt :Private
{
	my ($text, $strip_tags) = @_;

	$text =~ s/<[^>]+>/ /g if $strip_tags;
	$text =~ s/\s+/ /g;
	$text =~ s/\A\s+|\s+\z//g;

	my $limit = $config{excerpt_length};

	return length($text) > $limit ? substr($text, 0, $limit) . '...' : $text;
}

# _check_expiry
# Purpose:     expired and soon-to-expire certificates.
# Entry:       $tls->{ok} is true.
# Exit:        $findings.
# Side effects: may add tls-expired or tls-expiring.
sub _check_expiry :Private
{
	my ($findings, $host, $tls) = @_;

	my $days = $tls->{days_left};
	return $findings unless defined $days;

	my $vars = { days => abs $days, not_after => $tls->{not_after} // __PACKAGE__->i18n('report.unknown') };
	if($days < 0) {
		_flag($findings, 'tls-expired', host => $host, vars => $vars);
	} elsif($days < $config{tls_expiry_warn_days}) {
		_flag($findings, 'tls-expiring', host => $host, vars => $vars,
			severity => $days < $config{tls_expiry_high_days} ? 'high' : 'medium');
	}

	return $findings;
}

# _check_protocols
# Purpose:     deprecated protocol versions and weak ciphers.
# Entry:       $tls->{ok} is true.
# Exit:        $findings.
# Side effects: may add tls-legacy-protocol and tls-weak-cipher.
sub _check_protocols :Private
{
	my ($findings, $host, $tls) = @_;

	my %accepted = map { $_ => 1 } @{ $tls->{protocols} || [] };
	my @legacy = grep { $accepted{$_} } @LEGACY_PROTOCOLS;

	# TLS 1.0 is the worse of the two.
	_flag($findings, 'tls-legacy-protocol', host => $host,
		severity => $accepted{ $LEGACY_PROTOCOLS[0] } ? 'high' : 'medium',
		vars     => { protocols => join(', ', @legacy) },
	) if @legacy;

	my $cipher = $tls->{cipher} // '';
	_flag($findings, 'tls-weak-cipher', host => $host,
		vars => { cipher => $cipher, protocol => $tls->{protocol} // __PACKAGE__->i18n('report.unknown') },
	) if $cipher =~ $WEAK_CIPHER;

	return $findings;
}

# _check_ssh_banners
# Purpose:     OpenSSH banners older than ssh_min_version.
# Entry:       $open is the scan's open-port list.
# Exit:        $findings.
# Side effects: may add outdated-ssh-banner.
sub _check_ssh_banners :Private
{
	my ($findings, $host, $open) = @_;

	my $minimum = $config{ssh_min_version};
	my @outdated;
	for my $entry (@{$open}) {
		my $banner = $entry->{banner} // '';
		next unless $banner =~ /OpenSSH[_-](\d+(?:\.\d+)*)/i && _version_lt($1, $minimum);
		push @outdated, __PACKAGE__->i18n('outdated-ssh-banner.item', { port => $entry->{port}, banner => $banner });
	}

	_flag($findings, 'outdated-ssh-banner', host => $host,
		evidence => join('; ', @outdated), vars => { minimum => $minimum },
	) if @outdated;

	return $findings;
}

# _version_lt
# Purpose:     is one dotted version older than another?
# Entry:       both are digits and dots ("8.2.20", "9.0").
# Exit:        1 or 0; 0 if either does not parse.
# Side effects: none.
#
# version.pm, as dotted-decimal ("v8.10" is newer than "v8.9"), rather than
# the hand-written three-part comparison this replaced.
sub _version_lt :Private
{
	my ($left, $right) = @_;

	my $lt = eval { version->parse("v$left") < version->parse("v$right") };

	return $lt ? 1 : 0;
}

# _probe_path
# Purpose:     request one sensitive path and report it if really present.
# Entry:       $args from check_paths; $root has no trailing "/".
# Exit:        $findings.
# Side effects: one request; may add the probe's finding.
sub _probe_path :Private
{
	my ($findings, $args, $root, $probe) = @_;

	my $url = $root . $probe->{path};
	my $res = $args->{http}->fetch($url);
	my $body = $res->{body} // '';
	my $baseline = $args->{baseline} // '';

	# A catch-all application answers everything alike; only a response
	# that differs from the baseline AND looks like the real file counts.
	my $present = !$res->{error}
		&& ($res->{status} // 0) == $HTTP_OK
		&& !(length $baseline && fingerprint($res) eq $baseline)
		&& $body =~ $probe->{match};

	_flag($findings, $probe->{id},
		host      => $args->{host},
		url       => $url,
		severity  => $probe->{severity},
		reference => $probe->{reference},
		evidence  => _excerpt($body, 0),
	) if $present;

	return $findings;
}

# _fetch_ok
# Purpose:     the body of a URL that answered 200, else undef.
# Entry:       $http can fetch.
# Exit:        the body or undef.
# Side effects: one request.
sub _fetch_ok :Private
{
	my ($http, $url) = @_;

	my $res = $http->fetch($url);

	return (!$res->{error} && ($res->{status} // 0) == $HTTP_OK) ? ($res->{body} // '') : undef;
}

# _check_security_txt
# Purpose:     note a published security.txt, as a low-priority prompt.
# Entry:       as _probe_path.
# Exit:        $findings.
# Side effects: one request; may add security-txt-present.
sub _check_security_txt :Private
{
	my ($findings, $args, $root) = @_;

	my $body = _fetch_ok($args->{http}, $root . $SECURITY_TXT);
	_flag($findings, 'security-txt-present', host => $args->{host}, url => $root . $SECURITY_TXT)
		if defined $body && $body =~ /^\s*Contact\s*:/mi;

	return $findings;
}

# _check_robots
# Purpose:     robots.txt is not a vulnerability, but it often lists exactly
#              the paths an operator wanted to hide.
# Entry:       as _probe_path.
# Exit:        $findings.
# Side effects: one request; may add robots-disclosure.
sub _check_robots :Private
{
	my ($findings, $args, $root) = @_;

	my $body = _fetch_ok($args->{http}, $root . $ROBOTS_TXT) // '';
	my @disallow = $body =~ /^\s*Disallow:\s*(\S+)/gmi;

	# A slice of the first few, never past the end: grep over a slice that
	# runs past the end creates the missing elements and inflates the count.
	my $shown = join ' ', @disallow > $config{robots_limit} ? @disallow[0 .. $config{robots_limit} - 1] : @disallow;
	_flag($findings, 'robots-disclosure',
		host => $args->{host},
		url  => $root . $ROBOTS_TXT,
		vars => { count => scalar @disallow, paths => $shown },
	) if @disallow;

	return $findings;
}

1;

__END__

=head1 RULES

Each finding id, its usual severity and what triggers it.  The text is in
L<App::WebPerimeterScan::Messages>.

	hsts-missing / -short-max-age / -no-subdomains   HTTPS page, HSTS header
	csp-missing / -wildcard / -unsafe                CSP header, script sources
	clickjacking                                     no XFO, no frame-ancestors
	nosniff-missing, referrer-policy-missing,
	permissions-policy-missing                       header absent
	server-version-disclosed, x-powered-by,
	generator-disclosed                              version disclosure
	php2shell                                        PHP below the fix level
	cookie-flags                                     Secure/HttpOnly/SameSite
	directory-listing, error-disclosure              response body
	mixed-content-active / -passive                  http:// resources on HTTPS
	cors-misconfiguration                            CORS probe response
	trace-enabled, write-methods-enabled             OPTIONS response
	tls-*                                            TLS inspection
	port-open-N, ports-other-open,
	outdated-ssh-banner                              port scan
	(probe ids), security-txt-present,
	robots-disclosure                                path probes

=head1 LIMITATIONS

=over 4

=item * Several C<Content-Security-Policy> headers are joined and read as
one policy.  Browsers enforce each separately, so a strict second policy
can make a lax first one safe; this module would still report the lax one.

=item * The PHP2Shell rule trusts C<X-Powered-By>.  A server that hides or
fakes the header is judged on what it claims.

=item * Mixed content is found in the markup only; resources requested by
script or CSS at run time are not seen.

=item * The C<.svn/entries> probe matches the pre-1.7 format only.

=back

=head1 LICENSE

GPL2

=cut
