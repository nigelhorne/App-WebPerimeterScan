package App::WebPerimeterScan;

use strict;
use warnings;

use HTML::SimpleLinkExtor;
use Time::HiRes qw(time);
use URI;

use App::WebPerimeterScan::Checks;
use App::WebPerimeterScan::Findings;
use App::WebPerimeterScan::HTTP;
use App::WebPerimeterScan::Ports;
use App::WebPerimeterScan::Source;
use App::WebPerimeterScan::TLS;

use version; our $VERSION = version->declare('0.001.0');

# Crawling is for finding pages that share the site's header policy, not for
# mirroring the site.  These are skipped so a scan does not waste requests on
# assets.
my %SKIP_EXTENSION = map { $_ => 1 } qw(
	jpg jpeg png gif svg webp ico bmp tif tiff css js mjs json map
	pdf zip gz tgz bz2 xz rar 7z tar mp3 mp4 m4a avi mov wmv wav
	woff woff2 ttf eot otf exe dmg iso apk jar deb rpm
);

sub new
{
	my ($class, %args) = @_;

	my $self = bless {
		scope       => $args{scope},
		timeout     => $args{timeout} // 10,
		delay       => defined $args{delay} ? $args{delay} : 0.5,
		depth       => $args{depth} // 1,
		max_urls    => $args{max_urls} // 40,
		path_probes => exists $args{path_probes} ? $args{path_probes} : 1,
		reflection  => $args{reflection} ? 1 : 0,
		verbose     => $args{verbose} ? 1 : 0,
		ports       => $args{ports} // [ @App::WebPerimeterScan::Ports::DEFAULT_PORTS ],
		hosts       => {},
		findings    => App::WebPerimeterScan::Findings->new,
	}, $class;

	$self->{connect_timeout} = $args{connect_timeout} // 3;

	$self->{docroots}    = $args{docroots}    // [];
	$self->{source_dirs} = $args{source_dirs} // [];

	if(@{ $self->{docroots} } || @{ $self->{source_dirs} }) {
		$self->{source} = App::WebPerimeterScan::Source->new(
			docroots    => $self->{docroots},
			source_dirs => $self->{source_dirs},
		);
	}

	$self->{http} = App::WebPerimeterScan::HTTP->new(
		timeout  => $self->{timeout},
		delay    => $self->{delay},
		max_size => $args{max_size} // 2_000_000,
	);

	return $self;
}

sub findings
{
	my ($self) = @_;

	return $self->{findings};
}

sub http
{
	my ($self) = @_;

	return $self->{http};
}

sub host_reports
{
	my ($self) = @_;

	return [ map { $self->{hosts}{$_} } sort keys %{ $self->{hosts} } ];
}

sub run
{
	my ($self) = @_;

	my @entries = $self->{scope}->hosts;
	die "No concrete hosts in scope (only wildcards?)\n" unless @entries;

	for my $entry (@entries) {
		eval { $self->_scan_host($entry) };
		if(my $error = $@) {
			chomp $error;
			$self->{findings}->add(
				id => 'scan-error', severity => 'info',
				host => $entry->{host},
				title => "Scan of $entry->{host} did not complete",
				detail => $error,
			);
		}
	}

	$self->_source_pass;

	return $self->{findings};
}

# The parsed headers of a response plus the raw block exactly as it arrived,
# so a finding can be checked after the fact - by another person, or on a
# machine that cannot reach the host at all.  Duplicates are preserved
# because a second CSP or Set-Cookie header is part of the evidence.
sub _record_response
{
	my ($self, $url, $method, $res, $note) = @_;

	return unless $res && !$res->{error};

	my %headers;
	for my $name (keys %{ $res->{headers} || {} }) {
		$headers{$name} = [ @{ $res->{headers}{$name} } ];
	}

	my $record = {
		url          => $url,
		method       => $method || 'GET',
		status       => $res->{status},
		http_version => $res->{http_version},
		reason       => $res->{reason},
		headers      => \%headers,
		raw          => $res->{raw_headers},
	};
	$record->{note} = $note if defined $note && length $note;

	return $record;
}

sub _keep_response
{
	my ($self, $report, $url, $method, $res, $note) = @_;

	my $record = $self->_record_response($url, $method, $res, $note) or return;

	push @{ $report->{responses} }, $record;

	return $record;
}

sub _say
{
	my ($self, $message) = @_;

	print STDERR "[webperimeter] $message\n" if $self->{verbose};

	return;
}

sub _scan_host
{
	my ($self, $entry) = @_;

	my $host = $entry->{host};
	$self->{scope}->assert_target_allowed($host);

	$self->_say("host $host");

	my $report = { host => $host, urls => [], entry => $entry };
	$self->{hosts}{$host} = $report;

	my $port_scan = App::WebPerimeterScan::Ports->scan(
		host    => $host,
		ports   => $self->{ports},
		timeout => $self->{connect_timeout},
	);
	$report->{open_ports} = $port_scan->{open};
	App::WebPerimeterScan::Checks::check_ports($self->{findings}, host => $host, scan => $port_scan);

	my ($base, $root) = $self->_fetch_root($entry);
	unless($base) {
		$self->{findings}->add(
			id => 'host-unreachable', severity => 'high',
			host => $host, url => '',
			title => 'Host did not answer over HTTP or HTTPS',
			detail => 'No usable response was received on the default web ports, so the web checks could not run.',
			evidence => 'Tried ' . join(', ', $self->_root_candidates($entry)),
			fix => 'Confirm the hostname resolves and the web server is listening.',
		);
		return;
	}

	$report->{base} = $base;
	$self->_say("base URL $base");

	# The exact block the header checks were run against, so the report can
	# be audited later without sending the request again.
	$report->{response} = $self->_record_response($base, 'GET', $root, 'main page');

	# Inspect TLS whenever HTTPS is actually served, and also when 443 is
	# open but the handshake failed - that failure is itself a finding.
	my $tls_port;
	if($base =~ m{^https://}i) {
		my $uri = URI->new($base);
		$tls_port = $uri->port || 443;
	} elsif(grep { $_->{port} == 443 || $_->{port} == 8443 } @{ $port_scan->{open} || [] }) {
		$tls_port = 443;
	}

	if($tls_port) {
		my $tls = App::WebPerimeterScan::TLS->inspect(
			host => $host, port => $tls_port, timeout => $self->{connect_timeout},
		);
		$report->{tls} = $tls;
		App::WebPerimeterScan::Checks::check_tls($self->{findings}, host => $host, tls => $tls);
	}

	my $root_url = $base;
	$root_url =~ s{/+$}{};

	# Same-origin probes: a foreign Origin header, an OPTIONS request, and
	# the plaintext hop that HSTS depends on.
	my $origin = App::WebPerimeterScan::Checks::probe_origin();
	my $cors = $self->{http}->fetch($base, headers => [ "Origin: $origin" ]);
	App::WebPerimeterScan::Checks::check_cors($self->{findings}, host => $host, url => $base, res => $cors);
	$self->_keep_response($report, $base, 'GET', $cors, "Origin: $origin");

	my $options = $self->{http}->fetch($base, method => 'OPTIONS');
	App::WebPerimeterScan::Checks::check_methods($self->{findings}, host => $host, url => $base, res => $options);
	$self->_keep_response($report, $base, 'OPTIONS', $options);

	if($base =~ m{^https://}i && !$entry->{port}) {
		my $plain = $self->{http}->fetch("http://$host/");
		$self->_keep_response($report, "http://$host/", 'GET', $plain, 'plaintext hop');
		if(!$plain->{error}) {
			my $location = $plain->{headers}{location} ? $plain->{headers}{location}[-1] : '';
			my $status = $plain->{status} // 0;
			if($status !~ /^30[1238]$/ || $location !~ m{^https://}i) {
				$self->{findings}->add(
					id => 'no-https-redirect', severity => 'medium',
					host => $host, url => '',
					title => 'Plain HTTP does not redirect to HTTPS',
					detail => 'The first request a visitor makes can be read or rewritten by a network attacker before any HSTS policy is learned.',
					evidence => "GET http://$host/ returned $status" . (length $location ? " with Location: $location" : ' with no HTTPS redirect'),
					fix => 'Redirect all HTTP requests to HTTPS with a 301, and send HSTS on the HTTPS response.',
					reference => 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections',
				);
			}
		}
	}

	# Crawl the site's own pages, depth-first from the root, within budget.
	my @queue = ([ $base, 0 ]);
	my %seen = ($base => 1);
	my $fetched = 0;

	while(@queue && $fetched < $self->{max_urls}) {
		my ($url, $depth) = @{ shift @queue };

		my $res = ($url eq $base) ? $root : $self->{http}->fetch($url);
		next if $res->{error};

		$fetched++;
		push @{ $report->{urls} }, $url;

		App::WebPerimeterScan::Checks::check_page(
			$self->{findings}, host => $host, url => $url, res => $res,
		);

		next if $depth >= $self->{depth};
		next unless ($res->{content_type} // '') =~ m{text/html|application/xhtml}i;

		for my $link ($self->_links($res->{body}, $url)) {
			my $uri = eval { URI->new($link) } or next;
			next unless $self->{scope}->covers($uri->host);
			next if $seen{$link}++;

			push @queue, [ $link, $depth + 1 ];
		}
	}

	$self->_say("$fetched URL(s) scanned on $host");

	if($self->{path_probes}) {
		my $token = _random_token();

		# A path that certainly does not exist.  Its fingerprint tells us
		# whether this application answers 200 for everything, in which case
		# a 200 on /.git/config proves nothing.
		my $miss = $self->{http}->fetch($root_url . "/ws-baseline-$token.html");
		my $baseline = App::WebPerimeterScan::Checks::fingerprint($miss);

		if(!$miss->{error} && ($miss->{status} // 0) == 200) {
			$self->{findings}->add(
				id => 'catch-all-200', severity => 'info',
				host => $host, url => '',
				title => 'Application answers 200 for paths that do not exist',
				detail => 'Path-probe results were compared against this response and only reported when the content actually matched, so there should be no false positives from the catch-all behaviour. It is still worth fixing: it confuses monitoring and search engines.',
				evidence => "GET /ws-baseline-$token.html returned 200",
				fix => 'Return 404 for unknown paths.',
			);
		}

		App::WebPerimeterScan::Checks::check_paths(
			$self->{findings},
			http     => $self->{http},
			host     => $host,
			base     => $base,
			baseline => $baseline,
		);
	}

	$self->_reflection_probe($host, $base) if $self->{reflection};

	$self->_unvisited_routes($host, $report) if $self->{source};

	return;
}

# ---------------------------------------------------------------------------
# Source-aware pass
#
# A black-box scan can only say that a URL answered.  Given a docroot and a
# source tree it can also say which file on disk is being served and which
# line of code defines the endpoint, which is what makes a finding actionable.
# ---------------------------------------------------------------------------

sub _url_path
{
	my ($self, $url) = @_;

	my $uri = eval { URI->new($url) } or return;

	return $uri->path;
}

sub _source_pass
{
	my ($self) = @_;

	my $source = $self->{source} or return;

	for my $finding ($self->{findings}->all) {
		next unless length $finding->{url};

		my $path = $self->_url_path($finding->{url});
		next unless defined $path && length $path;

		if(my $file = $source->file_for($path)) {
			$finding->{file} = $file->{path};
		}
		if(my $route = $source->route_for($path)) {
			$finding->{source} = "$route->{file}:$route->{line}";
		}
	}

	$self->_docroot_files($source);

	return;
}

# A sensitive file that is on disk but was not served is a deployment hazard
# waiting for one configuration change, so it ranks below the same file being
# served for real.  It is keyed on the file so several probes cannot repeat it.
sub _docroot_files
{
	my ($self, $source) = @_;

	my $findings = $self->{findings};

	for my $probe (App::WebPerimeterScan::Checks::sensitive_probes()) {
		next unless $probe->{severity} eq 'critical' || $probe->{severity} eq 'high';
		next if grep { $_->{id} eq $probe->{id} } $findings->all;

		my $hit = $source->file_for($probe->{path}) or next;

		$findings->add(
			id       => 'source-file-in-docroot',
			severity => $probe->{severity} eq 'critical' ? 'medium' : 'low',
			host     => '',
			url      => '',
			key      => $hit->{path},
			title    => "Sensitive file is inside a document root: $hit->{relative}",
			detail   => 'The file is on disk under a docroot but was not served during this scan. Any change that starts serving dotfiles - a handler, a rewrite, a new vhost - exposes it at once.',
			evidence => $hit->{path},
			fix      => 'Move it above the document root, or deny the path at the web server.',
		);
	}

	return;
}

# The routes in the source that no crawled page linked to: the coverage gap a
# link-following scan cannot see, and where real endpoints usually hide.
sub _unvisited_routes
{
	my ($self, $host, $report) = @_;

	my @routes = $self->{source}->routes;
	return unless @routes;

	my %visited;
	for my $url (@{ $report->{urls} }) {
		my $path = $self->_url_path($url);
		$visited{$path} = 1 if defined $path && length $path;
	}

	# Path probes are not part of the crawl, but a finding that names a URL
	# proves that URL was requested, so a route serving it is not a gap.
	for my $finding ($self->{findings}->all) {
		next unless length $finding->{url};
		my $path = $self->_url_path($finding->{url});
		$visited{$path} = 1 if defined $path && length $path;
	}

	my @unvisited;
	for my $route (@routes) {
		next if grep { $_ =~ $route->{re} } keys %visited;
		push @unvisited, $route;
	}
	return unless @unvisited;

	my $last = $#unvisited > 9 ? 9 : $#unvisited;
	$self->{findings}->add(
		id       => 'source-routes-unvisited',
		severity => 'info',
		host     => $host,
		url      => '',
		title    => scalar(@unvisited) . ' endpoint(s) defined in source were not scanned',
		detail   => 'These routes exist in the code but no crawled page linked to them, so none of the checks above saw how they behave. They are exactly the surface a link-following scan never reaches.',
		evidence => join('; ', map { "$_->{file}:$_->{line} $_->{method} $_->{pattern}" } @unvisited[ 0 .. $last ]),
		fix      => 'Name them explicitly, raise --max-urls, or review them by hand.',
	);

	return;
}

sub _root_candidates
{
	my ($self, $entry) = @_;

	my $host = $entry->{host};

	if($entry->{port}) {
		my $scheme = $entry->{scheme}
			|| ($entry->{port} == 443 || $entry->{port} == 8443 ? 'https' : 'http');
		return ("$scheme://$host:$entry->{port}/");
	}
	return ("$entry->{scheme}://$host/") if $entry->{scheme};
	return ("https://$host/", "http://$host/");
}

sub _fetch_root
{
	my ($self, $entry) = @_;

	for my $base ($self->_root_candidates($entry)) {
		my $res = $self->{http}->fetch($base);
		next if $res->{error};
		return ($base, $res);
	}

	return;
}

sub _links
{
	my ($self, $body, $base) = @_;

	return () unless defined $body && length $body;

	my $extor = eval { HTML::SimpleLinkExtor->new($base) };
	return () unless $extor;
	eval { $extor->parse($body) };
	return () if $@;

	my (@links, %seen);
	for my $found ($extor->links) {
		my $uri = eval { URI->new_abs($found, $base) } or next;
		my $scheme = lc($uri->scheme // '');
		next unless $scheme eq 'http' || $scheme eq 'https';

		$uri->fragment(undef);
		my $path = $uri->path // '';
		if($path =~ /\.([A-Za-z0-9]+)$/) {
			next if $SKIP_EXTENSION{ lc $1 };
		}

		my $string = $uri->as_string;
		next if $seen{$string}++;
		push @links, $string;
		last if @links >= 60;
	}

	return @links;
}

# Opt-in: send one harmless marker in a query parameter and see whether it
# comes back unencoded.  This is a hint for a human to follow up, not a proof
# of cross-site scripting, so it is reported as a low-severity prompt.
sub _reflection_probe
{
	my ($self, $host, $base) = @_;

	my $marker = 'wsp' . _random_token();
	my $payload = $marker . '</x>';

	my $uri = URI->new($base);
	my $query = $uri->query // '';
	$query .= '&' if length $query;
	$query .= 'wsprobe=' . $marker . '%3C%2Fx%3E';
	$uri->query($query);

	my $res = $self->{http}->fetch($uri->as_string);
	return if $res->{error};

	my $body = $res->{body} // '';
	return unless index($body, $payload) >= 0;

	$self->{findings}->add(
		id => 'reflected-input', severity => 'medium',
		host => $host, url => $uri->as_string,
		title => 'Query parameter is reflected without HTML encoding',
		detail => 'The marker was returned verbatim, including its angle brackets. That is the precondition for reflected cross-site scripting; it still needs a human to confirm that a browser will execute the result.',
		evidence => "Sent wsprobe=$marker%3C%2Fx%3E and received it back unencoded",
		fix => 'HTML-encode all output, and add a CSP that forbids inline script.',
		reference => 'https://cwe.mitre.org/data/definitions/79.html',
	);

	return;
}

sub _random_token
{
	my @chars = ( 'a' .. 'z', 0 .. 9 );

	return join '', map { $chars[ int rand @chars ] } 1 .. 10;
}

1;

__END__

=head1 NAME

App::WebPerimeterScan - check your own web perimeter the way an outsider sees it

=head1 VERSION

Version 0.001.0

=head1 SYNOPSIS

	use App::WebPerimeterScan;
	use App::WebPerimeterScan::Scope;

	my $scope = App::WebPerimeterScan::Scope->new->load_file('scope.txt');
	my $scanner = App::WebPerimeterScan->new(scope => $scope, depth => 1);
	my $findings = $scanner->run;

	print $_->{severity}, ' ', $_->{title}, "\n" for $findings->sorted;

=head1 DESCRIPTION

An external, unauthenticated scan of hosts you own: which ports are reachable,
what the TLS configuration allows, which security headers are missing, whether
session cookies are protected, and whether well-known sensitive paths have been
left in the document root.

It deliberately does not attempt exploitation.  There is no payload
injection, no credential guessing and no write request outside the single
B<OPTIONS> probe, so it is safe to point at a production site.

F<README.md> is generated from this POD by F<pod2github>: change the POD and
regenerate, rather than editing the README by hand.

The scope file is the authorisation boundary: a host that does not appear in
it is never contacted, including hosts discovered by following links.

=head1 REQUIREMENTS

Perl 5.10.0 or later, with the modules listed in F<Makefile.PL>.  The minimum
Perl was measured with L<Perl::MinimumVersion> rather than guessed, and the
suite is run against 5.10.1 as well as current perls.  C<cpan> installs
anything that is missing, so these floors matter mainly on a machine that
already has older copies of them:

=over 4

=item * C<Socket> 2.020

The core of Perl 5.10.1 ships 2.018, so this is a real installation step on
the minimum Perl.  The port scan reads C<SO_ERROR> from it to tell a refused
connection from an open one.

=item * C<Net::SSLeay> 1.92

The first release with OpenSSL 3 support.  Earlier releases are not
supported: 1.46 does not compile against OpenSSL 3 at all.

=item * C<IO::Socket::SSL> 2.000

=item * C<IO::Select> 1.17 and C<IO::Socket::INET> 1.31

The versions that ship with Perl 5.10.1, so the minimum Perl needs no
upgrade here.  They are stated because the port scan relies on how they
behave, not only on what they provide.

=back

Both SSL modules need the OpenSSL headers at install time, which the
installer cannot supply for you; install your distribution's C<openssl>
development package first if the build fails.

The remaining prerequisites are C<Getopt::Long> 2.50,
C<HTML::SimpleLinkExtor> 1.20, C<JSON::PP> 4.00, C<Time::HiRes> 1.97,
C<Time::Local> 1.28 and C<URI> 1.70, plus C<Test::More> 1.302 for the test
suite.  Several of these are newer than the copies that ship with Perl 5.10,
so on the minimum Perl let the installer upgrade them instead of pinning the
core versions.

=head1 USAGE

	bin/webperimeter --scope scope.txt --authorized

The scope file lists the hosts you are allowed to test, one per line.  Without
C<--authorized> the tool refuses to send any traffic.  Add C<--docroot DIR> and
C<--source DIR> to resolve findings back to the file on disk and the code that
serves them.

=head1 QUICK TEST

To check the tool works where you installed it, scan example.com.  RFC 2606
reserves the name for documentation and it is always available, so it makes a
stable target.  It is not a licence to scan other people's hosts: the scope
file is still the boundary.

	$ printf 'example.com\n' > scope.txt
	$ bin/webperimeter --scope scope.txt --authorized --ports 80,443 \
	    --max-urls 1 --no-path-probes --no-color

	webperimeter 0.001.0  2026-11-06T01:05:02Z
	Scope: scope.txt
	Requests: 4

	============================================================
	example.com
	------------------------------------------------------------
	  TLS: TLSv1_3, TLS_AES_256_GCM_SHA384, expires Dec 25 22:56:35 2026 GMT (49 days)
	  Certificate: /CN=example.com issued by /C=US/O=SSL Corporation/CN=Cloudflare TLS Issuing ECC CA 3
	  Open ports: 80, 443
	  URLs scanned: 1


	MEDIUM (4)
	----------
	[csp-missing] Content-Security-Policy is missing
	  Evidence: No Content-Security-Policy header on https://example.com/

	[...]

	Summary: 0 critical, 0 high, 4 medium, 2 low, 1 info

C<--max-urls 1> holds the crawl to the front page and C<--no-path-probes>
skips the sensitive path checks, so the run costs four requests.  Leave the
probes on when the target is a deployment of your own.

The findings are the point of the exercise.  example.com is a good smoke test
because it is not hardened: a run reporting missing CSP, HSTS and nosniff
shows the checks are wired up, and a run that reports nothing - or a critical
finding - means the scan is broken, not the site.

=head1 EXAMPLE

A real run against a local application, with its source tree supplied so the
report can name the endpoints it never reached.  The output is trimmed in the
middle for length.

	$ printf 'localhost:3000\n' > scope.txt
	$ bin/webperimeter --scope scope.txt --authorized --allow-private --ports 3000 \
	    --source ~/src/njh/Database-BI --no-path-probes --max-urls 6 --delay 0.2 --no-color

	webperimeter 0.001.0  2026-11-06T01:05:47Z
	Scope: scope.txt
	Requests: 8

	============================================================
	localhost
	------------------------------------------------------------
	  Open ports: 3000
	  URLs scanned: 6


	LOW (2)
	-------
	[csp-unsafe] Content-Security-Policy permits unsafe-inline or unsafe-eval
	  Evidence: default-src 'self'; script-src 'self' 'nonce-...' https://cdnjs.cloudflare.com https://unpkg.com; style-src 'self' 'unsafe-inline' https://unpkg.com; [...]

	[port-open-3000] Port 3000 accepts connections from outside the host
	  Evidence: TCP connect succeeded, no banner


	INFO (1)
	--------
	[source-routes-unvisited] 71 endpoint(s) defined in source were not scanned
	  Evidence: ~/src/njh/Database-BI/lib/Database/BI.pm:2713 GET /login; ~/src/njh/Database-BI/lib/Database/BI.pm:2714 POST /login; ~/src/njh/Database-BI/lib/Database/BI.pm:2715 POST /logout; [...]
	  Fix: Name them explicitly, raise --max-urls, or review them by hand.

	Summary: 0 critical, 0 high, 0 medium, 2 low, 1 info

C<--allow-private> is required for a loopback or RFC1918 target; without it the
host is refused before any traffic is sent.  The exit status is 0 here because
C<--fail-on> defaults to C<high> and nothing reached it.

C<--no-path-probes> skips the well-known sensitive path checks, which ask
whether a deployed document root exposes files such as C</.git/config>.  The
target here is local, so those paths can be inspected directly on disk - with
C<--docroot>, or by reading the tree - and the probes would only add requests.
Against a real deployment, leave them on.

C<source-routes-unvisited> is the reason to pass C<--source>: 71 routes exist in
the code that no crawled page linked to, so none of the checks above saw how
they behave.  That is exactly the surface a link-following scan cannot reach.
Raise C<--max-urls>, or review them by hand.

Findings also carry C<File:> and C<In source:> lines when C<--docroot> or
C<--source> lets the scan resolve them.

=head1 REPORT FORMAT

C<--format json> records the response header block behind each header finding,
so a report can be audited later without repeating the requests.  Abridged to
one header:

	"response": {
	   "headers" : {
	      "content-security-policy" : [ "default-src 'self'; script-src 'self' 'nonce-...' https://cdnjs.cloudflare.com https://unpkg.com; ..." ]
	   },
	   "http_version" : "HTTP/1.1",
	   "method" : "GET",
	   "note" : "main page",
	   "raw" : "HTTP/1.1 200 OK\r\nServer: ...",
	   "reason" : "OK",
	   "status" : 200,
	   "url" : "http://localhost:3000/"
	},
	"responses" : [ ... ]

A header appears once per value, so a second C<Content-Security-Policy> or
C<Set-Cookie> is not lost.  C<raw> is the block exactly as it arrived.
C<responses> holds the same structure for the CORS and C<OPTIONS> probes, which
is where the CORS and method findings come from.

=head1 LICENSE

GPL2

=cut
