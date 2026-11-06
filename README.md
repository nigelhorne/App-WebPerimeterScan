## Name

App::WebPerimeterScan - check your own web perimeter the way an outsider sees it

## Version

Version 0.001.0

## Synopsis

```perl
    use App::WebPerimeterScan;
    use App::WebPerimeterScan::Scope;

    my $scope = App::WebPerimeterScan::Scope->new->load_file('scope.txt');
    my $scanner = App::WebPerimeterScan->new(scope => $scope, depth => 1);
    my $findings = $scanner->run;

    print $_->{severity}, ' ', $_->{title}, "\n" for $findings->sorted;
```

## Description

An external, unauthenticated scan of hosts you own: which ports are reachable,
what the TLS configuration allows, which security headers are missing, whether
session cookies are protected, and whether well-known sensitive paths have been
left in the document root.

It deliberately does not attempt exploitation.  There is no payload
injection, no credential guessing and no write request outside the single
**OPTIONS** probe, so it is safe to point at a production site.

`README.md` is generated from this POD by `pod2github`: change the POD and
regenerate, rather than editing the README by hand.

The scope file is the authorisation boundary: a host that does not appear in
it is never contacted, including hosts discovered by following links.

## Requirements

Perl 5.10.0 or later, with the modules listed in `Makefile.PL`.  The minimum
Perl was measured with [Perl::MinimumVersion](https://metacpan.org/pod/Perl%3A%3AMinimumVersion) rather than guessed, and the
suite is run against 5.10.1 as well as current perls.  `cpan` installs
anything that is missing, so these floors matter mainly on a machine that
already has older copies of them:

- `Socket` 2.020

    The core of Perl 5.10.1 ships 2.018, so this is a real installation step on
    the minimum Perl.  The port scan reads `SO_ERROR` from it to tell a refused
    connection from an open one.

- `Net::SSLeay` 1.92

    The first release with OpenSSL 3 support.  Earlier releases are not
    supported: 1.46 does not compile against OpenSSL 3 at all.

- `IO::Socket::SSL` 2.000
- `IO::Select` 1.17 and `IO::Socket::INET` 1.31

    The versions that ship with Perl 5.10.1, so the minimum Perl needs no
    upgrade here.  They are stated because the port scan relies on how they
    behave, not only on what they provide.

Both SSL modules need the OpenSSL headers at install time, which the
installer cannot supply for you; install your distribution's `openssl`
development package first if the build fails.

The remaining prerequisites are `Getopt::Long` 2.50,
`HTML::SimpleLinkExtor` 1.20, `JSON::PP` 4.00, `Time::HiRes` 1.97,
`Time::Local` 1.28 and `URI` 1.70, plus `Test::More` 1.302 for the test
suite.  Several of these are newer than the copies that ship with Perl 5.10,
so on the minimum Perl let the installer upgrade them instead of pinning the
core versions.

## Usage

```
    bin/webperimeter --scope scope.txt --authorized
```

The scope file lists the hosts you are allowed to test, one per line.  Without
`--authorized` the tool refuses to send any traffic.  Add `--docroot DIR` and
`--source DIR` to resolve findings back to the file on disk and the code that
serves them.

## Quick Test

To check the tool works where you installed it, scan example.com.  RFC 2606
reserves the name for documentation and it is always available, so it makes a
stable target.  It is not a licence to scan other people's hosts: the scope
file is still the boundary.

```
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
```

`--max-urls 1` holds the crawl to the front page and `--no-path-probes`
skips the sensitive path checks, so the run costs four requests.  Leave the
probes on when the target is a deployment of your own.

The findings are the point of the exercise.  example.com is a good smoke test
because it is not hardened: a run reporting missing CSP, HSTS and nosniff
shows the checks are wired up, and a run that reports nothing - or a critical
finding - means the scan is broken, not the site.

## Example

A real run against a local application, with its source tree supplied so the
report can name the endpoints it never reached.  The output is trimmed in the
middle for length.

```
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
```

`--allow-private` is required for a loopback or RFC1918 target; without it the
host is refused before any traffic is sent.  The exit status is 0 here because
`--fail-on` defaults to `high` and nothing reached it.

`--no-path-probes` skips the well-known sensitive path checks, which ask
whether a deployed document root exposes files such as `/.git/config`.  The
target here is local, so those paths can be inspected directly on disk - with
`--docroot`, or by reading the tree - and the probes would only add requests.
Against a real deployment, leave them on.

`source-routes-unvisited` is the reason to pass `--source`: 71 routes exist in
the code that no crawled page linked to, so none of the checks above saw how
they behave.  That is exactly the surface a link-following scan cannot reach.
Raise `--max-urls`, or review them by hand.

Findings also carry `File:` and `In source:` lines when `--docroot` or
`--source` lets the scan resolve them.

## Report Format

`--format json` records the response header block behind each header finding,
so a report can be audited later without repeating the requests.  Abridged to
one header:

```
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
```

A header appears once per value, so a second `Content-Security-Policy` or
`Set-Cookie` is not lost.  `raw` is the block exactly as it arrived.
`responses` holds the same structure for the CORS and `OPTIONS` probes, which
is where the CORS and method findings come from.

## License

GPL2
