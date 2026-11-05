# App::WebPerimeterScan

Check the parts of your own web perimeter that an outsider can reach, from
Perl, without a SaaS subscription.

This is the same idea as the "external network pentest" products: you give it
a list of hosts, it works out what is exposed and what is misconfigured. What
it does *not* do is exploit anything. There is no payload injection, no
credential guessing, and no write request except a single `OPTIONS` probe, so
it is safe to point at a production site you own.

## Safety model

Two things guard the tool:

1. **A scope file is required.** It is the authorisation boundary. Hosts not
   listed there are never contacted — including hosts discovered by following
   links, so a crawler cannot wander onto a third party's site.
2. **`--authorized` is required to send any traffic.** It is a one-off
   acknowledgement that the hosts are yours. `--dry-run` prints the plan and
   sends nothing.

Loopback, RFC1918, link-local and CGNAT addresses are refused unless you pass
`--allow-private`, which is what you want when testing against a staging
server. Requests are throttled per host (`--delay`, default 0.5s) and capped
by `--max-urls`.

Only scan systems you own or have written permission to test. A scan is
traffic from your address to somebody's server; unauthorised scanning is
illegal in most jurisdictions even when nothing is exploited.

## Install

```sh
perl Makefile.PL
make
make test
make install
```

Requires `IO::Socket::SSL` and `HTML::SimpleLinkExtor`; everything else is
core.

## Usage

```sh
$ cat scope.txt
# hosts I own
www.example.com
shop.example.com
https://api.example.com/
*.preview.example.com

$ webperimeter --scope scope.txt --authorized
```

`*.example.com` authorises the domain itself and any sub-domain, but the
tool will not guess sub-domain names — it only visits hosts it is actually
served links to, or that you list.

Useful options:

| Option | Meaning |
| --- | --- |
| `--dry-run` | Print what would be scanned, send nothing |
| `--format text\|json\|html`, `-o FILE` | Report format and destination |
| `--depth N` | Link-following depth from each root (default 1) |
| `--max-urls N` | Page budget per host (default 40) |
| `--ports LIST` | Override the port list |
| `--docroot DIR` | Resolve discovered paths against a document root (repeatable) |
| `--source DIR` | Map endpoints back to the code that serves them (repeatable) |
| `--no-path-probes` | Skip the well-known sensitive path checks |
| `--reflection-probe` | Send one marker parameter to test output encoding |
| `--allow-private` | Permit loopback and RFC1918 targets |
| `--fail-on LEVEL` | Exit 1 at or above this severity (default `high`) |
| `--delay SECONDS` | Minimum gap between requests to one host |

Exit status is `0` when nothing at or above `--fail-on` was found, `1` when
something was, and `2` for a usage or setup error — so it drops straight into
cron or CI:

```sh
webperimeter --scope scope.txt --authorized \
    --format html -o /var/www/reports/perimeter.html --fail-on critical
```

## What it checks

**Reachable services**

- Non-blocking TCP connect scan of a short, relevant port list, with a banner
  read (an `SSH-2.0-OpenSSH_7.4` greeting is worth knowing about).
- Flags database, cache, RDP, SMB, VNC and Telnet ports that should not be
  internet-facing.

**TLS**

- Certificate subject, issuer and expiry, with 30-day and 14-day warnings.
- Full chain verification in a separate handshake, so a broken chain cannot
  hide behind the inspection connection.
- Self-signed certificates.
- Which of TLS 1.0, 1.1, 1.2 and 1.3 the server still negotiates.
- Weak negotiated ciphers (RC4, 3DES, NULL, EXPORT, anonymous).

**HTTP**

- HSTS (missing, short `max-age`, no `includeSubDomains`).
- CSP (missing, wildcard source, `unsafe-inline`/`unsafe-eval`).
- Clickjacking protection (`X-Frame-Options` or `frame-ancestors`).
- `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.
- `Server` and `X-Powered-By` version disclosure.
- Cookie flags: `Secure`, `HttpOnly`, `SameSite`.
- CORS: wildcard or reflected origin, especially with credentials.
- `TRACE` and write methods advertised on a public URL.
- Plain HTTP that does not redirect to HTTPS.
- Active and passive mixed content on HTTPS pages.
- Directory listing, verbose error output, generator meta tag.

**Exposed files**

`/.git/config`, `/.git/HEAD`, `/.svn/entries`, `/.env`, `/.htpasswd`,
`/.htaccess`, `/web.config`, `/wp-config.php.bak`, `/backup.sql`,
`/.DS_Store`, `/server-status`, `/server-info`, `/phpinfo.php`,
`/actuator/env`, `/composer.json`, `/package.json`, `/crossdomain.xml`, plus
`robots.txt` and `security.txt`.

Every probe is compared against a deliberately non-existent path first, so an
application that answers `200` to everything does not produce twenty false
positives.

**Known-vulnerable software**

If the site discloses a PHP version, it is compared against the PHP2Shell
fix levels (`8.5.12`, `8.4.27`, `8.3.36`, `8.2.35`). PHP 8.1 and older have
no upstream fix. The compensating Apache/FPM controls in `../php2shell/` are
referenced in the finding.

## Source-aware pass

The checks above only know what a stranger can see. Give the tool your docroot
and your source tree and the findings name the file and the line:

```sh
webperimeter --scope scope.txt --authorized \
    --docroot /srv/www/example \
    --source ~/src/example
```

With `--docroot`:

- Every finding whose URL resolves to a real file gains that file's path, so a
  served `/.git/config` is reported as `/srv/www/example/.git/config` rather
  than as an abstract URL.
- A sensitive file that is on disk but was **not** served is reported as
  `source-file-in-docroot`. That is a deployment hazard waiting for one
  configuration change rather than a live leak, so it ranks below the same
  file being served.
- Paths are resolved with `realpath` and must stay inside the docroot, so a
  `..` component, a symlink out of the tree or a percent-encoded traversal is
  refused instead of followed.

With `--source`:

- A finding whose URL matches a route declaration gains `file:line` for the
  handler that serves it.
- Routes defined in the source that the crawl never reached are listed once
  per host as `source-routes-unvisited`: the coverage gap a link-following
  scan cannot see, and usually where the interesting endpoints are.

Routes are read from Mojolicious-style declarations in `.pm`, `.pl`, `.psgi`
and `.cgi` files:

```perl
$r->get('/view/:table')->to('Dashboard#view');
```

`:name` matches one path segment and `*name` matches the rest. Route patterns
written as regexps are not interpreted.

## What it does not do

- No exploitation, no fuzzing, no injection payloads, no brute force.
- No authenticated scanning, so anything behind a login is out of reach.
- No sub-domain brute forcing.
- No JavaScript execution, so client-side-only behaviour is invisible.
- No CVE database. Only versions it can read from a response are matched, and
  only for PHP2Shell. A missing finding is not evidence of a patch.

A clean report means "none of these specific checks fired". It is not a
substitute for a proper pentest or for keeping dependencies patched.

## Adding a check

Add an entry to `@PROBES` in `lib/App/WebPerimeterScan/Checks.pm` for a path,
or a `check_*` function for anything response-based. A probe needs a `match`
regexp as well as a path: a 200 alone is not evidence that a file exists.

## Licence

GPL2.
