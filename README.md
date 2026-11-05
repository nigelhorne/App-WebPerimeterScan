## Name

App::WebPerimeterScan - check your own web perimeter the way an outsider sees it

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

The scope file is the authorisation boundary: a host that does not appear in
it is never contacted, including hosts discovered by following links.

## Usage

    bin/webperimeter --scope scope.txt --authorized

The scope file lists the hosts you are allowed to test, one per line.  Without
`--authorized` the tool refuses to send any traffic.  Add `--docroot DIR` and
`--source DIR` to resolve findings back to the file on disk and the code that
serves them.

## Example

A real run against a host in the scope file, with its document root and source
tree supplied.  It is trimmed in the middle for length.

```console
$ printf 'links.nigelhorne.com\n' > scope.txt
$ bin/webperimeter --scope scope.txt --authorized --delay 0.5 --ports 80,443 \
    --docroot ~/src/links --source ~/src/links --no-color

webperimeter 0.03  2026-11-05T21:42:10Z
Scope: scope.txt
Requests: 25

============================================================
links.nigelhorne.com
------------------------------------------------------------
  TLS: TLSv1_3, TLS_AES_256_GCM_SHA384, expires unknown
  Certificate:  issued by 
  Open ports: 80, 443
  URLs scanned: 1


HIGH (2)
--------
[tls-invalid-certificate] TLS certificate does not verify
  Evidence: SSL connect attempt failed error:0A000086:SSL routines::certificate verify failed

[tls-self-signed] TLS certificate is self-signed


MEDIUM (5)
----------
[source-file-in-docroot] Sensitive file is inside a document root: .git/config
  Evidence: /home/njh/src/njh/links/.git/config
  Fix: Move it above the document root, or deny the path at the web server.

[csp-missing] Content-Security-Policy is missing
  Evidence: No Content-Security-Policy header on https://links.nigelhorne.com/

[...]

Summary: 0 critical, 2 high, 5 medium, 3 low, 1 info
```

The exit status is 1, the default `--fail-on high` threshold having been met.

`source-file-in-docroot` is what `--docroot` adds: the file was on disk but was
not served during the scan, which is why it is reported at medium.  Had the
server returned it, the probe would have reported the same path at critical.
That distinction is the difference between "exposed now" and "one
configuration change away from being exposed".

Findings also carry `File:` and `In source:` lines when those are known.

## JSON output

`--format json` records the response header block behind each header finding,
so a report can be audited later without repeating the requests.  Abridged to
three headers:

```json
"response": {
   "headers" : {
      "content-length" : [ "870" ],
      "content-type" : [ "text/html" ],
      "server" : [ "Apache" ]
   },
   "http_version" : "HTTP/1.1",
   "method" : "GET",
   "raw" : "HTTP/1.1 200 OK\r\nDate: ...",
   "reason" : "OK",
   "status" : 200,
   "url" : "https://links.nigelhorne.com/"
},
"responses" : [ ... ]
```

A header appears once per value, so a second `Content-Security-Policy` or
`Set-Cookie` is not lost.  `responses` holds the same structure for the
plaintext hop and the `CORS` and `OPTIONS` probes, which is where the
`no-https-redirect` and method findings come from.

## License

GPL2
