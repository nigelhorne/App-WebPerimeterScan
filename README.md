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

## License

GPL2
