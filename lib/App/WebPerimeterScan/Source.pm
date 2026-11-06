package App::WebPerimeterScan::Source;

use strict;
use warnings;
use autodie qw(:all);

use Cwd qw(realpath);
use File::Find qw(find);
use File::Spec;
use Params::Get qw(get_params);
use Params::Validate::Strict qw(validate_strict);
use Readonly;
use Sub::Private { mode => 'enforce' };
use URI::Escape qw(uri_unescape);

use App::WebPerimeterScan::I18N ();
use parent -norequire, 'App::WebPerimeterScan::I18N';

our $VERSION = '0.001.0';

# Route declarations this understands.  Mojolicious is the common Perl web
# framework, so its $r->get('/path') form is what the indexer reads.  The
# pattern must start with "/": without that, $cache->get('key') and
# $ua->get('http://...') in the same tree were indexed as routes.  A route
# written as a regexp is left alone rather than approximated.
Readonly::Scalar my $ROUTE_RE => qr/->(get|post|put|patch|delete|any|under|websocket)\s*\(\s*(['"])(\/[^'"]*)\2/i;

# Files worth reading for routes, and directories never worth walking.
Readonly::Scalar my $SOURCE_FILE => qr/\.(?:pm|pl|psgi|cgi)\z/;
Readonly::Hash my %SKIP_DIRECTORY => map { $_ => 1 } qw(.git .svn blib node_modules);

# Path traversal: a ".." segment anywhere in the decoded path.
Readonly::Scalar my $TRAVERSAL => qr{(?:\A|/)\.\.(?:/|\z)};

# Route placeholders: ':name' is one segment, '*name' the rest of the path.
Readonly::Scalar my $ROUTE_TOKEN => qr/\G(?::([A-Za-z_]\w*)|(\*)([A-Za-z_]\w*)|(.))/s;
Readonly::Scalar my $ONE_SEGMENT => '[^/]+';
Readonly::Scalar my $REST_OF_PATH => '.*';

=encoding utf8

=head1 NAME

App::WebPerimeterScan::Source - map scan results onto files and code

=head1 VERSION

Version 0.001.0

=head1 SYNOPSIS

	my $source = App::WebPerimeterScan::Source->new(
		docroots    => ['/srv/www/example'],
		source_dirs => ['/home/me/src/example'],
	);

	my $file  = $source->file_for('/.git/config');   # or undef
	my $route = $source->route_for('/view/dogs');    # or undef

=head1 DESCRIPTION

A black-box scan knows only that a URL answered.  This turns that into
something actionable: which file under a document root is being served, and
which declaration in the source tree defines the endpoint.

Paths are resolved with C<realpath> and must stay inside the docroot, so a
C<..> component, a symlink pointing out of the tree or a percent-encoded
traversal resolves outside and is refused.

=head1 SUBROUTINES/METHODS

=head2 new

Purpose: describe where the site's files and code are.

Args: named C<docroots> and C<source_dirs>, each an array reference of
directory names.  Either may be empty.

Returns: the new object.

Side Effects: none; directories are read lazily.

Usage: C<< my $source = App::WebPerimeterScan::Source->new(docroots => [$dir]); >>

=head3 EXAMPLE

	my $source = App::WebPerimeterScan::Source->new(source_dirs => ['lib']);
	printf "%d route(s)\n", scalar @{ $source->routes };

=head3 API SPECIFICATION

=head4 INPUT

	{
		docroots    => { type => 'arrayref', optional => 1 },
		source_dirs => { type => 'arrayref', optional => 1 },
	}

=head4 OUTPUT

	{ type => 'object', isa => 'App::WebPerimeterScan::Source' }

=head3 MESSAGES

	Message                       Meaning / resolution
	----------------------------  ---------------------------------
	Unknown parameter 'X'         A misspelt argument name.

=head3 FORMAL SPECIFICATION

	┌─ InitSource ────────────────────────────────────────
	│ Source'; docroots?, source_dirs? : seq PATH
	├─────────────────────────────────────────────────────
	│ docroots' = docroots? ↾ DEFINED ∧ source_dirs' = source_dirs? ↾ DEFINED
	│ routes' = ⊥
	└─────────────────────────────────────────────────────

=cut

sub new
{
	my $class = shift;

	my $args = validate_strict(
		schema => {
			docroots    => { type => 'arrayref', optional => 1 },
			source_dirs => { type => 'arrayref', optional => 1 },
		},
		input => get_params(undef, \@_) // {},
	);

	return bless {
		map { $_ => [ grep { defined } @{ $args->{$_} || [] } ] } qw(docroots source_dirs)
	}, $class;
}

=head2 docroots

Purpose: the document roots that exist, resolved once.

Args: none.

Returns: an array reference of real paths, without duplicates.  A docroot
that does not exist is dropped rather than fatal: the scan is still worth
running without it.

Side Effects: caches the result.

Usage: C<< for my $dir (@{ $source->docroots }) { ... } >>

=head3 EXAMPLE

	print "serving from $_\n" for @{ $source->docroots };

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'arrayref', element_type => 'string' }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	┌─ Docroots ──────────────────────────────────────────
	│ ΞSource; result! : seq PATH
	├─────────────────────────────────────────────────────
	│ result! = squash(⟨ realpath(d) | d ∈ docroots ∧ is_dir(d) ⟩)
	└─────────────────────────────────────────────────────

=cut

sub docroots
{
	my ($self) = @_;

	$self->{_docroots} //= do {
		my %seen;
		[ grep { defined && !$seen{$_}++ } map { -d $_ ? scalar eval { realpath($_) } : undef } @{ $self->{docroots} } ];
	};

	return [ @{ $self->{_docroots} } ];
}

=head2 file_for

Purpose: the file on disk a URL path would be served from.

Args: C<$url_path>, the path part of a URL (a query or fragment is ignored;
percent-encoding is decoded first, as a server would).

Returns: a hash reference of C<docroot>, C<path> (the real path),
C<relative> and C<size>; or C<undef> when the file is not under any docroot.

Side Effects: file system reads.

Usage: C<< my $hit = $source->file_for('/.env'); >>

Decoding first is deliberate: C<%2e%2e%2f> becomes C<../> and is then
refused, rather than slipping through as an opaque name.

=head3 EXAMPLE

	if(my $hit = $source->file_for('/.git/config')) {
		print "served from $hit->{path} ($hit->{size} bytes)\n";
	}

=head3 API SPECIFICATION

=head4 INPUT

	{ url_path => { type => 'string', optional => 1, position => 0 } }

=head4 OUTPUT

	{
		type => 'hashref', optional => 1,
		schema => {
			docroot  => { type => 'string' },
			path     => { type => 'string' },
			relative => { type => 'string' },
			size     => { type => 'integer', min => 0 },
		},
	}

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	┌─ FileFor ───────────────────────────────────────────
	│ ΞSource; url_path? : STRING; result! : HIT ∪ {⊥}
	├─────────────────────────────────────────────────────
	│ r = unescape(strip_query(url_path?)) without leading "/"
	│ ".." ∈ segments(r) ⇒ result! = ⊥
	│ result! ≠ ⊥ ⇒ is_file(result!.path)
	│              ∧ result!.path = realpath(result!.docroot / r)
	│              ∧ result!.docroot prefix_of result!.path
	└─────────────────────────────────────────────────────

=cut

sub file_for
{
	my ($self, $url_path) = @_;

	my $relative = _url_to_relative($url_path);
	return undef unless defined $relative && $relative !~ $TRAVERSAL;

	for my $docroot (@{ $self->docroots }) {
		my $candidate = File::Spec->catfile($docroot, split m{/+}, $relative);
		next unless -e $candidate;

		# realpath follows symlinks, so a link out of the tree resolves
		# outside the docroot and is refused here.
		my $real = eval { realpath($candidate) };
		next unless defined $real && -f $real && _inside($real, $docroot);

		return {
			docroot  => $docroot,
			path     => $real,
			relative => $relative,
			size     => (-s $real) // 0,
		};
	}

	return undef;
}

=head2 sensitive_on_disk

Purpose: which of the sensitive paths the scan probes actually exist under a
docroot.  The caller passes the probe table so that what is looked for on
disk is exactly what was requested over the wire.

Args: C<$probes>, an array reference of hash references each with a C<path>.

Returns: an array reference of C<file_for> results, each with a C<probe>
key holding the probe it matched.

Side Effects: file system reads.

Usage: C<< my $hits = $source->sensitive_on_disk(App::WebPerimeterScan::Checks::sensitive_probes()); >>

=head3 EXAMPLE

	for my $hit (@{ $source->sensitive_on_disk([ { id => 'env-exposed', path => '/.env' } ]) }) {
		print "$hit->{probe}{id}: $hit->{path}\n";
	}

=head3 API SPECIFICATION

=head4 INPUT

	{ probes => { type => 'arrayref', element_type => 'hashref', position => 0 } }

=head4 OUTPUT

	{ type => 'arrayref', element_type => 'hashref' }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	┌─ SensitiveOnDisk ───────────────────────────────────
	│ ΞSource; probes? : seq PROBE; result! : seq HIT
	├─────────────────────────────────────────────────────
	│ result! = ⟨ FileFor(p.path) ⊕ {probe ↦ p}
	│             | p ∈ probes? ∧ FileFor(p.path) ≠ ⊥ ⟩
	└─────────────────────────────────────────────────────

=cut

sub sensitive_on_disk
{
	my ($self, $probes) = @_;

	return [
		map { my $hit = $self->file_for($_->{path}); $hit ? { %{$hit}, probe => $_ } : () }
		@{ $probes || [] }
	];
}

=head2 routes

Purpose: every route declaration under the source directories.

Args: none.

Returns: an array reference of hash references: C<method>, C<pattern>,
C<file>, C<line> and C<re> (a compiled regexp matching the paths the route
serves).

Side Effects: walks the source directories the first time and caches the
result.  An unreadable file is skipped with a warning.

Usage: C<< printf "%d route(s)\n", scalar @{ $source->routes }; >>

=head3 EXAMPLE

	for my $route (@{ $source->routes }) {
		print "$route->{method} $route->{pattern} at $route->{file}:$route->{line}\n";
	}

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'arrayref', element_type => 'hashref' }

=head3 MESSAGES

	Message                                Meaning / resolution
	-------------------------------------  ---------------------------------
	Skipping source file 'F': E (warning)  F could not be opened; check its
	                                       permissions.

=head3 FORMAL SPECIFICATION

	┌─ Routes ────────────────────────────────────────────
	│ ΔSource; result! : seq ROUTE
	├─────────────────────────────────────────────────────
	│ routes = ⊥ ⇒ routes' = ⁀/ ⟨ declared(f) | f ∈ files(source_dirs) ⟩
	│ routes ≠ ⊥ ⇒ routes' = routes
	│ result! = routes'
	└─────────────────────────────────────────────────────

=head3 PSEUDOCODE

	if not yet indexed
		walk each source directory, pruning .git, .svn, blib, node_modules
		for each .pm, .pl, .psgi or .cgi file
			record every ->get('/...')-style declaration with its line
	return a copy of the index

=cut

sub routes
{
	my ($self) = @_;

	$self->{routes} //= $self->_index_routes;

	return [ @{ $self->{routes} } ];
}

=head2 route_for

Purpose: the route that would serve a path, in declaration order.

Args: C<$url_path> (a query or fragment is ignored).

Returns: a route hash reference as in C<routes>, or C<undef>.

Side Effects: indexes the source on first use.

Usage: C<< my $route = $source->route_for('/view/dogs'); >>

=head3 EXAMPLE

	if(my $route = $source->route_for('/api/dirs')) {
		print "$route->{method} $route->{pattern} ($route->{file}:$route->{line})\n";
	}

=head3 API SPECIFICATION

=head4 INPUT

	{ url_path => { type => 'string', optional => 1, position => 0 } }

=head4 OUTPUT

	{ type => 'hashref', optional => 1 }

=head3 MESSAGES

As C<routes>.

=head3 FORMAL SPECIFICATION

	┌─ RouteFor ──────────────────────────────────────────
	│ ΞSource; url_path? : STRING; result! : ROUTE ∪ {⊥}
	├─────────────────────────────────────────────────────
	│ p = "/" ⁀ strip_query(url_path?) without leading "/"
	│ M = ⟨ r ∈ routes | p matches r.re ⟩
	│ M ≠ ⟨⟩ ⇒ result! = head M
	│ M = ⟨⟩ ⇒ result! = ⊥
	└─────────────────────────────────────────────────────

=cut

sub route_for
{
	my ($self, $url_path) = @_;

	my $path = _strip_query($url_path);
	my $route;

	if(defined $path) {
		$path = "/$path" unless $path =~ m{\A/};
		($route) = grep { $path =~ $_->{re} } @{ $self->routes };
	}

	return $route;
}

# _index_routes
# Purpose:     build the route index.
# Entry:       $self->{source_dirs} holds directory names.
# Exit:        arrayref of route records.
# Side effects: file system walk; warns on unreadable files.
sub _index_routes :Private
{
	my ($self) = @_;

	my @routes;
	for my $dir (grep { -d } @{ $self->{source_dirs} }) {
		find({
			no_chdir => 1,
			wanted   => sub {
				my $name = $File::Find::name;
				my (undef, undef, $leaf) = File::Spec->splitpath($name);

				# Prune, rather than filter, so a large .git is not walked.
				if(-d $name) {
					$File::Find::prune = 1 if $SKIP_DIRECTORY{$leaf};
					return;
				}
				push @routes, @{ $self->_routes_in_file($name) } if $name =~ $SOURCE_FILE;
			},
		}, $dir);
	}

	return \@routes;
}

# _routes_in_file
# Purpose:     every route declaration in one file.
# Entry:       $file is a regular file.
# Exit:        arrayref of route records (empty if unreadable).
# Side effects: reads the file; warns when it cannot be opened.
sub _routes_in_file :Private
{
	my ($self, $file) = @_;

	my $fh = eval { open my $handle, '<', $file; $handle };
	unless($fh) {
		$self->_warn('source.unreadable', { file => $file, error => App::WebPerimeterScan::I18N::clean_error($@) });
		return [];
	}

	my @routes;
	while(my $line = <$fh>) {
		while($line =~ /$ROUTE_RE/g) {
			push @routes, {
				method  => uc $1,
				pattern => $3,
				file    => $file,
				line    => $.,
				re      => _pattern_re($3),
			};
		}
	}
	close $fh;

	return \@routes;
}

# _pattern_re
# Purpose:     compile a route pattern into a regexp over URL paths.
# Entry:       $pattern is the quoted string from the declaration.
# Exit:        a qr// anchored at both ends, allowing one trailing "/".
# Side effects: none.
#
# '/view/:table' matches /view/dogs but not /view/a/b; '/files/*path' matches
# the rest of the path.  Everything else is matched literally, so a dot in a
# route is a dot.
sub _pattern_re :Private
{
	my ($pattern) = @_;

	my $re = '';
	while($pattern =~ /$ROUTE_TOKEN/g) {
		$re .= defined $1 ? $ONE_SEGMENT : defined $2 ? $REST_OF_PATH : quotemeta $4;
	}

	return qr{\A$re/?\z};
}

# _strip_query
# Purpose:     the path part of a URL path, without query or fragment.
# Entry:       $url_path may be undef.
# Exit:        the path, or undef when there is nothing left.
# Side effects: none.
sub _strip_query :Private
{
	my ($url_path) = @_;

	my $path = defined $url_path ? $url_path =~ s/[?#].*//sr : '';

	return length $path ? $path : undef;
}

# _url_to_relative
# Purpose:     decode a URL path the way a server would before it looks
#              for a file, and make it relative.
# Entry:       $url_path may be undef.
# Exit:        the relative path, or undef for the root or nothing.
# Side effects: none.
sub _url_to_relative :Private
{
	my ($url_path) = @_;

	my $path = _strip_query($url_path);
	$path = uri_unescape($path) =~ s{\A/+}{}r if defined $path;

	return (defined $path && $path ne '' && $path ne '.') ? $path : undef;
}

# _inside
# Purpose:     is a real path the docroot itself or below it?
# Entry:       both arguments are realpath() results.
# Exit:        1 or 0.
# Side effects: none.
sub _inside :Private
{
	my ($path, $docroot) = @_;

	return ($path eq $docroot || index($path, "$docroot/") == 0) ? 1 : 0;
}

1;

__END__

=head1 LIMITATIONS

=over 4

=item * Only Mojolicious-style C<< ->get('/path') >> declarations are
recognised.  Dancer's C<get '/path' =E<gt> sub>, Catalyst actions,
Plack mounts and routes built at run time are not, and a regexp route is
skipped rather than approximated.

=item * A route pattern can only be matched against a path, so two routes
that differ only by HTTP method are both reported for the same path.

=item * C<_inside> compares paths with "/", which is what C<realpath>
returns on Unix; Windows paths are not tested.

=back

=head1 LICENSE

GPL2

=cut
