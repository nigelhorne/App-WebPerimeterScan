package App::WebPerimeterScan::Source;

use strict;
use warnings;

use Cwd qw(realpath);
use File::Find qw(find);
use File::Spec;

our $VERSION = '0.001.0';

# Route declarations this understands.  Mojolicious is the common Perl web
# framework, so its $r->get('/path') form is what the indexer reads; a route
# written as a regexp is left alone rather than approximated.
my $ROUTE_RE = qr/->(get|post|put|patch|delete|any|under|websocket)\s*\(\s*(['"])([^'"]+)\2/i;

sub new
{
	my ($class, %args) = @_;

	return bless {
		docroots    => [ grep { defined } @{ $args{docroots}    // [] } ],
		source_dirs => [ grep { defined } @{ $args{source_dirs} // [] } ],
	}, $class;
}

# The document roots, resolved once.  A docroot that does not exist is
# dropped rather than fatal: the scan is still worth running without it.
sub docroots
{
	my ($self) = @_;

	return @{ $self->{_docroots} } if $self->{_docroots};

	my @real;
	for my $dir (@{ $self->{docroots} }) {
		next unless -d $dir;
		my $resolved = eval { realpath($dir) };
		next unless defined $resolved;
		push @real, $resolved unless grep { $_ eq $resolved } @real;
	}
	$self->{_docroots} = \@real;

	return @real;
}

# Turn a URL path into a filesystem path, only if it really lives under one of
# the docroots.  realpath is what makes "..", a symlink out of the tree and a
# percent-encoded traversal all fail closed: the resolved target either starts
# with the docroot or it is refused.
sub file_for
{
	my ($self, $url_path) = @_;

	my $relative = _url_to_relative($url_path);
	return unless defined $relative && length $relative;
	return if $relative =~ m{(?:\A|/)\.\.(?:/|\z)};

	for my $docroot ($self->docroots) {
		my $candidate = File::Spec->catfile($docroot, split m{/+}, $relative);
		next unless -e $candidate;

		my $real = eval { realpath($candidate) };
		next unless defined $real && -f $real;
		next unless _inside($real, $docroot);

		return {
			docroot  => $docroot,
			path     => $real,
			relative => $relative,
			size     => (-s $real) // 0,
		};
	}

	return;
}

# Which of the sensitive paths this scan probes actually exist on disk.  The
# caller passes the probe table so the two halves of the report talk about the
# same files.
sub sensitive_on_disk
{
	my ($self, @probes) = @_;

	my @found;
	for my $probe (@probes) {
		my $hit = $self->file_for($probe->{path}) or next;
		push @found, { %$hit, probe => $probe };
	}

	return @found;
}

# Index every route declaration under the source directories.
sub index_routes
{
	my ($self) = @_;

	return $self->{routes} if $self->{routes};

	my @routes;
	for my $dir (@{ $self->{source_dirs} }) {
		next unless -d $dir;

		find({
			no_chdir => 1,
			wanted   => sub {
				my $file = $File::Find::name;
				return unless -f $file;
				return unless $file =~ /\.(?:pm|pl|psgi|cgi)\z/;
				return if $file =~ m{/(?:blib|\.git)\/};
				push @routes, _routes_in_file($file);
			},
		}, $dir);
	}

	$self->{routes} = \@routes;

	return $self->{routes};
}

sub routes
{
	my ($self) = @_;

	return @{ $self->index_routes };
}

# The route that would serve this path, in declaration order.
sub route_for
{
	my ($self, $url_path) = @_;

	my $path = _url_path($url_path);
	return unless defined $path && length $path;
	$path = "/$path" unless $path =~ m{^/};

	for my $route ($self->routes) {
		return $route if $path =~ $route->{re};
	}

	return;
}

sub _routes_in_file
{
	my ($file) = @_;

	open my $fh, '<', $file or return;
	my (@routes, $line_no);
	$line_no = 0;
	while(my $line = <$fh>) {
		$line_no++;
		while($line =~ /$ROUTE_RE/g) {
			my ($method, undef, $pattern) = ($1, $2, $3);
			push @routes, {
				method  => uc $method,
				pattern => $pattern,
				file    => $file,
				line    => $line_no,
				re      => _pattern_re($pattern),
			};
		}
	}
	close $fh;

	return @routes;
}

# '/view/:table' matches /view/dogs but not /view/a/b; '/files/*path' matches
# the rest of the path.  Everything else is matched literally, so a dot in a
# route is a dot.
sub _pattern_re
{
	my ($pattern) = @_;

	my $re = '';
	pos($pattern) = 0;
	while($pattern =~ /\G(?::([A-Za-z_]\w*)|(\*)([A-Za-z_]\w*)|(.))/gs) {
		if(defined $1) {
			$re .= '[^/]+';
		} elsif(defined $2) {
			$re .= '.*';
		} else {
			$re .= quotemeta $4;
		}
	}

	return qr{\A$re/?\z};
}

sub _url_path
{
	my ($url_path) = @_;

	return unless defined $url_path && length $url_path;
	$url_path =~ s/[?#].*//s;

	return $url_path;
}

# Decode the path the way a server would before it looks for a file.  Decoding
# first is deliberate: '%2e%2e%2f' becomes '../' and is then refused by the
# traversal check, rather than slipping through as an opaque name.
sub _url_to_relative
{
	my ($url_path) = @_;

	my $path = _url_path($url_path);
	return unless defined $path && length $path;

	$path =~ s/%([0-9A-Fa-f]{2})/chr hex $1/ge;
	$path =~ s{^/+}{};
	return if $path eq '' || $path eq '.';

	return $path;
}

sub _inside
{
	my ($path, $docroot) = @_;

	return 1 if $path eq $docroot;

	return index($path, "$docroot/") == 0;
}

1;

__END__

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

=head1 LICENSE

GPL2

=cut
