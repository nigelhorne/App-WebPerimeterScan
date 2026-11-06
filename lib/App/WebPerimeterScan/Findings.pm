package App::WebPerimeterScan::Findings;

use strict;
use warnings;

our $VERSION = '0.001.0';

our @SEVERITIES = qw(critical high medium low info);

my %RANK = (
	critical => 5,
	high     => 4,
	medium   => 3,
	low      => 2,
	info     => 1,
);

sub new
{
	my ($class) = @_;

	return bless { items => [], seen => {} }, $class;
}

sub add
{
	my ($self, %args) = @_;

	my $severity = $args{severity} // 'info';
	$severity = 'info' unless exists $RANK{$severity};

	my $id = $args{id} // 'finding';

	# De-duplicate: the same id on the same host/url/key is one finding.
	my $dedupe = join "\0", $id, $args{host} // '', $args{url} // '', $args{key} // '';
	return 0 if $self->{seen}{$dedupe}++;

	push @{ $self->{items} }, {
		id        => $id,
		severity  => $severity,
		host      => $args{host} // '',
		url       => $args{url} // '',
		title     => $args{title} // $id,
		detail    => $args{detail} // '',
		evidence  => $args{evidence} // '',
		fix       => $args{fix} // '',
		reference => $args{reference} // '',
		# Filled in by the source-aware pass when a docroot or a source tree
		# is configured; empty otherwise.
		file      => $args{file} // '',
		source    => $args{source} // '',
	};

	return 1;
}

sub all
{
	my ($self) = @_;

	return @{ $self->{items} };
}

sub count
{
	my ($self) = @_;

	return scalar @{ $self->{items} };
}

# Worst first, then by host, then by title - stable output for diffing
# one run against the next.
sub sorted
{
	my ($self) = @_;

	return sort {
		$RANK{ $b->{severity} } <=> $RANK{ $a->{severity} }
			|| $a->{host} cmp $b->{host}
			|| $a->{title} cmp $b->{title}
			|| $a->{url} cmp $b->{url}
	} @{ $self->{items} };
}

sub counts
{
	my ($self) = @_;

	my %counts = map { $_ => 0 } @SEVERITIES;
	$counts{ $_->{severity} }++ for @{ $self->{items} };

	return \%counts;
}

sub rank
{
	my ($severity) = @_;

	return $RANK{$severity} // 0;
}

# Used for the process exit status: 1 when anything at or above the
# configured threshold was found.
sub at_or_above
{
	my ($self, $threshold) = @_;

	my $limit = $RANK{$threshold} or return ();
	return grep { $RANK{ $_->{severity} } >= $limit } @{ $self->{items} };
}

1;

__END__

=head1 NAME

App::WebPerimeterScan::Findings - collect and order scan results

=head1 VERSION

Version 0.001.0

=head1 SYNOPSIS

	use App::WebPerimeterScan::Findings;

	my $findings = App::WebPerimeterScan::Findings->new;

	$findings->add(
		id       => 'csp-missing',
		severity => 'medium',
		host     => 'example.com',
		url      => 'https://example.com/',
		title    => 'Content-Security-Policy is missing',
	);

	printf "%d finding(s), %d medium\n",
		$findings->count, $findings->counts->{medium};

	for my $finding ($findings->sorted) {
		print $finding->{severity}, ' ', $finding->{title}, "\n";
	}

	exit 1 if $findings->at_or_above('high');

=head1 DESCRIPTION

Findings are de-duplicated on (id, host, url, key) and sorted worst first so
that successive runs can be diffed.

=head1 LICENSE

GPL2

=cut
