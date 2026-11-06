package App::WebPerimeterScan::Findings;

use strict;
use warnings;
use autodie qw(:all);

use Params::Get qw(get_params);
use Params::Validate::Strict qw(validate_strict);
use Readonly;
use Scalar::Util qw(refaddr);
use Sub::Private { mode => 'enforce' };

use App::WebPerimeterScan::I18N ();
use parent -norequire, 'App::WebPerimeterScan::I18N';

our $VERSION = '0.001.0';

# Worst first.  Exported by name because the report formats walk it.
Readonly::Array our @SEVERITIES => qw(critical high medium low info);

# Every field a finding carries, in report order.  The JSON report uses the
# same list, so the two can never disagree about what a finding is.
Readonly::Array our @FIELDS => qw(id severity host url title detail evidence fix reference file source);

# Numeric rank of each severity, for sorting and thresholds.
Readonly::Hash my %RANK => (
	critical => 5,
	high     => 4,
	medium   => 3,
	low      => 2,
	info     => 1,
);

# What an unknown or missing severity becomes, and the id of a finding that
# was added without one.
Readonly::Scalar my $DEFAULT_SEVERITY => 'info';
Readonly::Scalar my $DEFAULT_ID       => 'finding';

# Fields annotate() may change after a finding is recorded: the source-aware
# pass fills them in once the whole scan is known.
Readonly::Hash my %ANNOTATABLE => (file => 1, source => 1);

# Joins the parts of a de-duplication key.  NUL cannot occur in any of them.
Readonly::Scalar my $KEY_SEPARATOR => "\0";

# Input schema for add(); report() accepts the same keys minus the text.
Readonly::Hash my %ADD_SCHEMA => (
	id        => { type => 'string', optional => 1 },
	severity  => { type => 'string', optional => 1 },
	host      => { type => 'string', optional => 1 },
	url       => { type => 'string', optional => 1 },
	key       => { type => 'string', optional => 1 },
	title     => { type => 'string', optional => 1 },
	detail    => { type => 'string', optional => 1 },
	evidence  => { type => 'string', optional => 1 },
	fix       => { type => 'string', optional => 1 },
	reference => { type => 'string', optional => 1 },
	file      => { type => 'string', optional => 1 },
	source    => { type => 'string', optional => 1 },
);

=encoding utf8

=head1 NAME

App::WebPerimeterScan::Findings - collect and order scan results

=head1 VERSION

Version 0.001.0

=head1 SYNOPSIS

	use App::WebPerimeterScan::Findings;

	my $findings = App::WebPerimeterScan::Findings->new;

	# Text comes from the message catalogue, keyed by the rule id
	$findings->report('csp-missing',
		severity => 'medium',
		host     => 'example.com',
		vars     => { url => 'https://example.com/' },
	);

	printf "%d finding(s), %d medium\n",
		$findings->count, $findings->counts->{medium};

	print "$_->{severity} $_->{title}\n" for @{ $findings->sorted };

	exit 1 if @{ $findings->at_or_above('high') };

=head1 DESCRIPTION

Findings are de-duplicated on (id, host, url, key) and sorted worst first so
that successive runs can be diffed.  Each finding is a hash reference with
the fields in C<@App::WebPerimeterScan::Findings::FIELDS>, every one a
string (empty when not applicable).

=head1 SUBROUTINES/METHODS

=head2 new

Purpose: create an empty collection.

Args: none.

Returns: the new object.

Side Effects: none.

Usage: C<< my $findings = App::WebPerimeterScan::Findings->new; >>

=head3 EXAMPLE

	my $findings = App::WebPerimeterScan::Findings->new;
	print $findings->count, "\n";	# 0

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'object', isa => 'App::WebPerimeterScan::Findings' }

=head3 MESSAGES

	Message                          Meaning / resolution
	-------------------------------  -----------------------------------
	Unknown parameter 'X'            new() takes no arguments.

=head3 FORMAL SPECIFICATION

	┌─ InitFindings ──────────────────────────────────────
	│ Findings'
	├─────────────────────────────────────────────────────
	│ items' = ⟨⟩ ∧ seen' = ∅
	└─────────────────────────────────────────────────────

=cut

sub new
{
	my $class = shift;

	# No arguments are accepted; an unknown one croaks.
	validate_strict(schema => {}, input => get_params(undef, \@_) // {});

	return bless { items => [], seen => {} }, $class;
}

=head2 add

Purpose: record one finding with its text already rendered.

Args: named: C<id>, C<severity> (one of C<@SEVERITIES>), C<host>, C<url>,
C<key> (an extra de-duplication component, not stored), C<title>,
C<detail>, C<evidence>, C<fix>, C<reference>, C<file>, C<source>.  All are
optional strings.

Returns: 1 if the finding was recorded, 0 if it duplicated one already held.

Side Effects: appends to the collection.  An unknown severity is recorded as
C<info> with a warning, so a typo cannot silently hide a finding below the
C<--fail-on> threshold without anyone noticing.

Usage: C<< $findings->add(id => 'x', severity => 'low', title => 'X') >>

=head3 EXAMPLE

	my $added = $findings->add(
		id => 'trace-enabled', severity => 'medium',
		host => 'example.com', url => 'https://example.com/',
		title => 'HTTP TRACE is enabled',
	);
	# A second identical call returns 0

=head3 API SPECIFICATION

=head4 INPUT

	{
		id        => { type => 'string', optional => 1 },
		severity  => { type => 'string', optional => 1 },
		host      => { type => 'string', optional => 1 },
		url       => { type => 'string', optional => 1 },
		key       => { type => 'string', optional => 1 },
		title     => { type => 'string', optional => 1 },
		detail    => { type => 'string', optional => 1 },
		evidence  => { type => 'string', optional => 1 },
		fix       => { type => 'string', optional => 1 },
		reference => { type => 'string', optional => 1 },
		file      => { type => 'string', optional => 1 },
		source    => { type => 'string', optional => 1 },
	}

=head4 OUTPUT

	{ type => 'integer', memberof => [ 0, 1 ] }

=head3 MESSAGES

	Message                                    Meaning / resolution
	-----------------------------------------  -------------------------------
	Unknown severity 'S' for finding 'I';      The severity is not one of
	recorded as info (warning)                 critical/high/medium/low/info.
	Unknown parameter 'X' (fatal)              A misspelt argument name.

=head3 FORMAL SPECIFICATION

	┌─ Add ───────────────────────────────────────────────
	│ ΔFindings
	│ id?, severity?, host?, url?, key? : STRING; result! : {0, 1}
	├─────────────────────────────────────────────────────
	│ k = (id?, host?, url?, key?)
	│ sev = if severity? ∈ SEVERITY then severity? else info
	│ k ∈ seen ⇒ items' = items ∧ seen' = seen ∧ result! = 0
	│ k ∉ seen ⇒ items' = items ⁀ ⟨finding(id?, sev, …)⟩
	│          ∧ seen' = seen ∪ {k} ∧ result! = 1
	└─────────────────────────────────────────────────────

=head3 PSEUDOCODE

	validate the arguments
	default the id; warn and default an unknown severity to info
	build the de-duplication key from id, host, url and key
	return 0 if the key has been seen
	store every field, empty string where not given
	return 1

=cut

sub add
{
	my $self = shift;

	my $args = validate_strict(schema => \%ADD_SCHEMA, input => get_params(undef, \@_) // {});

	my $id = $args->{id} // $DEFAULT_ID;
	my $severity = $args->{severity} // $DEFAULT_SEVERITY;
	unless(exists $RANK{$severity}) {
		$self->_warn('findings.unknown_severity', { severity => $severity, id => $id });
		$severity = $DEFAULT_SEVERITY;
	}

	# The same id on the same host/url/key is one finding, however many
	# pages or probes produced it.
	my $dedupe = join $KEY_SEPARATOR, $id, map { $args->{$_} // '' } qw(host url key);
	return 0 if $self->{seen}{$dedupe}++;

	# Every field is present and a string, so the report formats never
	# have to test for undef.
	my %finding = map { $_ => $args->{$_} // '' } @FIELDS;
	@finding{qw(id severity)} = ($id, $severity);
	$finding{title} = $id unless length $finding{title};

	push @{ $self->{items} }, \%finding;

	return 1;
}

=head2 report

Purpose: record a finding whose text comes from the message catalogue, so a
rule only states its id, severity and the values that vary.

Args: C<$id> (the rule id), then named: C<severity>, C<host>, C<url>,
C<key>, C<reference>, C<vars> (hashref of placeholder values),
C<evidence> (raw evidence; overrides the C<.evidence> template),
C<message> (the catalogue base key, when it differs from C<$id> - for
example C<port-open> for C<port-open-3306>) and C<rule> (a hash reference
with default C<severity> and C<reference>, overridden by those arguments).

Returns: as C<add>.

Side Effects: as C<add>.  C<confess>es if the catalogue has no C<.title> or
C<.detail> for the rule.

Usage: C<< $findings->report('tls-expired', severity => 'high', host => $h, vars => { days => 3 }) >>

=head3 EXAMPLE

	$findings->report('port-open-3306',
		message  => 'port-open',
		severity => 'high',
		host     => 'db.example.com',
		vars     => { port => 3306, has_banner => 'no' },
	);

=head3 API SPECIFICATION

=head4 INPUT

	{
		id        => { type => 'string', min => 1, position => 0 },
		severity  => { type => 'string', optional => 1 },
		host      => { type => 'string', optional => 1 },
		url       => { type => 'string', optional => 1 },
		key       => { type => 'string', optional => 1 },
		reference => { type => 'string', optional => 1 },
		evidence  => { type => 'string', optional => 1 },
		message   => { type => 'string', optional => 1 },
		vars      => { type => 'hashref', optional => 1 },
		rule      => { type => 'hashref', optional => 1 },
	}

=head4 OUTPUT

	{ type => 'integer', memberof => [ 0, 1 ] }

=head3 MESSAGES

	Message                              Meaning / resolution
	-----------------------------------  -----------------------------------
	No message is defined for "K"        The rule has no catalogue text; add
	(fatal, with stack trace)            K to App::WebPerimeterScan::Messages.

=head3 FORMAL SPECIFICATION

	┌─ Report ────────────────────────────────────────────
	│ ΔFindings; ΞCatalogue
	│ id?, base? : KEY; vars? : NAME ⇸ VALUE
	├─────────────────────────────────────────────────────
	│ b = if base? defined then base? else id?
	│ b ⁀ ".title" ∈ dom catalogue ∧ b ⁀ ".detail" ∈ dom catalogue
	│ Add[title? := i18n(b ⁀ ".title", vars?),
	│     detail? := i18n(b ⁀ ".detail", vars?)]
	└─────────────────────────────────────────────────────

=cut

sub report
{
	my ($self, $id, @rest) = @_;

	my $args = validate_strict(
		schema => {
			severity  => { type => 'string', optional => 1 },
			host      => { type => 'string', optional => 1 },
			url       => { type => 'string', optional => 1 },
			key       => { type => 'string', optional => 1 },
			reference => { type => 'string', optional => 1 },
			evidence  => { type => 'string', optional => 1 },
			message   => { type => 'string', optional => 1 },
			vars      => { type => 'hashref', optional => 1 },
			rule      => { type => 'hashref', optional => 1 },
		},
		input => get_params(undef, \@rest) // {},
	);

	my $base = $args->{message} // $id;
	my $vars = $args->{vars} // {};

	# A rule table supplies the usual severity and reference; an explicit
	# argument wins, for rules whose severity depends on what was found.
	my $rule = $args->{rule} || {};
	$args->{$_} //= $rule->{$_} for qw(severity reference);

	# Evidence that was captured (a banner, a body excerpt) is data and is
	# passed raw; evidence that is a sentence comes from the catalogue.
	my $evidence = $args->{evidence} // $self->_optional_text("$base.evidence", $vars);

	return $self->add(
		(map { defined $args->{$_} ? ($_ => $args->{$_}) : () } qw(severity host url key reference)),
		id       => $id,
		title    => $self->i18n("$base.title", $vars),
		detail   => $self->i18n("$base.detail", $vars),
		fix      => $self->_optional_text("$base.fix", $vars),
		evidence => $evidence,
	);
}

=head2 annotate

Purpose: attach the file on disk or the line of source behind a finding,
once the scan is complete.

Args: C<$finding> (a hash reference from C<all> or C<sorted>), then named
C<file> and/or C<source> (strings).

Returns: C<$self>, for chaining.

Side Effects: changes the finding in place.  Only C<file> and C<source> can
be changed; the identifying fields are fixed once recorded.

Usage: C<< $findings->annotate($finding, file => '/srv/www/.env') >>

=head3 EXAMPLE

	for my $finding (@{ $findings->all }) {
		$findings->annotate($finding, source => 'lib/App.pm:42')
			if $finding->{url} =~ m{/api/};
	}

=head3 API SPECIFICATION

=head4 INPUT

	{
		finding => { type => 'hashref', position => 0 },
		file    => { type => 'string', optional => 1 },
		source  => { type => 'string', optional => 1 },
	}

=head4 OUTPUT

	{ type => 'object', isa => 'App::WebPerimeterScan::Findings' }

=head3 MESSAGES

	Message                                   Meaning / resolution
	----------------------------------------  -------------------------------
	annotate() was given a finding that this  Pass a finding obtained from this
	collection did not record (fatal)         object's all() or sorted().

=head3 FORMAL SPECIFICATION

	┌─ Annotate ──────────────────────────────────────────
	│ ΔFindings; f? : FINDING; file?, source? : STRING
	├─────────────────────────────────────────────────────
	│ f? ∈ ran items
	│ items' = items ⊕ {f? ↦ f? ⊕ {file ↦ file?, source ↦ source?}}
	└─────────────────────────────────────────────────────

=cut

sub annotate
{
	my ($self, $finding, @rest) = @_;

	my $args = validate_strict(
		schema => { map { $_ => { type => 'string', optional => 1 } } keys %ANNOTATABLE },
		input  => get_params(undef, \@rest) // {},
	);

	# Identity, not equality: a copy of a finding must not be annotated as
	# though it were the original.
	my $address = ref $finding eq 'HASH' ? refaddr($finding) : -1;
	$self->_throw('findings.foreign')
		unless grep { refaddr($_) == $address } @{ $self->{items} };

	$finding->{$_} = $args->{$_} for grep { defined $args->{$_} } keys %ANNOTATABLE;

	return $self;
}

=head2 all

Purpose: the findings in the order they were recorded.

Args: none.

Returns: an array reference (a new array; the findings inside are shared).

Side Effects: none.

Usage: C<< for my $f (@{ $findings->all }) { ... } >>

=head3 EXAMPLE

	my @hosts = map { $_->{host} } @{ $findings->all };

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'arrayref', element_type => 'hashref' }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	┌─ All ───────────────────────────────────────────────
	│ ΞFindings; result! : seq FINDING
	├─────────────────────────────────────────────────────
	│ result! = items
	└─────────────────────────────────────────────────────

=cut

sub all
{
	my ($self) = @_;

	return [ @{ $self->{items} } ];
}

=head2 count

Purpose: the number of findings held.

Args: none.

Returns: a non-negative integer.

Side Effects: none.

Usage: C<< print $findings->count >>

=head3 EXAMPLE

	printf "%d finding(s)\n", $findings->count;

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'integer', min => 0 }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	┌─ Count ─────────────────────────────────────────────
	│ ΞFindings; result! : ℕ
	├─────────────────────────────────────────────────────
	│ result! = #items
	└─────────────────────────────────────────────────────

=cut

sub count
{
	my ($self) = @_;

	return scalar @{ $self->{items} };
}

=head2 sorted

Purpose: the findings worst first, then by host, title and URL, so the
output of two runs can be diffed.

Args: none.

Returns: an array reference.

Side Effects: none.

Usage: C<< for my $f (@{ $findings->sorted }) { ... } >>

=head3 EXAMPLE

	my $worst = $findings->sorted->[0];
	print "Worst: $worst->{title}\n" if $worst;

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'arrayref', element_type => 'hashref' }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	┌─ Sorted ────────────────────────────────────────────
	│ ΞFindings; result! : seq FINDING
	├─────────────────────────────────────────────────────
	│ items bag_of result! ∧ #result! = #items
	│ ∀ i : 1 .. #result! − 1 • key(result! i) ≤ key(result! (i + 1))
	│ key(f) = (−rank(f.severity), f.host, f.title, f.url)
	└─────────────────────────────────────────────────────

=cut

sub sorted
{
	my ($self) = @_;

	return [ sort {
		$RANK{ $b->{severity} } <=> $RANK{ $a->{severity} }
			|| $a->{host} cmp $b->{host}
			|| $a->{title} cmp $b->{title}
			|| $a->{url} cmp $b->{url}
	} @{ $self->{items} } ];
}

=head2 counts

Purpose: how many findings there are at each severity.

Args: none.

Returns: a hash reference with every severity as a key, zero where none.

Side Effects: none.

Usage: C<< my $high = $findings->counts->{high}; >>

=head3 EXAMPLE

	my $counts = $findings->counts;
	print "$counts->{critical} critical\n";

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'hashref' }	# keys: critical high medium low info

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	┌─ Counts ────────────────────────────────────────────
	│ ΞFindings; result! : SEVERITY → ℕ
	├─────────────────────────────────────────────────────
	│ ∀ s : SEVERITY • result! s = #{ f : ran items | f.severity = s }
	└─────────────────────────────────────────────────────

=cut

sub counts
{
	my ($self) = @_;

	my %counts = map { $_ => 0 } @SEVERITIES;
	$counts{ $_->{severity} }++ for @{ $self->{items} };

	return \%counts;
}

=head2 rank

Purpose: the numeric rank of a severity name, higher is worse.

Args: C<$severity> (string).  A function, not a method.

Returns: 5 for C<critical> down to 1 for C<info>; 0 for anything else.

Side Effects: none.

Usage: C<< App::WebPerimeterScan::Findings::rank('high') >>

=head3 EXAMPLE

	my @worst_first = sort {
		App::WebPerimeterScan::Findings::rank($b) <=> App::WebPerimeterScan::Findings::rank($a)
	} qw(low critical medium);

=head3 API SPECIFICATION

=head4 INPUT

	{ severity => { type => 'string', optional => 1, position => 0 } }

=head4 OUTPUT

	{ type => 'integer', min => 0, max => 5 }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	┌─ Rank ──────────────────────────────────────────────
	│ severity? : STRING; result! : 0 .. 5
	├─────────────────────────────────────────────────────
	│ severity? ∈ dom RANK ⇒ result! = RANK(severity?)
	│ severity? ∉ dom RANK ⇒ result! = 0
	└─────────────────────────────────────────────────────

=cut

sub rank
{
	my ($severity) = @_;

	return defined $severity ? ($RANK{$severity} // 0) : 0;
}

=head2 at_or_above

Purpose: the findings at or above a severity, which is what decides the exit
status of the command-line tool.

Args: C<$threshold>, a severity name.

Returns: an array reference; empty for an unknown threshold.

Side Effects: none.

Usage: C<< exit 1 if @{ $findings->at_or_above('high') }; >>

=head3 EXAMPLE

	my $failing = $findings->at_or_above('medium');
	printf "%d finding(s) at medium or worse\n", scalar @{$failing};

=head3 API SPECIFICATION

=head4 INPUT

	{ threshold => { type => 'string', position => 0 } }

=head4 OUTPUT

	{ type => 'arrayref', element_type => 'hashref' }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	┌─ AtOrAbove ─────────────────────────────────────────
	│ ΞFindings; threshold? : STRING; result! : seq FINDING
	├─────────────────────────────────────────────────────
	│ threshold? ∉ dom RANK ⇒ result! = ⟨⟩
	│ threshold? ∈ dom RANK ⇒
	│     result! = items ↾ { f | RANK(f.severity) ≥ RANK(threshold?) }
	└─────────────────────────────────────────────────────

=cut

sub at_or_above
{
	my ($self, $threshold) = @_;

	# An unknown threshold matches nothing rather than everything.
	my $limit = rank($threshold);

	return $limit ? [ grep { $RANK{ $_->{severity} } >= $limit } @{ $self->{items} } ] : [];
}

# _optional_text
# Purpose:     render a catalogue key that a rule may leave out (.fix,
#              .evidence).
# Entry:       $key is a full key; $vars a hashref.
# Exit:        the rendered text, or '' when the key does not exist.
# Side effects: none.
sub _optional_text :Private
{
	my ($self, $key, $vars) = @_;

	return $self->has_message($key) ? $self->i18n($key, $vars) : '';
}

1;

__END__

=head1 LIMITATIONS

=over 4

=item * Findings are plain hash references, so code holding one can change
any field, not only through C<annotate>.  Returning copies would stop that
but would also break C<annotate>, which needs the original; a finding class
with read-only accessors is the complete fix and is left for a later
release.

=item * De-duplication is exact: the same problem reported under two URLs is
two findings, which is deliberate for page-level rules and noisy for
host-level ones.  Rules that are about the host pass an empty C<url>.

=back

=head1 LICENSE

GPL2

=cut
