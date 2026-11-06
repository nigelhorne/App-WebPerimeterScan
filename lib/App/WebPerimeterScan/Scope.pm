package App::WebPerimeterScan::Scope;

use strict;
use warnings;

use Socket qw(inet_aton);

use URI;

our $VERSION = '0.001.0';

# The scope file is the authorisation boundary.  Nothing in this distribution
# will send traffic to a host that does not appear here, so a crawler cannot
# wander onto a third party's site.

sub new
{
	my ($class, %args) = @_;

	return bless {
		entries       => [],
		allow_private => $args{allow_private} ? 1 : 0,
		source        => $args{source} // '(none)',
	}, $class;
}

sub load_file
{
	my ($self, $file) = @_;

	open my $fh, '<', $file or die "Cannot read scope file '$file': $!\n";
	my $count = 0;
	while(my $line = <$fh>) {
		$line =~ s/\s*#.*//;
		$line =~ s/^\s+|\s+$//g;
		next unless length $line;

		if($self->_add_entry($line)) {
			$count++;
		} else {
			warn "Ignoring unparsable scope line: $line\n";
		}
	}
	close $fh;

	die "Scope file '$file' contains no usable hosts\n" unless $count;

	$self->{source} = $file;

	return $self;
}

# Accepts:
#   example.com
#   example.com:8443
#   https://example.com/
#   *.example.com            (the domain and any sub-domain)
#   192.0.2.10
sub _add_entry
{
	my ($self, $line) = @_;

	my %entry;

	if($line =~ m{^https?://}i) {
		my $uri = URI->new($line);
		my $host = $uri->host or return 0;
		$entry{host}   = lc $host;
		$entry{port}   = $uri->port;
		$entry{scheme} = lc $uri->scheme;
	} elsif($line =~ /^\*\.([A-Za-z0-9][A-Za-z0-9._-]*)$/) {
		$entry{host}     = lc $1;
		$entry{wildcard} = 1;
	} elsif($line =~ /^([A-Za-z0-9][A-Za-z0-9._-]*)(?::(\d+))?$/) {
		$entry{host} = lc $1;
		$entry{port} = $2 if $2;
	} else {
		return 0;
	}

	$entry{host} =~ s/\.$//;
	return 0 unless length $entry{host};

	push @{ $self->{entries} }, \%entry;

	return 1;
}

sub entries
{
	my ($self) = @_;

	return @{ $self->{entries} };
}

sub source
{
	my ($self) = @_;

	return $self->{source};
}

# Concrete hosts to scan: every entry, minus wildcards, de-duplicated.
# A wildcard entry still authorises its sub-domains, but we do not guess
# sub-domain names - we only follow links we are actually served.
sub hosts
{
	my ($self) = @_;

	my %seen;
	return grep { !$seen{$_->{host}}++ }
		grep { !$_->{wildcard} }
		@{ $self->{entries} };
}

# Is this hostname inside the authorised scope?
sub covers
{
	my ($self, $host) = @_;

	return 0 unless defined $host && length $host;
	$host = lc $host;
	$host =~ s/\.$//;

	for my $entry (@{ $self->{entries} }) {
		return 1 if $host eq $entry->{host};
		return 1 if $entry->{wildcard} && $host =~ /\.\Q$entry->{host}\E$/;
	}

	return 0;
}

# Refuse loopback, RFC1918, link-local and CGNAT space unless the operator
# asked for it.  Scanning 127.0.0.1 is how you test this tool; scanning
# somebody's 10/8 is usually a mistake.
sub is_private_target
{
	my ($self, $host) = @_;

	my $packed = inet_aton($host);
	if(!defined $packed) {
		my @addrs = gethostbyname($host);
		$packed = $addrs[4] if @addrs > 4;
	}
	return 0 unless defined $packed && length($packed) == 4;

	my $n = unpack('N', $packed);
	return 1 if ($n & 0xff000000) == 0x7f000000;	# 127/8
	return 1 if ($n & 0xff000000) == 0x0a000000;	# 10/8
	return 1 if ($n & 0xfff00000) == 0xac100000;	# 172.16/12
	return 1 if ($n & 0xffff0000) == 0xc0a80000;	# 192.168/16
	return 1 if ($n & 0xffff0000) == 0xa9fe0000;	# 169.254/16
	return 1 if ($n & 0xffc00000) == 0x64400000;	# 100.64/10
	return 1 if ($n & 0xff000000) == 0x00000000;	# 0/8
	return 1 if ($n & 0xff000000) == 0xc0000000;	# 192.0.2/24 documentation
	return 1 if ($n & 0xff000000) == 0xdf000000;	# 223/8 multicast-ish

	return 0;
}

sub assert_target_allowed
{
	my ($self, $host) = @_;

	die "Refusing to scan '$host': not listed in " . $self->{source} . "\n"
		unless $self->covers($host);

	return 1 if $self->{allow_private};
	die "Refusing to scan '$host': it resolves into private address space (use --allow-private if this is intentional)\n"
		if $self->is_private_target($host);

	return 1;
}

1;

__END__

=head1 NAME

App::WebPerimeterScan::Scope - authorisation boundary for an external scan

=head1 VERSION

Version 0.001.0

=head1 SYNOPSIS

	my $scope = App::WebPerimeterScan::Scope->new(allow_private => 0);
	$scope->load_file('scope.txt');
	$scope->assert_target_allowed('www.example.com');
	print "in scope\n" if $scope->covers('api.example.com');

=head1 DESCRIPTION

Every network request the scanner makes is checked against this object.
Hosts that are not listed in the scope file are never contacted.

=head1 REQUIREMENTS

Perl 5.10 or later, with C<URI> 1.70, which is not part of Perl 5.10's core
and so is installed for you.  Addresses are resolved with C<Socket>, which is
core.

=head1 LICENSE

GPL2

=cut
