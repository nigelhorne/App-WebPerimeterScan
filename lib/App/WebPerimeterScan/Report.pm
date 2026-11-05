package App::WebPerimeterScan::Report;

use strict;
use warnings;

use JSON::PP ();

use App::WebPerimeterScan::Findings ();

our $VERSION = '0.01';

my %COLOR = (
	critical => 'bold red',
	high     => 'red',
	medium   => 'yellow',
	low      => 'cyan',
	info     => 'white',
);

sub _use_color
{
	my ($requested) = @_;

	return $requested ? 1 : 0 if defined $requested;
	return -t STDOUT ? 1 : 0;
}

sub as_text
{
	my ($findings, %meta) = @_;

	my $color = _use_color($meta{color});
	my $paint = sub {
		my ($severity, $text) = @_;
		return $text unless $color;
		require Term::ANSIColor;
		return Term::ANSIColor::colored($text, $COLOR{$severity} // 'white');
	};

	my $out = '';
	$out .= "webperimeter $meta{version}  " . ($meta{generated} // '') . "\n";
	$out .= "Scope: " . ($meta{scope_source} // '') . "\n";
	$out .= "Requests: $meta{requests}\n" if defined $meta{requests};

	for my $host (@{ $meta{hosts} || [] }) {
		$out .= "\n" . ('=' x 60) . "\n$host->{host}\n" . ('-' x 60) . "\n";

		if(my $tls = $host->{tls}) {
			if($tls->{ok}) {
				my $expiry = defined $tls->{days_left}
					? "$tls->{not_after} ($tls->{days_left} days)"
					: 'unknown';
				$out .= "  TLS: " . ($tls->{protocol} // '?')
					. ', ' . ($tls->{cipher} // '?')
					. ", expires $expiry\n";
				$out .= "  Certificate: " . ($tls->{subject} // '?')
					. ' issued by ' . ($tls->{issuer} // '?') . "\n";
			} else {
				$out .= "  TLS: handshake failed (" . ($tls->{error} // 'unknown') . ")\n";
			}
		}

		if(exists $host->{open_ports}) {
			$out .= '  Open ports: ' . (@{ $host->{open_ports} }
				? join(', ', map { $_->{port} } @{ $host->{open_ports} })
				: 'none of the tested ports') . "\n";
		}

		$out .= '  URLs scanned: ' . scalar(@{ $host->{urls} || [] }) . "\n";
	}

	my $counts = $findings->counts;
	$out .= "\n";

	my @sorted = $findings->sorted;
	if(!@sorted) {
		$out .= "No findings. That is a clean result for the checks this tool performs,\n";
		$out .= "not proof that the site is secure - see the limits in the README.\n";
		return $out;
	}

	my $current;
	for my $finding (@sorted) {
		if(!defined $current || $current ne $finding->{severity}) {
			$current = $finding->{severity};
			$out .= "\n" . uc($current) . ' (' . $counts->{$current} . ")\n"
				. ('-' x length(uc($current) . ' (' . $counts->{$current} . ')')) . "\n";
		}

		$out .= $paint->($current, "[$finding->{id}]");
		$out .= ' ' . $finding->{title} . "\n";
		$out .= '  ' . $finding->{url} . "\n" if length $finding->{url};
		$out .= '  File: ' . $finding->{file} . "\n" if length($finding->{file} // '');
		$out .= '  In source: ' . $finding->{source} . "\n" if length($finding->{source} // '');
		$out .= "  $finding->{detail}\n" if length $finding->{detail};
		if(length $finding->{evidence}) {
			(my $evidence = $finding->{evidence}) =~ s/\s+/ /g;
			$out .= "  Evidence: $evidence\n";
		}
		$out .= "  Fix: $finding->{fix}\n" if length $finding->{fix};
		$out .= "  See: $finding->{reference}\n" if length $finding->{reference};
		$out .= "\n";
	}

	$out .= 'Summary: ' . join(', ',
		map { "$counts->{$_} $_" } @App::WebPerimeterScan::Findings::SEVERITIES
	) . "\n";

	return $out;
}

sub as_json
{
	my ($findings, %meta) = @_;

	my $data = {
		tool      => 'webperimeter',
		version   => $meta{version},
		generated => $meta{generated},
		scope     => $meta{scope_source},
		requests  => $meta{requests},
		summary   => $findings->counts,
		hosts     => $meta{hosts},
		findings  => [ map { {
			id        => $_->{id},
			severity  => $_->{severity},
			host      => $_->{host},
			url       => $_->{url},
			title     => $_->{title},
			detail    => $_->{detail},
			evidence  => $_->{evidence},
			fix       => $_->{fix},
			reference => $_->{reference},
			file      => $_->{file},
			source    => $_->{source},
		} } $findings->sorted ],
	};

	return JSON::PP->new->canonical->pretty->encode($data);
}

sub as_html
{
	my ($findings, %meta) = @_;

	my $counts = $findings->counts;
	my %class = (
		critical => 'critical',
		high     => 'high',
		medium   => 'medium',
		low      => 'low',
		info     => 'info',
	);

	my $summary = join '', map {
		my $severity = $_;
		qq{<li class="pill $class{$severity}">$severity: $counts->{$severity}</li>}
	} grep { $counts->{$_} } @App::WebPerimeterScan::Findings::SEVERITIES;

	my @rows;
	for my $finding ($findings->sorted) {
		push @rows, join '',
			qq{<tr class="$class{ $finding->{severity} }">},
			'<td>' . _escape($finding->{severity}) . '</td>',
			'<td><code>' . _escape($finding->{id}) . '</code></td>',
			'<td>' . _escape($finding->{title}) . '</td>',
			'<td><code>' . _escape($finding->{url}) . '</code></td>',
			'<td><code>' . _escape($finding->{file}) . '</code></td>',
			'<td><code>' . _escape($finding->{source}) . '</code></td>',
			'<td>' . _escape($finding->{detail}) . '</td>',
			'<td><code>' . _escape($finding->{evidence}) . '</code></td>',
			'<td>' . _escape($finding->{fix}) . '</td>',
			'</tr>';
	}

	my $host_rows = join '', map {
		my $tls = $_->{tls};
		my $tls_text = $tls && $tls->{ok}
			? _escape(($tls->{protocol} // '?') . ' / ' . ($tls->{cipher} // '?')
				. (defined $tls->{days_left} ? " / $tls->{days_left} days left" : ''))
			: 'not inspected';
		my $ports = exists $_->{open_ports}
			? join(', ', map { $_->{port} } @{ $_->{open_ports} })
			: '';
		'<tr><td>' . _escape($_->{host}) . '</td><td>' . _escape($tls_text)
			. '</td><td>' . _escape($ports) . '</td><td>'
			. scalar(@{ $_->{urls} || [] }) . '</td></tr>';
	} @{ $meta{hosts} || [] };

	my $rows = @rows ? join("\n", @rows) : '<tr><td colspan="9">No findings.</td></tr>';

	return <<"HTML";
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Perimeter scan - $meta{generated}</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; color: #1b1b1b; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; }
  th, td { border: 1px solid #d5d5d5; padding: 0.5rem; text-align: left; vertical-align: top; font-size: 0.9rem; }
  th { background: #f2f2f2; }
  code { font-family: ui-monospace, monospace; font-size: 0.85em; overflow-wrap: anywhere; }
  .pill { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 999px; margin-right: 0.5rem; font-weight: 600; }
  .critical { background: #7f1d1d; color: #fff; }
  .high { background: #fee2e2; }
  .medium { background: #fef3c7; }
  .low { background: #e0f2fe; }
  .info { background: #f1f5f9; }
  h1 { margin-bottom: 0.25rem; }
  .meta { color: #555; margin-bottom: 1.5rem; }
</style>
</head>
<body>
<h1>External perimeter scan</h1>
<div class="meta">webperimeter $meta{version} &middot; $meta{generated} &middot; scope: @{[ _escape($meta{scope_source}) ]} &middot; @{[ defined $meta{requests} ? "$meta{requests} requests" : '' ]}</div>
<ul style="list-style:none;padding:0">$summary</ul>
<h2>Hosts</h2>
<table>
<thead><tr><th>Host</th><th>TLS</th><th>Open ports</th><th>URLs scanned</th></tr></thead>
<tbody>$host_rows</tbody>
</table>
<h2>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>URL</th><th>File</th><th>Source</th><th>Detail</th><th>Evidence</th><th>Fix</th></tr></thead>
<tbody>$rows</tbody>
</table>
</body>
</html>
HTML
}

sub _escape
{
	my ($text) = @_;

	$text = '' unless defined $text;
	$text =~ s/&/&amp;/g;
	$text =~ s/</&lt;/g;
	$text =~ s/>/&gt;/g;
	$text =~ s/"/&quot;/g;
	$text =~ s/'/&#39;/g;

	return $text;
}

1;

__END__

=head1 NAME

App::WebPerimeterScan::Report - text, JSON and HTML output

=head1 SYNOPSIS

	print App::WebPerimeterScan::Report::as_text($findings,
		version => '0.01', generated => '2026-11-05T10:00:00Z', hosts => \@hosts);

=head1 LICENSE

GPL2

=cut
