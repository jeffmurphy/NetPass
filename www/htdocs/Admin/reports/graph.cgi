#!/usr/bin/perl
#
#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense
#

use CGI;
use GD;
use GD::Graph;
my $q = new CGI;

my @labels = ();
my @values = ();
my $type   = 'pie';


foreach my $p ($q->param) {
	if($p eq 'type') {
		$type = $q->param($p);
		next;
	}
	push(@labels, $p);
	push(@values, $q->param($p));
}

my $data = [ \@labels, \@values ];

print_chart($q, $data, $type);

sub print_chart {
	my $q    = shift;
	my $data = shift;
	my $type = shift;

	eval "require GD::Graph::$type";
	my $graph = eval "new GD::Graph::$type(250, 250)";

	$graph->set('3d' => 0);

	if ($type eq 'pie') {
		$graph->set('start_angle'	=> 90,
			    'suppress_angle'	=> 5,
			   );
	}

	$graph->set_value_font(GD::Font->Large);

	print $q->header("Content-type: image/png");
	binmode STDOUT;
	print $graph->plot($data)->png;
}

</%perl>
