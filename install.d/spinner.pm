package spinner;
use strict;

my @S = ('|', '/', '-', '\\');
my $s = 0;
sub spinner {
	$s = ($s+1) % 4;
	my $p = ('|', '/', '-', '\\')[$s];
	print "\b$p";
	#for(my $i=0; $i<1000;$i++){}
}

1;
