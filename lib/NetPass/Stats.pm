# $Header: /tmp/netpass/NetPass/lib/NetPass/Stats.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense


package NetPass::Stats;
use strict;

use FileHandle;

require Carp;

sub new {
	my($class, $self) = (shift, {});


	return bless($self, $class);
}

sub cpuStats {
	my $self = shift;

	my $statsfile = "/proc/stat";
	die "$statsfile not existant" if (!-e $statsfile); 

	my $fh = new FileHandle($statsfile);
	my $tot;

	while (<$fh>) {
		if (/^cpu\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+$/) {
			$tot = $1 + $2 + $3 + $4;
			$fh->close;
			last;		
		}
	}
	$fh->close;

	return $tot;
}

