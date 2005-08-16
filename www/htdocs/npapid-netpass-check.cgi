#!/opt/perl/bin/perl -w
#
# we dont use mhtml because we dont want the Apache::Session
# cookie files created since they are difficult to delete.

use strict;
use Proc::ProcessTable;
my $pt = new Proc::ProcessTable();

print "Content-type: text/plain\n\n";
foreach my $p (@{$pt->table}) {
	if ($p->cmndline =~ /npapid/) {
		print "NPAPID-OK\n";
		exit 0;
	}
}
print "NPAPID-NOK\n";
exit 0;
