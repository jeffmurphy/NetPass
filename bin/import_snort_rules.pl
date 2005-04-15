#!/opt/perl/bin/perl -w

=head1 NAME

 import_snort_rules.pl

=head1 SYNOPSIS

 import_snort_rules.pl [-D] [-q] [-c cstr] [-U dbuser/dbpass] <-l rulesdir> <-s sigdir>
     -l rulesdir	  directory where the snort rules are located        	 
     -s sigdir	  	  directory where all the snort signature files are located        	 
     -h                   this message


=head1 DESCRIPTION

This script goes through a snort rules directory and imports all the 
rules into the snortRules database.

=head1 SEE ALSO

C<netpass.conf>

=head1 AUTHOR

Matt Bell <mtbell@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

=cut

# ./import_snort_rules.pl -l ~/snort/rules/ -s ~/snort/doc/signatures


use strict;
use Getopt::Std;
use Pod::Usage;
use FileHandle;
use DBI;

use lib '/opt/netpass/lib';
use NetPass;
use NetPass::DB;

my %opts;

getopts('c:U:Dqs:l:h?', \%opts);
pod2usage(2) if exists $opts{'h'} || exists $opts{'?'} ||
	     !exists($opts{'l'}) || !exists($opts{'s'});

my ($dbuser, $dbpass) = exists $opts{'U'} ? split('/', $opts{'U'}) : (undef, undef);

my $np = new NetPass(-cstr => exists $opts{'c'} ? $opts{'c'} :  undef,
		     -dbuser => $dbuser, -dbpass => $dbpass,
		     -debug  => exists $opts{'D'} ? 1 : 0,
		     -quiet  => exists $opts{'q'} ? 1 : 0);

my $dbh = $np->db->{dbh};

my $data = {};


die "Cannot cd into ".$opts{'l'} unless(-d $opts{'l'});
opendir(DIR, $opts{'l'}) || die "unable to open ".$opts{'l'};

foreach my $file (readdir(DIR)) {
	next if ($file !~ /\.rules$/);

	my $fh    = new FileHandle;
	my $sidfh = new FileHandle;
	if (!$fh->open($opts{'l'}.'/'.$file)) {
		warn "Unable to open file $file skipping...";
		next;
	}
	while (my $line = $fh->getline) {
		next if ($line !~ /^alert/);
		my $sid;
	
		if ($line =~ /sid\:(\d+)\;/) {
			$sid = $1;	
		} else {
			warn "Rule doesnt contain a sid skipping...";
			next;
		}

		my $sidfile = $opts{'s'}.'/'.$sid.'.txt';

		if (-e $sidfile && $sidfh->open($sidfile)) {
			my $b = 0;
			while (my $l = $sidfh->getline) {
				last if ($l =~ /^\-\-/ && $b == 1); 
				if ($b) {
					$data->{$sid}{desc} .= $l;
				}
				$b = 1 if ($l =~ /^Detailed Information:/) 
			}
			$sidfh->close;

		} else {
			$data->{$sid}{desc} = "none";
		}

		$data->{$sid}{rule} = $line;

		if ($line =~ /msg\:\"([\w-]+)\s+([^";]+)\"\;/) {
			$data->{$sid}{category} = $1;
			$data->{$sid}{name}     = $2;
		}

		if ($line =~ /rev\:(\d+)\;/) {
                        $data->{$sid}{rev} = $1;
                }

                if ($line =~ /classtype\:([^;]+)\;/) {
                        $data->{$sid}{classtype} = $1;
                }

                if ($line =~ /reference\:([^;]+)\;/) {
                        $data->{$sid}{reference} = $1;
                }
	}

	$fh->close;
}
closedir(DIR);

my $sql = qq{INSERT IGNORE INTO snortRules (
				     snortID, name, category, classtype, 
				     description, rule, addedBy, lastModifiedBy,
				     revision, other_refs
				    ) VALUES (?,?,?,?,?,?,'import', 'import',?,?)};

my $sth = $dbh->prepare($sql);

foreach my $sid (sort keys %$data) {
	$sth->execute($sid, $data->{$sid}{name},
			    $data->{$sid}{category},
			    $data->{$sid}{classtype},
			    $data->{$sid}{desc},
			    $data->{$sid}{rule},
			    $data->{$sid}{rev},
			    $data->{$sid}{reference});
}

$sth->finish;
$dbh->disconnect;
exit 0;
