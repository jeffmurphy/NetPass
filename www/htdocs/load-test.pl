#!/usr/bin/perl -w

# $Header: /tmp/netpass/NetPass/www/htdocs/load-test.pl,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense


# Model script:
# cookbook:/opt/netpass/www/htdocs/Admin/Scan/info.mhtml

# <%args>
#$id      => '';
#</%args>

#Begin<P>

#<%once>
use strict;
use Apache::DBI;
use DBI;
use English;

use lib '/opt/netpass/lib';
use NetPass;

my $username = 'root';
my $password = '';
my $database = 'netpass';

# $SIG{CHLD} = 'IGNORE';
$SIG{ALRM} = sub { die "timeout" }; # set SIGALRM's return value.
$SIG{CHLD} = sub { wait };
#</%once>

#<%perl>

my %ARGS = ();

Apache::DBI->connect_on_init('dbi:mysql:netpass', $username, $password);
Apache::DBI->setPingTimeOut('dbi:mysql:netpass', 0);

for (1..15) {
  fork_routine ();
}

sub getInfo {

  my $dbh = shift;
  my $id = shift;

  my $stmt = "SELECT * FROM audit";

  my $sth = $dbh->prepare($stmt);
  if (!defined($sth)) {
      return ("prepare failed: ". $dbh->errstr, -1);
  }

  if (!$sth->execute($id) ) {
     return ("execute failed: ". $dbh->errstr, -1);
  }

  my $rv = $sth->rows;
  my $rc = $sth->finish || die $sth->errstr;
                                                                                
  return ($sth, $rv);
}

sub fork_routine {

  # my %ARGS = shift;

  if (my $cpid = fork ()) {
     # parent code here
     # child process pid is available in $cpid
                                                                                                    
     print "forking cpid $cpid...\n";
  }
  elsif (defined ($cpid)) { # $cpid is zero here if defined
       # child code here
       # parent process pid is available with getppid

       print "childe process $cpid\n";
       # test_npdbh (%ARGS);

       eval {

         alarm (1 * 60); # alarm if we hit this many seconds.

         alarm (0);
         exit (0); # child is done...exitting
       };
                                                                                                    
       if ($EVAL_ERROR) { # lets us customize timeout code rather than just die.
          if ($EVAL_ERROR =~ /timeout/) {
             exit (-1);
          }
          else {
             alarm (0); # clear the still-pending alarm
             die;
          }
       }
  }
}
