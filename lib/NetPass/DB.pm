# $Header: /tmp/netpass/NetPass/lib/NetPass/DB.pm,v 1.6 2004/12/31 19:09:09 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

package NetPass::DB;

use strict;
use Class::ParmList qw(simple_parms parse_parms);
use NetPass::LOG qw(_log _cont);
use DBI;
use Data::Dumper;
use Sys::Hostname;

my $VERSION = '1.0001';

sub DESTROY {
    my $self = shift;
    $self->{'dbh'}->disconnect if defined $self->{'dbh'};
}

sub D {
    my $self = shift;

    return $self->{'D'};
}

=head2 NetPass::DB::new(connstr, user, password, debug)

Create a new NetPass DB object and connect to the underlying
database (using DBI) with the specified details. If debug is 
defined and non-zero, log debugging information using NetPass::LOG;

=cut

sub new {
    my ($class, $self) = (shift, {});
    my ($s, $u, $p, $d) = (shift, shift, shift, shift);

    # this should match, exactly, what's in mod_perl's startup.pl 
    # script. otherwise you'll get a 1:N (N > 1) ration of 
    # httpd to mysqld processes

    my $dbh = DBI->connect($s, $u, $p,
			   { 
			    PrintError => 0, # warn() on errors
			    RaiseError => 0, # die() on errors
			    AutoCommit => 1  # commit on execute
			   }
			  );
    return undef if ( !defined($dbh) );

    $self->{'dbh'} = $dbh;
    $self->{'s'}   = $s;
    $self->{'u'}   = $u;
    $self->{'p'}   = $p;
    $self->{'D'}   = $d;
    $self->{'err'} = "";

    return bless $self, $class;
}

sub dbh {
	my $self = shift;
	return $self->{'dbh'};
}

sub error {
    my $self = shift;
    return defined($self->{'dbh'}) ? $self->{'dbh'}->errstr : $DBI::errstr;
}

=head2 macStatus(macAddr)

Returns:

=over 4

=item "UNQUAR"

if registered and shouldn't be quarantined

=item "QUAR"

if registered and has results pending

=item "PQUAR"

if registered and is manually quarantined

=item "PUNQUAR"

if registered and is manually unquarantined

=item C<undef>

if not registered or failure

=back

=cut

sub macStatus {
    my $self = shift;
    my $ma   = shift;

    my $sql  = qq{SELECT status FROM register WHERE macAddress = '$ma'};

    $self->reconnect() || return undef;

    my $a    = $self->{'dbh'}->selectrow_arrayref($sql);
    return undef if (!defined($a) || (ref($a) ne "ARRAY"));
    return $a->[0];

}

=head2 yes|no = UQLinkUp($mac)

Given a mac, return whether or not it qualifies to be unquarantined
when link comes up. Returns 1 (yes, unquar on linkup) or 0 (no,
dont unquar on linkup) if the mac is registered.

Returns C<undef> if the mac is not registered.

=cut

sub UQLinkUp {
	my $self = shift;
	my $ma   = shift;

	my $sql  = qq{SELECT uqlinkup FROM register where macAddress = '$ma'};
	$self->reconnect() || return undef;
	my $a    = $self->{'dbh'}->selectrow_arrayref($sql);
	return undef if (!defined($a) || (ref($a) ne "ARRAY"));
	return $a->[0];
}

=head2 0 | 1 = UQLinkUp_itDependsCheck($macList)

This routine returns true (1) if the following is true:

   - all of the given macs are registered
   - they are all unquarantined
   - they are all tagged with uqlinkup = 'yes'

Otherwise it returns false (0). This routine is used by resetport.pl

Finally, if an error occurs, we return C<undef>

=cut

sub UQLinkUp_itDependsCheck {
	my $self = shift;
	my $ml   = shift;
	return  0 if (!defined($ml) && (ref($ml) ne "ARRAY"));

	# M1 M2
	# select count(*) from register where
	#    (macAddress = 'M1' AND uqlinkup = 'yes' AND (status = 'UNQUAR' OR status = 'PUNQUAR'))
	#    AND
	#    (macAddress = 'M2' AND uqlinkup = 'yes' AND (status = 'UNQUAR' OR status = 'PUNQUAR'))
	#
	# should return "2" if everything is OK.

	my $sql = "SELECT count(*) FROM register WHERE ";
	for (my $i = 0 ; $i <= $#$ml ; $i++) {
		my $m = $ml->[$i];
		$sql .= qq{ (macAddress = '$m' AND uqlinkup = 'yes' AND (status = 'UNQUAR' OR status = 'PUNQUAR')) };
		$sql .= " OR " if ($i < $#$ml);
	}
	#_log("DEBUG", "sql=$sql\n");
	$self->reconnect();
	my $a = $self->{'dbh'}->selectrow_arrayref($sql);
	return $a->[0];
}


=head2 macIsRegistered(macAddr)

Returns:

=over 4

=item 1

if registered

=item 0

if not registered

=item -1

if an error occurred.

=back

=cut

sub macIsRegistered {
    my $self = shift;
    my $ma   = shift;

    $self->reconnect() || return -1;

    return 0 if ($ma eq "REMOTE");
    return 0 if ($ma !~ /^[0-9a-fA-F]+$/); # must be a hex number

    my $sql = "SELECT count(*) FROM register WHERE macAddress = '$ma'";
    my $row = $self->{'dbh'}->selectrow_arrayref($sql);

    #use Data::Dumper;
    #print STDERR Dumper($row), "\n";

    return -1 if (!defined($row) || (ref($row) ne "ARRAY"));

    my $count = $row->[0];

    #_log("DEBUG", "rowcount=$count\n");

    return ($count > 0);
}

=head2 ($s, $p) = lookupSwitchPort(macAddr)

Returns:

=over 4

=item 2 values (switch, port)

if MAC is registered in the database

=item 2 values (undef, undef)

MAC is not registered

=item undef

a failure occurred.

=back

=cut

sub lookupSwitchPort {
    my $self = shift;
    my $ma   = shift;

    $self->reconnect() || return undef;

    my $sth = $self->{'dbh'}->prepare("SELECT switchIP,switchPort FROM register WHERE macAddress = '$ma'");
    if(!defined($sth)) {
	_log "ERROR", "prepare failed: ".$self->{'dbh'}->errstr;
	$self->error("prepare failed: ".$self->{'dbh'}->errstr);
	return undef;
    }
    if( !$sth->execute ) {
	_log "ERROR", "execute failed: ".$self->{'dbh'}->errstr;
	$self->error("execute failed: ".$self->{'dbh'}->errstr);
	return undef;
    }
    my ($s,$p) = ($sth->fetchrow_array)[0,1];
    $sth->finish;
    return ($s,$p);
}

=head2 $rv = setSwitchPort(macAddr, switch, port)

Update our record to reflect the switch and port we are on. Returns
1 on success, 0 on failure.

=cut

sub setSwitchPort {
    my $self = shift;
    my $ma   = shift;
    my ($sw, $po) = (shift, shift);

    $self->reconnect() || return 0;

    my $sql = qq{UPDATE register SET switchIP = '$sw', switchPort = $po WHERE macAddress = '$ma'};

    return 1 if ( $self->{'dbh'}->do($sql) );
    _log "ERROR", $self->{'dbh'}->errstr."\n";
    return 0;
}


=head2 setMessage(mac, message | url)

This routine will set the message on an already registered MAC. It will over-write
any existing message. If the message begins with "http:" then the web front end
will assume it's a URL. Otherwise, the web frontend will assume it's text or HTML
code and display it appropriately. It's OK to set the message to C<undef>. Returns:

=over 4

=item 1

on success 

=item 0

on failure (e.g. mac isnt registered)

=cut

sub setMessage {
    my $self = shift;
    my ($ma, $msg) = (shift, shift);

    #called by macIsReg .. $self->reconnect() || return 0;

    my $rv = $self->macIsRegistered($ma);
    return 0 if ($rv < 1);

    if (defined($msg) && ($msg !~ /^null$/i)) {
	$msg = $self->{'dbh'}->quote($msg);
    } else {
	$msg = 'NULL';
    }

    my $sql = "UPDATE register SET message = $msg WHERE macAddress = '$ma'";

    _log ("DEBUG", "$ma setMessage to $msg (sql=$sql)\n");

    return 1 if $self->{'dbh'}->do($sql);

    _log("ERROR", "setMessage failed: ".$self->{'dbh'}->errstr."\n");

    return 0;
}

=head2 $msg = getMessage(mac)

This routine will get the message on an already registered MAC. Returns:

=over 4

=item C<scalar>

on success

=item undef

on failure or no message set

=cut

sub getMessage {
    my $self = shift;
    my $ma = shift;

    #called by macIsReg .. $self->reconnect() || return undef;

    my $rv = $self->macIsRegistered($ma);
    return undef if ($rv ==  0);
    return undef if ($rv == -1);
	  
    my $sql = "SELECT message FROM register WHERE macAddress = '$ma'";

    my $a    = $self->{'dbh'}->selectrow_arrayref($sql);
    _log "ERROR", "select failed: ".$self->{'dbh'}->errstr."\n" 
      unless (defined($a) && (ref($a) eq "ARRAY"));
    return $a->[0];
}

=head2 $msg = getRegisteredIP(mac[, mac, ...])

This routine will get the registered info on an already registered MAC. Returns:

=over 4

=item C<HASHREF> containing keys that correspond to the macAddresses given.
values of C<HASHREF> are C<HASHREF>s containing keys: ipAddress, firstSeen,
registeredOn, status, message, username, OS, switchIP, switchPort, uqlinkup.

If the Mac is not registered, it won't be in the HASHREF returned.  

on success

=item undef

SQL failure

=cut

sub getRegisterInfo {
    my $self = shift;

    $self->reconnect() || return undef;

    my @crit = ();

    foreach my $ma (@_) {
	    push @crit, "macAddress = '$ma'";
    }

    my $sql = "SELECT macAddress, ipAddress, firstSeen, registeredOn, status, message, username, OS, switchIP, switchPort, uqlinkup FROM register WHERE " .
      join (" OR " , @crit) ;

    my $a    = $self->{'dbh'}->selectall_hashref($sql, 'macAddress');

    return $a if (defined($a) && (ref($a) eq "HASH"));

    _log "ERROR", "select failed: ".$self->{'dbh'}->errstr."\n";
    return undef;
}

=head2 $msg = getPage($name, $massage)

Give a page name (e.g. 'msg:welcome') retrieve the page from the database. If
C<massage> is "1", then we'll strip any C<head>, C<body> and C<html> tags
(openning and closing) out of the HTML before returning it. This is useful
when we want to embed the page inside of another page.

Returns a scalar string on success, C<undef> on failure.

=cut

sub getPage {
    my $self = shift;
    my $name = shift;
    my $massageHTML = shift;

    $self->reconnect() || return undef;

    return undef unless defined($name) && ($name =~ /^msg:/);
    my $sql = "SELECT content FROM pages WHERE name = '$name'";
    my $sth = $self->{'dbh'}->prepare($sql);
    return undef unless defined $sth;
    my $rv = $sth->execute;
    if (!defined($rv)) {
	$sth->finish;
	return undef;
    }
    my $val = $sth->fetchrow_arrayref;
    $sth->finish;

    if (defined($massageHTML) && ($massageHTML)) {
	$val->[0] =~ s/\<\/{0,1}html\>//g;
	$val->[0] =~ s/\<\/{0,1}body\>//g;
	$val->[0] =~ s/\<head\>.*<\/head\>//g;
    }

    return $val->[0];
}

    
=head2 requestMovePort(-switch => switch, -port => port, -vlan => <quarantine | unquarantine>)

Submit a port move request into the portMoves database table. A script,
C<portmover.pl> watches that table for new entries and does as instructed. We do
this to avoid deadlocks with a web script moving a port around before the web
server can complete the transaction and close the TCP connection. If a port move
for this switch and port is already pending, then we won't create another. We'll
return success.

Returns 1 on success, 0 on failure.

=cut

sub requestMovePort {
    my $self = shift;
    my ($hn, $port, $vlan, $by) = simple_parms([qw(-switch -port -vlan -by)], @_);

    return 1 if ($self->portMovePending(-switch=>$hn, -port=>$port) == 1);

    my $serverid = hostname;

    my $sql = qq{INSERT INTO portMoves (serverid, rowid, requested, requestedBy, switchIP, switchPort, vlanId, status) VALUES ('$serverid', NULL, NOW(), '$by', '$hn', $port, '$vlan', 'pending')};

    $self->reconnect() || return 0;

    _log "DEBUG", "requestMovePort sql=\"$sql\"\n" if $self->D;

    my $sth = $self->{'dbh'}->do($sql);
    if ( !defined($sth) ) {
	_log "ERROR", "failed to 'do': ".$self->{'dbh'}->errstr."\n";
	return 0;
    }
    return 1;
}


=head2 $rv = portMovePending(-switch => switch, -port => port)

Return 1 if there are any port moves pending. Return 0 if there aren't.

=cut


sub portMovePending {
    my $self = shift;
    my ($hn, $port) = simple_parms([qw(-switch -port)], @_);
    my $sql = qq{SELECT count(*) FROM portMoves WHERE status = 'pending' AND switchIP = '$hn' AND switchPort = '$port'};

    $self->reconnect() || return 0;

    my @rv = $self->{'dbh'}->selectrow_array($sql);
    return 1 if ($rv[0] > 0);
    return 0;
}

=head2 $ar = getPortMoveList($status = 'pending')

Find all 'pending' transactions in the portMoves table. Return them as a reference to
an array that contains a list of array references. The first element of each sub-array
is the rowid. Use this along with C<portMoveCompleted()>
to change the transaction from 'pending' to 'completed'. Returns an ARRAY ref on success,
C<undef> on failure.

Example:

 my $ar = $dbh->getPortMoveList();
 foreach my $row (@$ar) {
      ($serverid, $rowid, $switch, $port, $vlanid) = 
         ($row->[0],
          $row->[1],
          $row->[2],
          $row->[3],
          $row->[4]);
 }

=cut

sub getPortMoveList {
    my $self   = shift;
    my $status = shift;

    $status = 'pending' unless (defined($status) && ($status ne ""));

    # we will only be selecting records that pertain to us.
    # mysql replication requires this for now.

    my $sid = hostname;

    my $sql = qq{SELECT serverid, rowid, switchIP, switchPort, vlanId FROM portMoves WHERE status = '$status' AND serverid = '$sid'};
    
    $self->reconnect() || return undef;

    my $ret = $self->{'dbh'}->selectall_arrayref($sql);
    #print Dumper ($ret), "\n";
    return $ret;
}

=head2 $rv = reconnect(retries = 10, pause = 3)

Check to see if the database connection is still valid. If not, reconnect
C<retries> number of times (default is 3), pausing for C<pause> seconds
between attempts. Returns 1 if the db is connected, 0 if we couldnt reconnect.

=cut

sub reconnect {
    my $self  = shift;
    my $retry = shift;
    my $pause = shift;

    return 1 if $self->{'dbh'}->ping();

    $retry = 10 unless defined($retry && ($retry > 0));
    $pause =  3 unless defined($pause && ($pause > 0));

    while($retry --) {

	_log ("DEBUG", "database connection went away: trying to reconnect $retry\n")
	  if $self->D;

	if ( $self->{'dbh'}->ping() ) {
		_log ("DEBUG", "database connection went away: reconnect successful\n")
		  if $self->D;
		return 1;
	}

	my $dbh2 =  DBI->connect($self->{'s'}, 
				 $self->{'u'}, 
				 $self->{'p'});

	$self->{'dbh'} = $dbh2 if defined($dbh2);

	select (undef, undef, undef, $pause);
    }
    _log ("ERROR", "database connection went away. reconnect failed.\n");
    return 0;
}


=head2 $rv = portMoveCompleted($id, $state)

Given the row-id, set the transaction to completed so we don't do it twice. Returns 1 on 
success, 0 on failure.

You can optionally pass in a state. The default is 'completed'. Another possible state
is 'unmanaged' which means we were asked to move an unmanaged port. We don't want to
mark it as complete, because that would be misleading when troubleshooting and we
don't want to leave it as pending. So we tag it as unmanaged.

=cut

sub portMoveCompleted {
    my $self = shift;
    my $id   = shift;
    my $st   = shift;

    if (defined($st)) {
	if (($st ne "completed") && ($st ne "unmanaged")) {
	    _log "ERROR", "valid states are 'completed' and 'unmanaged'\n";
	    return 0;
	}
    }

    $st = 'completed' unless (defined($st) && ($st eq "unmanaged"));
    
    $self->reconnect() || return 0;


    my $serverid = hostname;

    my $sql = qq{UPDATE portMoves SET status = '$st' WHERE rowid = $id AND serverid = '$serverid'};
    my $rv = $self->{'dbh'}->do($sql);
    if (!defined($rv)) {
	_log "ERROR", "failed to 'do' ($sql): ".$self->{'dbh'}->errstr."\n";
	return 0;
    }
    return 1;
}

=head2 $aref = getNessusPluginList($type = <enabled | disabled | all>)

Retrieve the list of plugins registered with the NetPass database. Returns
an C<array reference> on success, C<undef> on failure.

=cut

sub getNessusPluginList {
    my $self = shift;
    my $type = shift;
    return undef unless ($type =~ /^(enabled|disabled|all)$/);
    my $sql =  qq{SELECT pluginID FROM nessusScans };

    $self->reconnect() || return undef;

    if ($type ne "all") {
	$sql .= qq{where status = '$type'};
    }
    my $pids = $self->{'dbh'}->selectcol_arrayref($sql);
    return $pids if (defined($pids) && (ref($pids) eq "ARRAY"));
    return undef;
}

=head2 $rv = registerHost($mac, $ip, $os, $username)

Insert a new record into the registry or update an existing one. 
This routine should only be called after the host has successfully
passed all checks and has been determined to be clean. For existing
hosts, their record will be updated and their status set to unquarantined.

Returns 1 on success, 0 on failure.

=cut

sub registerHost {
    my $self = shift;
    my ($mac, $ip, $os, $username) = (shift, shift, shift, shift);
    
    $mac = NetPass::padMac($mac); # ensure specific format

    my $sql = qq{insert into register (macAddress, ipAddress, firstSeen, registeredOn, status, message, username, OS, switchIP, switchPort, uqlinkup) values ('$mac', '$ip', NOW(), NOW(), 'unquar', NULL, '$username', '$os', NULL, NULL, 'no')};

    _log("DEBUG", "$mac $ip sql=$sql\n") if $self->D;

    $self->reconnect() || return 0;
    
    my $rv = $self->{'dbh'}->do($sql);
    if (!defined($rv)) {
	if ($self->{'dbh'}->errstr !~ /Duplicate entry/i) {
	    _log("ERROR", "$mac $ip insert failed ".$self->{'dbh'}->errstr."\n");
	    return 0;
	} else {
            _log("ERROR", "$mac $ip insert failed \"".$self->{'dbh'}->errstr."\" .. trying UPDATE\n");

	    # the record already exists.. update it
	    # if we arent given a username and/or OS, then leave the original
	    # values in the table.

	    my $osC; my $unC;
	    $osC = qq{OS='$os', } if defined($os) && ($os ne "") &&  ($os ne "Unknown");
	    $unC = qq{username='$username', } if defined($username) && ($username ne "");

	    $sql = qq{UPDATE register SET ipAddress='$ip', registeredOn=NOW(), status='unquar', message=NULL, $unC $osC switchIP=NULL, switchPort=NULL WHERE macAddress = '$mac'};
	    _log("DEBUG", "$mac $ip sql=$sql\n");
	    $rv = $self->{'dbh'}->do($sql);
	    if (!defined($rv)) {
		_log("ERROR", "$mac $ip insert failed ".$self->{'dbh'}->errstr."\n");
		return 0;
	    }
	}
    }
    return 1;
}

=head2 ($shortName, $info) = getNessusInfo($pluginID)

Retrieve the name and info fields from the nessusScans database table for the given
plugin ID. Returns C<undef> on failure.

=cut

sub getNessusInfo {
    my $self = shift;
    my $pid  = shift;
    my $sql  = qq{SELECT name, info FROM nessusScans WHERE pluginID = $pid};

    $self->reconnect() || return undef;

    my $a    = $self->{'dbh'}->selectrow_arrayref($sql);

    if (defined($a) && (ref($a) eq "ARRAY")) {
	return ($a->[0], $a->[1]);
    }

    _log "ERROR", "select failed: ".$self->{'dbh'}->errstr."\n";
    return undef;
}


=head2 $groups = getUserGroups($username)

Given a username, return their group memberships as a hash reference
so you can write things like

  if ( exists $groups->{'Admin'} ) { ... }

returns C<undef> on failure, returns an empty hash ref if the user
exists, but is not a member of any groups.

=cut

sub getUserGroups {
    my $self = shift;
    my $u    = shift;
    if(defined($u)) {
	$self->reconnect() || return undef;

	my $sql = qq{SELECT groups FROM users WHERE username = '$u'};
	my $a   = $self->{'dbh'}->selectrow_arrayref($sql);
	my $hr = {};
	foreach my $f ( split(/\;/, $a->[0]) ) {
	    $hr->{$f} = 1;
	}
	return $hr;
    }
    return undef;
}

=head2 $groups = getUsers()

Fetch the list of configured users. Returns an array ref on success,
C<undef> on failure.

=cut

sub getUsers {
    my $self = shift;

    $self->reconnect() || return undef;

    my $sql = qq{SELECT username FROM users ORDER BY username};
    my $a   = $self->{'dbh'}->selectcol_arrayref($sql);
    return $a;
}

=head2 $hashref = getUsersAndGroups($username = all)

Fetch the list of configured users and the groups that each user belongs too. This
routine is just here for efficiency to avoid calling GetUsers and GetUserGroups
multiple times. Returns a hash ref on success, C<undef> on failure. Hash
is keyed on username and the value is an array ref containing the list
of groups that the user is in.

=cut

sub getUsersAndGroups {
    my $self = shift;
    my $u    = shift;

    $self->reconnect() || return undef;

    my $sql = qq{SELECT username,groups FROM users };
    $sql .= qq{ WHERE username = '$u' } if (defined($u) && ($u ne ""));
    $sql .= qq{ ORDER BY username};

    my $a   = $self->{'dbh'}->selectall_arrayref($sql);
    my $hr  = undef;
    foreach my $row (@$a) {
	$hr->{$row->[0]} = [ split(/\;/, $row->[1]) ];
    }
    return $hr;
}

=head2 setUsersAndGroups($hashref)

Given a hashref where the keys are the usernames and the values are
array references, update each user (key) and set the user's groups to
the values of the corresponding array. If the array is empty (the user
has no group membership) then the user will be deleted from the
table. Returns 0 on failure, 1 on success.

XX AUDIT

=cut

sub setUsersAndGroups {
    my $self = shift;
    my $uh   = shift;

    foreach my $u (keys %$uh) {
	my $groups = join(';', @{$uh->{$u}});

	$self->reconnect() || return 0;

	if ($groups eq "") {
	    my $sql = qq{DELETE FROM users WHERE username = '$u'};
	    if (!$self->{'dbh'}->do($sql)) {
		_log "ERROR", "failed to delete user $u ".$self->{'dbh'}->errstr."\n";
		return 0;
	    } else {
		_log "INFO", "user $u deleted\n";
	    }
	} else {
	    my $sql = qq{UPDATE users SET groups = '$groups' WHERE username = '$u'};
	    if (!$self->{'dbh'}->do($sql)) {
		_log "ERROR", "failed to change groups to ($groups) for $u ".$self->{'dbh'}->errstr."\n";
		return 0;
	    }
	}
    }
    return 1;
}

=head2 createUserWithGroups($username, $group1, $group2, ...)

Insert a new record into the C<users> table with the given data. Returns 0 
on failure, 1 on success. 

=cut

sub createUserWithGroups {
    my $self = shift;
    my $user = shift;
    my @groups = @_;

    if (!defined($user) || ($user eq "")) {
	_log "ERROR", "no username given\n";
	return 1;
    }

    if ($#groups == -1) {
	_log "ERROR", "no groups given for $user\n";
	return 0;
    }

    $self->reconnect() || return 0;

    my $gs = join(';', @groups);
    my $sql = qq{INSERT INTO users VALUES ('$user', '$gs')};
    _log "DEBUG", "sql=$sql\n";
    if (!$self->{'dbh'}->do($sql)) {
	_log "ERROR", "Failed to create user $user with groups $gs ".$self->{'dbh'}->errstr."\n";
	return 0;
    }
    return 1;
}

=head2 getAppAction ()

Fetch the current list of pending tasks for appStarter to perform. Returns a
reference to an array of array references. 

   [ [ $application, $action, $actionAs] , [ $application, ... ] , ... ] 

=cut

sub getAppAction {
    my $self = shift;

}

=head2 reqAppAction ($proc, $action, $actionas)

Request a particular action be preformed on the specified process.
Returns 0 on failure, 1 on success.

      Example

      $dbh->reqAppAction('netpass', 'restart', '');

=cut

sub reqAppAction {
    my $self     = shift;
    my $proc     = shift;
    my $action   = shift;
    my $actionas = shift;

    if (!defined($proc) || ($proc eq "")) {
        _log "ERROR", "no process name given\n";
        return 0;
    }

    if ($action !~ /start|stop|restart/) {
        _log "ERROR", "action $action is unknown\n";
        return 0;
    }

    $self->reconnect() || return 0;

    my $sql = qq{SELECT status FROM appStarter WHERE application = '$proc'
                 AND status = 'pending' AND action = '$action'};

    my $ins = qq{INSERT INTO appStarter (requested, application,
              action, actionas, status)
              VALUES(FROM_UNIXTIME(?), ?, ?, ?, ?)};

    _log "DEBUG", "sql=$sql\n";
    my $sth = $self->{'dbh'}->prepare($sql);

    if (!$sth->execute()) {
        _log "ERROR", "Failed to query appStarter for $proc ".$self->{'dbh'}->errstr."\n";
        return 0;
    }

    if ($sth->rows() > 0) {
        _log "DEBUG", "Process $proc is already registered for $action\n";
        return 1;
    }
    $sth->finish;

    _log "DEBUG", "sql=$ins\n";
    $sth = $self->{'dbh'}->prepare($ins);

    if (!$sth->execute(time(), $proc, $action, $actionas, 'pending')) {
        _log "ERROR", "Failed to insert $proc into appStarter ".$self->{'dbh'}->errstr."\n";
        return 0;
    }

    $sth->finish;

    return 1;
}

=head2 $pass = getPasswd($username)

Lookup the password for a given user in the local database. Returns
a scalar on success and C<undef> on failure.

=cut

sub getPasswd {
	my $u = shift;
	my $s = "SELECT password FROM passwd WHERE username = ".$self->{'dbh'}->quote($u);
	my $x = $self->{'dbh'}->selectrow_arrayref($sql);
	return $x->[0] if ($#x);
	return undef;
}

=head2 0 | 1 = setPasswd($username, $password)

Set the password for the given user (creating the user if it does not exist)
in the local database. Returns 1 on success.

=cut

sub setPasswd {
	my ($u, $p) = (shift, shift);
	my $s = "INSERT INTO passwd (username, password) VALUES ('$u', ENCRYPT('$p', 'xx'))";
	if ($self->{'dbh'}->do($sql) == 1) {
		return 1;
	}
	my $s = "UPDATE passwd SET password = ENCRYPT('$p', 'xx') WHERE username = '$u'";
	if ($self->{'dbh'}->do($sql) == 1) {
		return 1;
	}
	return 0;
}

=head2 0 | 1 = deletePasswd($username)

Delete the user from the passwd table. Returns 1 on success.

=cut

sub deletePasswd {
	my ($u, $p) = (shift, shift);
	my $s = "DELETE FROM passwd WHERE username = '$u'";
	if ($self->{'dbh'}->do($sql) == 1) {
		return 1;
	}
	return 0;
}

=head2 audit(severity => $sev,  $mac => $mac, ip => $ip, user => $username, $msg, ...)

Submit an entry into the audit table.

=over 4

=item severity

 DEBUG | ALERT | CRITICAL | ERROR | WARNING | NOTICE | INFO

 default if not specified is INFO

=item mac

 mac address passed as number (no colons, etc). 

=item ip

 the ip address of the client. 

=item user

 the username the client is logged in as.

=item msg

 an array of messages. they will be joined with spaces before insertion into the
 database. if there is more than one element in the array, and the first element
 has ANY percent signs in it, then we assume you want us to feed it thru sprintf.

=back

 Example

 $dbh->audit(-mac => 112233445566, -ip => '1.2.3.4', -user => 'foo',
             "this user", "did something");

 results in "this user did something" being inserted.

 $dbh->audit(-mac => 112233445566, -ip => '1.2.3.4', -user => 'foo',
             "this user %s something", "did");

 results in "this user did something" being inserted.
 
=cut

sub audit {
    my $self = shift;

    my $parms = parse_parms({
			     -parms => \@_,
			     -defaults => {
					   -severity  => "INFO",
					   -mac       => undef,
					   -ip        => undef,
					   -user      => undef,
					   -msg       => [],
					  }
			    }
			   );
    die Carp::longmess (Class::ParmList->error) if (!defined($parms));

    my ($s, $m, $i, $u, $msg) = $parms->get('-severity', '-mac', '-ip', '-user', '-msg');

    $m = 0 if ($m =~ /REMOTE/i);

    use Sys::Hostname;

    my $sql = "INSERT INTO audit ( ts, server, "; 

    $sql .= "username, " if defined($u);
    $sql .= "ipAddress, " if defined($i);
    $sql .= "macAddress, " if defined($m);
    $sql .= "severity, " if defined($s);
    
    my (@loc) = caller(1);
    my $loc = sprintf("%s::%s [%d]", $loc[0], $loc[3], $loc[2]);

    $sql .= "location, " if defined($loc);

    my $msg2;
    if ( ($msg->[0] =~ /%/) && ($#$msg > 0) ) {
        $msg2 = sprintf($msg->[0], $msg->[1..$#$msg]);
    } else {
	$msg2 = join(' ', @$msg);
    }

    $sql .= "message ) VALUES ( NOW(), ".$self->{'dbh'}->quote(hostname).", ";
    $sql .= "'$u', " if defined($u);
    $sql .= "'$i', " if defined($i);
    $sql .= "'$m', " if defined($m);
    $sql .= "'$s', " if defined($s);
    $sql .= "'$loc', " if defined($loc);
    $sql .= "'$msg2' )";

    #_log "DEBUG", "audit $sql\n";

    $self->reconnect() || return 0;


    if (! $self->{'dbh'}->do($sql) ) {
	_log "ERROR", "failed to submit audit entry ".$self->{'dbh'}->errstr." ($sql)\n";
	return 0;
    }

    return 1;
}
    
sub commit {
	my $self = shift;
	$self->reconnect() || return 0;
	return $self->{'dbh'}->commit;
}

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: DB.pm,v 1.6 2004/12/31 19:09:09 jeffmurphy Exp $

1;
