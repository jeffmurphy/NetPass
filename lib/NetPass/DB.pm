# $Header: /tmp/netpass/NetPass/lib/NetPass/DB.pm,v 1.36 2005/04/29 00:30:07 jeffmurphy Exp $

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

sub disconnect {
	my $self = shift;
	$self->{'dbh'}->disconnect  if defined $self->{'dbh'};
}

sub D {
    my $self = shift;

    return $self->{'D'};
}

=head1 SYNOPSIS

This is the interface for accessing the NetPass database. All SQL should be
located in this module and abstracted away from higher-level modules.

=head1 METHODS

=head2 NetPass::DB::new(connstr, user, password, debug)

Create a new NetPass DB object and connect to the underlying
database (using DBI) with the specified details. If debug is 
defined and non-zero, log debugging information using NetPass::LOG;

The NetPass architecture specifies that the database be on the local
machine. The connstr, user and password are optional. We will assume
"dbi:mysql:database=netpass", "root" and "" as defaults. 

=cut

sub new {
    my ($class, $self) = (shift, {});
    my ($s, $u, $p, $d) = (shift, shift, shift, shift);

    $s ||= "dbi:mysql:database=netpass";
    $u ||= "root";
    $p ||= "";

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

=back

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

=back

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

=head2 $rv = getRegisterInfo(-mac => mac, -macs => [], -ip => ip, -ips => [])

This routine will get the registered info on an already registered MAC. Returns:

=over 4

=item C<HASHREF> 

containing keys that correspond to the macAddresses given.
values of C<HASHREF> are C<HASHREF>s containing keys: ipAddress, lastSeen,
registeredOn, status, message, username, OS, switchIP, switchPort, uqlinkup.

If the Mac is not registered, it won't be in the HASHREF returned.  

on success

=item "invalid parameters" 

if routine was called improperly.

=item "db failure" 

some sort of SQL failure

=back

=cut

sub getRegisterInfo {
    my $self = shift;
    my $kfield;

    $self->reconnect() || return undef;

    my $parms = parse_parms({
			     -parms    => \@_,
			     -legal    => [ qw(-mac -macs -ip -ips) ],
			     -defaults => { -mac  => '',
					    -macs => [],
					    -ip   => '',
					    -ips  => []
					  }
			    }
			   );

    return "invalid params\n".Carp::longmess(Class::ParmList->error) if (!defined($parms));
    
    my ($mac, $macs, $ip, $ips) = $parms->get('-mac', '-macs', 
					      '-ip', '-ips');

    my $sql = "SELECT macAddress, ipAddress, lastSeen, registeredOn, status, message, username, OS, switchIP, switchPort, uqlinkup FROM register WHERE ";
    if ($mac ne "") {
	    $sql .= " macAddress = ".$self->dbh->quote($mac);
	    $kfield = "macAddress";
    }
    elsif ($ip ne "") {
	    $sql .= " ipAddress = ".$self->dbh->quote($ip);
	    $kfield = "ipAddress";
    }
    elsif ($#{$macs} > -1) {
	    $sql .= join (" OR ", (map (" macAddress = ".$self->dbh->quote($_), @{$macs})));
	    $kfield = "macAddress";
    }
    elsif ($#{$ips} > -1) {
	    $sql .= join (" OR ", (map (" ipAddress = ".$self->dbh->quote($_), @{$ip})));
	    $kfield = "ipAddress";
    }

    my $a    = $self->{'dbh'}->selectall_hashref($sql, $kfield);

    return $a if (defined($a) && (ref($a) eq "HASH"));

    _log "ERROR", "select failed: ".$self->{'dbh'}->errstr."\n";
    return undef;
}

=head2 $msg = getPageList(-name => $name, -group => '')

Given a name (SQL wildcards OK) and a group, look up the page list 
that matches. If 'group' isn't specified, all is assumed. 


Returns:

HASHREF->{'name'}->[]
       ->{'group'}->[]   on success
"invalid parameters"     on failure
"db failure"             on failure

=cut

sub getPageList {
    my $self = shift;
    my $parms = parse_parms({
			     -parms => \@_,
			     -required => [ qw() ],
			     -defaults => {
					   -name   => '',
					   -group  => ''
					  }
			    }
			   );

    if (!defined($parms)) {
	    return "invalid parameters: ".
		 Carp::longmess (Class::ParmList->error)."\n";
    }
    
    my ($name, $group) = $parms->get('-name', '-group');

    my $sql = "SELECT network, name FROM pages ";
    if ($name ne "") {
           $sql .= " WHERE name LIKE ".$self->dbh->quote($name."%");
    } 
    if ($group ne "") {
	    if ($name ne "") {
		    $sql .= " AND ";
	    } else {
		    $sql .= " WHERE ";
	    }
	    if ($group =~ /%/) {
		    $sql .= " network LIKE ".$self->dbh->quote($group);
	    } else {
		    $sql .= " network = ".$self->dbh->quote($group);
	    }
    }

    $sql .= " ORDER BY name ASC ";
    $self->reconnect() || return undef;

    my $ar = $self->dbh->selectall_arrayref($sql);

    if (defined($ar)) {
         my $rv = { 'name' => [], 'group' => [] };

         foreach my $row (@$ar) {
                push @{$rv->{'name'}}, $row->[1];
                push @{$rv->{'group'}}, $row->[0];
         }
         return $rv;
    }

    return "db failure (sql=$sql) ". $self->dbh->errstr;
}


=head2 $msg = getPage(-name => $name, -nohtml => $massage, -ip => '', -group => '')

Give a page name (e.g. 'msg:welcome') retrieve the page from the database. If
C<massage> is "1", then we'll strip any C<head>, C<body> and C<html> tags
(openning and closing) out of the HTML before returning it. This is useful
when we want to embed the page inside of another page.

Using the IP parameter, we can lookup the network and determine if it's 
part of a group. If it is, we will look up the page for that group. If 
that doesn't exist, we'll look up the page for the network. If that
does not exist, we'll use the default page.

If we are given the group explicitly, we'll use it.

Returns a scalar string on success, C<undef> on failure.

=cut

sub getPage {
    my $self = shift;

    my $parms = parse_parms({
			     -parms => \@_,
			     -required => [ qw(-name -npcfg) ],
			     -defaults => {
					   -name   => '',
					   -npcfg  => undef,
					   -ip     => 'default',
					   -nohtml => 0,
					   -group  => ''
					  }
			    }
			   );

    if (!defined($parms)) {
	    _log("ERROR", "invalid parameters: ".
		 Carp::longmess (Class::ParmList->error)."\n");
	    return undef;
    }
    
    my ($name, $massageHTML, $ip, $npcfg, $group) = $parms->get('-name', '-nohtml', '-ip', '-npcfg',
								'-group');

    $self->reconnect() || return undef;

    return undef unless defined($name) && ($name =~ /^msg:/);

    my $sql  = "SELECT content FROM pages WHERE name = ".$self->dbh->quote($name);
    my $page = '';

    if ($group ne "") {
	    $sql .= " AND network = ".$self->dbh->quote($group);
	    $page = $self->getPage2($sql);
	    goto done;
    } 
    elsif ($ip eq "default") {
	    $sql .= " AND network = 'default' ";
	    $page = $self->getPage2($sql);
    } 
    else {
	    # if we were given an IP, then look up the corresponding
	    # network. 

	    if (defined($ip) && ($ip ne "")) {
		    my $network = $npcfg->getMatchingNetwork(-ip => $ip);
		    my $netgroup;
		    if ($network =~ /\//) {
			    $netgroup = $npcfg->getNetgroup($network);
			    if ($netgroup ne "") {
				    $page = $self->getPage2($sql. " AND network = ".$self->dbh->quote($netgroup));
				    goto done if defined($page);
			    }
			    $page = $self->getPage2($sql. " AND network = ".
						    $self->dbh->quote($network));
			    goto done if defined($page);
		    }
	    }
	    $page = $self->getPage2($sql. " AND network = 'default'");
    }

  done:;
    if (defined($massageHTML) && $massageHTML) {
	    $page =~ s/\<\/{0,1}html\>//g;
	    $page =~ s/\<\/{0,1}body\>//g;
	    $page =~ s/\<head\>.*<\/head\>//g;
    }
    return $page;
}

sub getPage2 {
	my $self        = shift;
	my $sql         = shift;

	my $sth = $self->{'dbh'}->prepare($sql);
	return undef unless defined $sth;

	my $rv = $sth->execute;
	if (!defined($rv)) {
		$sth->finish;
		return undef;
	}
	my $val = $sth->fetchrow_arrayref;
	$sth->finish;
	
	return $val->[0];

}


=head2 setPage(-name => $name, -group => '', -content => '', -noupdate => 0)

Give a page name (e.g. 'msg:welcome') and a group ("Law School" or "128.205.10.0/24") 
and some content, save the page to the pages table. "noupdate" means if the INSERT 
fails, don't try an UPDATE. Useful if you want to save a copy of a page, but want
to throw an error if the user forgets to change the name or group.

If the page exists, it is updated, if not, it is created (unless noupdate=1)

Returns

                   0 on success
"invalid parameters" on failure
"db failure"         on failure


=cut

sub setPage {
    my $self = shift;

    my $parms = parse_parms({
			     -parms => \@_,
			     -required => [ qw(-name -content) ],
			     -defaults => {
					   -name   => '',
					   -group  => 'default',
					   -content => '',
					   -noupdate => 0
					  }
			    }
			   );

    if (!defined($parms)) {
	    return "invalid parameters: ".Carp::longmess (Class::ParmList->error);
    }
    
    my ($name, $group, $content, $noupdate) = $parms->get('-name', '-group', '-content', '-noupdate');

    $self->reconnect() || return "db failure";

    my $sql  = "INSERT INTO pages (content, network, name) VALUE (";
    $sql .= $self->dbh->quote($content) . ",";
    $sql .= $self->dbh->quote($group)   . ",";
    $sql .= $self->dbh->quote($name)    . ")";

    my $rv = $self->dbh->do($sql);

    if (!defined($rv)) {
	    if ($noupdate == 0) {
		    $sql  = "UPDATE pages SET content = ".$self->dbh->quote($content);
		    $sql .= " WHERE network = ".$self->dbh->quote($group);
		    $sql .= " AND name = ".$self->dbh->quote($name);
		    $rv = $self->dbh->do($sql);
	    }
	    if (!defined($rv) || ($rv == 0)) {
		    return "db failure ".$self->dbh->errstr;
	    }
    }
    return 0;
}


=head2 delPage(-name => $name, -group => '')

Give a page name (e.g. 'msg:welcome') and a group ("Law School" or "128.205.10.0/24") 
delete it from the database.

Returns

                   0 on success
"invalid parameters" on failure
"db failure"         on failure


=cut

sub delPage {
    my $self = shift;

    my $parms = parse_parms({
			     -parms => \@_,
			     -required => [ qw(-name) ],
			     -defaults => {
					   -name   => '',
					   -group  => 'default'
					  }
			    }
			   );

    if (!defined($parms)) {
	    return "invalid parameters: ".Carp::longmess (Class::ParmList->error);
    }
    
    my ($name, $group) = $parms->get('-name', '-group');

    $self->reconnect() || return "db failure";

    my $sql  = "DELETE FROM pages WHERE name = ";
    $sql .= $self->dbh->quote($name) . " AND network = ";
    $sql .= $self->dbh->quote($group);

    my $rv = $self->dbh->do($sql);
    if (!defined($rv)) {
	    return "db failure ".$self->dbh->errstr;
    }
    return 0;
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

=head2 $aref = getSnortRules($type = <enabled | disabled | all>)

Retrieve snort rules registered in the NetPass database. Returns
an C<array reference> on success, C<undef> on failure.

=cut

sub getSnortRules {
    my $self = shift;
    my $type = shift;

    return undef unless ($type =~ /^(enabled|disabled|all)$/);
    my $sql =  qq{SELECT rule FROM snortRules };

    $self->reconnect() || return undef;

    if ($type ne "all") {
        $sql .= qq{where status = '$type'};
    }

    my $rules = $self->{'dbh'}->selectcol_arrayref($sql);
    return $rules if (defined($rules) && (ref($rules) eq "ARRAY"));
    return undef;
}

=head2 $rule = getSnortRuleEntry(sid)

Retrieve the snort rule entry with id equal to sid. Returns a HASH ref
of all the columns in the database for that row on success, C<undef> on failure.

=cut

sub getSnortRuleEntry {
    my $self = shift;
    my $sid  = shift;

    return undef unless $sid =~ /\d+/;
    $self->reconnect() || return undef;

    my $query = "SELECT * FROM snortRules WHERE snortID = $sid";
    my $href  = $self->{'dbh'}->selectrow_hashref($query);

    return $href if (defined($href) && (ref($href) eq "HASH"));
    return undef;
}

=head2 $rv = addSnortRuleEntry(-rule => $rule -user => $user -desc => $desc)

Add the specified rule $rule to the snortRules table with description $desc and 
addedBy equal to $user. If rule already exists in database the entry
will be updated and revisions of the rule will be checked. Returns C<true> on
success, error description on failure.

=cut

sub addSnortRuleEntry {
    my $self = shift;
    my $data = {};

    $self->reconnect() || return undef;
    my $parms = parse_parms({
                             -parms    => \@_,
                             -legal    => [ qw(-rule -user -desc) ],
                             -defaults => { -rule   => '',
                                            -user   => '',
                                            -desc   => ''
                                          }
                            }
                           );

    return "invalid params\n".Carp::longmess(Class::ParmList->error) if (!defined($parms));
    my ($rule, $user, $desc) = $parms->get('-rule', '-user', '-desc');

    if ($rule =~ /sid\:(\d+)\;/) {
	$data->{sid} = $1;
    } else {
	return "undefined sid";
    }

    if ($rule =~ /msg\:\"([\w-]+)\s+([^";]+)\"\;/) {
	$data->{category} = $1;
	$data->{name}     = $2;
    } else {
	return "unknown msg";
    }

    if ($rule =~ /rev\:(\d+)\;/) {
	$data->{rev} = $1;
    } else {
	return "unknown rev";	
    }

    if ($rule =~ /classtype\:([^;]+)\;/) {
	$data->{classtype} = $1;
    } else {
	return "unknown classtype";
    }

    if ($rule =~ /reference\:([^;]+)\;/) {
	$data->{reference} = $1;
    }

    my $check = "SELECT revision FROM snortRules WHERE snortID = ".$data->{sid};
    my($rev)  = $self->dbh->selectrow_arrayref($check);

    if (defined $rev && $rev->[0] >= $data->{rev}) {
	return "sid ".$data->{sid}." with rev = $rev->[0] exists";
    }

    my $sth;
    my $rv;
    my $time = time();

    if (defined $rev && $rev->[0] > 0) {
	my $sql = qq{UPDATE snortRules SET name         = ?,
                                           category     = ?,
                                           classtype    = ?,
                                           description  = ?,
                                           rule         = ?,
                                           lastModifiedBy = ?,
                                           lastModifiedOn = FROM_UNIXTIME(?),
                                           revision     = ?,
                                           other_refs   = ?
                                           WHERE snortID = ?};

	$sth = $self->dbh->prepare($sql);
	$rv  = $sth->execute(
                             $data->{name},
                             $data->{category},
                             $data->{classtype},
                             $desc,
                             $rule,
			     $user,
			     $time,
                             $data->{rev},
                             $data->{reference},
			     $data->{sid}
	      		    );
    } else {
	my $sql = qq{INSERT INTO snortRules (
                                             snortID, name, category, classtype,
                                             description, rule, addedBy,lastModifiedBy,
                                             revision, other_refs
                                            ) VALUES (?,?,?,?,?,?,?,?,?,?)};

	$sth = $self->dbh->prepare($sql);
	$rv  = $sth->execute(
                             $data->{sid},
                             $data->{name},
                             $data->{category},
                             $data->{classtype},
                             $desc,
                             $rule,
			     $user,
			     $user,
                             $data->{rev},
                             $data->{reference}
			    );
    }

    if (!$rv) {
	return "unable to insert rule into database ".$self->dbh->errstr;
    }
    $sth->finish;

    return 1;   
}

=head2 $rv = deleteSnortRule(sid)

Delete the snort rule with Snort ID sid. Returns C<true> on success
C<undef> on failure.

=cut

sub deleteSnortRule {
    my $self = shift;
    my $sid  = shift;

    return undef unless $sid =~ /\d+/;
    $self->reconnect() || return undef;

    my $query = "DELETE FROM snortRules WHERE snortID = ?";
    my $sth = $self->dbh->prepare($query);

    if (!$sth->execute($sid)) {
	_log("ERROR", "Unable to delete Snort Rule $sid from database");
	return undef;
    }

    return 1;
}

=head2 $aref = getSnortIDs()

Returns an ARRAY ref of all the snortIDs in the database. Returns
C<undef> on failure.

=cut

sub getSnortIDs {
    my $self = shift;
    my @sids;

    $self->reconnect() || return undef;

    my $query = "SELECT distinct(snortID) FROM snortRules order by snortID";
    my $aref = $self->dbh->selectall_arrayref($query);

    if (!defined($aref) || ref($aref) ne 'ARRAY') {
	_log("ERROR", "Unable to retrieve snortIDs from database");
	return undef;
    }

    return [map($_->[0], @$aref)];
}

=head2 $history = getClientHistory(-mac => $mac)

Given a mac address retrieve all the corresponding Client History records
from the clientHistory table. Returns a HASHREF of all the fields in the
table on success the hash organized as shown below, C<undef> on failure.

 $history->{'dt'}->{'username'}
 $history->{'dt'}->{'macAddress'}
 $history->{'dt'}->{'notes'}

=cut

sub getClientHistory {
    my $self = shift;

    $self->reconnect() || return undef;

    my $parms = parse_parms({
                             -parms    => \@_,
                             -legal    => [ qw(-mac) ],
                             -defaults => { -mac  => '' }
                            }
                           );

    return "invalid params\n".Carp::longmess(Class::ParmList->error) if (!defined($parms));

    my ($mac) = $parms->get('-mac');
    my $sql   = "SELECT * FROM clientHistory WHERE macAddress = ".$self->dbh->quote($mac);

    my $h    = $self->dbh->selectall_hashref($sql, "dt");

    return $h if (defined($h) && (ref($h) eq "HASH"));

    _log "ERROR", "select failed: ".$self->{'dbh'}->errstr."\n";
    return undef;
}

=head2 $rv = addClientHistory(-mac => $mac, -user => $username, -notes => $notes)

Create a Client History record for $mac submitted by $username recording history
described in $notes. Returns C<true> on success, C<undef> on failure.

=cut

sub addClientHistory {
    my $self = shift;

    $self->reconnect() || return undef;

    my $parms = parse_parms({
                             -parms    => \@_,
                             -legal    => [ qw(-mac -user -notes) ],
                             -defaults => { -mac   => '',
					    -user  => '',
					    -notes => ''
					  }
                            }
                           );

    return "invalid params\n".Carp::longmess(Class::ParmList->error) if (!defined($parms));

    my ($mac, $user, $notes) = $parms->get('-mac', '-user', '-notes');
    my $sql = "INSERT INTO clientHistory (macAddress, username, dt, notes) VALUES(?,?,FROM_UNIXTIME(?),?)";

    my $sth = $self->dbh->prepare($sql);
    my $rv  = $sth->execute($mac, $user, time(), $notes);

    if (!$rv) {
	_log "ERROR", "insert failed: ".$self->{'dbh'}->errstr."\n";
	return undef;
    }

    return 1;
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

    my $sql = qq{insert into register (macAddress, ipAddress, lastSeen, registeredOn, status, message, username, OS, switchIP, switchPort, uqlinkup) values ('$mac', '$ip', NOW(), NOW(), 'unquar', NULL, '$username', '$os', NULL, NULL, 'no')};

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

=head2 ($shortName, $info, $description) = getNessusInfo($pluginID)

Retrieve the name, info and description fields from the nessusScans database table for 
the given plugin ID. Returns C<undef> on failure.

=cut

sub getNessusInfo {
    my $self = shift;
    my $pid  = shift;
    my $sql  = qq{SELECT name, info, description FROM nessusScans WHERE pluginID = $pid};

    $self->reconnect() || return undef;

    my $a    = $self->{'dbh'}->selectrow_arrayref($sql);

    if (defined($a) && (ref($a) eq "ARRAY")) {
	return ($a->[0], $a->[1], $a->[2]);
    }
    
    _log("ERROR", "select failed: ".$self->{'dbh'}->errstr."\n");
    return undef;
}

=head2 ($shortName, $info, $description) = getSnortInfo($pluginID)

Retrieve the name, info and description fields from the snortRules database table for 
the given snort ID. Returns C<undef> on failure.

=cut

sub getSnortInfo {
    my $self = shift;
    my $pid  = shift;
    my $sql  = qq{SELECT name, info, description FROM snortRules WHERE snortID = $pid};

    $self->reconnect() || return undef;

    my $a    = $self->{'dbh'}->selectrow_arrayref($sql);

    if (defined($a) && (ref($a) eq "ARRAY")) {
	return ($a->[0], $a->[1], $a->[2]);
    }
    
    _log("ERROR", "select failed: ".$self->{'dbh'}->errstr."\n");
    return undef;
}

=head2 addGroupToUser($username)

A convenience routine. 

Returns:

               0 on success
"nosuch user"    named user does not exist
"invalid params" routine called improperly
"db failure"     on error

=cut

sub addGroupToUser {
    my $self  = shift;
    my $user  = shift;

    return "invalid params" if (!defined($user) || ($user eq ""));
    return "invalid params" if ($#_ == -1);

    my $groups = $self->getUserGroups($user);
    return "nosuch user" if (!defined($groups));

    while(my $group = shift) {
          $groups->{$group} = 1;
    }

    my $uh;
    $uh->{$user} = [ keys %$groups ];
    
    return $self->setUsersAndGroups($uh);
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

	my $sql = qq{SELECT groups FROM users WHERE username = }.$self->dbh->quote($u);
	my $a   = $self->{'dbh'}->selectrow_arrayref($sql);
	return $self->decomposeGroupMembership($a->[0]);
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
multiple times. 

Returns 

HASHREF         on success
"db failure"    on failure

Hash is keyed on username and looks like this:

 $hr->{'joesmith'}->{'NetAdmin'};
 $hr->{'joesmith'}->{'Test Network'} = [ 'NetAdmin' ];
 $hr->{'joesmith'}->{'128.205.10.0/24'} = [ 'Reports', 'Users' ];

The above shows joesmith is a NetAdmin. Specifically, he's a NetAdmin
for the "Test Network" group of networks. He's also has access to
Reports and Users screens for the "128.205.10.0/24" network.

=cut

# go from NetAdmin;Test Network+NetAdmin;128.205.10.0/24+Reports+Users
# to the hash

sub decomposeGroupMembership {
	my $self = shift;
	my $gm   = shift;
	return {} unless ($gm ne "");
	my $rv = {};
	foreach my $c (split(/\;/, $gm)) {
		if ($c =~ /^([^\+]+)\+(.*)/) {
			my $network   = $1;
			my $netgroups = $2;
			$rv->{$network} = [ split(/\+/, $netgroups) ];
		} else {
			$rv->{$c} = 1;
		}
	}
	return $rv;
}

# go from the hash back to 
# NetAdmin;Test Network+NetAdmin;128.205.10.0/24+Reports+Users

sub composeGroupMembership {
	my $self = shift;
	my $gh   = shift;
	return "" unless (ref($gh) eq "HASH");

	my $gstring = "";
	foreach my $g (sort keys %$gh) {
		if (ref($gh->{$g}) eq "ARRAY") {
			$gstring .= "$g+".join('+', @{$gh->{$g}}).";";
		} else {
			$gstring .= "$g;";
		}
	}
	$gstring =~ s/;$//;
	return $gstring;
}

sub getUsersAndGroups {
    my $self = shift;
    my $u    = shift;

    $self->reconnect() || return undef;

    my $sql = qq{SELECT username,groups FROM users };
    $sql .= qq{ WHERE username = '$u' } if (defined($u) && ($u ne ""));
    $sql .= qq{ ORDER BY username};

    my $a   = $self->{'dbh'}->selectall_arrayref($sql);
    my $hr  = {};

    if (defined($a)) {
	    foreach my $row (@$a) {
		    $hr->{$row->[0]} = $self->decomposeGroupMembership($row->[1]);
	    }
    } else {
	    _log("ERROR", "db failure: sql=$sql err=".$self->dbh->errstr);
    }
    return $hr;
}

=head2 setUsersAndGroups(-userhash => $hashref, -whoami => username, -ip => ipaddr)

Given a hashref that looks just like what getUsersAndGroups returns,
update each user (key) and set the user's groups and ACL. If the ACL is
empty, remove the user from the table.

Returns 

           0 on success
"db failure" on failure

=cut

sub setUsersAndGroups {
    my $self   = shift;

    my $parms = parse_parms({
			     -parms => \@_,
			     -required => [ qw(-userhash -whoami -ip) ],
			     -defaults => {
					   -userhash => undef,
					   -whoami   => '',
					   -ip       => ''
					  }
			    }
			   );

    return "invalid parameters\n".Carp::longmess (Class::ParmList->error) 
      if (!defined($parms));
    
    my ($uh, $whoami, $myip) = $parms->get('-userhash', '-whoami', '-ip');

    $whoami ||= "unknown";
    $myip   ||= "unknown";

    foreach my $u (keys %$uh) {
	    my $groups = $self->composeGroupMembership($uh->{$u});
	    my $sql = '';

	    $self->reconnect() || return "db failure database down";
	    
	    # if groups contains no ACLs, then delete the user.
	    if ($groups !~ /\+/) {
		    $sql = qq{DELETE FROM users WHERE username = '$u'};
		    if (!$self->{'dbh'}->do($sql)) {
			    _log("ERROR", "$whoami failed to delete user $u ".$self->{'dbh'}->errstr."\n");
			    return "db failure ".$self->{'dbh'}->errstr;
		    } else {
			    _log("INFO", "$whoami deleted user $u\n");
			    $self->deletePasswd($u);
			    $self->audit(-ip => $myip, -user => $whoami, -severity => 'ALERT',
					 -msg => [ qq{user $u deleted} ]);
		    }
	    } else {
		    my $ugh = $self->getUserGroups($u);
		    if (!defined($ugh)) {
			    # user doesnt exist
			    $sql = "NSERT INTO users (username, groups) VALUES (";
			    $sql .= $self->dbh->quote($u). ",";
			    $sql .= $self->dbh->quote($groups). ")";
			    if (!$self->dbh->do($sql)) {
				    _log("ERROR", "failed to add user: $u sql=$sql err=".$self->dbh->errstr);
				    return "db failured ".$self->dbh->errstr;
			    }
			    _log ("INFO", qq{$whoami added user $u groups "$groups"});
			    $self->audit(-ip => $myip, -user => $whoami, -severity => 'ALERT',
					 "user added: $u groups: $groups");
		    } 

		    else {
			    # user already exists

			    my $groups_orig = $self->composeGroupMembership($ugh);
			    if ($groups ne $groups_orig) {
				    $sql  = qq{UPDATE users SET groups = };
				    $sql .= $self->dbh->quote($groups);
				    $sql .= " WHERE username = ".$self->dbh->quote($u);
				    if (!$self->{'dbh'}->do($sql)) {
					    _log("ERROR", 
						 "failed to change groups to ($groups) for $u ".$self->{'dbh'}->errstr."\n");
					    return "db failure ".$self->{'dbh'}->errstr;
				    }
				    _log ("INFO", qq{$whoami modified user $u groups "$groups_orig" to "$groups"});
				    $self->audit(-ip => $myip, -user => $whoami, -severity => 'ALERT',
						 "groups for $u changed from: $groups_orig to: $groups");
			    }
		    }
	    }
    }

    return 0;
}

=head2 createUserWithGroups($username, $group1, $group2, ...)

Insert a new record into the C<users> table with the given data. 


Returns 

               0 on success
"invalid params" on failure
"db failure"     on failure

=cut

sub createUserWithGroups {
    my $self = shift;
    my $user = shift;
    my @groups = @_;

    if (!defined($user) || ($user eq "")) {
	_log("ERROR", "no username given\n");
	return "invalid params (no username given)";
    }

    if ($#groups == -1) {
	_log("ERROR", "no groups given for $user\n");
	return "invalid params (no groups given)";
    }

    $self->reconnect() || return "db failure";

    my $gs = join(';', @groups);
    my $sql = qq{INSERT INTO users VALUES ('$user', '$gs')};
    _log("DEBUG", "sql=$sql\n");
    if (!$self->{'dbh'}->do($sql)) {
	_log("ERROR", "Failed to create user $user with groups $gs ".$self->{'dbh'}->errstr."\n");
	return "db failure ". $self->{'dbh'}->errstr;
    }
    return 0;
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
	my $self = shift;
	my $u    = shift;
	my $s    = "SELECT password FROM passwd WHERE username = ".$self->{'dbh'}->quote($u);
	my $x    = $self->{'dbh'}->selectrow_arrayref($s);
	return $x->[0] if ($#$x > -1);
	_log("ERROR", "failed to get passwd for $u: ".$self->dbh->errstr);
	return undef;
}

=head2 0 | 1 = setPasswd($username, $password)

Set the password for the given user (creating the user if it does not exist)
in the local database. Returns 1 on success.

=cut

sub setPasswd {
	my $self = shift;
	my ($u, $p) = (shift, shift);
	my $s = "INSERT INTO passwd (username, password) VALUES ('$u', ENCRYPT('$p', 'xx'))";
	if (!defined($self->{'dbh'}->do($s))) {
		$s = "UPDATE passwd SET password = ENCRYPT('$p', 'xx') WHERE username = '$u'";
		if ( !defined($self->{'dbh'}->do($s)) ) {
			_log("ERROR", "failed to set password for $u: ".$self->dbh->errstr);
			return 0;
		}
	}
	return 1;
}

=head2 0 | 1 = deletePasswd($username)

Delete the user from the passwd table. Returns 1 on success.

=cut

sub deletePasswd {
	my $self = shift;
	my ($u, $p) = (shift, shift);
	my $s = "DELETE FROM passwd WHERE username = '$u'";
	if ($self->{'dbh'}->do($s) == 1) {
		return 1;
	}
	_log("ERROR", "failed to delete password for $u: ".$self->dbh->errstr);
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


=head2 addResult(-mac => $mac, -type => [nessus|snort|manual|...], -id => $id)

Submit an entry into the results table. If the type is "manual" then you need to 
specify a specific message to show the user. Otherwise you specify the Snort or Nessus ID 
and NetPass will correlate that with the Nessus and Snort configuration data to derive the 
appropriate message to display for the user.

=over 4

=item mac

 MAC address passed as number (no colons, etc). We'll pad it out for you
 with leading zeros if needed.

=item type

 nessus - this is the result of a Nessus scan
 snort  - this is the result of a Snort hit
 manual - this is someone being manually quarantined (DMCA complaint, etc)
 ...    - the test type field is a 32 character text field. You can specify
          anything you like, the above types are pre-defined by NetPass.

=item id 

 The ID if the Nessus scan or Snort rule that matched for this client. If "type"
 is "manual" then this parameter would be something like "msg:dmca".

=back

 Example

 $dbh->addResult(-mac => 112233445566, -type => 'nessus', -id => 12219);
 $dbh->addResult(-mac => 112233445566, -type => 'manual', -id => 'msg:dmca');

 Returns

 0                    on success (so "addResult && die" should work)
 "invalid manual id"  if type = "manual" and msg does not exist 
 "invalid mac"        if mac not registered or is "remote"
 "invalid type"       if type is unknown
 "invalid parameters" if the routine was called improperly
 "duplicate result"   this result is already submitted and is "pending"
 "db failure"         if there was a DB failure

=cut

sub addResult {
    my $self = shift;

    my $parms = parse_parms({
			     -parms => \@_,
			     -required => [ qw(-mac -type -npcfg) ],
			     -defaults => {
					   -mac       => undef,
					   -type      => '',
					   -id        => '',
					   -force     => 0,
                                           -npcfg     => ''
					  }
			    }
			   );

    return "invalid parameters\n".Carp::longmess (Class::ParmList->error) 
      if (!defined($parms));
    
    my ($m, $t, $i, $f, $npcfg) = $parms->get('-mac', '-type', '-id', '-force', '-npcfg');
    
    if ($m =~ /REMOTE/) {
	    _log("WARNING", "cant add result for remote client\n");
	    return "invalid mac";
    }

    $m = NetPass::padMac($m);

    if ($m !~ /^[0-9a-f]+$/) {
	    _log("WARNING", "$m invalid mac address. not 0-9a-f\n");
	    return "invalid mac";
    }

    my $junk = $self->getResults(-mac => $m, -type => $t, -id => $i);
    if ( (ref($junk) eq "HASH") && ($#{$junk->{'timestamp'}} > -1) ) {
	    return "duplicate result" unless $f;
    }

    $t ||= '';
    $i ||= '';

    if ($t =~ /^manual$/i) {
	    $junk = $self->getPage(-name => $i, -npcfg => $npcfg);
	    if (!defined($junk) && !$f) {
		    _log("ERROR", "$m cant add 'manual' result with invalid ID '$i'\n");
		    return "invalid manual id";
            }
    }

    elsif ($t =~ /^nessus$/) {
            if ( ($i !~ /^\d+$/) || ($i < 1) ) {
                     _log("ERROR", "$m type=nessus but id($i) is not a number\n");
                     return "invalid parameters (nessus id must be number)";
            }
    }

    elsif ($t =~ /^snort$/) {
            if ( ($i !~ /^\d+$/) || ($i < 1) ) {
                     _log("ERROR", "$m type=snort but id($i) is not a number\n");
                     return "invalid parameters (nessus id must be number)";
            }
    }

    my $sql;

    $sql  = "INSERT INTO results (macAddress, dt, testType, ID) VALUES (";
    $sql .= $self->dbh->quote($m). ",";
    $sql .= "NOW(),";
    $sql .= $self->dbh->quote($t). ",";
    $sql .= $self->dbh->quote($i). ")";

    $self->reconnect() || return "db failure";

    my $rv = $self->dbh->do($sql);

    if (!defined($rv)) {
            _log ("ERROR", qq{$m sql failure sql="$sql" err=}.$self->dbh->errstr);
            return "db failure\n".$self->dbh->errstr;
    }

    return 0;
}



=head2 getResults(-mac => $mac, -type => [nessus|snort|manual|...], -id => $id, -status => [pending|user-fixed|fixed|any])

Fetch entries from the results table. The MAC address parameter is the only
required one. If you call this routine with just a MAC address, all "pending" results
will be returned. Specify additional parameters to narrow down what is returned (or
expand the results set by saying -status=>'any')

=over 4

=item mac

 MAC address passed as number (no colons, etc). We'll pad it out for you
 with leading zeros if needed.

=item type

 nessus - only return results of Nessus scans
 snort  - only return results of Snort hits
 manual - only return manually inserted results (e.g. DMCA)
 ...    - the test type parameter is a 32 character text field.
          you can specify anything, the above values are pre-defined
          and reserved by NetPass.

=item id 

 Limit the results set to the given ID (if type is "nessus" or "snort").

=item status

 Limit the results set to results of this type. 
       pending    - the results have not yet been fixed.
       user-fixed - the user claims they fixed it (i.e. a snort hit that can't be
                    immediately and actively verified as being fixed)
       fixed      - this result has been confirmed to be fixed.

=back

 Example

 To retrieve all pending results for a host:

 $dbh->getResults(-mac => 112233445566);

 To retrieve all results for a host (even "fixed" results - i.e. historical):

 $dbh->getResults(-mac => 112233445566, -status => 'any');

 To test to see if a particular result is pending:

 $dbh->getResults(-mac => 112233445566, -type => 'nessus', -id => 12219);

 Or

 $dbh->getResults(-mac => 112233445566, -type => 'manual', -id => 'msg:dmca');

 Returns

 HASHREF              on success (so addResult && die should work)
 "invalid mac"        if mac doesnt look right ([0-9a-f]) or is "remote"
 "invalid type"       if type is invalid
 "invalid parameters" if the routine was called improperly
 "db failure"         if there was a DB failure

 The HASHREF will contain the keys "type", "id" and "status". These keys will
 point to ARRAYREFs which will contain the actual results. So to process the
 first result you might write

 print
   $hr->{'type'}->[0]     , ' ',
   $hr->{'id'}->[0]       , ' ',
   $hr->{'timestamp'}->[0], ' ',
   $hr->{'status'}->[0];

=cut

sub getResults {
    my $self = shift;

    my $parms = parse_parms({
			     -parms => \@_,
			     -required => [ qw(-mac -type) ],
			     -defaults => {
					   -mac       => undef,
					   -type      => '',
					   -id        => '',
					   -status    => 'pending',
					  }
			    }
			   );

    return "invalid parameters\n".Carp::longmess (Class::ParmList->error) 
      if (!defined($parms));
    
    my ($m, $t, $i, $s) = $parms->get('-mac', '-type', '-id', '-status');
    
    if ($s !~ /^(pending|fixed|user-fixed|any)$/) {
	    _log("WARNING", "invalid 'status' of '$s' given\n");
	    return "invalid paramters (status=$s)";
    }

    if ($m =~ /REMOTE/) {
	    _log("WARNING", "cant add result for remote client\n");
	    return "invalid mac";
    }

    $m = NetPass::padMac($m);

    if ($m !~ /^[0-9a-f]+$/) {
	    _log("WARNING", "$m invalid mac address. not 0-9a-f\n");
	    return "invalid mac";
    }

    $t ||= '';
    $i ||= '';

    my $sql = "SELECT unix_timestamp(dt) AS timestamp, testType AS type, status, id FROM results WHERE macAddress = " . $self->dbh->quote($m);

    $sql .= " AND testType = ".$self->dbh->quote($t)  if ($t ne "");
    $sql .= " AND ID = ".$self->dbh->quote($i)        if ($i ne "");
    $sql .= " AND status = ".$self->dbh->quote($s)    if ($s ne "any");

    $sql .= " ORDER BY dt DESC";

    $self->reconnect() || return "db failure";

    my $rv = $self->dbh->selectall_arrayref($sql);

    if (!defined($rv)) {
            _log ("ERROR", qq{$m sql failure sql="$sql" err=}.$self->dbh->errstr);
            return "db failure\n".$self->dbh->errstr;
    }

    my $hv = { 'timestamp' => [], 'type' => [], 'status' => [], 'id' => [], 'sql' => $sql };

    foreach my $row (@{$rv}) {
	    push @{$hv->{'timestamp'}}, $row->[0];
	    push @{$hv->{'type'}}     , $row->[1];
	    push @{$hv->{'status'}}   , $row->[2];
	    push @{$hv->{'id'}}       , $row->[3];
    }

    return $hv;
}

=head2 updateResult(-mac => '', -type => '', -id => '', -status => [fixed|user-fixed|pending])

Set the status of the matching result to whatever you specified. 

Returns:
 0                   on success
"invalid parameters" on failure
"db failure"         on failure

=cut

sub updateResult {
    my $self = shift;

    my $parms = parse_parms({
			     -parms => \@_,
			     -required => [ qw(-mac -type -id -status) ],
			     -defaults => {
					   -mac       => undef,
					   -type      => '',
					   -id        => '',
					   -status    => 'user-fixed',
					  }
			    }
			   );

    return "invalid parameters\n".Carp::longmess (Class::ParmList->error) 
      if (!defined($parms));
    
    my ($m, $t, $i, $s) = $parms->get('-mac', '-type', '-id', '-status');
    
    if ($s !~ /^(pending|fixed|user-fixed)$/) {
	    _log("WARNING", "invalid 'status' of '$s' given\n");
	    return "invalid paramters (status=$s)";
    }

    if ($m =~ /REMOTE/) {
	    _log("WARNING", "cant modify result for remote client\n");
	    return "invalid mac";
    }

    $m = NetPass::padMac($m);

    if ($m !~ /^[0-9a-f]+$/) {
	    _log("WARNING", "$m invalid mac address. not 0-9a-f\n");
	    return "invalid mac";
    }

    $t ||= '';
    $i ||= '';

    my $sql = "UPDATE results SET status = ".$self->dbh->quote($s)." WHERE macAddress = " . $self->dbh->quote($m);

    $sql .= " AND testType = ".$self->dbh->quote($t)  if ($t ne "");
    $sql .= " AND ID = ".$self->dbh->quote($i)        if ($i ne "");

    $self->reconnect() || return "db failure";

    my $rv = $self->dbh->do($sql);

    #_log("DEBUG", "sql=$sql\n");

    if (!defined($rv)) {
            _log ("ERROR", qq{$m sql failure sql="$sql" err=}.$self->dbh->errstr);
            return "db failure\n".$self->dbh->errstr;
    }

    return 0;
}

=head2 putConfig(-config => ARRAYREF, -user => "username", -log => ARRAYREF)

Insert a new configuration file into the database ("config" table).  This file
becomes the current, active configuration almost immediately (or as soon 
as C<NetPass::Config::reloadIfChanged> notices).

=over 4

=item config

 This is an array reference that contains the new configuration file in 
 C<Config::General> format.

=item user

 A username or identifier of the person who is importing the new configuration.

=item log

 An optional array reference containing some text describing what changes
 have been made. 

Returns

 0                     on success.
 "db failure"          something failed with the DB
 "invalid parameters"  the routine was called improperly.

=back

=cut

sub putConfig {
    my $self = shift;

    my $parms = parse_parms({
			     -parms => \@_,
			     -required => [ qw(-config -user) ],
			     -defaults => {
					   -config    => [],
					   -user      => '',
					   -log       => []
					  }
			    }
			   );

    return "invalid parameters\n".Carp::longmess (Class::ParmList->error) 
      if (!defined($parms));
    
    my ($c, $u, $l) = $parms->get('-config', '-user', '-log');

    return "invalid parameters (config empty)" unless (ref($c) eq "ARRAY" && $#{$c} >= 0);
    return "invalid parameters (user empty)" unless ($u ne "");

    my $ts = time();

    my $sql = "INSERT INTO config (dt, user, config) VALUES ( ";
    $sql .= "FROM_UNIXTIME($ts), ";
    $sql .= $self->dbh->quote($u). ", ";
    $sql .= $self->dbh->quote(join('', @$c)). ")";

    my $rv = $self->dbh->do($sql);
    return "db failure ".$self->dbh->errstr if (!defined($rv));

    $sql = "SELECT rev FROM config WHERE user = ".$self->dbh->quote($u). 
           " AND dt = FROM_UNIXTIME($ts) ";
    $rv = $self->dbh->selectall_arrayref($sql);
    return "db failure ".$self->dbh->errstr if (ref($rv) ne "ARRAY");

    # append an initial message

    my $rv2 = $self->appendLogToConfig(-rev => $rv->[0]->[0], -user => $u, 
			     -log => [ 'created' ]);

    return $rv2 if $rv2;

    # append the user's log message.

    $rv = $self->appendLogToConfig(-rev => $rv->[0]->[0], -user => $u, 
			     -log => $l);

    return $rv if $rv;

    return 0;
}


=head2 getConfig(-rev => integer, -user => 'username', -lock => [0 | 1])

Fetch the specified configuration from the database. If "rev" is not
give, fetch the highest (latest) config from the database. If "lock"
is "1", place an advisory lock on the configuration so that other people
can't edit it without a warning.

=over 4

=item rev

 An optional integer identifying which configuration to retrieve
 from the database. Default is to fetch the latest.

=item user

 This parameter is required of lock is "1". 

=item lock

 0 = get the config, I don't plan on editting it. (DEFAULT)
 1 = get the config, I plan on editting it, so warning anyone else
     who tries to edit the config.

=back

Returns

 HASHREF        containing keys:
                  { 'config'    => ARRAYREF,
                    'log'       => ARRAYREF,
                    'timestamp' => integer,
                    'rev'       => integer,
                    'user'      => scalar string
                  }
 "lock failed"  you said lock=1 but someone else already has a 
                config locked for editting
 "db failure"   something failed with the DB

=cut


sub getConfig {
    my $self = shift;

    my $parms = parse_parms({
			     -parms => \@_,
			     -required => [ qw() ],
			     -defaults => {
					   -rev    => 0,
					   -lock   => 0,
					   -user   => ''
					  }
			    }
			   );

    return "invalid parameters\n".Carp::longmess (Class::ParmList->error) 
      if (!defined($parms));
    
    my ($r, $l, $u) = $parms->get('-rev', '-lock', '-user');

    $r ||= 0;

    return "invalid parameters (rev)" unless ($r >= 0);
    return "invalid parameters (lock)" unless ($l == 0 || $l == 1);
    return "invalid parameters (user)" if ( ($l == 1) && ($u eq "") );

    my $rv;

    if ($l) {
	    $rv = $self->lockConfig(-rev => $r, -user => $u);
	    return $rv if ($rv);
    }

    my $sql = "SELECT config, log, UNIX_TIMESTAMP(dt) AS timestamp, rev, user FROM config ";
    $sql .= " WHERE rev = ".$self->dbh->quote($r) if $r;
    $sql .= " WHERE rev = (select MAX(rev) FROM config)" if ($r == 0);

    $rv = $self->dbh->selectall_arrayref($sql);

    return "db failure ".$self->dbh->errstr if (ref($rv) ne "ARRAY");

    return   { 'config'    => [ split("\n", $rv->[0]->[0]) ], 
	       'log'       => [ split("\n", $rv->[0]->[1]) ], 
	       'timestamp' => $rv->[0]->[2]  , 
	       'rev'       => $rv->[0]->[3]  , 
	       'user'      => $rv->[0]->[4] 
	     };
}


=head2 isConfigLocked(  )

Check to see if the config is currently locked. If it is, return information
about the lock.

Returns

 0                    not locked
 HASHREF              locked. see keys for details.
 "db failure"         something failed with the DB

=cut

sub isConfigLocked {
    my $self = shift;

    my $sql = "SELECT rev, user FROM config WHERE xlock = 1";
    my $rv  = $self->dbh->selectall_arrayref($sql);

    return "db failure ".$self->dbh->errstr unless (ref($rv) eq "ARRAY");

    if ($#{$rv} > 0) {
            _log("ERROR", "multiple locks on config detected.");
    }

    return 0 if ($#{$rv} == -1);  # no locks

    return { 'rev'  => $rv->[0]->[0],
             'user' => $rv->[0]->[1]
           };
}

=head2 lockConfig(-rev => rev, -user => username)

Lock the configuration so other people know we are editting it. A note
will be appended to the "log" for the configuration.  The latest
configuration will be "locked" unless "rev" is specified. See
C<NetPass::Config::rev()> 

=over 4

=item rev

 The revision to lock. Required. Pass in the revision of the currently
 running config.

=item user

 An identifier denoting who is locking the config. Required

=back

Returns

 0                    on success
 "lock failed"        someone has it locked already. check the log by fetching
                      the config. See C<NetPass::DB::getConfig>
 "invalid parameters" the routine was called improperly 
 "db failure"         something failed with the DB

=cut

sub lockConfig {
    my $self = shift;

    my $parms = parse_parms({
			     -parms => \@_,
			     -required => [ qw(-rev -user) ],
			     -defaults => {
					   -rev    => 0,
					   -user   => ''
					  }
			    }
			   );

    return "invalid parameters\n".Carp::longmess (Class::ParmList->error) 
      if (!defined($parms));

    my ($r, $u) = $parms->get('-rev', '-user');

    return "invalid parameters (rev)" unless ($r >= 0);
    return "invalid parameters (user)" unless ($u ne "");

    my $sql = "SELECT xlock, rev, user FROM config WHERE xlock = 1";
    my $rv  = $self->dbh->selectall_arrayref($sql);
    return "db failure ".$self->dbh->errstr unless (ref($rv) eq "ARRAY");

    if ($#{$rv} > -1) {
	    return "lock failed alreadyLocked rev=".$rv->[0]->[1]. " user=".$rv->[0]->[2];
    }
    $sql = "UPDATE config SET xlock = 1, user = ".$self->dbh->quote($u)." WHERE rev = ".$self->dbh->quote($r);
    $rv  = $self->dbh->do($sql);

    if (!defined($rv)) {
	    return "db failure ". $self->dbh->errstr;
    }

    $self->appendLogToConfig(-rev => $r, -user => $u, -log => [ 'config locked' ]);
    return 0;
}


=head2 unlockConfig(-rev => rev, -user => 'username')

Unlock the configuration. Both parameters are required.

Returns

 0                    on success
 "invalid parameters" the routine was called improperly 
 "db failure"         something failed with the DB

=cut

sub unlockConfig {
    my $self = shift;

    my $parms = parse_parms({
			     -parms => \@_,
			     -required => [ qw(-rev -user) ],
			     -defaults => {
					   -rev    => 0,
					   -user   => ''
					  }
			    }
			   );

    return "invalid parameters\n".Carp::longmess (Class::ParmList->error) 
      if (!defined($parms));
    
    my ($r, $u) = $parms->get('-rev', '-user');

    return "invalid parameters (rev)" unless ($r >= 0);
    return "invalid parameters (rev)" unless ($u ne "");

    my $rv = $self->appendLogToConfig(-rev => $r, -user => $u, -log => ['config unlocked']);
    return $rv if ($rv);

    my $sql = "UPDATE config SET xlock = 0";
    $rv = $self->dbh->do($sql);
    if (!defined($rv)) {
	    return "db failure ". $self->dbh->errstr;
    }
    return 0;
}



=head2 listConfigs( )

Fetch a listing of all of the stored configs. The listing will contain
the rev, timestamp, lock status, and user. If you want the log and
config, use getConfig. 

Returns

 HASHREF        on success containing keys: "rev", "timestamp",
                "lock", "user". Each of those point to ARRAYREFs.
 "db failure"   something failed with the DB

So the revision of the first config in the list (which should be the 
oldest) is  $hr->{'rev'}->[0]

=cut


sub listConfigs {
    my $self = shift;
    my $sql  = "SELECT rev, unix_timestamp(dt) AS timestamp, xlock, user FROM config ORDER BY rev ASC";
    my $rv   = $self->dbh->selectall_arrayref($sql);

    if (ref($rv) ne "ARRAY" || ($#{$rv} == -1)) {
	    return "db failure ".$self->dbh->errstr;
    }

    my $hv   = { 'rev' => [], 'timestamp' => [], 'lock' => [], 'user' => [] };
    foreach my $row (@$rv) {
	    push @{$hv->{'rev'}},       $row->[0];
	    push @{$hv->{'timestamp'}}, $row->[1];
	    push @{$hv->{'lock'}},      $row->[2];
	    push @{$hv->{'user'}},      $row->[3];
    }
    return $hv;
}


=head2 appendLogToConfig(-rev => rev, -user => username, -log => [] )

Add a log entry to the given config revision.

Returns

 0                    on success
 "invalid parameters" the routine was called improperly 
 "db failure"         something failed with the DB

=cut


sub appendLogToConfig {
    my $self = shift;

    my $parms = parse_parms({
			     -parms => \@_,
			     -required => [ qw(-rev -user -log) ],
			     -defaults => {
					   -rev    => 0,
					   -user   => '',
					   -log    => []
					  }
			    }
			   );

    return "invalid parameters\n".Carp::longmess (Class::ParmList->error) 
      if (!defined($parms));
    
    my ($r, $u, $l) = $parms->get('-rev', '-user', '-log');

    return "invalid parameters (rev)" unless ($r >= 0);
    return "invalid parameters (user)" unless ($u ne "");
    return 0 unless ( (ref($l) eq "ARRAY") && ($#{$l} >= 0)); #empty?

    my $sql = "SELECT log FROM config WHERE rev = ".$self->dbh->quote($r);

    my $rv = $self->dbh->selectall_arrayref($sql);

    if (ref($rv) ne "ARRAY") {
	    return "db failure ".$self->dbh->errstr;
    }

    if ($#{$rv} == -1) {
	    # the revision didnt exist. we dont throw an 
	    # error tho.
	    return 0;
    }

    $rv->[0]->[0] ||= "";

    my $l2  = join('', scalar(localtime)." $u\n", @$l, "\n", $rv->[0]->[0]);

    $sql = "UPDATE config SET log = ".$self->dbh->quote($l2). " WHERE rev = ".
      $self->dbh->quote($r);

    $rv = $self->dbh->do($sql);
    if (!defined($rv)) {
	    return "db failure ".$self->dbh->errstr;
    }

    return 0;
}



=head2 getUrlFilters()

Fetch the "urlFilters" table contents.

RETURNS

=over 4

 HASHREF              on success
  {network}->
     {'permit'}->{'re'}         = joined RE
     {'block'}->{'re'}          = joined RE
     {'soft-redirect'}->{'re'}  = joined RE
     {'hard-redirect'}->{'re'}  = joined RE

     {'permit'}->{'list'}->[]
     {'block'}->{'list'}->[]
     {'soft-redirect'}->{'list'}->[]
     {'hard-redirect'}->{'list'}->[]

     {'permit'}->{'hash'}->{url} = newurl
     {'block'}->{'hash'}->{url}  = newurl
     {'soft-redirect'}->{'hash'}->{url} = newurl
     {'hard-redirect'}->{'hash'}->{url} = newurl

 "db failure"         something failed with the DB

=back

=cut

sub getUrlFilters {
	my $self = shift;

	my $sql = "SELECT url, dst, network, action FROM urlFilters";
	my $hr  = $self->dbh->selectall_arrayref($sql);
	if (ref($hr) ne "ARRAY") {
		_log("ERROR", "failed to read urlFilters table: ".$self->dbh->errstr);
		return "db failure ".$self->dbh->errstr;
	}

	my $rv = {};
	my @permit;
	my @block;
	my @sredir;
	my @hredir;

	my $permit;
	my $block;
	my $sredir;
	my $hredir;

	my $dst;

	foreach my $row (@$hr) {
		my $url = $row->[0];
		#      $network     $url         $dst
		$dst->{$row->[2]}->{$row->[0]} = $row->[1];
		$permit->{$row->[2]}->{$row->[0]} = $row->[1];
		$block->{$row->[2]}->{$row->[0]} = $row->[1];
		$sredir->{$row->[2]}->{$row->[0]} = $row->[1];
		$hredir->{$row->[2]}->{$row->[0]} = $row->[1];

		if ($row->[3] eq "permit") {
			push @permit, $row->[0];
		}
		elsif ($row->[3] eq "block") {
			push @block, $row->[0];
		}
		elsif ($row->[3] eq "soft-redirect") {
			push @sredir, $row->[0];
		}
		elsif ($row->[3] eq "hard-redirect") {
			push @hredir, $row->[0];
		}
	}

	$rv->{'permit'}->{'re'} = '^'.join('|', @permit).'$';
	$rv->{'permit'}->{'list'} = \@permit;
	$rv->{'permit'}->{'hash'} = {};
	%{$rv->{'permit'}->{'hash'}} = map { $_ => 1 } @permit;

	$rv->{'block'}->{'re'} = '^'.join('|', @block).'$';
	$rv->{'block'}->{'list'} = \@block;
	$rv->{'block'}->{'hash'} = {};
	%{$rv->{'block'}->{'hash'}} = map { $_ => 1 } @block;

	$rv->{'soft-redirect'}->{'re'} = '^'.join('|', @sredir).'$';
	$rv->{'soft-redirect'}->{'list'} = \@sredir;
	$rv->{'soft-redirect'}->{'hash'} = {};
	%{$rv->{'soft-redirect'}->{'hash'}} = map { $_ => 1 } @sredir;

	$rv->{'hard-redirect'}->{'re'} = '^'.join('|', @hredir).'$';
	$rv->{'hard-redirect'}->{'list'} = \@hredir;
	$rv->{'hard-redirect'}->{'hash'} = {};
	%{$rv->{'hard-redirect'}->{'hash'}} = map { $_ => 1 } @hredir;

	return $rv;
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

$Id: DB.pm,v 1.36 2005/04/29 00:30:07 jeffmurphy Exp $

=cut

1;
