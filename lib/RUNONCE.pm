# $Header: /tmp/netpass/NetPass/lib/RUNONCE.pm,v 1.2 2005/08/04 20:41:18 jeffmurphy Exp $
#
# RUNONCE.pm
#
# Jeff Murphy, copyright, license, etc, at bottom of file,
# or use
#
# perldoc RUNONCE.pm 
#
# to read them.
#
# $Log: RUNONCE.pm,v $
# Revision 1.2  2005/08/04 20:41:18  jeffmurphy
# bug fixes to npsvc watcher, added some additional client logging
#
# Revision 1.1.1.1  2004/09/24 01:05:20  jeffmurphy
# Initial import.
#
# Revision 1.5  2001/03/22 20:03:52  jcmurphy
# *** empty log message ***
#
# Revision 1.4  2001/03/21 15:34:47  jcmurphy
# added fcntl
#
#

package RUNONCE;

use IO qw (Socket);
use IO::Socket;
use Fcntl;
my $listen  = undef;
$RUNONCE::VERSION = "1.0";
$RUNONCE::SANITY  = 1;

sub D { 0; }

sub close {
	if(defined($RUNONCE::listen)) {
		$RUNONCE::listen->close();
	}
}

# ROUTINE
#   alreadyRunning(pidSocket, retries, listenqueue)
#
# DESCRIPTION
#   create a tcp socket on the given port.
#   if we can't, somebody else (another copy of
#   ourself, presumably, is running. print out
#   info about that copy.
# 
#   if successful, hold the port open until the
#   script exits to prevent another copy running
#   concurrently.
#
# AUTHOR
#   jeff murphy

sub alreadyRunning {
	my ($ps, $rt, $lq) = (shift, shift, shift);

	my $psO = $ps;

	if(defined($ps)) {
		if($ps !~ /^\d+$/) {
			my $portNum = getservbyname($ps, 'tcp');
			if(!defined($portNum)) {
				die "$$ RUNONCE::alreadyRunning() : unknown port <$ps>";
			}
			$ps = $portNum;
		}

	} else {
		$ps = 16000; # default
	}

	$rt = 3 unless (defined($rt) && ($rt >= 0));
	$lq = 16 unless (defined($lq) && ($lq > 0));

	my $pid = undef;

	print "$$ RUNONCE::alreadyRunning($ps, $rt, $lq)\n"
	  if &RUNONCE::D;

	for (my $i = 0; $i < $rt ; $i++) {
		print "\n\n$$ alreadyRunning try #$i\n"
		  if &RUNONCE::D;

		$pid = RUNONCE::alreadyRunning2($ps, $lq, $psO);
		print "\n$$ alreadyRunning2 returned $pid\n"
		  if &RUNONCE::D;
		return $pid if($pid != -1);
	}

	return $pid;
}

sub alreadyRunning2($$$) {
	my ($ps, $lq, $psO) = (shift, shift, shift);
	my $mn = $0;
	if($mn =~ /([^\/]+)$/) {
		$mn = $1;
	} else {
		$mn = $0;
	}
	print "$$ myname = $mn [$0]\n" if &RUNONCE::D;

	$RUNONCE::listen = IO::Socket::INET->new(Listen    => $lq,
						 Proto     => 'tcp',
						 LocalAddr => '127.0.0.1',
						 LocalPort => $ps,
						 Reuse     => 1,
						 Timeout   => 1);

	print "$$ returned from Socket create call\n" if &RUNONCE::D;

	if(!defined($RUNONCE::listen)) {
		my ($remoteName, $remotePid) = (undef,undef);

		print "$$ connecting to port $ps\n" if &RUNONCE::D;

		my $c = IO::Socket::INET->new(Proto    => 'tcp',
					      PeerAddr => '127.0.0.1',
					      PeerPort => $ps,
					      Reuse    => 1,
					      Timeout  => 1);
		print "$$ connected to port $ps\n" if &RUNONCE::D;

		if(defined($c)) {
		        print "$$ reading from remote\n" if &RUNONCE::D;
			my $l = $c->getline();
		        print "$$ read ", (defined($l)?length($l):"UNDEF"), " from remote\n" if &RUNONCE::D;

			if(!defined($l)) {
				# remote end closed cnx on us
				print "$$ \$l !def, remote end closed cnx?\n"
				  if &RUNONCE::D;
				return -1;
			}

			chomp($l);
			if (&RUNONCE::D) {
				print qq{$$ remote sent "$l" (expecting /^$psO/)\n} if !$RUNONCE::SANITY;
				print qq{$$ remote sent "$l" (expecting "$mn")\n} if $RUNONCE::SANITY;
			}

			if($l =~ /(\d+)\s(.*)/) {
				$remoteName = $2;
				$remotePid  = $1;

				# we read something that was parsable, 
				# but the remoteName doesnt match our
				# basename. this is a sanity check and
				# we punt if it fails.

				if($RUNONCE::SANITY && ($remoteName ne $mn)) {
					warn qq{$$ remoteName isnt what i expected.\nexpected="$mn" got="$remoteName" (sanity on)};
					return -1;
				} 
				elsif (!$RUNONCE::SANITY && ($remoteName !~ /^$psO/)) {
					warn qq{$$ remoteName isnt what i expected.\nexpected=/^$psO/ got="$remoteName" (sanity off)};
					return -1;
				}
			} else {
				# can't parse remote output
				warn "$$ can't parse remote's message: \"$l\"";
				return -1;
			}
				
			$c->close();
		} else {
			print "$$ cant connect to remote\n"
			  if &RUNONCE::D;
			$remotePid = -1;
		}

		print "$$ remotePid = $remotePid remoteName = $remoteName\n"
		  if $RUNONCE::D;

		return $remotePid;
	}

	# else, we got the socket. set close-on-exec so we dont
	# pass it to any children. if this call fails, be sure to
	# call RUNONCE::close() before using system(), etc to 
	# run other processes.

	my $rv = fcntl($RUNONCE::listen, F_SETFD, 1);
	if($rv != 0) {
		warn "RUNONCE failed to set close-on-exec (fcntl failed with \"$rv\")";
	}
	$RUNONCE::listen->blocking(0);
	return 0;
}

sub handleConnection {
        print "$$ handleConnection timeout(0)\n" if &RUNONCE::D;
	my $to  = $RUNONCE::listen->timeout(0);
        print "$$ handleConnection accept()\n" if &RUNONCE::D;
	my $cnx = $RUNONCE::listen->accept();
        print "$$ handleConnection backfrom accept()\n" if &RUNONCE::D;

	my $mn = $0;
	if($mn =~ /([^\/]+)$/) {
		$mn = $1;
	} else {
		$mn = $0;
	}
	print "$$ myname = $mn [$0]\n" if &RUNONCE::D;

	if(defined($cnx)) {
		print "\n$$ accepted incoming cnx. sending \"$$ $mn\"\n" 
		  if &RUNONCE::D;
		print $cnx "$$ $mn\n";
		$cnx->close();
	} else {
		print "\n$$ no cnx to accept.\n" if &RUNONCE::D;
	}
	$RUNONCE::listen->timeout($to);
}

1;
__END__

=head1 NAME

RUNONCE::alreadyRunning - Routine for controlling mutually exclusive executions of the same program.

=head1 SYNOPSIS

   use RUNONCE;
   my $otherPid = RUNONCE::alreadyRunning(12345);
   die "another copy is currently running on pid $otherPid"
        if(defined($otherPid) && ($otherPid != 0));
       .
       .
       .

=head1 DESCRIPTION

C<RUNONCE::alreadyRunning> provides a mechanism for controlling
scripts that must be run with no concurrence. Typically, this 
is achieved by writing some sort of a lock file and aborting if
that file already exists, etc. 

Instead, we create a TCP server listening on a user-defined port 
(bound to the localhost interface). 

Since the kernel will only allow one application to bind to a 
specific TCP port, if the bind fails, we know another copy of 
our script is running and we abort. 

An advantage of this method is if our script aborts, we don't have 
to worry about cleaning the lockfile. The kernel handles freeing the
socket for re-use. 

=head1 USAGE

=over 4

=item close() returns NOTHING

     If you want to close the socket, to allow another copy 
     of the script to run (without exitting the currently
     running script) you can call this routine. 

     Also, RUNONCE attempts to set exec-on-close (via fcntl)
     so that the socket is not passed to child processes (launched
     via system() for example). If fcntl fails, child processes will
     hold the socket open and cause future runs of the script to
     fail. If that occurs, you can call close() before using system().
     Be aware that this implies that another copy of the script could
     start running after you call close(). If you try to call 
     alreadyRunning() again to grab the socket, you might not get it
     and you might have to retry.

=item handleConnection() returns NOTHING

     In order for RUNONCE to function correctly, you should 
     periodically call this routine. This routine need only
     be called by scripts that have successfully determined
     that they are running exclusively (see below). If you 
     don't call this script, other scripts will hang while they
     attempt to connect to the currently running script. This
     feature is actually useful.

     This routine handles connections from other instances
     of your script and is used to inform them that they are 
     not cleared to run exclusively. 

     An interesting side-effect of not calling this routine
     is that other instances of your script will queue up
     (hang) while they wait for the current instance to exit 
     and release the socket.

     If you have alot of scripts queued, the retry count (default 
     of 3 - see below) will eventually cause some of them to 
     die. The "listen" queue is set to 16 by default. If you 
     choose to not call handleConnection() then 16 copies of the
     script will queue while the running copies executes. The 17th
     (and beyond) copy will receive a connection refused message.
     This will causes a return value of -1 (error).

=item alreadyRunning(tcp_port, number_of_retries, listen-queue) returns INTEGER

     This routine performs the actual "is another copy of me running
     already" test. tcp_port number defaults to 16000, but you should
     definately override this. number_of_retries defaults to 3. 
     This routine will perform a sanity check incase somebody else
     as stolen our port.

     tcp_port          DEFAULT 16000

              The port to bind to. you should 
              select a port that can be used exclusively
              by your script. You can alternately specify 
              a service name which might make things more
              managable (e.g. register a service with the 
              same name as your script and then pass basename
              of $0 as the tcp_port).

     number_of_retries DEFAULT 3

              There are at least two race conditions which
              could cause RUNONCE to be unsure of whether
              or not another copy is running. If we're unsure,
              we will retry a specified number of times. If
              we are still unsure we return -1

    listen_queue       DEFAULT 16

              This value determines how many scripts will queue
              if you are not going to call handleConnection().
              It also comes into play if your scripts are firing
              of faster than the running script can handle the
              incoming connections. The kernel will queue up 
              16 connections before it starts refusing the connections.

=back

=head1 RETURN VALUES for alreadyRunning()

=over 4

 -1          =  FATAL ERROR

      We can't be sure that another copy isn't running.

  0          =  SUCCESS

      Another copy is _not_ running, we've bound to the tcp
      port and your script is cleared to proceed.

  1 or more  =  FAILURE

      Another copy of the script is already running, this
      value is the process ID of the other copy.

=back

=head1 AUTHOR

Jeff Murphy E<lt>F<jcmurphy@jeffmurphy.org>E<gt>

=head1 COPYRIGHT

Copyright (c) 2001 Jeff Murphy E<lt>F<jcmurphy@jeffmurphy.org>E<gt>. All rights reserved.
This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
