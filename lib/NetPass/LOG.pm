# $Header: /tmp/netpass/NetPass/lib/NetPass/LOG.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense


package NetPass::LOG;
use Sys::Syslog qw(:DEFAULT);
use FileHandle;
use Switch;
use Carp;

my $VERSION = '1.0001';

require Exporter;

@ISA    = qw(Exporter);
@EXPORT_OK = qw(_log _cont);

use strict;

=head1 NAME

NetPass::LOG - routine for coordinating log messages

=head1 SYNOPSIS

    use NetPass::LOG qw(_log _cont);

    NetPass::LOG::init (*STDERR);                   # filehandle
    NetPass::LOG::init ("/tmp/somefile.txt");       # file
    NetPass::LOG::init ($aFileHandle);              # filehandle
    NetPass::LOG::init ([ ident, facility ])        # Syslog

    _log "ERROR", "This is an error message.\n";
    _log "DEBUG", "This is an debugging message.\n";

    _log "INFO", "This is an informational message ..\n";
    _cont ".. with some", " additional text.\n";

=head1 DESCRIPTION

Just another wheel.

=head1 AUTHOR

Jeff Murphy <jcmurphy@buffalo.edu>

=head1 LICENSE

   (c) 2004 University at Buffalo.
   Available under the "Artistic License"
   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

=head1 REVISION

$Id: LOG.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

=cut

my $lh = undef;
my $SL  = 0;

sub init {
	my $handle = shift;

	$lh = \*STDERR;
	if( defined($handle) ) {
	    if (ref($handle) eq "ARRAY") { 
		openlog $handle->[0], 'cons,pid', $handle->[1];
		#print STDERR "LOG syslog $handle->[1]\n";
		$SL = 1;
	    } else {
		switch (ref(\$handle)) {
		    case "GLOB"       { $lh = $handle; }
		    case "SCALAR"     { $lh = new FileHandle $handle, O_WRONLY | O_APPEND | O_CREAT;
					die Carp::longmess "cant open $handle for writing: $!" 
					unless defined($lh);
				      }
	            case "FileHandle" { $lh = $handle; }
	            else { 
			die Carp::longmess "unknown parameter type ".
			  "expecting GLOB, SCALAR or FileHandle but i got \"".
			    ref(\$handle)."\"";
		    }
		}
	    }
        }
    }

my %syslogMap =
  ( 'EMERGENCY' => 'emerg',
    'ALERT'     => 'alert',
    'CRITICAL'  => 'crit',
    'ERROR'     => 'err',
    'WARNING'   => 'warn',
    'NOTICE'    => 'notice',
    'INFO'      => 'info',
    'DEBUG'     => 'debug'
  );

sub _log {
        return if !defined($lh);

        my ($package, $filename, $line, $subr, $has_args, $wantarray )= caller(1);

        my $MTYPE = $_[0];
	my $_SL   = $MTYPE;

        if ($MTYPE =~ /^(INFO|WARNING|DEBUG|ERROR)$/) {
                $MTYPE = sprintf("%5.5s", shift);
        } else {
                $MTYPE = " " x 5;
        }
	my $name = $0;
	if ($name =~ /([^\/]+)$/) {
	    $name = $1;
        }

        $package = "$name" unless defined($package);
        $subr    = "$name(main)" unless defined($subr);
        $line    = "?" unless defined($line);

	if ($SL == 0) {
	    print $lh '[', scalar(localtime), "] [$MTYPE] ${subr} [$line]: ";
	    print $lh join(' ', @_);
	} else {
	    my $s = sprintf("[$MTYPE] ${subr} [$line]: %s", join(' ', @_));
	    chomp($s);
	    $_SL =~ tr [A-Z] [a-z];
	    $_SL = ($_SL eq "error") ? "err" : $_SL;
	    #print STDERR "level: $_SL\n";
	    syslog($_SL, $s);
	}
}

sub _cont {
        return if !defined($lh);
	if($SL == 0) {
	    print $lh join(' ', @_);
	} else {
	    warn "_cont doesnt support SYSLOG"; # no way to know level
	}
}

1;
