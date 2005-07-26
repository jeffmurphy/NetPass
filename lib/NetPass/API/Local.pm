package NetPass::API::Local;

use strict;
use Carp;

my $VERSION = '0.01';

use lib qw(/opt/netpass/lib);
use NetPass::LOG qw(_log _cont);
use NetPass::Config;
use Class::ParmList qw(simple_parms parse_parms);

my $nph = $::np;

=head1 NAME

NetPass::API::Local - NetPass User Defined API functions

=head1 SYNOPSIS

    use NetPass::API::Local;

=head1 DESCRIPTION

There currently are hooks in the NetPass::API module that will
call functions in this module to execute user defined functionality.
For example if the API function quarantineByIp is called, NetPass::API
will check this module for a quarantineByIp function, if such a function
exists it will be executed with the same arguments that were passed
to the original call to NetPass::API::quarantineByIp. If a function
defined in this module returns a value less than 0 the corresponding
NetPass::API function called will return C<undef> and not execute.
The NetPass object is also available through a global variable $::np
to this module. 

=head1 METHODS

=cut

sub getSnortPCAPFilter {
	return 1;
}

sub getSnortRules {
	return 1;
}

sub snortEnabled {
	return 1;
}

sub snortEnabledNetworks {
	return 1;
}

sub getRegisterInfo {
	return 1;
}

sub addSnortRuleEntry {
	return 1;
}

sub quarantineByIP {
	return 1;
}

1;
