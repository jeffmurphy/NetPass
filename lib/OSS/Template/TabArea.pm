# $Header: /tmp/netpass/NetPass/lib/OSS/Template/TabArea.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

package OSS::Template::TabArea;

use OSS::Template;
use strict;

sub AUTOLOAD {
        no strict;
        return if($AUTOLOAD =~ /::DESTROY$/);
        if ($AUTOLOAD=~/(\w+)$/) {
                my $field = $1;
                *{$field} = sub {
                                my $self = shift;
                                @_ ? $self->{"_$field"} = shift
                                   : $self->{"_$field"};
                                };
                &$field(@_);
        } else {
                Carp::confess("Cannot figure out field name from '$AUTOLOAD'");
        }
}

sub new {
    my($class,%param) = @_;

    # Create the anonymous hash reference and bless it
    # into the proper class. This permits inheritance.

    my $self = {};
    bless $self, ref($class) || $class;

    my @p = ();

    $self->q(new OSS::Template());
    $self->panes(\@p);

    return($self);
}


sub add_pane {
        my ($self, %opts)       = @_;
	if($opts{'-to_front'}) {
		unshift(@{$self->panes()}, \%opts);
	} else {
		push(@{$self->panes()}, \%opts);
	}
}

sub display {
	my $self = shift;
	my $q = $self->q;

	my @tabs  = ();
	my $panes = "";
	my @panes = @{$self->panes()};

	my $colspan = $#panes + 2;  # have to include the empty tab...

	my $tabactive   = 'active';
	my $panedisplay = '';

	for(my $i=0;$i<=$#panes;$i++) {
		my $label    = $panes[$i]->{'-label'};
		my $content  = $panes[$i]->{'-content'};

		push(@tabs, $q->td({	-class => "tab_$tabactive",
					-id    => "tab_$i"
				   },
				  
				   $q->a({  -href    => '#',
					    -onclick => "showPane('$i'); return false;"
			 		 },
					 $label
				        )
				  )
		    );

		$panes  .= $q->div({ -id    => "pane_$i",
				     -style => "display: $panedisplay;"
				   },
				   $content
				  );

		$tabactive   = 'inactive';
		$panedisplay = 'none';
	}
	

	push(@tabs, $q->td({ -class => "no_tab"},'&nbsp;'));
	
	return $q->table({-class=>'tab_table'},
			 $q->TR(join("\n",@tabs)) .
			 $q->TR($q->td({ -class   => 'tabpanearea',
			   		 -colspan => $colspan
			 	       },
			 	       $panes
				      )
			       )
			);

}

1;

__END__

=head1 NAME

OSS::Template::TabArea - Tab Generator Class for use with OSS::Template

=head1 SYNOPSIS


  use OSS::Template;
  use OSS::Template::TabArea;

  my $q = new OSS::Template;

  print $q->header();

  print $q->start_html(-title     => 'Testing Tabs!');

  my $tabs = new OSS::Template::TabArea();

  $tabs->add_pane( -label   => 'English',
                   -content => 'Hello!',
                 );

  $tabs->add_pane( -label   => 'Italian',
                   -content => 'Ciao!'
                 );

  $tabs->add_pane( -label   => 'Spanish',
                   -content => 'Hola!'
                 );


  print $tabs->display();

  print $q->end_html();

=head1 ABSTRACT

This perl library encapsulates tab creation and allows users to create
a tabbed pane area without any knowledge of HTML, CSS, JS.

The current version of OSS::Template::TabArea is available at

  http://nerf.cit.buffalo.edu/perl/

=head1 METHODS

=over 4

=item B<new()>

This method returns a new OSS::Template::TabArea object.

This method has no flags

=item B<add_pane()>

This method adds a tabbed pane to the tab area.

This method has the following flags:

B<-label>

The label that will appear on the tab

B<-content>

The content that will appear within the pane area. There are no
limitations to what this content can be. Forms and other HTML
entities work fine within the tabbed pane area.

=item B<display()>

This method will return the tab area display string.

=back

=head1 LICENSE INFORMATION

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

L<OSS::Template>

=cut


