# $Header: /tmp/netpass/NetPass/lib/OSS/Template/Box.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

package OSS::Template::Box;

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

    my $q = new OSS::Template();
    my $img_root = $q->resource_root . "/images/Box";

    $self->q($q);
    
    if($param{-id}) {
    	$self->id($param{-id});
    } else {
	# generate random id
    	$self->id('generated');
    }

    foreach my $p ('delete', 'edit', 'minimize') {
    	$self->$p('0');
    	$self->$p($param{"-$p"}) if($param{"-$p"});
    }

    my $id = $self->id(); 
    $self->state('maximized');  # maximized, minimized, deleted
    $self->state($param{-state}) if($param{-state});
    $self->state($q->cookie("OSSBOX_state_$id")) if(defined($q->cookie("OSSBOX_state_$id")));

    $self->title('');
    $self->title($param{-title}) if($param{-title});

    $self->width('300px');
    $self->width($param{-width}) if($param{-width});

    $self->icon("$img_root/clrpxl.gif");
    $self->icon($param{-icon}) if($param{-icon});

    $self->content('');
    $self->content($param{-content}) if($param{-content});


    return($self);
}

sub display {
	my $self = shift;

	my $box = '';
	my $q = $self->q();

	my $buttons = $self->get_buttons();

	my @rows = ();

	push(@rows, 	$q->TR(
           		  $q->td({ -class=>'boxHeader' }, $q->img({-src=>$self->icon, -border=>0, -style=>'margin-right: 6px;'}) . $self->title()) .
			  $q->td({ -class=>'boxHeader', -align=>'right'}, $buttons),
        		 ));

	push(@rows, 	$q->TR(
           		  $q->td({-class=>'boxContent', -valign=>'top', -colspan=>'2'}, $self->content()),
        		 )) if($self->state() eq 'maximized');


	$box .= $q->table( { -class=>"box", -style=>"width: ".$self->width }, @rows) if($self->state() ne 'deleted');


      return $box;
}

sub get_buttons {
	my $self = shift;

	my $id = $self->id();
	my $q  = $self->q();
	my $img_root = $q->resource_root . "/images/Box";

	my @buttons = ();

	my $min_img  = $q->img({-src=>"$img_root/wd-underscore.gif", 	-alt=>'[minimize]', 
				-border=>'0', -style=>'vertical-align: middle;'});
	my $max_img  = $q->img({-src=>"$img_root/wd-box.gif",        	-alt=>'[maximize]', 
				-border=>'0', -style=>'vertical-align: middle;'});
	my $del_img  = $q->img({-src=>"$img_root/wd-X.gif", 	   	-alt=>'[close]',    
				-border=>'0', -style=>'vertical-align: middle;'});
	my $edit_img = $q->img({-src=>"$img_root/wd-X.gif", 	   	-alt=>'[edit]',     
				-border=>'0', -style=>'vertical-align: middle;'});

	my $c_id = "OSSBOX_state_$id";
	my $t    = 5000;             # 5000 days expire time
	
	$min_img  = $q->a( { -href=>'#', -onClick=>"setCookie('$c_id', 'minimized', $t); window.location.reload(true);" }, $min_img );
	$max_img  = $q->a( { -href=>'#', -onClick=>"setCookie('$c_id', 'maximized', $t); window.location.reload(true);" }, $max_img );
	$del_img  = $q->a( { -href=>'#', -onClick=>"setCookie('$c_id', 'deleted',   $t); window.location.reload(true);" }, $del_img );
	$edit_img = $q->a( { -href=>$self->edit()}, $edit_img );

	if($self->state() eq 'minimized') {
		push(@buttons, $max_img);
	} else {
		push(@buttons, $min_img) if($self->minimize);
	}

	#push(@buttons, $edit_img) if($self->edit() ne '');
	push(@buttons, $del_img) if($self->delete);

	return join('', @buttons);

}

sub add_content {
	my $self = shift;
	my $text = shift;

	$text = $self->content . $text;
	$self->content($text);
}

sub maximize_link {
	my $self = shift;

	my $c_id = "OSSBOX_state_" . $self->id();
	my $t    = 5000;             # 5000 days expire time

	my $link = $self->q->a( { -href=>'#', -onClick=>"setCookie('$c_id', 'maximized', $t); window.location.reload(true);" }, 
		                $self->title);
	return $link;
}

1;

__END__

=head1 NAME

OSS::Template::Box - Box Generator Class for use with OSS::Template

=head1 SYNOPSIS


  use OSS::Template;
  use OSS::Template::Box;

  my $q = new OSS::Template;

  print $q->header();

  print $q->start_html(-title     => 'Testing Box!');

  my $box1 = new OSS::Template::Box(  -id       => 'some unique label',
                                     -title    => 'test box',
                                     -width    => '300px',
                                     -icon     => '/style/images/icons/profile.gif',
                                     -minimize => 1,
                                     -delete   => 1,
                                     -edit     => '/path/to/edit/script.cgi',
                                     -content  => 'some html or something'
                                   );


  $box->add_content('forgot something');

  print $box->display();

  print $q->end_html();

=head1 ABSTRACT

This perl library encapsulates box creation and allows users to create
a custom box wrapper with minimize/delete/edit functionality without
any knowledge of HTML, CSS, JS.

The current version of OSS::Template::Box is available at

  http://nerf.cit.buffalo.edu/perl/

=head1 METHODS

=over 4

=item B<new()>

This method returns a new OSS::Template::Box object.

This method has the following flags:

B<-id>

The unique label used to reference this box. If none is
provided, it will be generated randomly.

B<-title>

The box title that will be displayed in the header.

B<-width>

The width of the box, in either pixel or percentage.
Default is 300px

B<-icon>

The path to the icon image shown in the title bar.
Default is no icon.

B<-minimize>

This flag causes the box to have a 'minimize' button attached
to it. when clicked, this will minimize the box to only show
the header. Default is '0'.

B<-delete>

This flag causes the box to have a 'delete' button attached
to it. when clicked, this will delete the box from the page.
Default is '0'.

B<-edit>

Setting this flag to the path of a script causes the box to
have an 'edit' button attached to it. when clicked, this will
bring the user to the script specified to edit the box content.
Default is ''.

B<-content>

The content that will appear within the box. There are no
limitations to what this content can be. Forms and other HTML
entities work fine within the box.

=item B<add_content()>

This method adds content to an existing box.

This method has no flags

=item B<display()>

This method will return the box display string.

=back

=head1 LICENSE INFORMATION

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

L<OSS::Template>

=cut


