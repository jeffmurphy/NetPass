# $Header: /tmp/netpass/NetPass/lib/OSS/Template/Menu.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

package OSS::Template::Menu;

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

    $self->{_menus} = ();
    $self->orientation('vertical');
    $self->main(0);
    $self->name('Menu');
    $self->js('');
    $self->subs(0);
    $self->width(120);
   
    if ($param{-mainmenu}) { 
    	$self->main($param{-mainmenu});
	$self->orientation('horizontal');
    }
    $self->orientation($param{-orientation}) if ($param{-orientation});
    $self->width($param{-width}) if ($param{-width});

    return($self);
}


sub add_menu_item {
        my ($self, %opts)       = @_;
	push(@{$self->{_menus}}, \%opts);

}

sub display {
	my $self = shift;

	my $menu = "";
	
	$menu .= "with(milonic=new menuname(\"" . $self->name() . "\")){\n";
	$menu .= "style=menuStyle;\n";
	$menu .= "itemwidth=" . $self->width() . ";\n";
	$menu .= "orientation=\"" . $self->orientation() . "\";\n";
	$menu .= "alwaysvisible=1;\nposition=\"relative\";\n" if($self->main());

	for(my $i=0;$i<=$#{$self->{_menus}};$i++) {
		my $label    = $self->{_menus}->[$i]->{'-label'};
		my $href     = $self->{_menus}->[$i]->{'-href'};
		my $submenu  = $self->{_menus}->[$i]->{'-submenu'};

		$menu .= "aI(\"";
		$menu .= "text=$label;" 	if ($label);
		$menu .= "url=$href;"   	if($href);
		$menu .= "status=$label;";
		
		if($submenu) {
			$self->{_subs}++;
			$submenu->name('sub_' . $self->subs() . $self->name());
			$menu .= "showmenu=" . $submenu->name() . ";";
			$self->{_js} .= "\n" . $submenu->display();
		}

		$menu .= "\");\n";
	}

	$menu .= "}\n\n";	

	return $self->all_js($menu . $self->js());

}

sub all_js {

	my $self = shift;
	my $js   = shift;

	if(!$self->main()) {
		return $js;
	}

return << "end_script";

<script>
_menuCloseDelay=300           // The time delay for menus to remain visible on mouse out
_menuOpenDelay=150            // The time delay before menus open on mouse over
_followSpeed=5                // Follow scrolling speed
_followRate=40                // Follow scrolling Rate
_subOffsetTop=0               // Sub menu top offset
_subOffsetLeft=0              // Sub menu left offset

with(menuStyle=new mm_style()){
onbgcolor="#4F8EB6";
oncolor="#ffffff";
offbgcolor="#DCE9F0";
offcolor="#515151";
bordercolor="#296488";
borderstyle="solid";
borderwidth=1;
separatorcolor="#2D729D";
separatorsize="1";
padding=5;
fontsize="85%";
//fontstyle="normal";
//fontfamily="Verdana, Tahoma, Arial";
//pagecolor="black";
//pagebgcolor="#82B6D7";
headercolor="#000000";
headerbgcolor="#ffffff";
subimage="http://new.oss.buffalo.edu/OSSTemplate/images/arrow.gif";
subimagepadding="2";
}

$js

drawMenus();

</script>

end_script

}

1;

__END__

=head1 NAME

OSS::Template::Menu - Menu Generator Class for use with OSS::Template

=head1 SYNOPSIS

  use OSS::Template;
  use OSS::Template::Menu;

  my $q = new OSS::Template;

  print $q->header();

  print $q->start_html( -title => 'Menu test!');


  my $file_menu = new OSS::Template::Menu();
     $file_menu->add_menu_item(-label => 'new item',   -href  => '?action=new'   );
     $file_menu->add_menu_item(-label => 'open item',  -href  => '?action=open'  );
     $file_menu->add_menu_item(-label => 'close item', -href  => '?action=close' );

  my $another_menu = new OSS::Template::Menu();
     $another_menu->add_menu_item(-label => 'something', -href    => '?action=anything');

  my $other_menu = new OSS::Template::Menu();
     $other_menu->add_menu_item(-label => 'search',     -href    => '?action=search' );
     $other_menu->add_menu_item(-label => 'list all',   -href    => '?action=list'   );
     $other_menu->add_menu_item(-label => 'delete all', -href    => '?action=delete' );
     $other_menu->add_menu_item(-label => 'file again', -submenu =>  $another_menu   );

  my $main_menu = new OSS::Template::Menu( -mainmenu => 1 );
     $main_menu->add_menu_item(-label => 'menu test',         -submenu  => $file_menu		        );
     $main_menu->add_menu_item(-label => 'link test',         -href     => 'http://www.oss.buffalo.edu' );
     $main_menu->add_menu_item(-label => 'sub sub menu test', -submenu  => $other_menu                  );

  print $main_menu->display();

  print $q->end_html();

=head1 ABSTRACT

This perl library encapsulates menu creation and allows users to create
nested DHTML menus without any knowledge of HTML, CSS, JS.

The current version of OSS::Template::Menu is available at

  http://nerf.cit.buffalo.edu/perl/

=head1 METHODS

=over 4

=item B<new()>

This method returns a new OSS::Template::Menu object.

This method has the following flags:

B<-orientation>

This flag can be set to 'horizontal' or 'vertical' and it
determines the menu direction.

B<-width>

This flag sets the width of the menus. Default: 120px;

B<-mainmenu>

This flag sets the menu as visible and does some other
behind-the-scenes magic to make the menus work. This flag 
should only be set on top-level menus. It should not be
set for any menu that will be used as a sub-menu.

=item B<add_menu_item()>

This method adds a new menu item to the menu. The menu
items can consist of either a link or another menu.

This method has the following flags:

B<-label>

The text that is displayed for the menu item and in the status
bar when this selection is hovered over.

B<-href>

A link, relative or absolute, that is visited when this menu
item is clicked. This flag can be be combined with the
-submenu flag.

B<-submenu>

This flag specifies that another OSS::Template::Menu object
is a submenu to this menu item. This flag can be be combined
with the -href flag to create an item with a submenu and a
link.

=item B<display()>

This method returns the menu display string and should only
be called for the main menu.

=back

=head1 LICENSE INFORMATION

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

L<OSS::Template>

=cut


