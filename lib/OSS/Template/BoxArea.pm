# $Header: /tmp/netpass/NetPass/lib/OSS/Template/BoxArea.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

package OSS::Template::BoxArea;

use strict;
use OSS::Template;
use OSS::Template::Box;


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

    $self->q(new OSS::Template());
    
    $self->width('1%');
    $self->width($param{-width}) if($param{-width});

    $self->columns('2');
    $self->columns($param{-columns}) if($param{-columns});

    my @a = ();
    my @b = ();
    $self->boxes(\@a);
    $self->links(\@b);

    return($self);
}

sub display {
	my $self = shift;

	my @boxes    = @{$self->boxes()};
	my $columns  = $self->columns();

        my $del_links = join('<br>', @{$self->links()});

	my $del_box = new OSS::Template::Box( -id	=> 'deleted_box',
                                     	      -title    => 'More Available Page Content',
                                              -minimize => 1,
                                              -content  => $del_links
                                            );

	push(@boxes, $del_box->display) if($del_links ne '');

	# $first will help even out the columns if we have an odd number of boxes
	# this isn't perfect... but works pretty well...

	my $first = ( int(($#boxes+1)/$columns) != (($#boxes+1)/$columns))?1:0;
	my $bpc = int((($#boxes+1)/$columns)+.5);
	my $cols = '';

	while(my @a = splice(@boxes, 0, ($bpc+$first)) ) {
                $cols .= $self->q->td({-valign=>'top', align=>'center'}, join('<br>', @a));
		$first = 0;
	}

	return $self->q->table({-border=>0, -cellspacing=>5, -width=>$self->width}, $self->q->Tr($cols));

}

sub add {
	my $self = shift;
	my $box  = shift;

	if($box->state() eq 'deleted') {
		push(@{$self->links()}, $box->maximize_link);
	} else {
		push(@{$self->boxes()}, $box->display);
	}
}

1;

__END__

=head1 NAME

OSS::Template::BoxArea - BoxArea Generator Class for use with OSS::Template

=head1 SYNOPSIS

  use OSS::Template;
  use OSS::Template::Box;
  use OSS::Template::BoxArea;

  my $q = new OSS::Template;

  print $q->header();

  print $q->start_html(-title     => 'Testing Box!');

  my $boxArea = new OSS::Template::BoxArea( -columns=>2 );

  my $box1 = new OSS::Template::Box(  -id       => 'some unique label',
                                     -title    => 'test box',
                                     -width    => '300px',
                                     -icon     => '/style/images/icons/profile.gif',
                                     -minimize => 1,
                                     -delete   => 1,
                                     -edit     => '/path/to/edit/script.cgi',
                                     -content  => 'some html or something'
                                   );

  $boxArea->add($box1);
  $boxArea->add($box1);	# we add this multiple times just for
  $boxArea->add($box1); # demonstration purposes...
  $boxArea->add($box1);
  $boxArea->add($box1);
  $boxArea->add($box1);

  print $boxArea->display;

  print $q->end_html();

=head1 ABSTRACT

This perl library creates an area to hold multiple Box objects. It
provides the functionality for balancing box objects on a page.

The current version of OSS::Template::BoxArea is available at

  http://nerf.cit.buffalo.edu/perl/

=head1 METHODS

=over 4

=item B<new()>

This method returns a new OSS::Template::BoxArea object.

This method has the following flags:

B<-columns>

This is the number of columns the BoxArea will have.
The BoxArea will try to balance the boxes across all
columns.

=item B<add()>

This method adds a Box object to the BoxArea.

This method has no flags

=item B<display()>

This method will return the BoxArea display string.

=back

=head1 LICENSE INFORMATION

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

L<OSS::Template>
L<OSS::Template::Box>

=cut


