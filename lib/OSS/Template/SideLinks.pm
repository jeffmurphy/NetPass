# $Header: /tmp/netpass/NetPass/lib/OSS/Template/SideLinks.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

package OSS::Template::SideLinks;

use OSS::Template;
use DBI;
use strict;

my @links;
my $q;

sub AUTOLOAD {
   no strict;
   return if ($AUTOLOAD =~/::DESTROY$/);
   if ( $AUTOLOAD =~ /(\w+)$/ ) {
      my $field = $1;
      *{$field} = sub { my $self = shift;
                        @_ ? $self->{"_$field"} = shift
                           : $self->{"_$field"};
                      };

      &$field(@_);
   } else {
      Carp::confess("Cannot figure out field name from '$AUTOLOAD'");
   }
}

sub new {
   my ($class,%params) = @_;

   my $self = {};
   bless $self, ref($class) || $class;

   $q = new OSS::Template();

   return($self);
}

sub add_link {
   my ($self, %opts) = @_;
   push(@links, \%opts);
}

sub get_default {
   my $self = shift;
   my $cnct = "DBI:mysql:database=www;host=db.cit.buffalo.edu;mysql_socket=/www/db/mysql.sock";
   my $dbHandle = DBI->connect($cnct,"jcmurphy","");
   if ( !defined($dbHandle) ) {
      print "ERROR:  Can not connect to database:$DBI::errstr:$!";
   }
   $dbHandle->{AutoCommit} = 1;

   my @rArray;
   my $query = "SELECT * from OSSTemplate_SideLinks order by parentID";
   if ( !defined($dbHandle) ) {
      print "ERROR: DBHandle Not Defined:$DBI::errstr:$!";
   }

   my $sth = $dbHandle->prepare($query);
   if ( !defined($sth) ) {
      print "ERROR: Unable to prepare:$DBI::errstr:$!";
   }

   if ( !defined($sth->execute) ) {
      $sth->finish;
      print "ERROR: Unable to execute:$DBI::errstr:$!";
   }
   my %tempHash;
   my $i = 0;
   while ( my $rows = $sth->fetchrow_arrayref ) {
      $rArray[$i][0]=$$rows[0];
      $rArray[$i][1]=$$rows[1];
      $rArray[$i][2]=$$rows[2];
      $rArray[$i][3]=$$rows[3];
      $rArray[$i][4]=$$rows[4];
      $rArray[$i][5]=$$rows[5];
      $i++;
   }
   $sth->finish;

   my @temp;
   foreach my $headerElement ( @rArray ) {
      if ( $headerElement->[4] == "0" ) {
         push ( @temp, $headerElement);
      }
   }

   my $nextID=1;
   my @sideLinks;
   foreach my $arrayElement ( @rArray ) {
      next if ( $arrayElement->[4] == 0 );
      if ( $arrayElement->[4] == $nextID ) {
         push ( @sideLinks, shift(@temp) );
         $nextID++;
      }
      push(@sideLinks, $arrayElement );
   }

   $dbHandle->disconnect;
   undef $dbHandle;

   my $parAnswer;
   foreach my $element ( @sideLinks ) {
      if ( $element->[4] == "0" ) {
         $parAnswer = "yes";
      } else {
         $parAnswer = "no";
      }
      $self->add_link( -text   => $element->[1],
                -link   => $element->[2],
                -target => $element->[3],
                -header => $parAnswer
              );
   }
}

sub display {
   my $self = shift;
   my @foo = ();

   for ( my $i=0; $i<=$#links;$i++) {
      my $text = $links[$i]->{'-text'};
      my $newLink = $links[$i]->{'-link'};
      my $target = $links[$i]->{'-target'};
      my $header = uc($links[$i]->{'-header'});
      my $classType;

      if ( defined($header) && $header eq "YES") {
         push ( @foo, "<p>" );
         $classType = "sbHeader";
      } else {
         $classType = "sbLinks";
      }
      push ( @foo, $q->a({ -href => $newLink,
                                   -target => $target,
                                   -class => $classType
                                 },
                                 $text
                          ),$q->br
            );
   }

   return $q->table( $q->TR($q->td({-width   => "1%",
                                    -valign  => "top",
                                    -rowspan => "5",
                                    -class   => "borderBar"
                                   },
                                   join("\n",@foo) 
                                  ) 
                           ) 
                   );
}

1;

__END__

=head1 NAME

OSS::Template::SideLinks - Side Link Generator Class for use with OSS::Template

=head1 SYNOPSIS

  use OSS::Template;
  use OSS::Template::SideLinks;

  my $q = new OSS::Template;
  
  print $q->header();

  print $q->start_html( -title => 'SideLinks' );

  my $sideLinks = new OSS::Template::SideLinks();

  print $sideLinks->get_default();

  print $sideLinks->add_link( -text   => 'About OSS',
                              -link   => 'http://new.oss.buffalo.edu/',
                              -target => 'new',
                              -header => 'yes'
                            );

  print $sideLinks->add_link( -text   => 'Mission Statement',
                              -link   => 'http://new.oss.buffalo.edu/oss_mission.html',
                              -header => 'no'
                            );

  print $sideLinks->add_link( -text => 'Staff Directory',
                              -link => 'http://new.oss.buffalo.edu/Staff.html'
                            );

  print $sideLinks->display();

  print $q->end_html();

=head1 ABSTRACT

This perl library encapsulates side link creation and allows users to create the default side links or add side links they need without any knowledge of HTML,CSS,JS.

The current version of OSS::Template::SideLinks is available at

  http://nerf.cit.buffalo.edu/perl/

=head1 METHODS

=over 4

=item B<new()>

This method returns a new OSS::Template::SideLinks object.

This method has no flags.

=item B<add_link()>

This method adds a link to the side link area.

This method has the following flags:

B<-text>

The text that will appear for the href.

B<-link>

The url that the link will be directed to.

B<-target>

The target frame.  Default is blank.

B<-header>

The link must be a header or a sub link of a header.  YES/NO field.  Default is NO.

=item B<get_default()>

This method loads the default OSS links that are found in the database.

This method has no flags.

=item B<display()>

This method will return the side links display string.

=back

=head1 LICENSE INFORMATION

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO

L<OSS::Template>

=cut
