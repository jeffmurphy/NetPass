# $Header: /tmp/netpass/NetPass/lib/OSS/Template.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

package OSS::Template;

$OSS::Template::revision = '$Id: Template.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $';
$OSS::Template::VERSION  = '1.0';

use CGI;
use OSS::Template::Templates::Site;

@ISA  = qw( CGI );

my $resource_root  = '/OSSTemplate';

sub new {
    my($class,%param) = @_;

    # Create the anonymous hash reference and bless it
    # into the proper class. This permits inheritance.

    my $self = new CGI(%param);
    bless $self, ref($class) || $class;
	
    $self->{'content'} = OSS::Template::Templates::Site->content($resource_root);

    return($self);
}

sub start_html {

    my($self, %data) = @_;

    ($self->{'head'}, $self->{'foot'}) = (" ", " ");

    my $css = [
		"$resource_root/css/OSSTemplate.css.cgi",
		"$resource_root/css/site.css",
		"$resource_root/css/calendar.css"
	      ];

    my $js  = [
		{
		 -language => 'JavaScript',
		 -src      => "$resource_root/js/OSSTemplate.js"
	      	},
		{
		 -language => 'JavaScript',
		 -src      => "$resource_root/js/cal/calendar.js"
	      	},
		{
		 -language => 'JavaScript',
		 -src      => "$resource_root/js/cal/calendar-setup.js"
	      	},
		{
		 -language => 'JavaScript',
		 -src      => "$resource_root/js/cal/calendar-en.js"
	      	},
		{
		 -language => 'JavaScript',
		 -src      => "$resource_root/js/menu/menu_src.js"
	      	},
		{
		 -language => 'JavaScript',
		 -src      => "$resource_root/js/menu/menu_dom.js"
	      	}
	      ];

    if(ref($data{-style}{-src}) eq 'ARRAY') {
    	push(@$css, @{$data{-style}{-src}});
    } else {
	push(@$css, $data{-style}{-src}) if($data{-style}{-src});
    }
    $data{-style}{-src} = $css;

    if(ref($data{-script}) eq 'ARRAY') {
	push(@$js, @{$data{-script}});
    } else {
	push(@$js, $data{-script}) if($data{-script});
    }
    $data{-script} = $js;
    
    return $self->SUPER::start_html( %data ) if($data{-printable});

    ($self->{'head'}, $self->{'foot'}) = $self->getTemplate(%data);

    return $self->SUPER::start_html( %data ) . $self->{'head'};
}

sub end_html {

    my($self, %data) = @_;
    return $self->SUPER::end_html( %data ) if($data{-printable});
    return $self->{'foot'} . $self->SUPER::end_html( %data );
}

sub start_form {

    my($self, %data)    = @_;

    # allow onSubmit to be over-written
    $data{-onSubmit} = 'return checkForm(this);' if(!$data{-onSubmit});
    
    return $self->SUPER::start_form( %data );

}

sub startform {
    my($self, %data)    = @_;

    return $self->start_form(%data);
}


sub datefield {

    my($self, %data)    = @_;
    my $datefield	= '';
    
    $data{-id}     = $data{-name} if(!$data{-id});
    $data{-format} = '%Y/%m/%d'   if(!$data{-format});

    my $showsTime = ($data{-format}=~/\%M/)?'true':'false';

    my $button_id	= "trigger_" . $data{-id};

    $datefield .= $self->SUPER::textfield(%data);
    $datefield .= $self->SUPER::reset( 	-name  => '...',
					-id    => $button_id
				     );

    $datefield .= "<script type=\"text/javascript\">Calendar.setup({ inputField:\"$data{-id}\", button:\"$button_id\", ifFormat:\"$data{-format}\", showsTime: $showsTime });</script>";

    return $datefield;
}

sub getTemplate {
	my($self, %data) = @_;

        $self->replace("__WHEREAMI__", $self->whereami());
        $self->replace("__URI__", $self->url);
	$self->setUser();

	if($data{-updated}) {
        	$self->replace( "__LASTUPDATE__", "Last Updated: " . $data{-updated});
	}

	if($data{-edit}) {
        	$self->enable("MNG");
	}

	# kill any tags we missed or haven't set...
	$self->replace('__\w+__', "");

	return split(/\[CONTENTAREA\]/, $self->{'content'});

}

sub resource_root {
	return $resource_root;
}

sub replace {
	my ($self, $string, $val) = @_;
	$self->{'content'} =~ s/$string/$val/g;
	return;
}

sub enable {
        my ($self, $target) = @_;

        my $scom  = "<!--";
        my $ecom  = "-->";

        my $start = "<!--toggle::$target";
        my $end   = "toggle::$target-->";

	$self->{'content'} =~ s/$start/$start $ecom/g;
	$self->{'content'} =~ s/$end/$scom $end/g;

        return;
}

sub setUser {
        my ($self) = @_;

	# figure this out
	#XXX
	return;
	#my($uid) = split(':', $self->cookie('OSS::AuthCookieHandler_OSSINT'));
	my($uid) = split(':', $self->cookie('PROD::AuthCookieHandler_OSSINT'));
        
	if(!defined($uid) ) {
                $self->enable( "LOGIN" );
                $self->replace( "__LOGINURL__", "/login.pl" );
        } else {
                $self->replace( "__USERID__", $uid );
                $self->replace( "__LOGOUTURL__", "/?logout=1" );
               $self->enable ( "LOGOUT" );
        }
        return;
}

sub whereami {
        my ($self) = @_;

	my $name_of_home        = 'Home';
	my $joining_character   = ' &gt; ';

	my $whereami = '';
	my @urlparts = ();
	my $urlpath  = '/';
	my @uri      = split '/', $self->url(-absolute => 1);

	# check hostname then
	# unshift (@uri, "netstats");

	while (@uri) {
        	my $original = shift @uri;
        	my $display = $original;
        	$display =~ s:\.html$::;
        	$display =~ s:\.htm$::;
        	$display =~ s:\.cgi$::;
        	$display =~ s:index$::;
        	$display =~ s:/::;
        	$display =~ tr/_/ /;

        	push @urlparts, {
                	         display  => ucfirst($display),
                        	 original => $original
                  	      };
	}

	@urlparts = grep { $_->{original} ne '' && $_->{display} ne '' } @urlparts;

	@uri = map {
        	    $urlpath = sprintf("%s%s",$urlpath,$_->{original});
           	    $urlpath .= '/' unless $_->{original} =~ m:html$:;
                    sprintf(qq{<a href="%s">%s</a>},$urlpath,$_->{display});
                   } @urlparts;

	$whereami = join $joining_character,qq{<a href="/">$name_of_home</a>},@uri;

	return $whereami;

}

1;

__END__

=head1 NAME

OSS::Template - OSS CGI Template Class

=head1 SYNOPSIS

  use OSS::Template;

  my $q = new OSS::Template;

  print $q->header();

  print $q->start_html(
                        -title     => 'Testing!',
                        -updated   => 'Dec 20 2004'
                    );

  print $q->start_form();

  print $q->textfield( 	-name      => 'ip_address',
               		-size      => 50,
               		-maxlength => 80,
               		-required  => 1,
               		-filter    => '/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/',
               		-error     => 'Shucks, the ip field must be filled in correctly e.g. 128.205.10.10'
                     );

  print $q->br();

  print $q->datefield(	-name     => 'date1',
              		-size     => 20,
              		-format   => '%Y/%m/%d %H:%M',
              		-onUpdate => 'alert('done!);',
             	     );


  print $q->end_form();

  print $q->end_html();


=head1 ABSTRACT

This perl library extends CGI.pm in order to make existing scripts
easier to port and to allow for easy usage.

Other modules in the OSS::Template directory provide additional
utilities for making web work easier.

The current version of OSS::Template is available at

  http://nerf.cit.buffalo.edu/perl/


The current version of CGI.pm is available at

  http://www.genome.wi.mit.edu/ftp/pub/software/WWW/cgi_docs.html
  ftp://ftp-genome.wi.mit.edu/pub/software/WWW/

=head1 NEW FEATURES ADDED TO THE CGI OBJECT

=over 4

=item B<start_html()>

This method inserts site-specific CSS, JS, and HTML to the
output of the CGI::start_html. All functions and features of the
original are still available.

This method was extended to include 1 new flag:

B<-updated>

This flag is used to populate the 'updated' field at the bottom
of the template. If this field is not used, the 'updated' field
will not be displayed.

=item B<end_html()>

This method was extended to insert site-specific CSS, JS, and HTML to
the output of the CGI::end_html. All functions and features of the
original are still available.

=item B<start_form()>

This method was extended to insert a JS function call onSubmit that
checks the form for required fields and filters that are set using
the textfield method. All functions and features of the original are 
still available, with the exception of the B<-onSubmit> flag. 
Currently, any value passed in via B<-onSubmit> will be overwritten.
This will be fixed in upcoming versions.

=item B<textfield()>

This method was extended to include 3 new flags:

B<-filter>

When this flag is set to a regular expression, the form will throw
an error if any input in the field does not match the filter. This
flag can be used in conjunction with -required to make a field that
is required and must match a certain pattern.

B<-required>

When this flag is set to 1, the form will throw an error if the field
is not filled in. This flag can be used in conjunction with -filter
to make a field that is required and must match a certain pattern.

B<-error>

When this flag is set, it will replace the default error message.

=item B<datefield()>

This is a completely new field type that generates a textfield with an attached
calendar object for selecting dates and times.

This method has the following flags:

B<-name>

The name of the datefield

B<-size>

The size of the datefield

B<-format>

A strftime() format string that specifies how you want the date/time formatted.
If this string contains any time formating options, then a clock will also be
displayed within the calendar.

B<-onUpdate>

A chunk of javascript that you want executed when the time is updated via the
calendar.

=back

=head1 LICENSE INFORMATION

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

L<OSS::Template>

L<OSS::Template::Menu>

L<OSS::Template::TabArea>

L<OSS::Template::SideLinks>

=cut


