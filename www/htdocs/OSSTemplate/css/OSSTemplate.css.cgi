#!/usr/bin/perl -w

# $Header: /tmp/netpass/NetPass/www/htdocs/OSSTemplate/css/OSSTemplate.css.cgi,v 1.1 2004/09/24 01:05:21 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense

use strict;
use OSS::Template;

my $q = new OSS::Template;

print $q->header(-type=>'text/css');

my $resource_root = $q->resource_root();

print << "END_PRINT";

.tab_table {
	padding: 0px;
	margin:  0px;
	width:  100%;
	border-collapse: collapse;
}

.tab_active {
	width: 10%;
	padding: 5px;
	margin: 0px;
	font-weight: bold;
	border-top: 1px solid black;
	border-right: 1px solid black;
	border-left: 1px solid black;
}

.tab_active a {
	color: black;
	text-decoration: none;

}

.tab_inactive a {
	color: black;
	text-decoration: none;
}

.tab_inactive {
	width: 10%;
	padding: 5px;
	margin: 0px;
	font-weight: bold;
	/* the background image looks great... BUT images defeat the purpose! */
	background: url($resource_root/images/TabArea/bg_tab.gif) left bottom repeat-x #CCCCCC;
	border-top: 1px solid black;
	border-right: 1px solid black;
	border-left: 1px solid black;
}

.no_tab {
	height: 25px;
	width: 80%;
	border-bottom: 1px solid black;;
}

.tabpanearea {
	border-right: 1px solid black;
	border-left: 1px solid black;
	border-bottom: 1px solid black;
	border-top: 0px solid black;
	padding: 6px;
}

.box {
	border-collapse: collapse;
}

.boxContent {
	border: 1px solid black;
	padding: 5px;
        background: #EFEFEF;
	
}

.boxHeader {
	border: 1px solid black;
	padding-left: 3px;
	padding-right: 3px;
	padding-top: 1px;
	padding-bottom: 1px;
        color: #FFFFFF;
        background: #000000;
        font-weight: bold;
	height: 20px;
}

.boxHeaderDeact {
        color: #FFFFFF;
        background: #111111;
        font-weight: bold;
}


END_PRINT

exit;

