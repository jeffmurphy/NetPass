# $Header: /tmp/netpass/NetPass/lib/OSS/Template/Templates/Site.pm,v 1.1 2004/09/24 01:05:20 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense


package OSS::Template::Templates::Site;

use strict;
use OSS::Template;

my $resource_root = $OSS::Template::resource_root;


sub content {
	my $self	  = shift;
	my $resource_root = shift;

	return << "end_content";

<table width="100%" border="0" cellspacing="0" cellpadding="0" id="headerTable">
  <tr>
   <td colspan="2">&nbsp; </td>
  </tr>
  <tr>
    <td class="borderBar" valign="top" align="left"><img src="$resource_root/images/corner.gif" height="26" width="13" alt=""></td>
    <td width="100%" class="borderBar" valign="middle" align="left">
      <p class="sbLinks">UB NetPass __WHEREAMI__</p>
    </td>
  </tr>
</table>

<table width="100%" border="0" cellspacing="0" cellpadding="0" id="subHeaderTable">
  <tr>
    <td valign="middle" class="borderSubbar" height="30">
      <p class="sbHeader">&nbsp; University at Buffalo</p>
    </td>
    <td valign="middle" align="right" class="borderSubbar" height="30">
      <p class="sbHeader">Computing and Information Technology &nbsp; </p>
    </td>
  </tr>
</table>

<table width="100%" border="0" cellspacing="0" cellpadding="8">
  <tr>
    <td valign="top" width="99%">
      <!-- start middle content -->
	<br>
	[CONTENTAREA]

      <!-- end middle content -->
      <img src="$resource_root/images/clrpxl.gif" height="3" width="220" border="0" alt=""><br>
    </td>
  </tr>
</table>

<table width="100%" border="0" cellpadding="0" cellspacing="0">
  <tr>
    <td class="borderBar" style="height: 8px; border-top: solid 4px #FFFFFF;"></td>
  </tr>
  <tr>
    <td align=center>
      <p class="small">
        &copy; 2004 University at Buffalo
      </p>
        
      </p>
    </td>
  </tr>
</table>
</body>
</html>

end_content

}

1;

