/*
# $Header: /tmp/netpass/NetPass/www/htdocs/OSSTemplate/js/OSSTemplate.js,v 1.1 2004/09/24 01:05:21 jeffmurphy Exp $

#   (c) 2004 University at Buffalo.
#   Available under the "Artistic License"
#   http://www.gnu.org/licenses/license-list.html#ArtisticLicense
*/

function getObj(name)
{
  if (document.getElementById)
  {
        this.obj = document.getElementById(name);
        this.style = document.getElementById(name).style;
  }
  else if (document.all)
  {
        this.obj = document.all[name];
        this.style = document.all[name].style;
  }
  else if (document.layers)
  {
        this.obj = document.layers[name];
        this.style = document.layers[name];
  }
} // end func

function showHideObj (obj,link) {
        var x = new getObj(obj);
        if (x.style.display=="none"){
                x.style.display=""
    		re = /\+/gi;
                link.innerHTML=link.innerHTML.replace(re, "-");
        } else {
                x.style.display="none"
    		re = /\-/gi;
                link.innerHTML=link.innerHTML.replace(re, "+");
        }
} // end func

function hideObj (obj) {
        var x = new getObj(obj);
        x.style.display="none"
} // end func

function showObj (obj) {
        var x = new getObj(obj);
        x.style.display=""
} // end func

function open_save(url) {
        opts="top=0,left=0,scrollbars,status=no,menubar=yes,location=yes,toolbar=no,resizable=yes,fullsize=no,width=320,height=240";
        window.open(url, "Save", opts);
}

function hideAllTabPanes () {

    var expr = /^pane_/;

    var div_array = document.getElementsByTagName( "DIV" );

    for ( i=0; i < div_array.length; i++ ) {
        if ( expr.test( div_array[i].id ) ) {
            hideObj(div_array[i].id);
        }
    }
} // end func

function deactivateAllTabs () {
    var expr = /^tab_/;

    var div_array = document.getElementsByTagName( "TD" );

    for ( i=0; i < div_array.length; i++ ) {
        if ( expr.test( div_array[i].id ) ) {
            deactivateTab(div_array[i].id);
        }
    }

} // end func

function checkForm (formObj) {

    var all_errors = '';
    var div_array = formObj.getElementsByTagName( "input" );

    for ( i=0; i < div_array.length; i++ ) {

        if ( (div_array[i].getAttribute('required') == 1) && (div_array[i].value == '')) {
		var err = div_array[i].getAttribute('error');
		err = (err)?err: div_array[i].name + ' is required!';	
		all_errors += err + "\n";
		continue;
	}
        
	if ( (div_array[i].getAttribute('filter') != '')   &&
	     (div_array[i].getAttribute('filter') != null) && 
	     (div_array[i].value != '') 		     ) {

    		var expr = eval (div_array[i].getAttribute('filter'));
        	if ( !expr.test( div_array[i].value ) ) {
			var err = div_array[i].getAttribute('error');
			err = (err)?err: div_array[i].name + ' is not correctly formatted!';	
			all_errors += err + "\n";
			continue;
		}
        }
    }

    if(all_errors != '') {
	alert(all_errors);
    	return false;
    } else {
	return true;
    }

} // end func

function showPane (which) {
	var panename = 'pane_' + which;
	var tabname  = 'tab_'  + which;

	hideAllTabPanes();
	showObj(panename);
	
	deactivateAllTabs();
	activateTab(tabname);

	return false;
} // end func


function activateTab (which) {
        var x = new getObj(which);
        x.obj.className='tab_active';
} // end func

function deactivateTab (which) {
        var x = new getObj(which);
        x.obj.className='tab_inactive';
} // end func

function setCookie(cookieName,cookieValue,nDays) {
	var today  = new Date();
	var expire = new Date();
	if (nDays==null || nDays==0) nDays=1;

	expire.setTime(today.getTime() + 3600000*24*nDays);
 	document.cookie = cookieName+"="+escape(cookieValue) + ";expires="+expire.toGMTString();
}

