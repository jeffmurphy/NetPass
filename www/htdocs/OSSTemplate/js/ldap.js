// when the ldap server field changes,
// do a submit to refresh the page

function ldap_onchange_ldapServer(prefix) {
	var RN = "ldap_onchange_ldapServer";
	dbg (1, RN);
	var o = document.getElementById(prefix + 'ldapServer');
	for (var i = 1 ; i < o.options.length ; i++) {
		if (o.options[i].selected)
			document.forms[0].submit();
	}
}

function ldap_onfocus_addServer(prefix) {
	var RN = "ldap_onfocus_addServer";
	dbg (1, RN);
	var o = document.getElementById(prefix + 'ldapAddServer');
	if (o && o.value == "Add Server...") 
		o.value = '';
}

function ldap_onblur_addServer(prefix) {
	var RN = "ldap_onfocus_addServer";
	dbg (1, RN);
	var o = document.getElementById(prefix + 'ldapAddServer');
	var l = document.getElementById(prefix + 'ldapServer');
	if (o && l && o.value) {
		var oo = new Option (o.value, o.value, false, false);
		l.options[l.options.length] = oo;
		unHighLightList(prefix + 'ldapServer');
		sortList(prefix + 'ldapServer');
		ldap_clear_fields(prefix);
	}
	o.value = 'Add Server...';
}

function ldap_onclick_delServer() {
	var RN = "ldap_onfocus_addServer";
	dbg (1, RN);
	var o = document.getElementById(prefix + 'ldapServer');
	if (o) {
		for (var i = o.options.length-1 ; i > 0 ; i--) {
			if (o.options[i].selected)
				o.options[i] = undefined;
		}
	}
}

function ldap_clear_fields(prefix) {
	var o = document.getElementById(prefix + 'ldapBase');
	if (o) o.value = '';
	o = document.getElementById(prefix + 'ldapFilter');
	if (o) o.value = '';
	o = document.getElementById(prefix + 'ldapPasswordField');
	if (o) o.value = '';
}
