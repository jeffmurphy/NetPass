// when the ldap server field changes,
// do a submit to refresh the page

function ldap_xh_results_getLDAP(r, prefix) {
	var RN = "ldap_xh_results_getLDAP";

	var sf = document.getElementById(prefix + "ldapBase");
	if (!sf) return;

	var ra = r.split(/\s+/);
	var i  = 0;
	while (i < ra.length && ra[i] != "OK" && ra[i] != "NOK") { i++ }
	if (ra[i] == "OK") {
		sf.value = ra[2];
		sf = document.getElementById(prefix + "ldapFilter");
		if (sf) sf.value = ra[3];
		sf = document.getElementById(prefix + "ldapPasswordField");
		if (sf) sf.value = ra[4];
	} else {
		alert("failed to getSecret " + r);
	}
}

function ldap_xh_results_setLDAP(r, prefix) {
	var RN = "ldap_xh_results_setLDAP";

	var ra = r.split(/\s+/);
	var i  = 0;
	while (i < ra.length && ra[i] != "OK" && ra[i] != "NOK") { i++ }
	if (ra[i] == "OK") {
		alert("LDAP setting changed");
	} else {
		alert("failed to set LDAP setting " + r);
	}
}

function ldap_onchange_ldapServer(prefix) {
	var RN = "ldap_onchange_ldapServer";
	dbg (1, RN);
	var o = document.getElementById(prefix + 'ldapServer');
	var gotOne = false;
	for (var i = 1 ; i < o.options.length ; i++) {
		if (o.options[i].selected) {
			gotOne = true;
			xh_post("/Admin/cmd/getLDAP.mhtml?server=" + 
				o.options[i].value, "ldap_xh_results_getLDAP", prefix);
		}
	}
	if (!gotOne) ldap_clear_fields(prefix);
}

function ldap_onblur_ldapBase(prefix) {
	var RN = "ldap_onblur_ldapBase";
	dbg (1, RN);
	var s = document.getElementById(prefix + 'ldapServer');
	var f = document.getElementById(prefix + 'ldapBase');
	if (f && s && (f.value != '') && (s.selectedIndex > 0)) {
		xh_post("/Admin/cmd/setLDAP.mhtml?server=" +
			s.options[s.selectedIndex].value + 
			"&base=" + f.value,
			"ldap_xh_results_setLDAP", prefix);
	}
}

function ldap_onblur_ldapFilter(prefix) {
	var RN = "ldap_onblur_ldapFilter";
	dbg (1, RN);
	var s = document.getElementById(prefix + 'ldapServer');
	var f = document.getElementById(prefix + 'ldapFilter');
	if (f && s && (f.value != '') && (s.selectedIndex > 0)) {
		xh_post("/Admin/cmd/setLDAP.mhtml?server=" +
			s.options[s.selectedIndex].value + 
			"&filter=" + f.value,
			"ldap_xh_results_setLDAP", prefix);
	}
}

function ldap_onblur_ldapPasswordField(prefix) {
	var RN = "ldap_onblur_ldapPasswordField";
	dbg (1, RN);
	var s = document.getElementById(prefix + 'ldapServer');
	var f = document.getElementById(prefix + 'ldapPasswordField');
	if (f && s && (f.value != '') && (s.selectedIndex > 0)) {
		xh_post("/Admin/cmd/setLDAP.mhtml?server=" +
			s.options[s.selectedIndex].value + 
			"&passwordField=" + f.value,
			"ldap_xh_results_setLDAP", prefix);
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
	var RN = "ldap_onblur_addServer";
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
				o.options[i] = null; // IE doesnt like undefined;
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
