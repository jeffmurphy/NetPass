function netgroup_onchange_netgroups() {
	var o = document.getElementById("netgroups");
	if (!o) return;
	if (o.options[0].selected == true) { //IE
		o.options[0].selected == false;
		return;
	}
	document.forms[0].submit();
}

