// when the radius server field changes,
// do a submit to refresh the page

function radius_onchange_radiusServer(prefix) {
	var RN = "radius_onchange_radiusServer";
	dbg (1, RN);
	var o = document.getElementById(prefix + 'radiusServer');
	for (var i = 1 ; i < o.options.length ; i++) {
		if (o.options[i].selected)
			document.forms[0].submit();
	}
}

function radius_onfocus_addServer(prefix) {
	var RN = "radius_onfocus_addServer";
	dbg (1, RN);
	var o = document.getElementById(prefix + 'radiusAddServer');
	if (o && o.value == "Add Server...") 
		o.value = '';
}

function radius_onblur_addServer(prefix) {
	var RN = "radius_onfocus_addServer";
	dbg (1, RN);
	var o = document.getElementById(prefix + 'radiusAddServer');
	var l = document.getElementById(prefix + 'radiusServer');
	if (o && l && o.value) {
		var oo = new Option (o.value, o.value, false, false);
		l.options[l.options.length] = oo;
		unHighLightList(prefix + 'radiusServer');
		sortList(prefix + 'radiusServer');
		radius_clear_fields(prefix);
	}
	o.value = 'Add Server...';
}

function radius_onclick_delServer() {
	var RN = "radius_onfocus_addServer";
	dbg (1, RN);
	var o = document.getElementById(prefix + 'radiusServer');
	if (o) {
		for (var i = o.options.length-1 ; i > 0 ; i--) {
			if (o.options[i].selected)
				o.options[i] = undefined;
		}
	}
}

function radius_clear_fields(prefix) {
	var o = document.getElementById(prefix + 'radiusSecret');
	if (o) o.value = '';
}
