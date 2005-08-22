// when the radius server field changes,
// do a submit to refresh the page

function radius_xh_results_getSecret(r, prefix) {
	var RN = "radius_xh_results_getSecret";

	var sf = document.getElementById(prefix + "radiusSecret");
	if (!sf) return;

	var ra = r.split(/\s+/);
	var i  = 0;
	while (i < ra.length && ra[i] != "OK" && ra[i] != "NOK") { i++ }
	if (ra[i] == "OK") {
		sf.value = ra[2];
	} else {
		alert("failed to getSecret " + r);
	}
}

function radius_xh_results_setSecret(r, prefix) {
	var RN = "radius_xh_results_setSecret";

	var ra = r.split(/\s+/);
	var i  = 0;
	while (i < ra.length && ra[i] != "OK" && ra[i] != "NOK") { i++ }
	if (ra[i] == "OK") {
		alert("secret changed");
	} else {
		alert("failed to setSecret " + r);
	}
}

function radius_onchange_radiusServer(prefix) {
	var RN = "radius_onchange_radiusServer";
	dbg (1, RN);
	var o = document.getElementById(prefix + 'radiusServer');
	var gotOne = false;
	for (var i = 1 ; i < o.options.length ; i++) {
		if (o.options[i].selected) {
			gotOne = true;
			xh_post("/Admin/cmd/getRadiusSecret.mhtml?server=" + 
				o.options[i].value, "radius_xh_results_getSecret", prefix);
		}
	}
	if (!gotOne) {
		var sf = document.getElementById(prefix + "radiusSecret");
		sf.value = '';
	}
}

function radius_onblur_radiusSecret(prefix) {
	var RN = "radius_onblur_radiusSecret";
	dbg (1, RN);
	var sc = document.getElementById(prefix + 'radiusSecret');
	var sv = document.getElementById(prefix + 'radiusServer');

	if ( sc && sv && (sc.value != '') && (sv.selectedIndex > 0) ) {
		xh_post("/Admin/cmd/setRadiusSecret.mhtml?server=" +
			sv.options[sv.selectedIndex].value + 
			"&secret=" + sc.value,
			"radius_xh_results_setSecret", prefix);
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

function radius_onclick_delServer(prefix) {
	var RN = "radius_onclick_delServer";
	dbg (1, RN);
	var o = document.getElementById(prefix + 'radiusServer');
	if (o) {
		for (var i = o.options.length-1 ; i > 0 ; i--) {
			if (o.options[i].selected)
				o.options[i] = null; //IE doesnt like undefined;
		}
	}
}

function radius_clear_fields(prefix) {
	var o = document.getElementById(prefix + 'radiusSecret');
	if (o) o.value = '';
}

