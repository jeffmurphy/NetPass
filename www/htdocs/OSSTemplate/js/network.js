
function network_onblur_addNetwork(o) {
	var RN = "network_onblur_addNetwork";
	dbg(1, RN);
	var nw = document.getElementById('network');
	if (nw && o.value != "") {
		if ( o.value.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+$/) ) {
			var exists = false;
			for(var i = 1 ; i < nw.options.length ; i++) {
				if (nw.options[i].value == o.value) exists = true;
			}
			if (!exists) {
				var no = new Option(o.value, o.value, false, false);
				nw.options[nw.options.length] = no;
				unHighLightList("network");
				nw.options[nw.options.length-1].selected = true;
				sortList("network");
			} else {
				dbg (1, RN + ": network already exists: " + o.value);
			}
		} else {
			dbg (1, RN + ": " + o.value + " not in CIDR notation.");
		}
	}
	o.value = "Add Network...";
}

function network_onfocus_addNetwork(o) {
	var RN = "network_onblur_addNetwork";
	dbg(1, RN);
	if (o && o.value == "Add Network...") o.value = '';
}

function network_onchange_network() {
	var RN = "network_onchange_network";
	dbg (1, RN);
	var o = document.getElementById("network");
	if (!o) return;
	if(o.options[0].selected == true) { //IE
		o.options[0].selected == false;
		return;
	}

	document.forms[0].submit();
}
