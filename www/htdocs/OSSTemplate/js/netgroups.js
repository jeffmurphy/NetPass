function netgroup_onchange_netgroups() {
	var RN = "netgroup_onchange_netgroups";

	var o = document.getElementById("netgroups");
	if (!o) return;
	if (o.options[0].selected == true) { //IE
		o.options[0].selected == false;
		return;
	}

	var ngn = o.options[o.selectedIndex].value;
	var nw  = document.getElementById("networks");
	unHighLightList("networks");

	dbg(1, RN + ": populate networks..");
	for (var i = 1 ; i < nw.options.length ; i++) {
		dbg (1, RN + ": (" + nw.options[i].value + ") " + netgroup_Map[nw.options[i].value][0] + " =? " + ngn);
		if (netgroup_Map[nw.options[i].value][0] == ngn) {
			nw.options[i].selected = true;
		} else {
			nw.options[i].selected = false;
		}
	}
	document.forms[0].submit();
}

function netgroup_onchange_networks() {
	var RN = "netgroup_onchange_networks";
}


function netgroup_onfocus_addNetgroup(o) {
	var RN = "netgroup_onfocus_addNetgroup";
	dbg(1, RN);
	if (o && o.value == "Add Netgroup...") o.value = "";
}

function netgroup_onblur_addNetgroup(o) {
	var RN = "netgroup_onblur_addNetgroup";
	dbg(1, RN);

	var ng = document.getElementById("netgroups");
	var nw = document.getElementById("networks");

	if (ng && nw && o.value != "") {
		if (netgroup_reservedGroups[o.value] == undefined) {
			var exists = 0;
			for(var i = 1 ; i < ng.options.length ; i++) {
				if (ng.options[i].value == o.value) {
					exists = 1;
				}
			}
			// you can't name a netgroup the same as a network.
			for(var i = 1 ; i < nw.options.length ; i++) {
				if (nw.options[i].value == o.value) {
					exists = 1;
				}
			}
			if (!exists) {
				var no = new Option(o.value, o.value, false, false);
				ng.options[ng.options.length] = no;
				unHighLightList("netgroups");
				ng.options[ng.options.length-1].selected = true;
				sortList("netgroups");
			} else {
				dbg (1, RN + ": group already exists: " + o.value);
			}
		} else {
			dbg (1, RN + ": group name is reserved: " + o.value);
		}
	}
	o.value = "Add Netgroup...";
}
