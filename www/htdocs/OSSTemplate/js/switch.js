function switch_onclick_submitButton() {
	var RN = "switch_onclick_submitButton";
	dbg(1, RN);
	var vm = document.getElementById('vlanmap');
	if (vm) {
		for (var i = vm.options.length-1 ; i > 0 ; i--) {
			vm.options[i].selected = true;
		}
	} else {
		dbg (1, RN + ": cant find vlanmap field");
	}
	return false;
}

function switch_onfocus_addSwitch(o) {
	var RN = "switch_onfocus_addSwitch";
	dbg(1, RN);
	if (o && o.value == "Add Switch...") o.value = '';
}

function switch_onblur_addSwitch(o) {
	var RN = "switch_onblur_addSwitch";
	dbg(1, RN);
	var sw = document.getElementById('switch');
	if (sw && o.value != '') {
		if ( o.value.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) ) {
                        var exists = false;
                        for(var i = 1 ; i < sw.options.length ; i++) {
                                if (sw.options[i].value == o.value) exists = true;
                        }
                        if (!exists) {
                                var no = new Option(o.value, o.value, false, false);
                                sw.options[sw.options.length] = no;
                                unHighLightList("switch");
                                sw.options[sw.options.length-1].selected = true;
                                sortList("switch");
                        } else {
                                dbg (1, RN + ": switch already exists: " + o.value);
                        }
                } else {
                        dbg (1, RN + ": " + o.value + " not an IP address.");
                }

	}
	o.value = 'Add Switch...';
}

function switch_onchange_switch() {
	var RN = "switch_onchange_switch";
	dbg (1, RN);
	var o = document.getElementById("switch");
	if (!o) return;
	if(o.options[0].selected == true) { //IE
		o.options[0].selected == false;
		return;
	}

	document.forms[0].submit();
}

function switch_onblur_addVlan(o) {
	var RN = "switch_onblur_addVlan";
	dbg(1, RN);
	var vm = document.getElementById('vlanmap');
	if (vm && o.value != '') {
		if (o.value.match(/^[\d\-\,]+:\d+\/\d+/)) {
			var exists = false;
			for (var i = 1 ; i < vm.options.length ; i++) {
				if (vm.options[i].value == o.value) exists = true;
			}
			if (!exists) {
                                var no = new Option(o.value, o.value, false, false);
                                vm.options[vm.options.length] = no;
                                unHighLightList("vlanmap");
                                vm.options[vm.options.length-1].selected = true;
                                sortList("vlanmap");				
			} else {
				dbg (1, RN + ": " + o.value + " already exists in vlanmap");
			}
		} else {
			dbg(1, RN + ": " + o.value + " does not match /^[\d\-\,]+:\d+\/\d+/");
		}
	}
	o.value = 'Add Vlan Map...';
}

function switch_onfocus_addVlan(o) {
	var RN = "switch_onfocus_addVlan";
	dbg(1, RN);
	if (o && o.value == "Add Vlan Map...") o.value = '';
}

function switch_onclick_deleteVlan() {
	var RN = "switch_onclick_deleteVlan";
	dbg(1, RN);
	var vm = document.getElementById('vlanmap');
	if (vm) {
		for (var i = vm.options.length-1 ; i > 0 ; i--) {
			if (vm.options[i].selected) {
				vm.options[i] = undefined;
			}
		}
	} else {
		dbg (1, RN + ": cant find vlanmap field");
	}
	return false;
}
