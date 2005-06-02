function network_show_haOptions() {
	var i    = 1;
	var done = false;
	while (!done) {
		var fn = 'haOptions'+ i++;
		var o = document.getElementById(fn);
		if (o)
			o.style.display = "";
		else
			done = true;
	}
}

function network_hide_haOptions() {
	var i    = 1;
	var done = false;
	while (!done) {
		var fn = 'haOptions' + i++;
		var o = document.getElementById(fn);
		if (o)
			o.style.display = "none";
		else
			done = true;
	}
}

function network_onchange_haToggle(o) {
	if (o && o.value) {
		if (o.value == "Enabled")  network_show_haOptions();
		if (o.value == "Disabled") network_hide_haOptions();
	}
}


function network_show_garpOptions() {
	var i    = 1;
	var done = false;
	while (!done) {
		var fn = 'garpOptions'+ i++;
		var o = document.getElementById(fn);
		if (o)
			o.style.display = "";
		else
			done = true;
	}
}

function network_hide_garpOptions() {
	var i    = 1;
	var done = false;
	while (!done) {
		var fn = 'garpOptions' + i++;
		var o = document.getElementById(fn);
		if (o)
			o.style.display = "none";
		else
			done = true;
	}
}

function network_onchange_garpToggle(o) {
	if (o && o.value) {
		if (o.value == "Enabled")  network_show_garpOptions();
		if (o.value == "Disabled") network_hide_garpOptions();
	}
}



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

function network_onclick_submitButton() {
	highLightList("haNPServers");
	highLightList("switches");
	document.forms[0].submit();
}


function network_onblur_addHaNPServer(o) {
	var RN = "network_onblur_addServer";
	dbg(1, RN);
	var servs = document.getElementById('haNPServers');
	if (servs && o && o.value != "") {
		var exists = false;
		for(var i = 0 ; i < servs.options.length ; i++) {
			if (servs.options[i].value == o.value) exists = true;
		}
		if (!exists) {
			var no = new Option(o.value, o.value, false, false);
			servs.options[servs.options.length] = no;
			unHighLightList("haNPServers");
			servs.options[servs.options.length-1].selected = true;
			sortList("haNPServers");
		} else {
			dbg (1, RN + ": server already exists: " + o.value);
		}
	}
	if (o) o.value = "Add Server...";
	return false;
}

function network_onfocus_addHaNPServer(o) {
	var RN = "network_onblur_addHaNPServer";
	dbg(1, RN);
	if (o && o.value == "Add Server...") o.value = '';
}

function network_onclick_delHaNPServer() {
	var RN = "network_delHaNPServer";
	dbg (1, RN);

	var servs = document.getElementById('haNPServers');
	if (servs) {
		// element 0 is the WH
		for(var i = servs.options.length-1 ; i > 0 ; i--) {
			if (servs.options[i].selected) {
				// you cant delete yourself.
				if (servs.options[i].value != network_ourHostname) {
					dbg(1, RN + ": del " + servs.options[i].value);
					servs.options[i] = undefined;
				}
			}
		}
	}
	return false;
}

function network_onclick_cfgSwitch() {
	var switches = document.getElementById('switches');
	if (switches) {
		for(var i = 0 ; i < switches.options.length ; i++) {
			if (switches.options[i].selected) {
				document.location.href = 'switch.mhtml?switch=' +
					switches.options[i].value;
			}
		}
	}
	return false;
}

function network_onclick_delSwitch() {
	var switches = document.getElementById('switches');
	if (switches) {
		// element 0 is WH
		for(var i = switches.options.length-1 ; i > 0 ; i--) {
			if (switches.options[i].selected) 
				switches.options[i] = undefined;
		}
	}
	return false;
}


function network_onblur_addSwitch(o) {
	var RN = "network_onblur_addSwitch";
	dbg(1, RN);
	var servs = document.getElementById('switches');
	if (servs && o && o.value != "") {
		var exists = false;
		for(var i = 0 ; i < servs.options.length ; i++) {
			if (servs.options[i].value == o.value) exists = true;
		}
		if (!exists) {
			var no = new Option(o.value, o.value, false, false);
			servs.options[servs.options.length] = no;
			unHighLightList("switches");
			servs.options[servs.options.length-1].selected = true;
			sortList("switches");
		} else {
			dbg (1, RN + ": switch already exists: " + o.value);
		}
	}
	if (o) o.value = "Add Switch...";
	return false;
}

function network_onfocus_addSwitch(o) {
	var RN = "network_onblur_addSwitch";
	dbg(1, RN);
	if (o && o.value == "Add Switch...") o.value = '';
}

