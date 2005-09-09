
function lockConfig_results(r) {
	var RN = "lockConfig_results";

	dbg(1, RN + ": r="+r);

	var b = document.getElementById('lockButton');
	if (b) {
		b.disabled = '';
		b.innerHTML = "Lock Config";
	}
	lockOpPending = false;
	var ra = r.split(/\s+/);
	var i = 0;
	while (i < ra.length && ra[i] != "OK" && ra[i] != "NOK") { i++ }

	if (ra[i] == "OK") {
		// something succeeded
		if (ra[i+1] == "lock") {
			// we got the lock, change button to
			// green and text to 'unlock'
			b.style.backgroundColor = '#77FF77';
			b.innerHTML = 'Config is Locked (by you)<BR>Unlock Config';
			adjust_onClick(b, "return lockConfig(0, 0);");
			lockConfig_enableElements();
		} else {
			// we got the unlock, button -> yellow
			// text -> 'lock'
			b.style.backgroundColor = '#FFFF77';
			b.innerHTML = 'Config is Unlocked<BR>Lock Config';
			adjust_onClick(b, "return lockConfig(1, 0);");
			lockConfig_disableElements();
		}
	} else {
		// something failed

		if (ra[i+1] == "lock") {
			// we didnt get the lock, change button to
			// red and text to 'force lock'
			b.style.backgroundColor = '#FF7777';
			b.innerHTML = 'Config is Locked by '+ra[i+2]+'<BR>Force Lock Config';
			adjust_onClick(b, "return lockConfig(1, 1);");
			lockConfig_disableElements();
		} else {
			// we didnt get the unlock, 
			// button -> red
			// text -> 'force unlock'
			b.style.backgroundColor = '#FF7777';
			b.innerHTML = 'Config is Locked by '+ra[i+2]+'<BR>Force Unlock Config';
			adjust_onClick(b, "return lockConfig(0, 1);");
			lockConfig_disableElements();
		}
	}
}

function lockConfig(lock, force) {
	// lock: 0 = unlock, 1 = lock
	// force: 0 = no, 1 = yes

	if (lockOpPending) return;

	var b = document.getElementById('lockButton');
	if (b) {
		b.innerHTML = "Wait ...";
		adjust_onClick(b, "return false;");
		b.disabled = true;
	}

	lockOpPending = true;
	var url = "/Admin/cmd/lockcfg.mhtml?printable=2&lock=" 
		+ lock 
		+ "&force=" + force
		+ "&npsess=" + session_id;
	xmlhttp.open("GET", url , true);
	xmlhttp.onreadystatechange=function() {
		if (xmlhttp.readyState == 4) {
			lockConfig_results(xmlhttp.responseText);
		}
	};
	xmlhttp.send(null);
	return false;
}

function lockConfig_enableElements() {
	if (lockConfig_EE.length) {
		for (var i = 0 ; i < lockConfig_EE.length ; i++) {
			enable_element(lockConfig_EE[i]);
		}
	}
}

function lockConfig_disableElements() {
	if (lockConfig_EE.length) {
		for (var i = 0 ; i < lockConfig_EE.length ; i++) {
			disable_element(lockConfig_EE[i]);
		}
	}
}

function lockConfig_show_unlock() {
	var b = document.getElementById('lockButton');
}
