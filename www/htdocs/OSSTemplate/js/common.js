
function adjust_onClick(obj, fn) {
	if (browserType_IE) {
		obj.onclick = eval("x=function(e){"+fn+"}");
	} else {
		obj.setAttribute('ONCLICK', fn);
	}
}

function enable_element(o) {
	if (!o) return;
	var o2;
	if (typeof o == "string") {
		o2 = document.getElementById(o);
		if (!o2) return;
	} else {
		o2 = o;
	}
	o2.disabled = false;
}

function disable_element(o) {
	if (!o) return;

	var o2;

	if (typeof o == "string") {
		o2 = document.getElementById(o);
		if (!o2) return;
	}
	else {
		o2 = o;
	}

	o2.disabled = true;
}

function sortList(ln) {
	if (ln) {
		var l = document.getElementById(ln);
		if (l && l.options.length) {
			var oa = new Array();
			for (var i = 1 ; i < l.options.length ; i++) {
				oa[oa.length] = new Option( l.options[i].text, 
							    l.options[i].value, 
							    l.options[i].defaultSelected, 
							    l.options[i].selected);
				oa = oa.sort( function(a,b) {
						      if ((a.value+"") < (b.value+"")) { return -1; }
						      if ((a.value+"") > (b.value+"")) { return 1; }
						      return 0; } 
					      );
				for ( i = 0 ; i < oa.length ; i++) {
					l.options[i+1] = new Option(oa[i].text,
								    oa[i].value,
								    oa[i].defaultSelected,
								    oa[i].selected)
						;
				}
			}
		}
	}
}
