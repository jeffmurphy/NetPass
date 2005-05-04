
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

function unHighLightList(oname, item) {
        var RN  = "unHighLightList";

        var acl = document.getElementById(oname);
        if (acl) {
                for(var i = 0 ; i < acl.options.length ; i++) {
                        if (i && item) {
                                if (item == acl.options[i].value)
                                        acl.options[i].selected = false;
                        } else {
                                acl.options[i].selected = false;
                        }
                }
        } else {
                dbg (1, RN + ": error cant find " + oname + " object");
        }
}


function highLightList(oname, item) {
        var RN  = "highLightList";

        var acl = document.getElementById(oname);
        if (acl) {
                for(var i = 1 ; i < acl.options.length ; i++) {
                        if (item) {
                                if (acl.options[i].value == item)
                                        acl.options[i].selected = true;
                        }
                        else {
                                acl.options[i].selected = true;
                        }
                }
        } else {
                dbg (1, RN + ": error cant find " + oname + " object");
        }
}


function disableList(oname) {
	var RN  = "disableList";

	var l = document.getElementById(oname);
	if (l) {
		for(var i = 1 ; i < l.options.length ; i++) {
			l.options[i].selected = false;
			l.options[i].disabled = true;
		}
	} else {
		dbg (1, RN + ": error cant find " + oname + " object");
	}
}

function enableList(oname) {
	var RN  = "enableList";

	var l = document.getElementById(oname);
	if (l) {
		for(var i = 1 ; i < l.options.length ; i++) {
			l.options[i].disabled = false;
		}
	} else {
		dbg (1, RN + ": error cant find " + oname + " object");
	}
}
