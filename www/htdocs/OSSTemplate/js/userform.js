// userform.js

function userform_changeToUser(o) {
	var RN = "userform_changeToUser";

	dbg(1, RN);

	var gl  = document.getElementById('GroupList');
	var agl = document.getElementById('AvailableGroupList');

	// figure out what's been selected.

	var selectedUser = undefined; 

	userform_unHighLight("AvailableGroupList");
	userform_unHighLight("AccessControlList");
	userform_disableList("AccessControlList");

	// IE doesnt support <option disabled>
	//http://msdn.microsoft.com/workshop/author/dhtml/reference/properties/disabled_3.asp

	o.options[0].selected = false;

	// we should use selectedIndex here

	for (var i = 0 ; i < o.options.length ; i++) {
		if (o.options[i].selected) {
			selectedUser = o.options[i];
			break;
		}
	}

	if (selectedUser == undefined) {
		dbg (1, RN + ": no user selected?");

		if (usingAuthDB) {
			var pwd = document.getElementById('passwdDialog');
			pwd.style.display = 'none';
		}
		return;
	}

	if (gl && agl && (userhash[selectedUser.value] != undefined) ) {
		// unhighlight the GroupList and AccessControlList

		var glo;
		for (var i = gl.options.length-1 ; i ; i--) {
			glo = gl.options[i];
			if (glo) {
				glo.selected = false;
				if (browserType_IE) gl.options[i] = null;
				agl.options[agl.options.length] = glo;
			} else {
				dbg(1, RN + ": " + gl.options.length + 
				    " move to available: glo=NULL options["+i+"]");
			}
		}

		dbg(1, RN + ": unhighlight ACL");

		userform_unHighLight("AccessControlList");

		// populate the grouplist with the currently
		// selected user's groups, removing them from the
		// availablegrouplist

		var mygroup;
		for(mygroup in userhash[selectedUser.value]) {
			dbg (1, RN + ": move from available: mygroup = " + mygroup);

			for (var i = agl.options.length-1 ; i ; i--) {
				if (agl.options[i].value == mygroup) {
					if (browserType_IE) {
						var old = agl.options[i];
						agl.options[i] = null;
						gl.options[gl.options.length] = old;
					} else {
						gl.options[gl.options.length] = agl.options[i];
					}
				}
			}
		}
		userform_sortList("GroupList");
		userform_sortList("AvailableGroupList");

		if (usingAuthDB) {
			var pwd = document.getElementById('passwdDialog');
			pwd.style.display = '';
		}

	} else {
		dbg (1, RN + ": one of: gl || agl || userhash["+selectedUser.value+"] is undef");
	}
}

function userform_editACL() {
	var RN = "userform_editACL";
	dbg (1, RN);

	var user  = userform_lookupSelectedUser();
	var group = userform_lookupSelectedGroup();
	
	if (user == undefined) {
		dbg (1, RN + ": problem figuring out which user is being editted");
		return;
	}

	if (group == undefined) {
		dbg (1, RN + ": problem figuring out which group is being editted");
		return;
	}

	if (group == "__multiple") {
		// if there are multiple groups selected,
		// we dont do anything. they need to click
		// the 'add to all' or 'rem from all' button
		// to process multiple groups at once
		return;
	}

	if (userhash[user] == undefined) {
		dbg (1, RN + ": userhash["+user+"] == undefined");
		return;
	}

	if (userhash[user][group] == undefined) {
		dbg (1, RN + ": userhash["+user+"]["+group+"] == undefined");
		return;
	}

	var acl = document.getElementById("AccessControlList");
	if (acl) {
		if (acl.options[0].selected) {
			acl.options[0].selected = false; //IE
			userform_showACLforGroup();
			return;
		}
		for (var i = 1 ; i < acl.options.length ; i++) {
			var val = acl.options[i].value;
			if (acl.options[i].selected) {
				//dbg (1, RN + ": userhash["+user+"]["+group+"]["+val+"] = 1");
				userhash[user][group][val] = 1;
			} else {
				//dbg (1, RN + ": userhash["+user+"]["+group+"]["+val+"] = undef");
				var gobj = userhash[user][group];
				delete gobj[val];
			}					
		}
	}


	userform_setAclHash();
}

function userform_setAclHash() {
	var RN = "userform_setAclHash";
	var ah = userform_genAclHash(userhash, "userhash");
	var af = document.getElementById("aclHash");
	if (af) {
		dbg (1, RN + ": set aclHash to " + ah);
		af.value = ah;
	} else {
		dbg (1, RN + ": cant find aclHash object");
	}
}

function userform_genAclHash(o, b) {
	var RN     = "userform_genAclHash";
	var SEP    = "$";

	var s = "";

	if (typeof o == "object") {
		var haskeys = false;
		for (var x in o) {
			haskeys = true;
			if (typeof o[x] == "object") {
				s += userform_genAclHash(o[x], b + SEP + x);
			} else {
				s += ";" + b + SEP + x;
			}
		}
		if (haskeys == false) {
			s += ";" + b;
		}
	} else {
		s = b;
	}
	return s;
}

/* determine who the currently selected user is */

function userform_saveUserSettings(o) {
	var RN = "userform_saveUserSettings";
	dbg(1, "save user");
	var ul = document.getElementById('UserList');
	if (o && ul) {
		for (var i = 0 ; i < ul.options.length ; i++) {
			if (ul.options[i].selected) {
				dbg(1, ul.options[i].value + " was selected");
			}
		}
	}
}

function userform_lookupSelectedUser() {
	var RN = "userform_lookupSelectedUser";
	var ul = document.getElementById('UserList');
	if (ul) {
		for (var i = 1 ; i < ul.length ; i++) {
			if (ul.options[i].selected)
				return ul.options[i].value;
		}
	} else {
		dbg (1, RN + ": error, cant find UserList object");
	}
	return undefined;
}

function userform_lookupSelectedGroup() {
	var RN = "userform_lookupSelectedGroup";
	var gl = document.getElementById('GroupList');
	if (gl) {
		var group  = "";
		var numsel = 0;
		for (var i = 1 ; i < gl.length ; i++) {
			if (gl.options[i].selected) {
				numsel++;
				group = gl.options[i].value;
			}
		}
		if (numsel  > 1) return "__multiple";
		return group;
	} else {
		dbg (1, RN + ": error, cant find GroupList object");
	}
	return undefined;
}

function userform_unHighLight(oname, item) {
	var RN  = "userform_unHighLightACL";
	if (oname == undefined) oname = "AccessControlList";

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

function userform_highLight(oname, item) {
	var RN  = "userform_highLightACL";
	if (oname == undefined) oname = "AccessControlList";
	var acl = document.getElementById(oname);
	if (acl) {
		for(var i = 1 ; i < acl.options.length ; i++) {
			//dbg (1, RN + ": " + acl.options[i].value + " == " + item + "?");
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


function userform_disableList(oname) {
	var RN  = "userform_disableList";

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

function userform_enableList(oname) {
	var RN  = "userform_enableList";

	var l = document.getElementById(oname);
	if (l) {
		for(var i = 1 ; i < l.options.length ; i++) {
			l.options[i].disabled = false;
		}
	} else {
		dbg (1, RN + ": error cant find " + oname + " object");
	}
}

function userform_onchange_availableGroups() {
	userform_unHighLight("GroupList");
	userform_unHighLight("AccessControlList");
	userform_disableList("AccessControlList");
}

function userform_enableModAll() {
	var RN = "userform_enableModAll";
	dbg(1, RN);
	var o = document.getElementById("addToAll");
	if (o) o.disabled = false;
	else  dbg(1, RN + ": cant find addToAll object");
	o = document.getElementById("remFromAll");
	if (o) o.disabled = false;
	else  dbg(1, RN + ": cant find remFromAll object");
}

function userform_disableModAll() {
	var RN = "userform_disableModAll";
	dbg(1, RN);
	var o = document.getElementById("addToAll");
	if (o) o.disabled = true;
	else  dbg(1, RN + ": cant find addToAll object");
	o = document.getElementById("remFromAll");
	if (o) o.disabled = true;
	else  dbg(1, RN + ": cant find remFromAll object");
}

/* userform_showACLforGroup(o)
 * 
 * this routine is called when there's a change to the
 * GroupList menu. if only one group is selected, we will
 * highlight the Access Types enabled for this group
 * (in the AccessControlList menu. if more than one group is 
 * selected, we will deselect and disable all entries in the 
 * AccessControlList menu. 
 */

function userform_showACLforGroup() {
	var RN = "userform_showACLforGroup";
	var su = userform_lookupSelectedUser();

	userform_unHighLight("AccessControlList");
	userform_unHighLight("AvailableGroupList");
	userform_enableList("AccessControlList");

	var o = document.getElementById("GroupList");

	if (o && su && userhash[su][o.value]) {

		// figure out if there are multiple groups selected
		var selected = 0;

		if (o.options[0].selected) {
			o.options[0].selected = false; //IE
			userform_unHighLight("GroupList");
			return;
		}

		for (var i = 0 ; i < o.options.length ; i++) {
			if (o.options[i].selected) {
				if (i == 0) {
					// IE doesnt support <option disabled>
					// deselect if selected
					//http://msdn.microsoft.com/workshop/author/dhtml/reference/properties/disabled_3.asp
					o.options[0].selected = false;
				} else {
					selected++;
				}
			}
		}

		if (selected == 0) return;

		if (selected > 1) {
			// clear the ACL and enable the modify all 
			// buttons
			userform_unHighLight("AccessControlList");
			userform_enableModAll();
		}
		else {
			for(var acl in userhash[su][o.value]) {
				userform_disableModAll();
				dbg(1, RN + ": acl/"+su+"/"+o.value+"="+acl);
				userform_highLight("AccessControlList", acl);
			} 
		}
	}
}

/* userform_addGroupToUser()
 * flip over the groups in the AvailableGroupList and move
 * any that are selected to the GroupList. at the same time, 
 * create the appropriate entries in the userhash.
 */

function userform_addGroupToUser() {
	var RN  = "userform_addGroupToUser";
	var su  = userform_lookupSelectedUser();
	var agl = document.getElementById('AvailableGroupList');
	var gl  = document.getElementById('GroupList');
	if (agl && gl) {
		userform_unHighLight("GroupList");
		userform_unHighLight("AccessControlList");
		for (var i = agl.options.length-1 ; i > 0 ; i--) {
			dbg (1, RN + ": move agl/" + i + " to gl");
			if (agl.options[i].selected) {
				var opt = agl.options[i];
				if (browserType_IE) agl.options[i] = null;
				gl.options[gl.options.length] = opt;
				userhash[su][opt.value] = new Object;
			}
		}
		userform_enableList("AccessControlList");
		DBG_objDump(userhash, "userhash");
		userform_setAclHash();
		userform_sortList("GroupList");
		userform_sortList("AvailableGroupList");
	} else {
		dbg (1, RN + ": cant find AvailableGroupList and/or GroupList object");
	}
	return false;
}

function userform_remGroupFromUser() {
	var RN = "userform_remGroupFromUser";
	var su = userform_lookupSelectedUser();
	var agl = document.getElementById('AvailableGroupList');
	var gl  = document.getElementById('GroupList');
	if (agl && gl) {
		for (var i = gl.options.length-1 ; i > 0 ; i--) {
			dbg (1, RN + ": move gl/" + i + " to agl");
			if (gl.options[i].selected) {
				var opt = gl.options[i];
				if (browserType_IE) gl.options[i] = null;
				agl.options[agl.options.length] = opt;
				delete userhash[su][opt.value];
			}
		}
		userform_unHighLight("AccessControlList");
		userform_disableList("AccessControlList");
		DBG_objDump(userhash, "userhash");
		userform_setAclHash();
		userform_sortList("GroupList");
		userform_sortList("AvailableGroupList");
	} else {
		dbg (1, RN + ": cant find AvailableGroupList and/or GroupList object");
	}
	return false;
}


function userform_onfocus_addUser(o) {
	var RN = "userform_onfocus_addUser";
	dbg (1, RN);

	if (o && o.value == "Add user...") o.value = "";

	if (usingAuthDB) {
		var pwd = document.getElementById('passwdDialog');
		pwd.style.display = '';
	}

}

function userform_sortList(ln) {

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

function userform_onblur_addUser(o) {	
	var RN = "userform_onblur_addUser";
	dbg (1, RN);

	if (userhash[o.value] != undefined) {
		dbg(1, RN + ": user " + o.value + " already exists");
		return;
	}

	if (o && o.value == "") o.value = "Add user...";
	if (o && o.value == "Add user...") return;

	var ul = document.getElementById('UserList');
	if (!ul) {
		dbg(1, RN + ": cant find UserList object");
		return;
	}

	userhash[o.value] = new Object();
	var no = new Option(o.value, o.value, false, false);
	ul.options[ul.options.length] = no;

	userform_unHighLight("UserList");
	ul.options[ul.options.length-1].selected = true;

	if(o) o.value = "Add user...";
	userform_sortList("UserList");
}
