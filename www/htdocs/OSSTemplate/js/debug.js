var DBGLEVEL = 3;
var dbgwin;
var browserType_IE = 0;

function DBG_init() {
        var UA     = navigator.userAgent.toLowerCase ();
        var is_ie  = (UA.indexOf ("msie") != -1 && document.all);
        var is_ie5 = (UA.indexOf ("msie 5") != -1 && document.all);
        var is_nav = !is_ie && (UA.indexOf ("mozilla") != -1);

        if (is_ie) {
                browserType_IE = 1;
                //return;
        }

        if (DBGLEVEL)
                dbgwin = window.open("about:blank", "DEBUGOUTPUT",
                             "resizable,width=400,height=400,scrollbars");

}

function dbg(l, msg) {

        //if (browserType_IE) return;

        if ( (DBGLEVEL >= l) && dbgwin) {
                if (browserType_IE) {
                        if (dbgwin) {
                                dbgwin.document.writeln(msg + "<BR>");
                        } else
                                alert("dbgwin is null");
                } else {
                        var p = dbgwin.document.createElement("DIV");
                        p.appendChild(document.createTextNode(msg));
                        dbgwin.document.body.appendChild(p);
                }
        }
}

function objDump(o, b) {
	for (var x in o) {
		if (typeof o[x] == "object") {
			reDump(o[x], "uh."+x);
		} else {
			document.writeln(b + "." + x + "=" + o[x] + "<BR>");
		}
	}
}
