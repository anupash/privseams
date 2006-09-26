var showipExtPrefs = {

Show: function() {
	// for the mozilla suite
	window.open("chrome://ipv6ident/content/ipv6ident-pref.xul", "ipv6prefs", "chrome,width=500,height=440");
},

// clear complete listbox (from adblock)
_ClearList: function() {
	var list = document.getElementById("EntryList");
	list.parentNode.replaceChild(list.cloneNode(false), list);
},

// add a cell to a list row
_AddCell: function (li, label) {
	var cell = document.createElement('listcell');
	cell.setAttribute('label', label);
	li.appendChild(cell);
},

// add a row to the list
_AddEntry: function(isipv4, isipv6, ishost, title, url) {
	var lb = document.getElementById("EntryList");
	var li = document.createElement("listitem");
	this._AddCell(li, isipv4);
	this._AddCell(li, isipv6);
	this._AddCell(li, ishost);
	this._AddCell(li, title);
	this._AddCell(li, url);
	lb.appendChild(li);
},

// set the global vars used in preferences and in the main program
Init: function() {
	this.prefs = Components.classes["@mozilla.org/preferences-service;1"].
                getService(Components.interfaces.nsIPrefBranch);
	this.hiddentab = null;
	this.newtab = null;
	this.color = null;
	this.menuurls = null;
	this.ipv4style = 0; // 0:'d'ecimal, 1:'o'ctal, 2:'h'ex or 3:d'w'ord
//var ipv6_menus = null;


	var urls = null;
	if (this.prefs.getPrefType("ipv6ident.urls") == this.prefs.PREF_STRING){
		urls = this.prefs.getCharPref("ipv6ident.urls");
	} else {
		// default
	urls = "||4|whois.sc|http://www.whois.sc/##||6|ipv6tools reverse|http://www.ipv6tools.com/tools/ptr.ch?ip=##&src=ShowIP||H|netcraft|http://uptime.netcraft.com/up/graph/?host=##||H|ipv6tools AAAA lookup|http://www.ipv6tools.com/tools/lookup.ch?name=##&type=AAAA&src=ShowIP||6|ipv6tools ping|http://www.ipv6tools.com/tools/ping.ch?ip=##&src=ShowIP||6H|ipv6tools whois|http://www.ipv6tools.com/tools/whois.ch?ip=##&src=ShowIP||6|ipv6tools info|http://www.ipv6tools.com/tools/aboutipv6.ch?ip=##&src=ShowIP||6|ipv6tools traceroute|http://www.ipv6tools.com/tools/tracert.ch?ip=##&src=ShowIP||4|ipv6tools convert ipv4|http://www.ipv6tools.com/tools/v6fromv4.ch?domain=##&src=ShowIP||4H|dnsstuff whois|http://www.dnsstuff.com/tools/whois.ch?ip=##&src=ShowIP||4|dnsstuff timing|http://www.dnsstuff.com/tools/dnstime.ch?name=##&type=A&src=ShowIP||4|dnsstuff traceroute|http://www.dnsstuff.com/tools/tracert.ch?ip=##&src=ShowIP||46H|esymbian ip2country|http://ip2country.esymbian.info/?host=##||H|whois.sc|http://www.whois.sc/domain-explorer/?q=##&sub=Search&filter=y&pool=C&rows=100&bc=25&last=||4|dnsstuff all|http://www.DNSstuff.com/tools/ipall.ch?ip=##&src=ShowIP";
	}
	this.menuurls = urls;

	if (this.prefs.getPrefType("ipv6ident.newtab") == this.prefs.PREF_BOOL){
		this.newtab = this.prefs.getBoolPref("ipv6ident.newtab");
	} else {
		this.newtab = true;
	}

	if (this.prefs.getPrefType("ipv6ident.hiddentab") == this.prefs.PREF_BOOL){
		this.hiddentab = this.prefs.getBoolPref("ipv6ident.hiddentab");
	} else {
		this.hiddentab = true;
	}
	this.color = new Array();
	if (this.prefs.getPrefType("ipv6ident.color") == this.prefs.PREF_STRING){
		this.color['unknown'] = this.prefs.getCharPref("ipv6ident.color");
	} else {
		this.color['unknown'] = "#000000";
	}

	if (this.prefs.getPrefType("ipv6ident.colorv4") == this.prefs.PREF_STRING){
		this.color['ipv4'] = this.prefs.getCharPref("ipv6ident.colorv4");
	} else {
		this.color['ipv4'] = "#FF0000";
	}

	if (this.prefs.getPrefType("ipv6ident.colorv6") == this.prefs.PREF_STRING){
		this.color['ipv6'] = this.prefs.getCharPref("ipv6ident.colorv6");
	} else {
		this.color['ipv6'] = "#00FF00";
	}

	if (this.prefs.getPrefType("ipv6ident.ipv4style") == this.prefs.PREF_INT){
		this.ipv4style = this.prefs.getIntPref("ipv6ident.ipv4style");
	}
},

DialogInit: function () {
	this.Init();
	var entries = this.menuurls.split("||");
	for(var i = 0; i < entries.length; i++) {
		var parts = entries[i].split("|");
		if (parts.length != 3)
			continue;
		this._AddEntry( 
			parts[0].indexOf("4") != -1,
			parts[0].indexOf("6") != -1,
			parts[0].indexOf("H") != -1,
			parts[1],
			parts[2]
			);
	}
	document.getElementById("newtab").checked = this.newtab;
	document.getElementById("hiddentab").disabled = !this.newtab;
	document.getElementById("hiddentab").checked = this.hiddentab;
	document.getElementById("ipv6_coldef").value = this.color['unknown'];
	document.getElementById("ipv6_colv4").value = this.color['ipv4'];
	document.getElementById("ipv6_colv6").value = this.color['ipv6'];
	document.getElementById("ipv6_colpdef").color = this.color['unknown'];
	document.getElementById("ipv6_colpv4").color = this.color['ipv4'];
	document.getElementById("ipv6_colpv6").color = this.color['ipv6'];
	document.getElementById("showip_stylev4").selectedIndex = this.ipv4style;
},

Save: function() {
	this.prefs.setBoolPref("ipv6ident.hiddentab", document.getElementById("hiddentab").checked);
	this.prefs.setBoolPref("ipv6ident.newtab", document.getElementById("newtab").checked);

	this.prefs.setCharPref("ipv6ident.color", document.getElementById("ipv6_coldef").value);
	this.prefs.setCharPref("ipv6ident.colorv4", document.getElementById("ipv6_colv4").value);
	this.prefs.setCharPref("ipv6ident.colorv6", document.getElementById("ipv6_colv6").value);
	this.prefs.setIntPref("ipv6ident.ipv4style", document.getElementById("showip_stylev4").selectedIndex);
	var urls = "";
	var lb = document.getElementById("EntryList");
	// i = 2 to skip header
	for(var i = 2; i < lb.childNodes.length; i++) {
		var li = lb.childNodes[i];
		var newstr = "";

		newstr += ((li.childNodes[0].getAttribute("label") == "true" )?"4":"");
		newstr += ((li.childNodes[1].getAttribute("label") == "true" )?"6":"");
		newstr += ((li.childNodes[2].getAttribute("label") == "true" )?"H|":"|");
		newstr += li.childNodes[3].getAttribute("label") + "|";
		newstr += li.childNodes[4].getAttribute("label");
		if (newstr.indexOf("||") != -1) // this is the delimiter - don't save it.
			continue;
		urls = urls + "||" + newstr;
	}
	this.prefs.setCharPref("ipv6ident.urls", urls);
},

AddEntry: function() {
	this._AddEntry(
		document.getElementById("entryIPv4").checked,
		document.getElementById("entryIPv6").checked,
		document.getElementById("entryHost").checked,
		document.getElementById("entryTitle").value,
		document.getElementById("entryURL").value);

	document.getElementById("entryTitle").value = "";
	document.getElementById("entryURL").value = "";
},

UpdEntry: function() {
	var lb = document.getElementById("EntryList");
	if (lb.selectedIndex == -1) {
		alert("No item selected");
		return;
	}
	var li = lb.selectedItem;
	li.childNodes[0].setAttribute("label", document.getElementById("entryIPv4").checked);
	li.childNodes[1].setAttribute("label", document.getElementById("entryIPv6").checked);
	li.childNodes[2].setAttribute("label", document.getElementById("entryHost").checked);
	li.childNodes[3].setAttribute("label", document.getElementById("entryTitle").value);
	li.childNodes[4].setAttribute("label", document.getElementById("entryURL").value);
},

DelEntry: function() {
	var lb = document.getElementById("EntryList");
	if (lb.selectedIndex == -1) {
		alert("No item selected");
		return;
	}
	lb.removeChild(lb.selectedItem);
},

CopyEntry: function() {
	var lb = document.getElementById("EntryList");
	if (lb.selectedIndex == -1)
		return;
	var li = lb.selectedItem;
	document.getElementById("entryIPv4").checked = (li.childNodes[0].getAttribute("label") == "true" );
	document.getElementById("entryIPv6").checked = (li.childNodes[1].getAttribute("label") == "true" );
	document.getElementById("entryHost").checked = (li.childNodes[2].getAttribute("label") == "true" );
	document.getElementById("entryTitle").value = li.childNodes[3].getAttribute("label");
	document.getElementById("entryURL").value =  li.childNodes[4].getAttribute("label");
},

NewtabClick: function() {
	var newtab = document.getElementById("newtab").checked;
	document.getElementById("hiddentab").disabled = !newtab;
},

updatecolor: function(picker, id) {
	document.getElementById(id).value = picker.color;
},

updatecolorp: function(textbox, id) {
	document.getElementById(id).color = textbox.value;
}
};
