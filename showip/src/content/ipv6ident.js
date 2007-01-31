
const PREFS_CID = "@mozilla.org/preferences;1";
const PREFS_I_PREF = "nsIPref";
const PREF_STRING = "browser.dom.window.dump.enabled";
try {
	var Pref =new Components.Constructor(PREFS_CID, PREFS_I_PREF); 
	var pref =new Pref( );
	pref.SetBoolPref(PREF_STRING, true);
} catch(e) {}

const IPV6_NOTIFY_STATE_DOCUMENT =
	Components.interfaces.nsIWebProgress.NOTIFY_STATE_DOCUMENT;
const IPV6_NOTIFY_LOCATION =
	Components.interfaces.nsIWebProgress.NOTIFY_LOCATION;
const IPV6_STATE_IS_DOCUMENT =
	Components.interfaces.nsIWebProgressListener.STATE_IS_DOCUMENT;
const IPV6_STATE_START =
	Components.interfaces.nsIWebProgressListener.STATE_START;
//const IPV6_NOTIFY_ALL =
//	Components.interfaces.nsIWebProgressListener.NOTIFY_ALL;


window.addEventListener("load", function() { showipExt.init(); }, false);
window.addEventListener("unload", function() { showipExt.destroy(); }, false);

var showipExt = {
init: function()  {
	this.dnscache = new Array();
	this.rdnscache = new Array();
	this.localip = null;
	this.hipUsed = 1;
	this.currentLocation = "";
	this.dnscache['none'] = new Array();
	this.strings = document.getElementById("showip_strings");
	// shamelessly taken from flagfox extension 
	this.Listener = {
	onStateChange:function(aProgress,aRequest,aFlag,aStatus) { 
	/*
		try {
			if (!aRequest || aRequest.name == "")
				this.parent.updatestatus("none");
		} catch(e) { 
			this.parent.updatestatus("none");
		}
	*/
	},
	onLocationChange:function(aProgress,aRequest,aLocation){
		try {
			if (aLocation && aLocation.host && (aLocation.scheme != 'chrome')
				 && (aLocation.scheme != 'file') )
				 this.parent.updatestatus(aLocation.host);
			else
				this.parent.updatestatus("none");
		} catch(e) { 
			this.parent.updatestatus("none");
		}
	},
	onProgressChange:function(a,b,c,d,e,f){},
	onStatusChange:function(a,b,c,d){},
	onSecurityChange:function(aWebProgress, aRequest, aState){
		this.parent.updateHipStatus(aState);
	},
	onLinkIconAvailable:function(a){}
	}; // this.Listener
	this.Listener.parent = this;

	this.PrefObserver = {
	register: function() {
		  var prefService = Components.classes["@mozilla.org/preferences-service;1"].
			  getService(Components.interfaces.nsIPrefService);
		  this._branch = prefService.getBranch("ipv6ident.");

		  var pbi = this._branch.QueryInterface(Components.interfaces.nsIPrefBranchInternal);
		  pbi.addObserver("", this, false);
	  },

	unregister: function()
	    {
		    if(!this._branch) return;

		    var pbi = this._branch.QueryInterface(Components.interfaces.nsIPrefBranchInternal);
		    pbi.removeObserver("", this);
	    },

	observe: function(aSubject, aTopic, aData)
	 {
		 if(aTopic != "nsPref:changed") return;
		 // aSubject is the nsIPrefBranch we're observing
		 this.parent.prefs.Init();
		 // update color
		var panel = document.getElementById("showip_status_text");
		panel.setAttribute("style", "color:" + this.parent.prefs.color[panel.getAttribute("status")]+";");
	 }
	}; // this.prefObserver
	this.PrefObserver.parent = this;
	
	// load preferences
	this.prefs = showipExtPrefs;
	this.prefs.Init();

	this.ipv6enabled = !this.prefs.prefs.getBoolPref("network.dns.disableIPv6");

	//var appcontent = document.getElementById("appcontent");
	//appcontent.addEventListener("load", this.onPageLoad, true);
	window.getBrowser().addProgressListener(this.Listener, IPV6_NOTIFY_LOCATION | IPV6_NOTIFY_STATE_DOCUMENT);
	this.PrefObserver.register();
},

destroy: function()  {
	this.PrefObserver.unregister();
	window.getBrowser().removeProgressListener(this.Listener);
},

// setup ipv6_localip with all local ips
getLocalIp: function() {
	if (this.localip)
		return this.localip;
	// register dns class 
	var cls = Components.classes['@mozilla.org/network/dns-service;1'];
	var iface = Components.interfaces.nsIDNSService;
	var dns = cls.getService(iface);
	var a = new Array();
	// doc.location is the Location object
	try {
		var nsrecord = dns.resolve(dns.myHostName, true);
		while (nsrecord.hasMore()) {
			a[a.length] = nsrecord.getNextAddrAsString();
		}
	} catch (e) { }
	this.localip = a.join(" | ");
	return this.localip;
},

// 'load' event handler
onPageLoad: function(e) {
	var doc = e.originalTarget;
	if (doc && doc.location &&
			(
			(doc.location.protocol == 'http:') ||
			(doc.location.protocol == 'ftp:') ||
			0	
			)
		   )
		this.updatestatus(doc.location.host);
	else
		this.updatestatus("none");
},
	
// return the ip of host
resolveIp: function(host) {
	if (this.dnscache[host])
		return this.dnscache[host];
	try {       
		// register dns class 
		var cls = Components.classes['@mozilla.org/network/dns-service;1'];
		var iface = Components.interfaces.nsIDNSService;
		var dns = cls.getService(iface);
		// doc.location is the Location object
		// alert("Try to look up " + host);

	//	var ns = dns.asyncResolve(host, false, ipv6_DnsListener);
	//	alert(host);
		var nsrecord = dns.resolve(host, false);
		var ip = new Array();
		while (nsrecord.hasMore()) {
			var myip = nsrecord.getNextAddrAsString();

			ip.push(myip);
			this.rdnscache[myip] = host;
		}
		this.dnscache[host] = ip;
		return ip;
	} catch(e) { }
	this.dnscache[host] = new Array();  // empty array for no ips
	this.rdnscache[host] = host;
	return new Array();

},

// convert num to base 'radix'
dec2radix: function(num, radix, pad) {
	var a = [0,1,2,3,4,5,6,7,8,9,'A','B','C','D','E','F'];
	var s = '';
	while(num > 0) {
		s = a[num % radix] + s;
		num = Math.floor(num / radix);
	}
	while((pad - s.length) > 0) {
		s = '0' + s;
	}
	return s;
},

// update the statusbar panel
updatestatus: function(host) {
	dump("updatestatus\n");
	if (!host)
		return;
	var panel = document.getElementById("showip_status_text");
	var text = "";
	var status = "";
	var ips = this.resolveIp(host);
	if (ips.length) {
		var j = 0;
		text = ips[j];
		// if ipv6 is disabled try to find a ipv4 address
		// for display
		while (!this.ipv6enabled && (text.indexOf(':') != -1) &&
		        ( j < ips.length) ) {
			text = ips[j];
			j++;
		}
		// if ipv6 is enabled try to find a ipv6 address
		// for display
		while (this.ipv6enabled && (text.indexOf('.') != -1) &&
		        ( j < ips.length) ) {
			text = ips[j];
			j++;
		}
	} else
		text = this.strings.getString("nopage");
	// text is ip or host here
	if (text.indexOf(":") != -1) {
		// ipv6
		status = "ipv6";
	} else if (text.indexOf(".") != -1) {
		// ipv4
		status = "ipv4";
		// 0: break; // decimal
		if (this.prefs.ipv4style) {
			var n = text.split('.');
			var i;
			for(i=0;i<4;i++) {
				n[i]=parseInt(n[i]);
			} 
			switch(this.prefs.ipv4style) {
			case 1: 
				for(i=0;i<4;i++) {
					n[i] = this.dec2radix(n[i], 8, 4);
				}
				text = n.join('.');
				break; // octal
			case 2: 
				for(i=0;i<4;i++) {
					n[i] = '0x' + this.dec2radix(n[i], 16, 2);
				}
				text = n.join('.');
				break; // hex
			case 3: 
			 	text = (n[0]*16777216)+(n[1]*65536)+(n[2]*256)+n[3];
				break; // dword
			}
		}
	} else {
		// unknown
		status = "unknown";
	}
//	panel.setAttribute("label", text);
	panel.setAttribute("ip", ips.join(','));
	panel.setAttribute("host", host);
	if (ips.length > 1)
		text += ' (' + (ips.length - 1) + ' ' + this.strings.getString("more") + ')';
	panel.setAttribute("value", text);
	panel.setAttribute("tooltiptext", this.strings.getFormattedString("localips",  [this.getLocalIp()])); 
	panel.setAttribute("status", status);
	
	// Check if HIP is used
	this.hipUsed = isHipUsed(ips);
	if (this.hipUsed == 1) {
		panel.setAttribute("value", "HIP");
		this.currentLocation = "HIP";
		//panel.setAttribute("style", "color:#6030f0");
	}
	else {
		this.currentLocation = text;
		//panel.setAttribute("style", "color:" + this.prefs.color[status]+";");
	}
	
	var popup = document.getElementById("showip_ipmenu");
	if (popup)
		// re-arm
		popup.onpopupshowing = function() {showipExt.AddIPItems(this);};
},

updateHipStatus: function(aState) {
	dump("updateHipStatus\n");
	var urlbar = document.getElementById("urlbar"); //TODO
	var securityButton = document.getElementById("security-button");
	const wpl = Components.interfaces.nsIWebProgressListener;
	//securityButton.removeAttribute("label");

	var hipToUrlbar = 1;
	switch (aState) {
	case wpl.STATE_IS_SECURE | wpl.STATE_SECURE_HIGH:
		hipToUrlbar = 1;
	break;
	case wpl.STATE_IS_SECURE | wpl.STATE_SECURE_LOW:
		hipToUrlbar = 1;
	break;
	case wpl.STATE_IS_BROKEN:
		hipToUrlbar = 1;
	break;
	case wpl.STATE_IS_INSECURE:
		hipToUrlbar = 1;
	default:
	break;
	}
	if (this.hipUsed == 1) {
		if (urlbar && (hipToUrlbar == 1)) {
			urlbar.setAttribute("level", "hip");
			var lockIcon = document.getElementById("lock-icon");
			if (lockIcon)
				lockIcon.setAttribute("tooltiptext", "Host Identity Protocol");
		
		}
		if (securityButton) {
			securityButton.setAttribute("level", "hip");
			securityButton.setAttribute("tooltiptext", "Host Identity Protocol");
			securityButton.setAttribute("label", this.currentLocation);
		}
		
	}
},

// build popup menu
// @ident 4, 6 or H
// @hostname IP or Hostname
_AddPopupItems: function(popupname, ident, hostname) {
	var popup = document.getElementById(popupname);
	if (!popup) {
		alert(popupname + 'not found');
		return;
	}
	// top 3 items remain (currentip, seperator, copy to clipboard
	if (popup.childNodes.length > 1)
		for(var j=popup.childNodes.length - 1; j>=3; j--)
			popup.removeChild(popup.childNodes.item(j));

	var entries = this.prefs.menuurls.split("||");
	for(var i = 0; i < entries.length; i++) {
		var parts = entries[i].split("|");
		if (parts.length != 3)
			continue;
		if (parts[0].indexOf(ident) == -1 )
			continue;
		var item = document.createElement("menuitem");
		item.setAttribute("label", parts[1]);
		item.setAttribute("oncommand", "showipExt.openurl(\"" + parts[2] + "\",\"" + hostname + "\",\"" + ident + "\")");
		popup.appendChild(item);
	}
},

// Hostname menu
AddHostItems: function(parent) {
	var title = document.getElementById("showip_currenthost");
	title.setAttribute("label", this.strings.getFormattedString("hostmenutitle" , [this.gethostname()]));
	this._AddPopupItems("showip_hostmenu", "H", this.gethostname());
	/* not needed here
	if (parent)
		// re-arm
		parent.onpopupshowing = function() {showipExt.AddHostItems(this);};
	*/
},

// IP menu
// @parent menupopup throwing this event
AddIPItems: function(parent) {

	// prevent recursion
	parent.onpopupshowing = null;

	var title = document.getElementById("showip_currentip");
	var ip = this.gethostip();
	var ips = ip.split(',');
	if (ips.length == 1) {
		// just one ip, old style
		title.label = this.strings.getFormattedString("ipmenutitle", [ip]);
		if (ip.indexOf(":") != -1)
			this._AddPopupItems("showip_ipmenu", "6", ip);
		else
			this._AddPopupItems("showip_ipmenu", "4", ip);

	} else {
		// multiple IPs
		var popup = document.getElementById("showip_ipmenu");
		title.label = this.strings.getFormattedString("ipmenutitle", [ips[0] + ', ...']);
		// remove everything but the top most entries
		for(var j=popup.childNodes.length - 1; j>=3; j--)
			popup.removeChild(popup.childNodes.item(j));

		// TODO sort by real IP value
		ips.sort();
		// show one submenus for every IP
		var i;
		for(i = 0; i < ips.length; i++) {
			var xip = ips[i];

			var menu = document.createElement("menu");
			menu.setAttribute("label", xip);
			popup.appendChild(menu);

			var mp = document.createElement("menupopup");
			mp.id = "showip_ipmenu_" + xip;
			// dummy function to prevent recursion
			mp.onpopupshowing = function() {};
			menu.appendChild(mp);

			var mi = document.createElement("menuitem");
			mi.setAttribute("label", this.strings.getString("copytoclipboard"));
			mi.setAttribute("oncommand", "showipExt.copytoclip(\"" + xip + "\");");
			mp.appendChild(mi);

			if (xip.indexOf(":") != -1)
				this._AddPopupItems("showip_ipmenu_" + xip, "6", xip);
			else
				this._AddPopupItems("showip_ipmenu_" + xip, "4", xip);
		}
		// ff will crash if you remove this return...
		return;
	}
	if (parent)
		// re-arm
		parent.onpopupshowing = function() {showipExt.AddIPItems(this);};
},
 
// return the host-ip, saved in the statusbar-panel label
gethostip: function() {
	var panel = document.getElementById("showip_status_text");
	return panel.getAttribute("ip");
},

// take ip and to a reverse lookup
gethostname: function() {
	var panel = document.getElementById("showip_status_text");
	return panel.getAttribute("host");
},

// openurl in newtab/hiddentab/same tab
openurl: function(url, rep, ident) {

	// complete uri
	url = url.replace(/###/, encodeURIComponent(getBrowser().currentURI.spec));
	// only domain/ip
	url = url.replace(/##/, rep);
	// extract domain name
	if (ident == 'H') {
		var x = rep.split(/\./);
		var dn = rep;
		if (x.length > 1) {
			var tld = x[x.length - 1];
			var sld = x[x.length - 2];
			dn = sld + '.' + tld;
			// handle co.uk etc.
			if ((sld.length < 3) && (x.length > 2))
				dn = x[x.length - 3] + '.' + dn;
		} 
		url = url.replace(/#D#/, dn);
	}
	if (url.indexOf('!') == 0) {
		// call local program
		// create an nsILocalFile for the executable
		var file = Components.classes["@mozilla.org/file/local;1"]
			.createInstance(Components.interfaces.nsILocalFile);
		file.initWithPath(url.substr(1));

		// create an nsIProcess
		var process = Components.classes["@mozilla.org/process/util;1"]
			.createInstance(Components.interfaces.nsIProcess);
		process.init(file);

		// Run the process.
		// If first param is true, calling process will be blocked until
		// called process terminates. 
		// Second and third params are used to pass command-line arguments
		// to the process.
		var args = [rep];
		process.run(false, args, args.length);
		return;
	}
	if (this.prefs.newtab) {
		var tab = getBrowser().addTab(url);
		if (!this.prefs.hiddentab)
			getBrowser().selectedTab = tab;

	} else
		getBrowser().loadURI(url);
},

// copy first argument to clipboard
copytoclip: function(host) {
  const gClipboardHelper = Components.classes["@mozilla.org/widget/clipboardhelper;1"]
      .getService(Components.interfaces.nsIClipboardHelper);
        gClipboardHelper.copyString(host);
}

}; // showipExt

function isHipUsed(aIps) {
        // Try to detect, whether using HIP...
        var iphip = aIps.join(',');
        var i = iphip.indexOf(':');
        var iship = 0;
        if (i != -1)
        {
                var v1 = iphip.substring(0, i);
                var v2 = iphip.substring(i + 1, i + 5);
                var i1 = parseInt(v1, 16);
                var i2 = parseInt(v2, 16) & 0xfff0;
                if (i1 == 0x2001) iship = 1;
                if (i2 != 0x0070) iship = 0;
        }
        //return iship;
	return iship;
}



