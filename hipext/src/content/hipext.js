var hipext = {

  onLoad: function() {
    this.Listener = {
      onLocationChange: function(aProgress, aRequest, aURI) {
	this.parent.updatePanel(aURI);
      },
      onStateChange: function() {},
      onProgressChange: function() {},
      onStatusChange: function() {},
      onSecurityChange: function() {},
      onLinkIconAvailable: function() {}
    };

    this.Listener.parent = this;
    window.getBrowser().addProgressListener(this.Listener,
		 Components.interfaces.nsIWebProgress.NOTIFY_STATE_DOCUMENT);
  },

  onUnload: function() {
	window.getBrowser().removeProgressListener(this.Listener);
  },

  isHip: function(host) {
	/* Resolve address from hostname */
	var ips = new Array();
	var dns = Components.classes["@mozilla.org/network/dns-service;1"].
            getService(Components.interfaces.nsIDNSService);
	var dnsrecord = dns.resolve(host, 0);
	while (dnsrecord.hasMore()) {
		var ip = dnsrecord.getNextAddrAsString();
		ips.push(ip);
	}

        /* Determine whether address is a HIT */
        var iphip = ips.join(',');
        var i = iphip.indexOf(':');
        var iship = 0;
        if (i != -1)
        {
                var v1 = iphip.substring(0, i);
                var v2 = iphip.substring(i + 1, i + 5);
                var i1 = parseInt(v1, 16);
                var i2 = parseInt(v2, 16) & 0xfff0;
                if ((i1 == 0x2001) && (i2 == 0x0010)) iship = 1;
        }
	return iship;
  },

  updatePanel: function(aURI) {
    var img = "";
    var tooltip = "";

    if (aURI && aURI.host && (aURI.scheme != "chrome")
		&& (aURI.scheme != "file") && this.isHip(aURI.host)) {
	  img = "chrome://browser/skin/Secure.png";
	  tooltip = "Host Identity Protocol";
    }

    var panel = document.getElementById("hip-status");
    panel.setAttribute("src", img);
    panel.setAttribute("tooltiptext", tooltip);
  }

};

window.addEventListener("load", function(e) { hipext.onLoad(); }, false);
window.addEventListener("unload", function() { hipext.onUnload(); }, false);
