include $(TOPDIR)/rules.mk

PKG_NAME:=hipl
PKG_VERSION:=1.0.6
PKG_RELEASE:=6

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://hipl.hiit.fi/hipl/contrib/openwrt/
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/hipl-hipd
    SECTION:=net
    CATEGORY:=Network
    DEPENDS:=hipl-common +genl +ip +kmod-ipsec4 +kmod-ipsec6 +kmod-loop +kmod-nbd +kmod-tun +libpthread +losetup +kmod-dummy +kmod-ipip +kmod-crypto-authenc +kmod-ip6-tunnel
    TITLE:=HIPL daemon
    URL:=http://hipl.hiit.fi/
endef

define Package/hipl-hipd/description
 The daemon for HIPL.
endef

define Package/hipl-hipfw
    SECTION:=net
    CATEGORY:=Network
    DEPENDS:=hipl-common +libconfig +iptables +ip6tables +kmod-ipt-queue
    TITLE:=HIPL firewall
    URL:=http://hipl.hiit.fi/
endef

define Package/hipl-hipfw/description
 The firewall for HIPL.
endef

define Package/hipl-common
    SECTION:=net
    CATEGORY:=Network
    #this list includes ALL modules necessary for running hipl on openwrt
    #note: modules will be automatically selected for compilation and
    #will be required by ipkg on the openwrt box
    #TODO remove unnecessary modules
    DEPENDS:=+kmod-crypto-aes +kmod-crypto-hmac +kmod-crypto-null +kmod-crypto-sha1 +kmod-ipv6 +libgcc +libopenssl
    BUILDONLY:=1
    TITLE:=HIPL common files
    URL:=http://hipl.hiit.fi/
endef

define Package/hipl-common/description
 The libraries and configs needed for HIPL.
endef

CONFIGURE_VARS += LIBS="-lz"

define Build/Configure
	$(call Build/Configure/Default, \
            --sysconfdir=/etc \
            --disable-debug \
    );
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)
	$(MAKE) -C $(PKG_BUILD_DIR) DESTDIR="$(PKG_INSTALL_DIR)" install-strip
endef

define Package/hipl-hipd/install
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_DIR) $(1)/usr/sbin/

	$(INSTALL_BIN) ./files/hipd.init $(1)/etc/init.d/hipd
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/hipd $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/hipconf $(1)/usr/sbin/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/hipdnsproxy $(1)/usr/sbin/
endef

define Package/hipl-hipfw/install
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_DIR) $(1)/usr/sbin/

	$(INSTALL_BIN) ./files/hipfw.init $(1)/etc/init.d/hipfw
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/hipfw $(1)/usr/sbin/
endef

define Package/hipl-common/install
	$(INSTALL_DIR) $(1)/etc/hip/
	$(INSTALL_DIR) $(1)/etc/modules.d/

	$(INSTALL_DATA) ./files/hipl.modules $(1)/etc/modules.d/35-hipl
endef

$(eval $(call BuildPackage,hipl-common))
$(eval $(call BuildPackage,hipl-hipd))
$(eval $(call BuildPackage,hipl-hipfw))
