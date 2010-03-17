include $(TOPDIR)/rules.mk

PKG_NAME:=hipl
PKG_BRANCHNAME:=main
PKG_VERSION:=0.9
PKG_RELEASE:=2

PKG_SOURCE:=$(PKG_NAME)-$(PKG_BRANCHNAME).tar.gz
PKG_SOURCE_URL:=http://hipl.hiit.fi/hipl/contrib/openwrt/
PKG_CAT:=zcat

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_BRANCHNAME)
PKG_INSTALL_DIR:=$(PKG_BUILD_DIR)/ipkg-install

include $(INCLUDE_DIR)/package.mk

define Package/hipl-hipd
    SECTION:=net
    CATEGORY:=Network
    DEPENDS:=+hipl-common +genl +ip +kmod-ipsec +kmod-ipsec4 +kmod-ipsec6 +kmod-loop +kmod-nbd +kmod-tun +libpthread +libuuid +losetup +kmod-dummy +kmod-ipip +kmod-crypto-authenc +kmod-ip6-tunnel
             # TODO: probably not needed:
             #+kmod-capi +libpcap +udevtrigger +ipsec-tools +isakmpd
    TITLE:=HIPL deamon
    URL:=http://hipl.hiit.fi/
endef

define Package/hipl-hipd/description
 The daemon for HIPL.
endef

define Package/hipl-hipfw
    SECTION:=net
    CATEGORY:=Network
    DEPENDS:=+hipl-common +iptables +ip6tables +kmod-ip6tables +kmod-ipt-queue
             # TUN/TAP support - might be needed at some point instead of kmod-ipt-queue
             #+kmod-tun
    TITLE:=HIPL firewall
    URL:=http://hipl.hiit.fi/
endef

define Package/hipl-hipfw/description
 The firewall for HIPL.
endef

define Package/hipl-hipconf
    SECTION:=net
    CATEGORY:=Network
    DEPENDS:=+hipl-hipd
    TITLE:=HIPL configuration application
    URL:=http://hipl.hiit.fi/
endef

define Package/hipl-hipconf/description
 The configuration application for the hipd of the HIPL implementation.
endef

define Package/hipl-hipproxy
    SECTION:=net
    CATEGORY:=Network
    DEPENDS:=+hipl-hipd +hipl-hipfw
    TITLE:=HIPL proxy
    URL:=http://hipl.hiit.fi/
endef

define Package/hipl-hipproxy/description
 The scripts for running the hipproxy.
endef

define Package/hipl-test
    SECTION:=net
    CATEGORY:=Network
    DEPENDS:=+hipl-hipd
    TITLE:=HIPL testing application
    URL:=http://hipl.hiit.fi/
endef

define Package/hipl-test/description
 Some applications and configs needed for testing HIPL.
endef

define Package/hipl-common
    SECTION:=net
    CATEGORY:=Network
    #this list includes ALL modules necessary for running hipl on openwrt
    #note: modules will be automatically selected for compilation and
    #will be required by ipkg on the openwrt box
    #TODO remove unnecessary modules
    DEPENDS:=+libconfig +kmod-crypto-aes +kmod-crypto-hmac +kmod-crypto-null +kmod-crypto-sha1 +kmod-ipv6 +libgcc +libopenssl +libxml2
    TITLE:=HIPL common files
    URL:=http://hipl.hiit.fi/
endef

define Package/hipl-common/description
 The libraries and configs needed for HIPL.
endef

# seen when compiling hipl: -lxml2 -lcap -lsqlite3 -lipq -luuid -lm -lcrypto
CONFIGURE_VARS += \
    LIBS="-lxml2 -lcrypto -lm -lz" \
    CPPFLAGS="$$$$CPPFLAGS -I$(STAGING_DIR)/usr/include/libxml2 -I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/include -I$(TOOLCHAIN_DIR)/include -I$(STAGING_DIR)/usr/include/libconfig" \
    LDFLAGS="$$$$LDFLAGS -L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib -L$(TOOLCHAIN_DIR)/lib" \
    OPENWRT="-L$(STAGING_DIR)/usr/lib -L$(STAGING_DIR)/lib -L$(TOOLCHAIN_DIR)/lib" \

define Build/Configure
	(cd $(PKG_BUILD_DIR); rm -rf config.{cache,status}; ./autogen.sh --host=$(GNU_TARGET_NAME) --target=$(GNU_TARGET_NAME));

	(cd ..;);

	$(CONFIGURE_VARS);

	$(call Build/Configure/Default, \
            --enable-shared \
            --enable-midauth \
            --enable-openwrt \
            --disable-dht \
            --disable-agent \
            --disable-privsep \
            --disable-i3 \
            --disable-debug \
    );
endef

define Build/Compile
	($(CONFIGURE_VARS) $(MAKE) -C $(PKG_BUILD_DIR));
	$(MAKE) -C $(PKG_BUILD_DIR) DESTDIR="$(PKG_INSTALL_DIR)" INSTALL="install -c" install
endef

define Package/hipl-hipd/install
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_DIR) $(1)/usr/sbin/

	$(INSTALL_BIN) ./files/hipd.init $(1)/etc/init.d/hipd
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/hipd $(1)/usr/sbin/
endef

define Package/hipl-hipfw/install
	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_DIR) $(1)/usr/sbin/

	$(INSTALL_BIN) ./files/hipfw.init $(1)/etc/init.d/hipfw
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/hipfw $(1)/usr/sbin/
endef

define Package/hipl-hipconf/install
	$(INSTALL_DIR) $(1)/usr/sbin/

	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/hipconf $(1)/usr/sbin/
endef

define Package/hipl-hipproxy/install
	$(INSTALL_DIR) $(1)/usr/sbin/

	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/hipdnsproxy $(1)/usr/sbin/
endef

define Package/hipl-test/install
	$(INSTALL_DIR) $(1)/etc/hip/test/
	$(INSTALL_DIR) $(1)/usr/bin/

	$(INSTALL_BIN) ./files/test/* $(1)/etc/hip/test/
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/conntest* $(1)/usr/bin/
endef

define Package/hipl-common/install
	$(INSTALL_DIR) $(1)/etc/hip/
	$(INSTALL_DIR) $(1)/etc/modules.d/
	$(INSTALL_DIR) $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/include/libipsec

	$(INSTALL_DATA) ./files/hipl.modules $(1)/etc/modules.d/35-hipl
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/lib/libhipcore.so* $(1)/usr/lib/
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/lib/libhipcore.la $(1)/usr/lib/
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/lib/libhipconf.so* $(1)/usr/lib/
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/lib/libhipconf.la $(1)/usr/lib/
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/lib/libhiptool.so* $(1)/usr/lib/
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/lib/libhiptool.la $(1)/usr/lib/
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/lib/libopphip.so* $(1)/usr/lib/
	$(INSTALL_DATA) $(PKG_INSTALL_DIR)/usr/lib/libopphip.la $(1)/usr/lib/
endef

$(eval $(call BuildPackage,hipl-common))
$(eval $(call BuildPackage,hipl-hipd))
$(eval $(call BuildPackage,hipl-hipfw))
$(eval $(call BuildPackage,hipl-hipconf))
$(eval $(call BuildPackage,hipl-hipproxy))
$(eval $(call BuildPackage,hipl-test))
