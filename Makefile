include $(TOPDIR)/rules.mk

PKG_NAME:=vxlan-ipv6-sanitize
PKG_VERSION:=1.2.19
PKG_RELEASE:=1

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/vxlan-ipv6-sanitize
	SECTION:=net
	CATEGORY:=Network
	TITLE:=VXLAN IPv6 RA/DHCPv6 sanitizer
	DEPENDS:=+kmod-nfnetlink-queue +kmod-nft-queue +kmod-nft-bridge +libnetfilter-queue
endef

define Package/vxlan-ipv6-sanitize/description
	Low-memory NFQUEUE sanitizer for bridged VXLAN IPv6 configuration
	traffic. It preserves Router Advertisement prefix/route information and
	DHCPv6 address assignments, neutralizes remote RA default-router lifetime,
	normalizes RA RDNSS and DHCPv6 DNS option 23 to one local ingress ULA,
	and removes advertised DNS search lists.
endef

define Package/vxlan-ipv6-sanitize/conffiles
/etc/config/vxlan-ipv6-sanitize
endef

TARGET_CFLAGS += -Os -Wall -Wextra -Wformat=2 -Wshadow -Wstrict-prototypes \
	-Werror=implicit-function-declaration -ffunction-sections -fdata-sections
TARGET_LDFLAGS += -Wl,--gc-sections

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(CP) ./LICENSE $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) \
		$(TARGET_CFLAGS) \
		$(TARGET_CPPFLAGS) \
		-o $(PKG_BUILD_DIR)/vxlan-ipv6-sanitize \
		$(PKG_BUILD_DIR)/vxlan-ipv6-sanitize.c \
		$(PKG_BUILD_DIR)/helper.c \
		$(PKG_BUILD_DIR)/logging.c \
		$(TARGET_LDFLAGS) \
		-lnetfilter_queue
endef

define Package/vxlan-ipv6-sanitize/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/vxlan-ipv6-sanitize \
		$(1)/usr/sbin/vxlan-ipv6-sanitize
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/vxlan-ipv6-sanitize.init \
		$(1)/etc/init.d/vxlan-ipv6-sanitize
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/vxlan-ipv6-sanitize.config \
		$(1)/etc/config/vxlan-ipv6-sanitize
endef

$(eval $(call BuildPackage,vxlan-ipv6-sanitize))
