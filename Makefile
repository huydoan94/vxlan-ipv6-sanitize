include $(TOPDIR)/rules.mk

PKG_NAME:=vxlan-ipv6-sanitize
PKG_VERSION:=1.6
PKG_RELEASE:=1

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_BUILD_DEPENDS:=libnetfilter-queue libtins

include $(INCLUDE_DIR)/package.mk

define Package/vxlan-ipv6-sanitize
	SECTION:=net
	CATEGORY:=Network
	TITLE:=VXLAN IPv6 RA/DHCPv6 sanitizer
	DEPENDS:=+kmod-nft-queue +libnetfilter-queue +libtins
endef

define Package/vxlan-ipv6-sanitize/description
	NFQUEUE sanitizer for bridged VXLAN IPv6 configuration traffic. It
	preserves Router Advertisement prefix/route information and DHCPv6
	address assignments, neutralizes remote RA default-router lifetime,
	normalizes RA RDNSS and DHCPv6 DNS option 23 to one local ingress ULA,
	and removes advertised DNS search lists.
endef

define Package/vxlan-ipv6-sanitize/conffiles
/etc/config/vxlan-ipv6-sanitize
endef

SANITIZE_SOURCES := helper.cpp logging.cpp packet_parser.cpp vxlan-ipv6-sanitize.cpp
SANITIZE_WARNINGS := -Wall -Wextra -Wformat=2 -Wshadow

TARGET_CXXFLAGS += -Os $(SANITIZE_WARNINGS) -std=gnu++11 -ffunction-sections -fdata-sections
TARGET_CPPFLAGS += -isystem $(STAGING_DIR)/usr/include -DVXLAN_IPV6_SANITIZE_VERSION=\"$(PKG_VERSION)\"
TARGET_LDFLAGS += -Wl,--gc-sections

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(CP) ./LICENSE $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CXX) \
		$(TARGET_CXXFLAGS) \
		$(TARGET_CPPFLAGS) \
		-o $(PKG_BUILD_DIR)/vxlan-ipv6-sanitize \
		$(addprefix $(PKG_BUILD_DIR)/,$(SANITIZE_SOURCES)) \
		$(TARGET_LDFLAGS) \
		-lnetfilter_queue \
		-ltins
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
