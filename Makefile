include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk

PKG_NAME      := nfcd
PKG_VERSION   := 0.0.1
PKG_RELEASE   := 1
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

define Package/nfcd
    SECTION:=utils
	CATEGORY:=Utilities
	DEFAULT:=y
	TITLE:=File Queue Daemon
	DEPENDS:=+ubusd +ubus +ubox +libubus +libubox +libblobmsg-json +libnfc
endef

TARGET_CFLAGS += -Wall -DDEBUG
EXTRA_LDFLAGS += -lubus -lubox -lblobmsg_json -lnfc

define Build/Prepare
	$(Build/Prepare/Default)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/nfcd/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nfcd $(1)/usr/bin
endef

$(eval $(call BuildPackage,nfcd))

