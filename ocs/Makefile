#
# Copyright 2025 Morse Micro
# SPDX-License-Identifier: GPL-3.0-or-later
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ocs
PKG_RELEASE:=1

PKG_MAINTAINER:=Morse Micro <info@morsemicro.com>
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define Package/ocs
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=MM OCS Utility
  DEPENDS:=+libnl +libnl-genl
endef

define Package/ocs/description
  Morse Micro Command line ocs utility
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include/libnl3 \
	-I$(STAGING_DIR)/usr/include \
	-D_GNU_SOURCE

TARGET_LDFLAGS += \
	-lnl-3 \
	-lnl-genl-3

MAKE_FLAGS += \
	FPIC="$(FPIC)" \
	CFLAGS="$(TARGET_CFLAGS)" \
	LDFLAGS="$(TARGET_LDFLAGS)" \

define Package/ocs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ocs $(1)/usr/bin/ocs
endef

$(eval $(call BuildPackage,ocs))
