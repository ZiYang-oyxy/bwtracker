include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=bwtracker

include $(INCLUDE_DIR)/package.mk

define KernelPackage/bwtracker
	SUBMENU:=Network Support
	TITLE:=Bandwidth tracker
	DEPENDS:=
	FILES:= $(PKG_BUILD_DIR)/bwtracker.ko
	AUTOLOAD:=$(call AutoLoad,70,bwtracker)
endef

define KernelPackage/bwtracker/description
	Kernel module for monitor LAN clients bandwidth usage
endef

EXTRA_KCONFIG:= \
	CONFIG_BWTRACKER=m

EXTRA_CFLAGS:= \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=m,%,$(filter %=m,$(EXTRA_KCONFIG)))) \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=y,%,$(filter %=y,$(EXTRA_KCONFIG)))) \

MAKE_OPTS:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	SUBDIRS="$(PKG_BUILD_DIR)" \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
	$(EXTRA_KCONFIG)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
	$(MAKE_OPTS) \
	modules
endef

define KernelPackage/bwtracker/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(CP) ./files/* $(1)/
endef

$(eval $(call KernelPackage,bwtracker))
