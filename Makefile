OPENWRT = ${HOME}/oss/openwrt

KERNEL = ${OPENWRT}/build_dir/linux-ar71xx_generic/linux-3.3.8
PREFIX=$(OPENWRT)/staging_dir/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33.2/bin/mips-openwrt-linux-uclibc-
LD=$(PREFIX)ld
CC=$(PREFIX)gcc
EXTRA_LDSFLAGS="-I${OPENWRT}/build_dir/linux-ar71xx_generic -include symtab.h"
KBUILD_HAVE_NLS=no
CONFIG_SHELL="/bin/bash"

obj-m += bwtracker.o

all:
	make -C ${KERNEL} ARCH="mips" M=$(PWD) modules

clean:
	make -C ${KERNEL} M=$(PWD) clean
