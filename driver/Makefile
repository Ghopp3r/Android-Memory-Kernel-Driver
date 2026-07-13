# SPDX-License-Identifier: GPL-2.0
#
# Root Kbuild Makefile for the reconstructed Android kernel driver.
#
# Build system:
#   Plain in-tree Linux Kbuild (obj-m) — same pattern used by the
#   android-wuwa reference. The primary build path runs this Makefile
#   inside a ghcr.io/ylarod/ddk:<kmi>-<release> Docker image, which ships
#   a pre-extracted kernel tree at $KERNEL_SRC.
#
# Typical invocations:
#   # Inside ghcr.io/ylarod/ddk container:
#   make                                # uses $KERNEL_SRC automatically
#   make TARGET_PKG='"com.example.app"' # override target package
#   make DRIVER_NAME=my-driver        # override final .ko name
#
#   # On a developer box with kernel headers installed:
#   make KDIR=/lib/modules/$(uname -r)/build
#
#   # Clean:
#   make clean
#
#   # Compilation database (for clangd / IDE indexing):
#   make compdb
#
# Output: $(DRIVER_NAME).ko (default: my-driver.ko)

# -----------------------------------------------------------------------------
# Kbuild stage 2 — re-entered by the kernel build with KERNELRELEASE set.
# Delegate to Kbuild file in this directory.
# -----------------------------------------------------------------------------
ifneq ($(KERNELRELEASE),)

include $(src)/Kbuild

# -----------------------------------------------------------------------------
# Kbuild stage 1 — invoked from the shell. Locate the kernel build tree and
# recurse into it with M=$(PWD).
# -----------------------------------------------------------------------------
else

# DRIVER_NAME: the final .ko basename. Must match obj-m in Kbuild.
DRIVER_NAME ?= my-driver

# TARGET_PKG: Android package name that the driver targets. Propagated to C
# code as KCFG_TARGET_PACKAGE via Kbuild ccflags-y. Note the literal quotes
# inside the value — `make TARGET_PKG='"com.example"'` is the safe way to
# override from the shell.
TARGET_PKG ?= "cent.tmgp.sgame"

# Optional compile-time concealment features (strict boolean values).
HIDE_SELF_MODULE ?= 1
HIDE_KGSL ?= 0

# KDIR resolution order:
#   1) explicit `make KDIR=...` on the command line
#   2) $KERNEL_SRC inside a ghcr.io/ylarod/ddk container
#   3) /lib/modules/$(uname -r)/build on a developer machine
ifeq ($(KDIR),)
ifneq ($(KERNEL_SRC),)
KDIR := $(KERNEL_SRC)
else
KDIR := /lib/modules/$(shell uname -r)/build
endif
endif

PWD := $(shell pwd)

# Pass-through variables that the Kbuild file consumes.
export DRIVER_NAME
export TARGET_PKG
export HIDE_SELF_MODULE
export HIDE_KGSL

.PHONY: all modules clean help compdb modules_install

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@rm -f compile_commands.json

# compile_commands.json — driven by Kbuild's clang command DB generator.
# Requires a recent kernel tree (>= 5.10) with scripts/clang-tools/gen_compile_commands.py.
compdb:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	@if [ -x $(KDIR)/scripts/clang-tools/gen_compile_commands.py ]; then \
		$(KDIR)/scripts/clang-tools/gen_compile_commands.py -d $(PWD) -o $(PWD)/compile_commands.json; \
		echo "compile_commands.json generated"; \
	else \
		echo "WARNING: $(KDIR)/scripts/clang-tools/gen_compile_commands.py not found"; \
	fi

help:
	@echo "Build targets:"
	@echo "  make [all]          - build $(DRIVER_NAME).ko"
	@echo "  make clean          - remove build artefacts"
	@echo "  make modules_install- install to /lib/modules (needs root)"
	@echo "  make compdb         - regenerate compile_commands.json"
	@echo ""
	@echo "Configurable variables:"
	@echo "  KDIR=<path>         - kernel build tree (default: \$$KERNEL_SRC or /lib/modules/\$$(uname -r)/build)"
	@echo "  DRIVER_NAME=<name>  - output .ko basename (default: my-driver)"
	@echo "  TARGET_PKG='\"...\"' - Android package name baked into the driver (default: \"cent.tmgp.sgame\")"
	@echo "  HIDE_SELF_MODULE=0|1 - hide the LKM from module lists/sysfs (default: 1)"
	@echo "  HIDE_KGSL=0|1       - enable KGSL process concealment ioctl (default: 0)"

endif
