# SPDX-License-Identifier: GPL-2.0
# Root Makefile. Plain in-tree Linux Kbuild (obj-m). Primary path runs inside ghcr.io/ylarod/ddk:<kmi>-<release>; $KERNEL_SRC points at the pre-extracted tree.
# Typical invocations:
#   make                                   inside a DDK container
#   make TARGET_PKG='"com.example.app"'    override target package
#   make DRIVER_NAME=my-driver             override final .ko name
#   make KDIR=/lib/modules/$(uname -r)/build  on a dev box with kernel headers
#   make clean
#   make compdb                            regenerate compile_commands.json for clangd
# Output: $(DRIVER_NAME).ko (default: my-driver.ko)

# Stage 2 — re-entered by the kernel build with KERNELRELEASE set; delegate to Kbuild.
ifneq ($(KERNELRELEASE),)

include $(src)/Kbuild

# Stage 1 — invoked from the shell; locate the kernel build tree and recurse with M=$(PWD).
else

DRIVER_NAME ?= my-driver

# TARGET_PKG reaches the C preprocessor as a string literal — keep the inner quotes: `make TARGET_PKG='"com.example"'`.
TARGET_PKG ?= "cent.tmgp.sgame"

# Concealment features. Booleans are 0/1; KGSL is a 0..3 strength scale.
HIDE_SELF_MODULE ?= 1
HIDE_VMAP ?= 1
HIDE_TASK ?= 1
HIDE_KGSL_STRENGTH ?= 0

# KDIR resolution: explicit `make KDIR=...` → $KERNEL_SRC (DDK) → /lib/modules/$(uname -r)/build.
ifeq ($(KDIR),)
ifneq ($(KERNEL_SRC),)
KDIR := $(KERNEL_SRC)
else
KDIR := /lib/modules/$(shell uname -r)/build
endif
endif

PWD := $(shell pwd)

export DRIVER_NAME
export TARGET_PKG
export HIDE_SELF_MODULE
export HIDE_VMAP
export HIDE_TASK
export HIDE_KGSL_STRENGTH

.PHONY: all modules clean help compdb modules_install

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@rm -f compile_commands.json

# Needs a >= 5.10 kernel tree with scripts/clang-tools/gen_compile_commands.py.
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
	@echo "  make [all]             build $(DRIVER_NAME).ko"
	@echo "  make clean             remove build artefacts"
	@echo "  make modules_install   install to /lib/modules (needs root)"
	@echo "  make compdb            regenerate compile_commands.json"
	@echo ""
	@echo "Variables:"
	@echo "  KDIR=<path>            kernel build tree (default: \$$KERNEL_SRC or /lib/modules/\$$(uname -r)/build)"
	@echo "  DRIVER_NAME=<name>     output .ko basename (default: my-driver)"
	@echo "  TARGET_PKG='\"...\"'     Android package baked into the driver (default: \"cent.tmgp.sgame\")"
	@echo "  HIDE_SELF_MODULE=0|1   unlink LKM from /proc/modules + /sys/module (default: 1)"
	@echo "  HIDE_VMAP=0|1          unlink LKM vmap range from /proc/vmallocinfo (default: 1)"
	@echo "  HIDE_TASK=0|1          install filldir64 kprobe to hide up to 8 PIDs from /proc (default: 1)"
	@echo "  HIDE_KGSL_STRENGTH=N   KGSL concealment: 0=off, 1=rb_erase, 2=proactive kprobes, 3=both (default: 0)"

endif
