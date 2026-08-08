// SPDX-License-Identifier: GPL-2.0-only
// kallsyms_lookup_name shim and kprobe-blacklist neutralizer.

#include <linux/bug.h>
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#include <linux/cfi.h>
#endif

/* __nocfi is required for indirect calls through kallsyms-resolved pointers on kCFI kernels (Android 13+ / KMI 5.15+). On pre-5.13 or non-CFI builds it is a harmless no-op. */
#ifndef __nocfi
#define __nocfi
#endif

#include "kallsym.h"
#include "log.h"

typedef unsigned long(*kallsyms_lookup_name_fn_t)(const char *name);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static kallsyms_lookup_name_fn_t kallsym_lookup_name_ptr;
#endif

/* CFI-safe trampoline: the indirect call to a kallsyms-resolved address must bypass kCFI's caller-side type check, since the target was not built with the matching CFI metadata. */
static __nocfi unsigned long kallsym_call_resolved(kallsyms_lookup_name_fn_t fn, const char *name) {
	return fn(name);
}

int kallsym_init(void) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name",
	};
	int ret;

	if (kallsym_lookup_name_ptr)
		return 0;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		LOGE("kallsym_init: register_kprobe (kallsyms_lookup_name) failed: %d\n", ret);
		return ret;
	}

	/* kprobes resolves symbol_name -> kp.addr before arming, so kp.addr is valid post-unregister. */
	kallsym_lookup_name_ptr = (kallsyms_lookup_name_fn_t)kp.addr;
	unregister_kprobe(&kp);

	if (!kallsym_lookup_name_ptr) {
		LOGE("kallsym_init: kp.addr was NULL after register_kprobe\n");
		return -ENOSYS;
	}

	LOGI("kallsym_init: kallsyms_lookup_name resolved at %p\n", kallsym_lookup_name_ptr);
	return 0;
#else
	/* < 5.7: kallsyms_lookup_name () is still EXPORT_SYMBOL_GPL, no shim needed. */
	return 0;
#endif
}

unsigned long kallsym_lookup(const char *name) {
	if (!name)
		return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
	if (!kallsym_lookup_name_ptr) {
		int ret = kallsym_init();
		if (ret)
			return 0;
	}

	return kallsym_call_resolved(kallsym_lookup_name_ptr, name);
#else
	return kallsyms_lookup_name(name);
#endif
}

unsigned long kallsym_lookup_or_die(const char *name) {
	unsigned long addr = kallsym_lookup(name);

	if (!addr) {
		LOGE("kallsym_lookup_or_die: required symbol \"%s\" not found\n", name ? name : "(null)");
		WARN_ON(1);
	}

	return addr;
}

/* Local mirror: kernel header layout shifts across versions; only the two address fields are stable. */
struct drv_kprobe_blacklist_entry {
	struct list_head list;
	unsigned long start_addr;
	unsigned long end_addr;
};

int kallsym_disable_kprobe_blacklist(void) {
	struct list_head *kprobe_blacklist;
	struct drv_kprobe_blacklist_entry *ent;
	int count = 0;

	kprobe_blacklist = (struct list_head *)kallsym_lookup("kprobe_blacklist");
	if (!kprobe_blacklist) {
		LOGE("kallsym_disable_kprobe_blacklist: kprobe_blacklist not found\n");
		return -ENOENT;
	}

	/* kprobe_mutex is static in kernel/kprobes.c and not exported; we walk the blacklist unlocked. This is an init-time best-effort and matches the original .ko -- safe in practice because nothing else is registering kprobes yet at module load. */
	list_for_each_entry(ent, kprobe_blacklist, list) {
		if (!ent || ent->start_addr == 0 || ent->end_addr == 0)
			continue;
		ent->start_addr = 0;
		ent->end_addr = 0;
		count++;
	}

	LOGI("kallsym_disable_kprobe_blacklist: disabled %d entries\n", count);
	return 0;
}
