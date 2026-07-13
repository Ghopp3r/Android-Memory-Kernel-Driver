// SPDX-License-Identifier: GPL-2.0
/* Module entry point + compile-time module self-concealment. */

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

#include <asm/memory.h>
#include <asm/page.h>
#include <asm/sysreg.h>

#include <driver/types.h>

#include "comm.h"
#include "kallsym.h"
#include "lifecycle.h"
#include "log.h"
#include "memory.h"

struct drv_state drv;

#if KCFG_HIDE_SELF_MODULE
/* Preserve the original driver's self-concealment when requested at build
 * time. This directly mutates loader-owned state on every supported KMI. */
static void conceal_module(void) {
	struct module *mod = THIS_MODULE;

	/* Remove the module from /proc/modules and leave its list head valid. */
	list_del(&mod->list);
	INIT_LIST_HEAD(&mod->list);

	/* Remove /sys/module/<name>, then reproduce the original binary's second
	 * list_del() that poisons the detached kobject entry. */
	kobject_del(&mod->mkobj.kobj);
	list_del(&mod->mkobj.kobj.entry);
}
#endif

/* Initialise drv.m_page_level and drv.m_pgd_va from TCR_EL1 / TTBR1_EL1 — the
 * values the binary captures at dispatch_ioctl case 0xD1 (DRV_CMD_INSTALL_HOOKS).
 * Computed once at module init so write_ro_memory (and every hook_install path)
 * sees them populated regardless of which ioctl arrives first.
 *
 * TCR_EL1.T1SZ is bits [21:16] and controls TTBR1_EL1 (kernel-half) VA size;
 * m_page_level = (60 - T1SZ) / 9 == ceil((48 - T1SZ) / 9). For VA_BITS=39
 * (NP05J / Vivo / Android 6.6 typical) T1SZ=25 -> level_count=3 (PUD->PMD->PTE).
 * For VA_BITS=48 (other GKI configs) T1SZ=16 -> level_count=4. LPA2 / VA_BITS=52
 * yields level_count=5. The process-memory walker uses the kernel's pgtable
 * helpers and supports it; the legacy text PTE-flip fallback rejects an
 * unsupported depth locally instead of blocking unrelated driver features. */
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

int __init init_driver(void) {
	int ret;

	pr_drv("driver_entry\n");

	/* Capture swapper_pg_dir + pagewalk depth before any hook path can run -- write_ro_memory's level_count==0 guard would silently no-op every patch otherwise. */
	mm_globals_init();

	/* Do not reject the whole module based on the legacy text walker's
	 * limits. write_ro_memory_pte_flip() is gated by granule and depth at
	 * its call site; aarch64_insn_patch_text_nosync() and the process-memory
	 * walkers are independent of drv.m_page_level. */
	/* Resolve kallsyms_lookup_name + every kallsym-shimmed function pointer that a kprobe pre-handler may need (currently just task_work_add). Done here, in process context, so the prctl/reboot pre-handlers never re-enter register_kprobe in atomic context. */
	ret = kallsym_init();
	if (ret < 0) {
		pr_drv_err("kallsym_init failed: %d\n", ret);
		return ret;
	}

	/* Resolve the kernel's text patcher and get_cmdline BEFORE any ioctl/hook
	 * path can use them. Missing symbols are non-fatal: the text writer uses
	 * its locally gated fallback where supported, and package lookup reports
	 * -EOPNOTSUPP. */
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

#if KCFG_HIDE_SELF_MODULE
	conceal_module();
#endif
	return 0;
}

module_init(init_driver);

/* Cargo-culted namespace import preserved verbatim from the original .ko modinfo. The token does not name any namespace that exists in mainline Linux 5.4-6.12 (verified via Bootlin Elixir); MODULE_IMPORT_NS expands to a modinfo string only, so this is a no-op at build/load time, but we keep it because byte-exactness vs. the source binary is part of the spec. */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anonymous");
MODULE_DESCRIPTION("Android kernel driver");
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
