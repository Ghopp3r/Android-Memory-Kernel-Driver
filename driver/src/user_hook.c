// SPDX-License-Identifier: GPL-2.0-only
// ARM64 user-code constant-return hooks; callers must quiesce the target while patching.

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <asm/memory.h>
#include <asm/page.h>
#include <asm/processor.h>

#include <driver/uapi.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#include <linux/cfi.h>
#endif
#ifndef __nocfi
#define __nocfi
#endif

#include "kallsym.h"
#include "log.h"
#include "user_hook.h"

#define USER_HOOK_PATCH_BYTES 32u
#define USER_HOOK_MAX_INSNS (USER_HOOK_PATCH_BYTES / sizeof(u32))
#define ARM64_BTI_C 0xD503245Fu
#define ARM64_NOP 0xD503201Fu
#define ARM64_RET_X30 0xD65F03C0u

static bool is_bti(u32 insn) {
	return (insn & 0xFFFFFF1Fu) == 0xD503241Fu;
}

typedef int (*access_remote_vm_fn_t)(struct mm_struct *mm, unsigned long addr, void *buf, int len, unsigned int gup_flags);

struct user_hook_slot {
	struct list_head node;
	struct pid *pid;
	struct mm_struct *mm;
	pid_t display_pid;
	unsigned long addr;
	u32 original[USER_HOOK_MAX_INSNS];
	u32 expected[USER_HOOK_MAX_INSNS];
	bool expected_valid;
};

static LIST_HEAD(slots);
static DEFINE_MUTEX(slots_lock);
static access_remote_vm_fn_t access_remote_vm_ptr;
static bool user_hook_initialized;
static bool user_hook_ready;

static inline u32 arm64_movz(u32 rd, u16 imm16, u32 hw) { return 0xD2800000u | (hw << 21) | ((u32)imm16 << 5) | rd; }
static inline u32 arm64_movk(u32 rd, u16 imm16, u32 hw) { return 0xF2800000u | (hw << 21) | ((u32)imm16 << 5) | rd; }
static inline u32 arm64_movz_w(u32 rd, u16 imm16, u32 hw) { return 0x52800000u | (hw << 21) | ((u32)imm16 << 5) | rd; }
static inline u32 arm64_movk_w(u32 rd, u16 imm16, u32 hw) { return 0x72800000u | (hw << 21) | ((u32)imm16 << 5) | rd; }
static inline u32 arm64_fmov_s_w(u32 sd, u32 wn) { return 0x1E270000u | (wn << 5) | sd; }
static inline u32 arm64_fmov_d_x(u32 dd, u32 xn) { return 0x9E670000u | (xn << 5) | dd; }

static int emit_mov_x(u32 *out, u32 rd, u64 value) {
	int count = 0;

	out[count++] = arm64_movz(rd, (u16)(value & 0xFFFFu), 0);
	if ((value >> 16) & 0xFFFFu) out[count++] = arm64_movk(rd, (u16)((value >> 16) & 0xFFFFu), 1);
	if ((value >> 32) & 0xFFFFu) out[count++] = arm64_movk(rd, (u16)((value >> 32) & 0xFFFFu), 2);
	if ((value >> 48) & 0xFFFFu) out[count++] = arm64_movk(rd, (u16)((value >> 48) & 0xFFFFu), 3);
	return count;
}

static int emit_mov_w(u32 *out, u32 rd, u32 value) {
	int count = 0;

	out[count++] = arm64_movz_w(rd, (u16)(value & 0xFFFFu), 0);
	if ((value >> 16) & 0xFFFFu) out[count++] = arm64_movk_w(rd, (u16)((value >> 16) & 0xFFFFu), 1);
	return count;
}

static bool kind_supported(u32 kind) {
	return kind == DRV_PTE_HOOK_CONST_U64 || kind == DRV_PTE_HOOK_CONST_FLOAT || kind == DRV_PTE_HOOK_CONST_DOUBLE || kind == DRV_PTE_HOOK_VOID_RET;
}

static int build_patch(u32 out[USER_HOOK_MAX_INSNS], const u32 original[USER_HOOK_MAX_INSNS], u32 kind, u64 value) {
	int count = 0;

	if (!kind_supported(kind)) return -EOPNOTSUPP;
	memcpy(out, original, USER_HOOK_PATCH_BYTES);
	out[count++] = is_bti(original[0]) ? original[0] : ARM64_BTI_C;

	switch (kind) {
		case DRV_PTE_HOOK_CONST_U64:
			count += emit_mov_x(&out[count], 0, value);
			out[count++] = ARM64_RET_X30;
			break;
		case DRV_PTE_HOOK_CONST_FLOAT:
			count += emit_mov_w(&out[count], 1, (u32)value);
			out[count++] = arm64_fmov_s_w(0, 1);
			out[count++] = ARM64_RET_X30;
			break;
		case DRV_PTE_HOOK_CONST_DOUBLE:
			count += emit_mov_x(&out[count], 1, value);
			out[count++] = arm64_fmov_d_x(0, 1);
			out[count++] = ARM64_RET_X30;
			break;
		case DRV_PTE_HOOK_VOID_RET:
			out[count++] = ARM64_RET_X30;
			break;
		default:
			return -EOPNOTSUPP;
	}

	if (count > (int)USER_HOOK_MAX_INSNS) return -E2BIG;
	while (count < (int)USER_HOOK_MAX_INSNS)
		out[count++] = ARM64_NOP;
	return 0;
}

static int normalize_addr(u64 raw, unsigned long *out) {
	unsigned long addr;

	if (!out) return -EINVAL;
	addr = untagged_addr((unsigned long)raw);
	if (!addr || (addr & (sizeof(u32) - 1u))) return -EINVAL;
	if (addr > ULONG_MAX - USER_HOOK_PATCH_BYTES) return -EINVAL;
	if (offset_in_page(addr) > PAGE_SIZE - USER_HOOK_PATCH_BYTES) return -ERANGE;
	*out = addr;
	return 0;
}

static int validate_vma(struct mm_struct *mm, unsigned long addr) {
	struct vm_area_struct *vma;
	unsigned long end = addr + USER_HOOK_PATCH_BYTES;
	int rc = 0;

	mmap_read_lock(mm);
	vma = find_vma(mm, addr);
	if (!vma || addr < vma->vm_start || end > vma->vm_end) rc = -EFAULT;
	else if (!(vma->vm_flags & VM_EXEC)) rc = -EACCES;
	else if (vma->vm_flags & (VM_SHARED | VM_IO | VM_PFNMAP | VM_MIXEDMAP)) rc = -EOPNOTSUPP;
	mmap_read_unlock(mm);
	return rc;
}

static int resolve_access_remote_vm_locked(void) {
	return access_remote_vm_ptr ? 0 : -EOPNOTSUPP;
}

static __nocfi noinline int call_access_remote_vm(access_remote_vm_fn_t fn, struct mm_struct *mm, unsigned long addr, void *buf, int len, unsigned int flags) {
	return fn(mm, addr, buf, len, flags);
}

static int copy_remote_locked(struct mm_struct *mm, unsigned long addr, void *buf, bool write) {
	unsigned int flags = FOLL_FORCE;
	int copied;
	int rc;

	rc = resolve_access_remote_vm_locked();
	if (rc) return rc;
	if (write) flags |= FOLL_WRITE;
	copied = call_access_remote_vm(access_remote_vm_ptr, mm, addr, buf, USER_HOOK_PATCH_BYTES, flags);
	if (copied == USER_HOOK_PATCH_BYTES) return 0;
	return copied < 0 ? copied : -EFAULT;
}

static struct user_hook_slot *lookup_locked(struct pid *pid, unsigned long addr) {
	struct user_hook_slot *slot;

	list_for_each_entry(slot, &slots, node) {
		if (slot->pid == pid && slot->addr == addr) return slot;
	}
	return NULL;
}

static struct user_hook_slot *lookup_overlap_locked(struct mm_struct *mm, unsigned long addr) {
	struct user_hook_slot *slot;

	list_for_each_entry(slot, &slots, node) {
		if (slot->mm == mm && addr < slot->addr + USER_HOOK_PATCH_BYTES && slot->addr < addr + USER_HOOK_PATCH_BYTES) return slot;
	}
	return NULL;
}

static void free_slot(struct user_hook_slot *slot) {
	put_pid(slot->pid);
	mmdrop(slot->mm);
	kfree(slot);
}

static int write_transaction_locked(struct user_hook_slot *slot, const u32 desired[USER_HOOK_MAX_INSNS], const u32 rollback[USER_HOOK_MAX_INSNS], bool *rollback_ok) {
	int rc;

	*rollback_ok = false;
	rc = copy_remote_locked(slot->mm, slot->addr, (void *)desired, true);
	if (!rc) return 0;
	if (!copy_remote_locked(slot->mm, slot->addr, (void *)rollback, true)) *rollback_ok = true;
	return rc;
}

static int restore_slot_locked(struct user_hook_slot *slot, bool *mm_dead) {
	u32 observed[USER_HOOK_MAX_INSNS];
	bool rollback_ok;
	int rc;

	*mm_dead = false;
	if (!mmget_not_zero(slot->mm)) {
		*mm_dead = true;
		return 0;
	}
	rc = validate_vma(slot->mm, slot->addr);
	if (rc) goto out;
	rc = copy_remote_locked(slot->mm, slot->addr, observed, false);
	if (rc) goto out;
	if (memcmp(observed, slot->original, USER_HOOK_PATCH_BYTES) == 0) {
		rc = 0;
		goto out;
	}
	if (!slot->expected_valid) {
		rc = -EUCLEAN;
		goto out;
	}
	if (memcmp(observed, slot->expected, USER_HOOK_PATCH_BYTES) != 0) {
		rc = -ESTALE;
		goto out;
	}

	rc = write_transaction_locked(slot, slot->original, slot->expected, &rollback_ok);
	if (rc && !rollback_ok) slot->expected_valid = false;

out:
	mmput(slot->mm);
	return rc;
}

static int resolve_target(pid_t nr, struct pid **out_pid, struct task_struct **out_task, struct mm_struct **out_mm) {
	struct pid *requested;
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid;

	requested = find_get_pid(nr);
	if (!requested) return -ESRCH;
	task = get_pid_task(requested, PIDTYPE_PID);
	put_pid(requested);
	if (!task) {
		return -ESRCH;
	}
#if IS_ENABLED(CONFIG_COMPAT)
	if (is_compat_thread(task_thread_info(task))) {
		put_task_struct(task);
		return -EOPNOTSUPP;
	}
#endif
	pid = get_task_pid(task, PIDTYPE_TGID);
	if (!pid) {
		put_task_struct(task);
		return -ESRCH;
	}
	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		put_pid(pid);
		return -ESRCH;
	}
	*out_pid = pid;
	*out_task = task;
	*out_mm = mm;
	return 0;
}

static int resolve_tgid_pid(pid_t nr, struct pid **out_pid) {
	struct pid *requested;
	struct task_struct *task;
	struct pid *tgid;

	requested = find_get_pid(nr);
	if (!requested) return -ESRCH;
	task = get_pid_task(requested, PIDTYPE_PID);
	if (!task) {
		*out_pid = requested;
		return 0;
	}
	put_pid(requested);
	tgid = get_task_pid(task, PIDTYPE_TGID);
	put_task_struct(task);
	if (!tgid) return -ESRCH;
	*out_pid = tgid;
	return 0;
}

static long do_install(void __user *arg) {
	struct drv_pte_hook_install_req req;
	struct user_hook_slot *slot;
	struct user_hook_slot *dup;
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid;
	unsigned long addr;
	u32 next[USER_HOOK_MAX_INSNS];
	u32 observed[USER_HOOK_MAX_INSNS];
	bool rollback_ok;
	bool mm_dead;
	bool slot_owns_refs = false;
	int rc;

	if (copy_from_user(&req, arg, sizeof(req)) != 0) return -EFAULT;
	if (req.pid <= 0) return -EINVAL;
	if (!kind_supported(req.kind)) return -EOPNOTSUPP;
	if (req.tramp_addr || req.replace_addr) return -EINVAL;
	rc = normalize_addr(req.addr, &addr);
	if (rc) return rc;
	rc = resolve_target(req.pid, &pid, &task, &mm);
	if (rc) return rc;
	rc = validate_vma(mm, addr);
	if (rc) goto out_target;

	slot = kzalloc(sizeof(*slot), GFP_KERNEL);
	if (!slot) {
		rc = -ENOMEM;
		goto out_target;
	}

	mutex_lock(&slots_lock);
	dup = lookup_locked(pid, addr);
	if (!dup && lookup_overlap_locked(mm, addr)) {
		rc = -EBUSY;
		goto out_unlock_free_new;
	}
	if (dup && dup->mm != mm) {
		rc = restore_slot_locked(dup, &mm_dead);
		if (rc) goto out_unlock_free_new;
		list_del(&dup->node);
		free_slot(dup);
		dup = NULL;
	}

	if (dup) {
		rc = validate_vma(dup->mm, dup->addr);
		if (rc) goto out_unlock_free_new;
		rc = copy_remote_locked(dup->mm, dup->addr, observed, false);
		if (rc) goto out_unlock_free_new;
		if (!dup->expected_valid || memcmp(observed, dup->expected, USER_HOOK_PATCH_BYTES) != 0) {
			rc = -ESTALE;
			goto out_unlock_free_new;
		}
		rc = build_patch(next, dup->original, req.kind, req.ret_value);
		if (rc) goto out_unlock_free_new;
		if (memcmp(next, dup->expected, USER_HOOK_PATCH_BYTES) == 0) {
			rc = 0;
			goto out_unlock_free_new;
		}
		rc = write_transaction_locked(dup, next, dup->expected, &rollback_ok);
		if (rc) {
			if (!rollback_ok) dup->expected_valid = false;
			goto out_unlock_free_new;
		}
		memcpy(dup->expected, next, USER_HOOK_PATCH_BYTES);
		dup->expected_valid = true;
		LOGI("pte_hook: updated pid=%d addr=0x%lx kind=%u\n", req.pid, addr, req.kind);
		goto out_unlock_free_new;
	}

	INIT_LIST_HEAD(&slot->node);
	slot->pid = pid;
	pid = NULL;
	slot->mm = mm;
	slot->display_pid = req.pid;
	slot->addr = addr;
	mmgrab(mm);
	slot_owns_refs = true;
	rc = copy_remote_locked(mm, addr, slot->original, false);
	if (rc) goto out_unlock_free_new;
	rc = build_patch(slot->expected, slot->original, req.kind, req.ret_value);
	if (rc) goto out_unlock_free_new;
	slot->expected_valid = true;
	list_add_tail(&slot->node, &slots);
	rc = write_transaction_locked(slot, slot->expected, slot->original, &rollback_ok);
	if (rc) {
		if (rollback_ok) {
			list_del(&slot->node);
			free_slot(slot);
			slot_owns_refs = false;
		} else {
			slot->expected_valid = false;
			LOGE("pte_hook: install rollback failed pid=%d addr=0x%lx; recovery slot kept\n", req.pid, addr);
		}
		goto out_unlock;
	}
	LOGI("pte_hook: installed pid=%d addr=0x%lx kind=%u\n", req.pid, addr, req.kind);

out_unlock:
	mutex_unlock(&slots_lock);
	if (pid) put_pid(pid);
	mmput(mm);
	put_task_struct(task);
	return rc;

out_unlock_free_new:
	mutex_unlock(&slots_lock);
	if (slot_owns_refs) free_slot(slot);
	else kfree(slot);
	if (pid) put_pid(pid);
out_target:
	mmput(mm);
	put_task_struct(task);
	return rc;
}

static long do_remove(void __user *arg) {
	struct drv_ioctl_req req;
	struct user_hook_slot *slot;
	struct pid *pid;
	unsigned long addr;
	bool mm_dead;
	int rc;

	if (copy_from_user(&req, arg, sizeof(req)) != 0) return -EFAULT;
	if (!req.pid || req.pid > INT_MAX) return -EINVAL;
	rc = normalize_addr(req.addr, &addr);
	if (rc) return rc;
	rc = resolve_tgid_pid((pid_t)req.pid, &pid);
	if (rc) return rc;

	mutex_lock(&slots_lock);
	slot = lookup_locked(pid, addr);
	if (!slot) {
		rc = -ENOENT;
		goto out;
	}
	rc = restore_slot_locked(slot, &mm_dead);
	if (rc) goto out;
	list_del(&slot->node);
	LOGI("pte_hook: removed pid=%d addr=0x%lx%s\n", slot->display_pid, slot->addr, mm_dead ? " (mm gone)" : "");
	free_slot(slot);

out:
	mutex_unlock(&slots_lock);
	put_pid(pid);
	return rc;
}

static long do_clear_all(void) {
	struct user_hook_slot *slot;
	struct user_hook_slot *next;
	int first_error = 0;

	mutex_lock(&slots_lock);
	list_for_each_entry_safe(slot, next, &slots, node) {
		bool mm_dead;
		int rc = restore_slot_locked(slot, &mm_dead);

		if (rc) {
			if (!first_error) first_error = rc;
			LOGE("pte_hook: clear failed pid=%d addr=0x%lx rc=%d\n", slot->display_pid, slot->addr, rc);
			continue;
		}
		list_del(&slot->node);
		free_slot(slot);
	}
	mutex_unlock(&slots_lock);
	return first_error;
}

long do_pte_hook_cmd(unsigned int cmd, void __user *arg) {
	if (!user_hook_ready) return -EOPNOTSUPP;
	switch (cmd) {
		case DRV_CMD_PTE_HOOK_INSTALL:
			return do_install(arg);
		case DRV_CMD_PTE_HOOK_REMOVE:
			return do_remove(arg);
		case DRV_CMD_PTE_HOOK_CLEAR_ALL:
			return do_clear_all();
		default:
			return -ENOTTY;
	}
}

int user_hook_init(void) {
	if (user_hook_initialized) return user_hook_ready ? 0 : -EOPNOTSUPP;
	user_hook_initialized = true;
	BUILD_BUG_ON(sizeof(struct drv_pte_hook_install_req) != 40);
	access_remote_vm_ptr = (access_remote_vm_fn_t)kallsym_lookup("access_remote_vm");
	if (!access_remote_vm_ptr) {
		LOGN("pte_hook: unavailable on this kernel\n");
		return -EOPNOTSUPP;
	}
	user_hook_ready = true;
	return 0;
}
