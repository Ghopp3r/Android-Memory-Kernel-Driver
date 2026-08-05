// SPDX-License-Identifier: GPL-2.0-only
// AArch64 user execute-breakpoint overrides and hit capture.

#include <linux/errno.h>
#include <linux/hw_breakpoint.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/mutex.h>
#include <linux/perf_event.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <asm/compat.h>
#include <asm/cpufeature.h>
#include <asm/fpsimd.h>
#include <asm/memory.h>
#include <asm/processor.h>
#include <asm/uaccess.h>

#include <driver/uapi.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#include <linux/cfi.h>
#endif
#ifndef __nocfi
#define __nocfi
#endif

#include "hwbp.h"
#include "kallsym.h"
#include "log.h"

typedef struct perf_event *(*drv_register_user_hw_bp_fn_t)(struct perf_event_attr *attr, perf_overflow_handler_t handler, void *context, struct task_struct *task);
typedef void (*drv_unregister_hw_bp_fn_t)(struct perf_event *bp);
typedef int (*drv_modify_user_hw_bp_fn_t)(struct perf_event *bp, struct perf_event_attr *attr);
typedef int (*drv_access_remote_vm_fn_t)(struct mm_struct *mm, unsigned long addr, void *buf, int len, unsigned int gup_flags);
typedef void (*drv_fpsimd_preserve_current_state_fn_t)(void);
typedef void (*drv_fpsimd_update_current_state_fn_t)(const struct user_fpsimd_state *state);

static drv_register_user_hw_bp_fn_t drv_register_user_hw_bp_ptr;
static drv_unregister_hw_bp_fn_t drv_unregister_hw_bp_ptr;
static drv_modify_user_hw_bp_fn_t drv_modify_user_hw_bp_ptr;
static drv_access_remote_vm_fn_t drv_access_remote_vm_ptr;
static drv_fpsimd_preserve_current_state_fn_t drv_fpsimd_preserve_current_state_ptr;
static drv_fpsimd_update_current_state_fn_t drv_fpsimd_update_current_state_ptr;
static bool hwbp_initialized;
static bool hwbp_ready;
static bool hwbp_fp_ready;

static __nocfi noinline struct perf_event *drv_call_register_user_hw_bp(drv_register_user_hw_bp_fn_t fn, struct perf_event_attr *attr, perf_overflow_handler_t handler, void *context, struct task_struct *task) { return fn(attr, handler, context, task); }
static __nocfi noinline void drv_call_unregister_hw_bp(drv_unregister_hw_bp_fn_t fn, struct perf_event *bp) { fn(bp); }
static __nocfi noinline int drv_call_modify_user_hw_bp(drv_modify_user_hw_bp_fn_t fn, struct perf_event *bp, struct perf_event_attr *attr) { return fn(bp, attr); }
static __nocfi noinline int drv_call_access_remote_vm(drv_access_remote_vm_fn_t fn, struct mm_struct *mm, unsigned long addr, void *buf, int len, unsigned int flags) { return fn(mm, addr, buf, len, flags); }
static __nocfi noinline void drv_call_fpsimd_preserve_current_state(drv_fpsimd_preserve_current_state_fn_t fn) { fn(); }
static __nocfi noinline void drv_call_fpsimd_update_current_state(drv_fpsimd_update_current_state_fn_t fn, const struct user_fpsimd_state *state) { fn(state); }

enum hwbp_toggle_state {
	HWBP_TOGGLE_ORIGIN,
	HWBP_TOGGLE_NEXT,
};

struct hwbp_tracker {
	struct list_head node;
	struct pid *pid_ref;
	struct mm_struct *mm;
	struct perf_event *bp;
	u64 addr;
	u32 bp_len;
	u32 bp_type;
	u32 pass_through;
	u32 orphaned;
	spinlock_t override_lock;
	u32 override_count;
	struct drv_hwbp_reg_override overrides[DRV_HWBP_MAX_OVERRIDES];
	spinlock_t ring_lock;
	struct drv_hwbp_hit ring[DRV_HWBP_HIT_RING_SLOTS];
	u32 ring_head;
	u32 ring_tail;
	u32 ring_count;
	u64 ring_tail_seq;
	enum hwbp_toggle_state toggle;
};

static LIST_HEAD(hwbp_trackers);
static DEFINE_MUTEX(hwbp_mutex);

static int hwbp_validate_override(const struct drv_hwbp_reg_override *override) {
	if (!override)
		return -EINVAL;

	switch (override->kind) {
	case DRV_HWBP_REG_NONE:
		return 0;
	case DRV_HWBP_REG_X:
		return override->index <= 30u ? 0 : -EINVAL;
	case DRV_HWBP_REG_VLO:
	case DRV_HWBP_REG_VHI:
		if (!hwbp_fp_ready)
			return -EOPNOTSUPP;
		return override->index <= 31u ? 0 : -EINVAL;
	case DRV_HWBP_REG_PC:
		return override->index == 0 ? 0 : -EINVAL;
	default:
		return -EINVAL;
	}
}

static int hwbp_validate_overrides(const struct drv_hwbp_install_req *req) {
	u32 i;

	if (req->override_count > DRV_HWBP_MAX_OVERRIDES)
		return -EINVAL;
	for (i = 0; i < req->override_count; i++) {
		int rc = hwbp_validate_override(&req->overrides[i]);

		if (rc)
			return rc;
	}
	return 0;
}

static bool hwbp_request_has_pc_override(const struct drv_hwbp_install_req *req) {
	u32 i;

	for (i = 0; i < req->override_count; i++) {
		if (req->overrides[i].kind == DRV_HWBP_REG_PC)
			return true;
	}
	return false;
}

static bool hwbp_overrides_have_pc(const struct drv_hwbp_reg_override *overrides, u32 count) {
	u32 i;

	for (i = 0; i < count; i++) {
		if (overrides[i].kind == DRV_HWBP_REG_PC)
			return true;
	}
	return false;
}

static void hwbp_set_overrides(struct hwbp_tracker *tracker, const struct drv_hwbp_install_req *req) {
	unsigned long flags;

	spin_lock_irqsave(&tracker->override_lock, flags);
	tracker->override_count = req->override_count;
	memcpy(tracker->overrides, req->overrides, sizeof(tracker->overrides));
	spin_unlock_irqrestore(&tracker->override_lock, flags);
}

static u32 hwbp_snapshot_overrides(struct hwbp_tracker *tracker, struct drv_hwbp_reg_override *out) {
	unsigned long flags;
	u32 count;

	spin_lock_irqsave(&tracker->override_lock, flags);
	count = tracker->override_count;
	memcpy(out, tracker->overrides, sizeof(tracker->overrides));
	spin_unlock_irqrestore(&tracker->override_lock, flags);
	return count;
}

static void hwbp_ring_push(struct hwbp_tracker *tracker, const struct pt_regs *regs) {
	struct drv_hwbp_hit *hit;
	unsigned long flags;
	u32 i;

	spin_lock_irqsave(&tracker->ring_lock, flags);
	hit = &tracker->ring[tracker->ring_head];
	hit->timestamp_ns = ktime_get_boottime_ns();
	hit->pc = regs->pc;
	hit->sp = regs->sp;
	hit->pstate = regs->pstate;
	for (i = 0; i < ARRAY_SIZE(hit->x); i++)
		hit->x[i] = regs->regs[i];
	tracker->ring_head = (tracker->ring_head + 1u) % DRV_HWBP_HIT_RING_SLOTS;
	if (tracker->ring_count < DRV_HWBP_HIT_RING_SLOTS) {
		tracker->ring_count++;
	} else {
		tracker->ring_tail = (tracker->ring_tail + 1u) % DRV_HWBP_HIT_RING_SLOTS;
		tracker->ring_tail_seq++;
	}
	spin_unlock_irqrestore(&tracker->ring_lock, flags);
}

static void hwbp_apply_gp(struct pt_regs *regs, const struct drv_hwbp_reg_override *overrides, u32 count) {
	u32 i;

	for (i = 0; i < count; i++) {
		switch (overrides[i].kind) {
		case DRV_HWBP_REG_X:
			regs->regs[overrides[i].index] = overrides[i].value;
			break;
		case DRV_HWBP_REG_PC:
			regs->pc = overrides[i].value;
			break;
		default:
			break;
		}
	}
}

static void hwbp_apply_fp(const struct drv_hwbp_reg_override *overrides, u32 count) {
	struct user_fpsimd_state state;
	u64 *vregs;
	u32 i;

	if (!hwbp_fp_ready)
		return;
	drv_call_fpsimd_preserve_current_state(drv_fpsimd_preserve_current_state_ptr);
	state = current->thread.uw.fpsimd_state;
	vregs = (u64 *)&state.vregs[0];
	for (i = 0; i < count; i++) {
		if (overrides[i].kind == DRV_HWBP_REG_VLO)
			vregs[2u * overrides[i].index] = overrides[i].value;
		else if (overrides[i].kind == DRV_HWBP_REG_VHI)
			vregs[2u * overrides[i].index + 1u] = overrides[i].value;
	}
	drv_call_fpsimd_update_current_state(drv_fpsimd_update_current_state_ptr, &state);
}

static bool hwbp_has_fp_override(const struct drv_hwbp_reg_override *overrides, u32 count) {
	u32 i;

	for (i = 0; i < count; i++) {
		if (overrides[i].kind == DRV_HWBP_REG_VLO || overrides[i].kind == DRV_HWBP_REG_VHI)
			return true;
	}
	return false;
}

static int hwbp_set_breakpoint_address(struct perf_event *bp, u64 addr) {
	struct perf_event_attr attr = bp->attr;

	attr.bp_addr = addr;
	attr.disabled = 0;
	return drv_call_modify_user_hw_bp(drv_modify_user_hw_bp_ptr, bp, &attr);
}

static void hwbp_disable_orphaned(struct hwbp_tracker *tracker, struct perf_event *bp) {
	struct perf_event_attr attr = bp->attr;
	int rc;

	WRITE_ONCE(tracker->orphaned, 1u);
	attr.disabled = 1;
	rc = drv_call_modify_user_hw_bp(drv_modify_user_hw_bp_ptr, bp, &attr);
	if (rc)
		pr_drv_warn_ratelimited("hwbp: disable stale tracker rc=%d\n", rc);
}

static void hwbp_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
	struct hwbp_tracker *tracker;
	struct drv_hwbp_reg_override overrides[DRV_HWBP_MAX_OVERRIDES];
	u32 count;
	int rc;

	(void)data;
	if (!bp || !regs)
		return;
	tracker = bp->overflow_handler_context;
	if (!tracker)
		return;
	if (unlikely(READ_ONCE(tracker->orphaned) || current->mm != tracker->mm)) {
		hwbp_disable_orphaned(tracker, bp);
		return;
	}

	if (tracker->pass_through && READ_ONCE(tracker->toggle) == HWBP_TOGGLE_NEXT) {
		rc = hwbp_set_breakpoint_address(bp, tracker->addr);
		if (rc) {
			pr_drv_warn_ratelimited("hwbp: rearm rc=%d\n", rc);
			return;
		}
		WRITE_ONCE(tracker->toggle, HWBP_TOGGLE_ORIGIN);
		return;
	}

	count = hwbp_snapshot_overrides(tracker, overrides);
	hwbp_ring_push(tracker, regs);
	if (hwbp_has_fp_override(overrides, count))
		hwbp_apply_fp(overrides, count);
	hwbp_apply_gp(regs, overrides, count);
	if (!tracker->pass_through) {
		if (!hwbp_overrides_have_pc(overrides, count))
			regs->pc = regs->regs[30];
		return;
	}

	rc = hwbp_set_breakpoint_address(bp, tracker->addr + DRV_HWBP_LEN_EXECUTE);
	if (rc) {
		pr_drv_warn_ratelimited("hwbp: advance rc=%d\n", rc);
		return;
	}
	WRITE_ONCE(tracker->toggle, HWBP_TOGGLE_NEXT);
}
NOKPROBE_SYMBOL(hwbp_handler);

static struct hwbp_tracker *hwbp_lookup_locked(struct pid *pid_ref, u64 addr) {
	struct hwbp_tracker *tracker;

	list_for_each_entry(tracker, &hwbp_trackers, node) {
		if (tracker->pid_ref == pid_ref && tracker->addr == addr)
			return tracker;
	}
	return NULL;
}

static void hwbp_tracker_free(struct hwbp_tracker *tracker) {
	if (!tracker)
		return;
	if (tracker->mm)
		mmdrop(tracker->mm);
	if (tracker->pid_ref)
		put_pid(tracker->pid_ref);
	kfree(tracker);
}

static void hwbp_unregister_and_free(struct hwbp_tracker *tracker) {
	if (tracker->bp)
		drv_call_unregister_hw_bp(drv_unregister_hw_bp_ptr, tracker->bp);
	hwbp_tracker_free(tracker);
}

static int hwbp_validate_address(struct mm_struct *mm, unsigned long addr) {
	struct vm_area_struct *vma;
	int rc = 0;

	if (!addr || addr & (DRV_HWBP_LEN_EXECUTE - 1u) || addr > ULONG_MAX - DRV_HWBP_LEN_EXECUTE)
		return -EINVAL;
	mmap_read_lock(mm);
	vma = find_vma(mm, addr);
	if (!vma || addr < vma->vm_start || addr + DRV_HWBP_LEN_EXECUTE > vma->vm_end || !(vma->vm_flags & VM_EXEC) || (vma->vm_flags & (VM_IO | VM_PFNMAP)))
		rc = -EFAULT;
	mmap_read_unlock(mm);
	return rc;
}

static bool hwbp_is_control_flow(u32 insn) {
	if ((insn & 0x7C000000u) == 0x14000000u)
		return true;
	if ((insn & 0xFF000010u) == 0x54000000u)
		return true;
	if ((insn & 0x7E000000u) == 0x34000000u || (insn & 0x7E000000u) == 0x36000000u)
		return true;
	if ((insn & 0xFFE00000u) == 0xD4000000u || (insn & 0xFE000000u) == 0xD6000000u)
		return true;
	return false;
}

static int hwbp_validate_fallthrough(struct mm_struct *mm, unsigned long addr) {
	u32 insn;
	int rc;

	rc = drv_call_access_remote_vm(drv_access_remote_vm_ptr, mm, addr, &insn, sizeof(insn), FOLL_FORCE);
	if (rc != sizeof(insn))
		return rc < 0 ? rc : -EFAULT;
	return hwbp_is_control_flow(insn) ? -EOPNOTSUPP : 0;
}

static int hwbp_get_task_mm(struct pid *pid_ref, struct task_struct **out_task, struct mm_struct **out_mm) {
	struct task_struct *task;
	struct mm_struct *mm;

	*out_task = NULL;
	*out_mm = NULL;
	task = get_pid_task(pid_ref, PIDTYPE_PID);
	if (!task)
		return -ESRCH;
#if IS_ENABLED(CONFIG_COMPAT)
	if (is_compat_thread(task_thread_info(task))) {
		put_task_struct(task);
		return -EOPNOTSUPP;
	}
#endif
	mm = get_task_mm(task);
	if (!mm) {
		put_task_struct(task);
		return -ESRCH;
	}
	*out_task = task;
	*out_mm = mm;
	return 0;
}

static int hwbp_get_pid_ref(u64 raw_pid, struct pid **out_pid) {
	if (!raw_pid || raw_pid > INT_MAX)
		return -EINVAL;
	*out_pid = find_get_pid((pid_t)raw_pid);
	return *out_pid ? 0 : -ESRCH;
}

static int hwbp_normalize_install(struct drv_hwbp_install_req *req) {
	int rc;

	if (req->pid <= 0)
		return -EINVAL;
	req->addr = (u64)untagged_addr((unsigned long)req->addr);
	if (!req->bp_type)
		req->bp_type = DRV_HWBP_TYPE_EXECUTE;
	if (!req->bp_len)
		req->bp_len = DRV_HWBP_LEN_EXECUTE;
	if (req->bp_type != DRV_HWBP_TYPE_EXECUTE || req->bp_len != DRV_HWBP_LEN_EXECUTE || req->pass_through > 1u)
		return -EOPNOTSUPP;
	rc = hwbp_validate_overrides(req);
	if (rc)
		return rc;
	if (req->pass_through && hwbp_request_has_pc_override(req))
		return -EINVAL;
	return 0;
}

static long hwbp_install(void __user *arg) {
	struct drv_hwbp_install_req req;
	struct hwbp_tracker *tracker;
	struct hwbp_tracker *existing;
	struct perf_event_attr attr;
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_ref;
	int rc;

	if (copy_from_user(&req, arg, sizeof(req)) != 0)
		return -EFAULT;
	rc = hwbp_normalize_install(&req);
	if (rc)
		return rc;
	rc = hwbp_get_pid_ref((u64)req.pid, &pid_ref);
	if (rc)
		return rc;
	rc = hwbp_get_task_mm(pid_ref, &task, &mm);
	if (rc)
		goto out_put_pid;
	rc = hwbp_validate_address(mm, (unsigned long)req.addr);
	if (rc)
		goto out_put_task_mm;
	if (req.pass_through) {
		rc = hwbp_validate_address(mm, (unsigned long)req.addr + DRV_HWBP_LEN_EXECUTE);
		if (rc)
			goto out_put_task_mm;
		rc = hwbp_validate_fallthrough(mm, (unsigned long)req.addr);
		if (rc)
			goto out_put_task_mm;
	}

	mutex_lock(&hwbp_mutex);
	existing = hwbp_lookup_locked(pid_ref, req.addr);
	if (existing && existing->mm == mm) {
		if (existing->bp_type != req.bp_type || existing->bp_len != req.bp_len || existing->pass_through != req.pass_through) {
			rc = -EBUSY;
		} else {
			hwbp_set_overrides(existing, &req);
			rc = 0;
		}
		mutex_unlock(&hwbp_mutex);
		goto out_put_task_mm;
	}
	if (existing) {
		list_del(&existing->node);
		hwbp_unregister_and_free(existing);
	}
	tracker = kzalloc(sizeof(*tracker), GFP_KERNEL);
	if (!tracker) {
		mutex_unlock(&hwbp_mutex);
		rc = -ENOMEM;
		goto out_put_task_mm;
	}
	INIT_LIST_HEAD(&tracker->node);
	spin_lock_init(&tracker->override_lock);
	spin_lock_init(&tracker->ring_lock);
	tracker->pid_ref = get_pid(pid_ref);
	tracker->mm = mm;
	mmgrab(mm);
	tracker->addr = req.addr;
	tracker->bp_len = req.bp_len;
	tracker->bp_type = req.bp_type;
	tracker->pass_through = req.pass_through;
	tracker->toggle = HWBP_TOGGLE_ORIGIN;
	hwbp_set_overrides(tracker, &req);
	hw_breakpoint_init(&attr);
	attr.bp_addr = req.addr;
	attr.bp_len = DRV_HWBP_LEN_EXECUTE;
	attr.bp_type = HW_BREAKPOINT_X;
	attr.sample_period = 1;
	tracker->bp = drv_call_register_user_hw_bp(drv_register_user_hw_bp_ptr, &attr, hwbp_handler, tracker, task);
	if (IS_ERR_OR_NULL(tracker->bp)) {
		rc = tracker->bp ? PTR_ERR(tracker->bp) : -EIO;
		tracker->bp = NULL;
		hwbp_tracker_free(tracker);
		mutex_unlock(&hwbp_mutex);
		goto out_put_task_mm;
	}
	list_add_tail(&tracker->node, &hwbp_trackers);
	mutex_unlock(&hwbp_mutex);
	pr_drv("hwbp: installed pid=%d addr=%px passthrough=%u overrides=%u\n", req.pid, (void *)(uintptr_t)req.addr, req.pass_through, req.override_count);
	rc = 0;

out_put_task_mm:
	mmput(mm);
	put_task_struct(task);
out_put_pid:
	put_pid(pid_ref);
	return rc;
}

static long hwbp_set_override(void __user *arg) {
	struct drv_hwbp_install_req req;
	struct hwbp_tracker *tracker;
	struct task_struct *task;
	struct mm_struct *mm;
	struct pid *pid_ref;
	int rc;

	if (copy_from_user(&req, arg, sizeof(req)) != 0)
		return -EFAULT;
	if (req.pid <= 0)
		return -EINVAL;
	req.addr = (u64)untagged_addr((unsigned long)req.addr);
	rc = hwbp_validate_overrides(&req);
	if (rc)
		return rc;
	rc = hwbp_get_pid_ref((u64)req.pid, &pid_ref);
	if (rc)
		return rc;
	rc = hwbp_get_task_mm(pid_ref, &task, &mm);
	if (rc)
		goto out_put_pid;
	mutex_lock(&hwbp_mutex);
	tracker = hwbp_lookup_locked(pid_ref, req.addr);
	if (!tracker)
		rc = -ENOENT;
	else if (tracker->mm != mm)
		rc = -ESTALE;
	else {
		hwbp_set_overrides(tracker, &req);
		rc = 0;
	}
	mutex_unlock(&hwbp_mutex);
	mmput(mm);
	put_task_struct(task);
out_put_pid:
	put_pid(pid_ref);
	return rc;
}

static long hwbp_remove(void __user *arg) {
	struct drv_ioctl_req req;
	struct hwbp_tracker *tracker;
	struct pid *pid_ref;
	int rc;

	if (copy_from_user(&req, arg, sizeof(req)) != 0)
		return -EFAULT;
	req.addr = (u64)untagged_addr((unsigned long)req.addr);
	rc = hwbp_get_pid_ref(req.pid, &pid_ref);
	if (rc)
		return rc;
	mutex_lock(&hwbp_mutex);
	tracker = hwbp_lookup_locked(pid_ref, req.addr);
	if (!tracker) {
		mutex_unlock(&hwbp_mutex);
		put_pid(pid_ref);
		return -ENOENT;
	}
	list_del(&tracker->node);
	hwbp_unregister_and_free(tracker);
	mutex_unlock(&hwbp_mutex);
	put_pid(pid_ref);
	return 0;
}

static long hwbp_get_hits(void __user *arg) {
	struct drv_ioctl_req req;
	struct hwbp_tracker *tracker;
	struct drv_hwbp_hit *hits;
	struct pid *pid_ref;
	unsigned long flags;
	u64 start_tail_seq;
	u64 written;
	u32 capacity;
	u32 count;
	u32 i;
	int rc;

	if (copy_from_user(&req, arg, sizeof(req)) != 0)
		return -EFAULT;
	if (!req.buf || req.size < sizeof(*hits))
		return -EINVAL;
	req.addr = (u64)untagged_addr((unsigned long)req.addr);
	rc = hwbp_get_pid_ref(req.pid, &pid_ref);
	if (rc)
		return rc;
	capacity = min_t(u64, req.size / sizeof(*hits), DRV_HWBP_HIT_RING_SLOTS);
	hits = kcalloc(capacity, sizeof(*hits), GFP_KERNEL);
	if (!hits) {
		put_pid(pid_ref);
		return -ENOMEM;
	}

	mutex_lock(&hwbp_mutex);
	tracker = hwbp_lookup_locked(pid_ref, req.addr);
	if (!tracker) {
		rc = -ENOENT;
		goto out_unlock;
	}
	spin_lock_irqsave(&tracker->ring_lock, flags);
	count = min(tracker->ring_count, capacity);
	start_tail_seq = tracker->ring_tail_seq;
	for (i = 0; i < count; i++)
		hits[i] = tracker->ring[(tracker->ring_tail + i) % DRV_HWBP_HIT_RING_SLOTS];
	spin_unlock_irqrestore(&tracker->ring_lock, flags);
	written = (u64)count * sizeof(*hits);
	if (count && copy_to_user((void __user *)(uintptr_t)req.buf, hits, written) != 0) {
		rc = -EFAULT;
		goto out_unlock;
	}
	if (copy_to_user((u8 __user *)arg + offsetof(struct drv_ioctl_req, size), &written, sizeof(written)) != 0) {
		rc = -EFAULT;
		goto out_unlock;
	}
	spin_lock_irqsave(&tracker->ring_lock, flags);
	if (tracker->ring_tail_seq != start_tail_seq || tracker->ring_count < count) {
		spin_unlock_irqrestore(&tracker->ring_lock, flags);
		rc = -EAGAIN;
		goto out_unlock;
	}
	tracker->ring_tail = (tracker->ring_tail + count) % DRV_HWBP_HIT_RING_SLOTS;
	tracker->ring_count -= count;
	tracker->ring_tail_seq += count;
	spin_unlock_irqrestore(&tracker->ring_lock, flags);
	rc = 0;

out_unlock:
	mutex_unlock(&hwbp_mutex);
	kfree(hits);
	put_pid(pid_ref);
	return rc;
}

static long hwbp_clear_all(void) {
	struct hwbp_tracker *tracker;
	struct hwbp_tracker *next;

	mutex_lock(&hwbp_mutex);
	list_for_each_entry_safe(tracker, next, &hwbp_trackers, node) {
		list_del(&tracker->node);
		hwbp_unregister_and_free(tracker);
	}
	mutex_unlock(&hwbp_mutex);
	return 0;
}

int hwbp_init(void) {
	if (hwbp_initialized)
		return hwbp_ready ? 0 : -EOPNOTSUPP;
	hwbp_initialized = true;
	BUILD_BUG_ON(sizeof(struct drv_hwbp_reg_override) != 16);
	BUILD_BUG_ON(sizeof(struct drv_hwbp_install_req) != 192);
	BUILD_BUG_ON(sizeof(struct drv_hwbp_hit) != 280);
	drv_register_user_hw_bp_ptr = (drv_register_user_hw_bp_fn_t)kallsym_lookup("register_user_hw_breakpoint");
	drv_unregister_hw_bp_ptr = (drv_unregister_hw_bp_fn_t)kallsym_lookup("unregister_hw_breakpoint");
	drv_modify_user_hw_bp_ptr = (drv_modify_user_hw_bp_fn_t)kallsym_lookup("modify_user_hw_breakpoint");
	drv_access_remote_vm_ptr = (drv_access_remote_vm_fn_t)kallsym_lookup("access_remote_vm");
	if (!drv_register_user_hw_bp_ptr || !drv_unregister_hw_bp_ptr || !drv_modify_user_hw_bp_ptr || !drv_access_remote_vm_ptr) {
		pr_drv_notice("hwbp: unavailable on this kernel\n");
		return -EOPNOTSUPP;
	}
	drv_fpsimd_preserve_current_state_ptr = (drv_fpsimd_preserve_current_state_fn_t)kallsym_lookup("fpsimd_preserve_current_state");
	drv_fpsimd_update_current_state_ptr = (drv_fpsimd_update_current_state_fn_t)kallsym_lookup("fpsimd_update_current_state");
	hwbp_fp_ready = system_supports_fpsimd() && drv_fpsimd_preserve_current_state_ptr && drv_fpsimd_update_current_state_ptr;
	hwbp_ready = true;
	return 0;
}

long do_hwbp_cmd(unsigned int cmd, void __user *arg) {
	if (!hwbp_ready)
		return -EOPNOTSUPP;
	switch (cmd) {
	case DRV_CMD_HWBP_INSTALL:
		return hwbp_install(arg);
	case DRV_CMD_HWBP_SET_OVERRIDE:
		return hwbp_set_override(arg);
	case DRV_CMD_HWBP_REMOVE:
		return hwbp_remove(arg);
	case DRV_CMD_HWBP_GET_HITS:
		return hwbp_get_hits(arg);
	case DRV_CMD_HWBP_CLEAR_ALL:
		return hwbp_clear_all();
	default:
		return -ENOTTY;
	}
}
