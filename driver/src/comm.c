// SPDX-License-Identifier: GPL-2.0-only
/* userspace communication bootstrap and ioctl router */

#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/task_work.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include <driver/types.h>
#include <driver/uapi.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#include <linux/cfi.h>
#endif
#ifndef __nocfi
#define __nocfi
#endif

#if KCFG_HIDE_KGSL
#define DRV_KGSL_ENABLED 1
#else
#define DRV_KGSL_ENABLED 0
#endif

#include "comm.h"
#include "harvest.h"
#include "hook_engine.h"
#include "input_synth.h"
#include "kallsym.h"
#include "log.h"
#include "memory.h"
#include "sensor.h"
#if DRV_KGSL_ENABLED
#include "stealth.h"
#endif

static long dispatch_ioctl_unlocked(struct file *filp, unsigned int cmd, unsigned long arg);

typedef int (*task_work_add_fn_t)(struct task_struct *task, struct callback_head *work, enum task_work_notify_mode notify);
static task_work_add_fn_t task_work_add_ptr;

static noinline __nocfi int drv_call_task_work_add(task_work_add_fn_t fn, struct task_struct *task, struct callback_head *work, enum task_work_notify_mode notify) {
	return fn(task, work, notify);
}

static int drv_task_work_add(struct task_struct *task, struct callback_head *work, enum task_work_notify_mode notify) {
	if (!task_work_add_ptr) {
		task_work_add_ptr = (task_work_add_fn_t)kallsym_lookup("task_work_add");
		if (!task_work_add_ptr) {
			pr_drv_err("task_work_add not found\n");
			return -ENOENT;
		}
	}

	return drv_call_task_work_add(task_work_add_ptr, task, work, notify);
}

/* Pre-resolve task_work_add at module init from process context. Without this
   the first magic reboot/prctl handshake hits the lazy kallsym_lookup branch
   from inside the kprobe pre-handler — register_kprobe there sleeps in atomic
   context (mutex_lock(&kprobe_mutex) + stop_machine). */
int comm_warm_symbols(void) {
	if (!task_work_add_ptr) {
		task_work_add_ptr = (task_work_add_fn_t)kallsym_lookup("task_work_add");
		if (!task_work_add_ptr) {
			pr_drv_err("comm_warm_symbols: task_work_add not found\n");
			return -ENOENT;
		}
	}
	return 0;
}

static int drv_close_fd(unsigned int fd) {
	/* close_fd(unsigned) appeared in 5.11 (commit 8760c909f54e); pre-5.11
	 * vendor forks still expose __close_fd(struct files_struct *, unsigned). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	return close_fd(fd);
#else
	return __close_fd(current->files, fd);
#endif
}

/* .owner=THIS_MODULE pins module text for as long as any client holds the fd. */
const struct file_operations inofile_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = dispatch_ioctl_unlocked,
	.compat_ioctl = dispatch_ioctl_unlocked,
};

struct kprobe reboot_kp = {
	.symbol_name = "__arm64_sys_reboot",
	.pre_handler = reboot_handler_pre,
};

static bool drv_read_wrapped_syscall_args(struct pt_regs *regs, unsigned long args[4]) {
	unsigned long pt_regs_ptr;

	if (!regs)
		return false;

	pt_regs_ptr = regs->regs[0];
	if (!pt_regs_ptr)
		return false;

	/* copy_from_kernel_nofault is the canonical safe kernel-VA reader since
	 * 5.8 (commit fe557319aa06). Driver matrix floor is 5.10, so this is
	 * always available — no compat shim needed. */
	return copy_from_kernel_nofault(args, (const void *)(uintptr_t)pt_regs_ptr, sizeof(unsigned long) * 4) == 0;
}

static void drv_queue_fd_install(void __user *reply, const char *source) {
	struct driver_install_work *work;

	if (!reply) {
		pr_drv_warn("%s handshake missing reply pointer\n", source);
		return;
	}

	pr_drv("%s handshake hit: pid=%d\n", source, current->pid);

	/* pre-handler runs with preemption disabled; must not sleep. */
	work = kmalloc(sizeof(*work), GFP_ATOMIC | __GFP_HIGH);
	if (!work)
		return;

	work->head.next = NULL;
	work->head.func = driver_install_fd_tw_func;
	work->reply = reply;

	if (drv_task_work_add(current, &work->head, TWA_RESUME) != 0) {
		kfree(work);
		pr_drv_warn("install fd add task_work failed\n");
	}
}

int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs) {
	unsigned long args[4];

	(void)p;

	if (!regs)
		return 0;

	args[0] = regs->regs[0];
	args[1] = regs->regs[1];
	args[2] = regs->regs[2];
	args[3] = regs->regs[3];

	if ((u32)args[0] != COMM_REBOOT_MAGIC1 || (u32)args[1] != COMM_REBOOT_MAGIC2) {
		if (!drv_read_wrapped_syscall_args(regs, args))
			return 0;
		if ((u32)args[0] != COMM_REBOOT_MAGIC1 || (u32)args[1] != COMM_REBOOT_MAGIC2)
			return 0;
		drv_queue_fd_install((void __user *)args[3], "reboot/ptregs");
		return 0;
	}

	drv_queue_fd_install((void __user *)args[3], "reboot");

	return 0;
}

void driver_install_fd_tw_func(struct callback_head *twork) {
	struct driver_install_work *work = container_of(twork, struct driver_install_work, head);
	struct file *filp;
	int fd;
	int reply_fd;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_drv_err("fd_install: failed to get unused fd\n");
		reply_fd = fd;
		goto reply;
	}

	/* O_LARGEFILE is a no-op on arm64 but kept to match binary output */
	filp = anon_inode_getfile("[driver]", &inofile_fops, NULL, O_RDWR | O_LARGEFILE);
	if (IS_ERR(filp)) {
		pr_drv_err("fd_install: failed to create anon inode file\n");
		put_unused_fd(fd);
		reply_fd = PTR_ERR(filp);
		goto reply;
	}

	fd_install(fd, filp);
	pr_drv("fd installed: %d for pid %d\n", fd, current->pid);
	reply_fd = fd;

reply:
	pr_drv("[%d] install fd: %d\n", current->pid, reply_fd);

	if (copy_to_user(work->reply, &reply_fd, sizeof(reply_fd)) != 0) {
		pr_drv_err("install fd reply err\n");
		if (reply_fd >= 0)
			drv_close_fd(reply_fd);
	}

	kfree(work);
}

static int read_req(void __user *arg, struct drv_ioctl_req *out) {
	if (copy_from_user(out, arg, sizeof(*out)) != 0)
		return -EFAULT;
	return 0;
}

static void write_back_size(void __user *arg, u64 value) {
	void __user *size_slot = (u8 __user *)arg + offsetof(struct drv_ioctl_req, size);

	if (copy_to_user(size_slot, &value, sizeof(value)) != 0)
		pr_drv_warn("dispatch_ioctl: size writeback failed\n");
}

/* On success: task held (put_task_struct), mm held (mmput). On any failure both outputs are NULL. */
static void resolve_target_mm(pid_t pid, struct task_struct **out_task, struct mm_struct **out_mm) {
	struct pid *pidp;
	struct task_struct *task;
	struct mm_struct *mm;

	*out_task = NULL;
	*out_mm = NULL;

	pidp = find_get_pid(pid);
	if (!pidp)
		return;

	task = get_pid_task(pidp, PIDTYPE_PID);
	put_pid(pidp);
	if (!task)
		return;

	mm = get_task_mm(task);
	if (!mm || IS_ERR(mm)) {
		put_task_struct(task);
		return;
	}

	*out_task = task;
	*out_mm = mm;
}

static void release_target_mm(struct task_struct *task, struct mm_struct *mm) {
	if (mm)
		mmput(mm);
	if (task)
		put_task_struct(task);
}

static long do_memory_cmd(unsigned int cmd, void __user *arg) {
	struct drv_ioctl_req req;
	struct task_struct *task = NULL;
	struct mm_struct *mm = NULL;
	u64 result = 0;
	int rc;

	if (read_req(arg, &req) != 0)
		return 0;

	switch (cmd) {
	/* {read,write}_process_memory_{linear,vmap} already handle the user-side
	   buffer themselves via copy_to_user/copy_from_user under the target's
	   mmap_read_lock. The original .ko hands req.buf straight through; an
	   earlier reconstruction tried to add a kvmalloc kernel-bounce buffer but
	   never adjusted the inner functions' drv_user_ptr_in_range() guard,
	   which rejects every kernel pointer and silently returns -EFAULT —
	   making req.size==0 surface as Read16/ElfMagic failures on the client. */
	case DRV_CMD_READ_MEM_LINEAR:
		if (req.size == 0 || req.size > DRV_MEM_CMD_MAX_SIZE)
			break;
		resolve_target_mm((pid_t)req.pid, &task, &mm);
		if (!mm)
			break;
		rc = read_process_memory_linear(mm, req.addr, (void *)(uintptr_t)req.buf, req.size);
		if (rc == 0)
			result = req.size;
		break;
	case DRV_CMD_WRITE_MEM_LINEAR:
		if (req.size == 0 || req.size > DRV_MEM_CMD_MAX_SIZE)
			break;
		resolve_target_mm((pid_t)req.pid, &task, &mm);
		if (!mm)
			break;
		rc = write_process_memory_linear(mm, req.addr, (const void *)(uintptr_t)req.buf, req.size);
		if (rc == 0)
			result = req.size;
		break;
	case DRV_CMD_READ_MEM_VMAP:
		if (req.size == 0 || req.size > DRV_MEM_CMD_MAX_SIZE)
			break;
		resolve_target_mm((pid_t)req.pid, &task, &mm);
		if (!mm)
			break;
		rc = read_process_memory_vmap(mm, req.addr, (void *)(uintptr_t)req.buf, req.size);
		if (rc == 0)
			result = req.size;
		break;
	case DRV_CMD_WRITE_MEM_VMAP:
		if (req.size == 0 || req.size > DRV_MEM_CMD_MAX_SIZE)
			break;
		resolve_target_mm((pid_t)req.pid, &task, &mm);
		if (!mm)
			break;
		rc = write_process_memory_vmap(mm, req.addr, (const void *)(uintptr_t)req.buf, req.size);
		if (rc == 0)
			result = req.size;
		break;
	case DRV_CMD_GET_MODULE_BASE: {
		char name[256];
		long nread;

		resolve_target_mm((pid_t)req.pid, &task, &mm);
		if (!task)
			break;

		nread = strncpy_from_user(name, (const char __user *)(uintptr_t)req.addr, sizeof(name));
		if (nread < 0 || nread == 0)
			break;
		name[sizeof(name) - 1] = '\0';

		result = process_get_module_base(task, name);
		break;
	}
	case DRV_CMD_FIND_TASK_BY_COMM: {
		char comm[256];
		long nread;
		struct task_struct *found;

		nread = strncpy_from_user(comm, (const char __user *)(uintptr_t)req.addr, sizeof(comm));
		if (nread < 0) {
			result = (u64)(s64)-EFAULT;
			break;
		}
		if (nread >= (long)sizeof(comm))
			nread = sizeof(comm) - 1;
		comm[nread] = '\0';
		if (comm[0] == '\0') {
			result = (u64)(s64)-EINVAL;
			break;
		}

		found = process_find_task_by_comm(comm);
		if (found) {
			result = (u64)task_pid_nr(found);
			put_task_struct(found);
		} else {
			result = (u64)(s64)-1;
		}
		break;
	}
	case DRV_CMD_READ_VMA_COOKIE:
		/* binary walks mm_mt and matches vma->anon_name (16-byte tag) — NOT vm_file->d_name. */
		resolve_target_mm((pid_t)req.pid, &task, &mm);
		if (task) {
			char tag[16];

			if (copy_from_user(tag, (const char __user *)(uintptr_t)req.addr, sizeof(tag)) == 0)
				result = process_read_vma_cookie(task, tag);
		}
		break;
	case DRV_CMD_GET_TLS:
		resolve_target_mm((pid_t)req.pid, &task, &mm);
		if (task)
			result = process_get_tls(task);
		break;
	case DRV_CMD_HIDE_KGSL:
		/* Per-kernel holder / inner offsets and holder-pointer sanity
		 * checks live inside stealth.c so comm.c stays version-agnostic;
		 * a stale layout on an unfamiliar BSP surfaces here as
		 * -EOPNOTSUPP instead of an rbtree walk oops. Long-term fix:
		 * BTF-driven offset discovery (/sys/kernel/btf/kgsl) — tracked
		 * as a follow-up. */
#if DRV_KGSL_ENABLED
		result = (u64)(s64)hide_kgsl_by_pid(resolve_kgsl_driver(), (int)req.pid);
#else
		result = (u64)(s64)-EOPNOTSUPP;
#endif
		break;
	case DRV_CMD_MULTI_READ:
		resolve_target_mm((pid_t)req.pid, &task, &mm);
		if (mm) {
			rc = multi_read_process_memory(mm, (void __user *)(uintptr_t)req.buf, (unsigned int)req.extra);
			/* multi_read_process_memory returns 1 on success and a
			 * negative errno on failure; map both to the writeback
			 * convention (req.size = 1 on success, 0 on failure). */
			result = (rc > 0) ? 1 : 0;
		}
		break;
	case DRV_CMD_DUMP_VMAS:
		resolve_target_mm((pid_t)req.pid, &task, &mm);
		if (task) {
			rc = process_maps_get_a(task, (void __user *)(uintptr_t)req.buf, req.size);
			result = (rc > 0) ? (u64)rc : 0;
		}
		break;
	default:
		release_target_mm(task, mm);
		return -ENOTTY;
	}

	release_target_mm(task, mm);
	write_back_size(arg, result);
	return 0;
}

static long do_find_pid_by_package(void __user *arg) {
	struct drv_find_pid_req req;
	size_t package_len;
	pid_t pid;
	int rc;

	if (copy_from_user(&req, arg, sizeof(req)) != 0)
		return -EFAULT;
	if (req.flags != 0)
		return -EINVAL;

	package_len = strnlen(req.package, sizeof(req.package));
	if (!package_len)
		return -EINVAL;
	if (package_len == sizeof(req.package))
		return -ENAMETOOLONG;

	rc = process_find_pid_by_package(req.package, &pid);
	if (rc)
		return rc;

	req.pid = pid;
	if (copy_to_user(arg, &req, sizeof(req)) != 0)
		return -EFAULT;

	return 0;
}

static long do_hook_cmd(unsigned int cmd, void __user *arg) {
	switch (cmd) {
	case DRV_CMD_GAME_ASSET_READ_A:
		if (copy_to_user(arg, drv.wz_hero_addr_map, DRV_WZ_HERO_ADDR_MAP_BYTES) != 0)
			return -EFAULT;
		return 0;
	case DRV_CMD_INSTALL_HOOKS:
		return install_harvest_hooks();
	case DRV_CMD_TEAR_DOWN:
		wz_hero_addr_map_clear();
		memset(drv.wz_hero_objects, 0, sizeof(drv.wz_hero_objects));
		return 0;
	case DRV_CMD_GAME_ASSET_READ_B:
		if (copy_to_user(arg, drv.wz_hero_objects, DRV_WZ_HERO_OBJECTS_BYTES) != 0)
			return -EFAULT;
		return 0;
	case DRV_CMD_INSTALL_SIGSEGV_SUPPRESS:
		/* install_harvest_hooks () arms both paths under idempotency guards */
		return install_harvest_hooks();
	default:
		/* in-range unknowns (e.g. 0xD3) fall through to LABEL_511(return 0) in the binary */
		return 0;
	}
}

static long do_input_cmd(unsigned int cmd, void __user *arg) {
	struct drv_touch_inject_req t;
	int ret;

	/* lazy idempotent install of input-event kprobes + event pool */
	ret = install_input_hooks();
	if (ret)
		return ret;

	switch (cmd) {
	case DRV_CMD_TOUCH_DOWN:
		if (copy_from_user(&t, arg, sizeof(t)) != 0)
			return -EFAULT;
		touch_down((int)t.slot_id, (int)t.x, (int)t.y, (int)t.pressure);
		/* binary stamps the extra HIDWORD(== struct's last u32) to 1 as success flag before echo */
		t.pressure = 1;
		(void)copy_to_user(arg, &t, sizeof(t));
		return 0;
	case DRV_CMD_TOUCH_UP:
		if (copy_from_user(&t, arg, sizeof(t)) != 0)
			return -EFAULT;
		touch_up((int)t.slot_id);
		return 0;
	case DRV_CMD_TOUCH_MOVE:
		if (copy_from_user(&t, arg, sizeof(t)) != 0)
			return -EFAULT;
		touch_move((int)t.slot_id, (int)t.x, (int)t.y);
		return 0;
	case DRV_CMD_TOUCH_SLOT_LEGACY:
		return 0;
	case DRV_CMD_SENSOR_BIND: {
		struct drv_ioctl_req req;

		if (read_req(arg, &req) != 0)
			return -EFAULT;

		if (req.pid == 100) {
			/* Bind the libsensorservice uprobe to an explicit Event ABI. */
			if (req.size >= DRV_SENSOR_LAYOUT_COUNT)
				return -EINVAL;
			return sensor_hook_init((unsigned long)req.addr, (int)req.size);
		}

		gyro_x = (u32)req.addr;
		gyro_y = (u32)req.size;
		gyro_enable = (u8)(req.extra != 0);
		return 0;
	}
	default:
		/* unmapped cmds in [0x12D..0x18F] still return 0 after lazy-init */
		return 0;
	}
}

static long dispatch_ioctl_unlocked(struct file *filp, unsigned int cmd, unsigned long arg) {
	void __user *uarg = (void __user *)arg;
	u64 hello;

	(void)filp;

	if (cmd == DRIVER_IOCTL_PING)
		return 0;

	if (cmd == DRIVER_IOCTL_HELLO) {
		hello = DRIVER_IOCTL_HELLO;
		if (copy_to_user(uarg, &hello, sizeof(hello)) != 0)
			return -EFAULT;
		return 0;
	}

	if (cmd == DRV_CMD_FIND_PID_BY_PACKAGE)
		return do_find_pid_by_package(uarg);

	if (cmd >= DRV_CMD_READ_MEM_LINEAR && cmd <= DRV_CMD_DUMP_VMAS)
		return do_memory_cmd(cmd, uarg);

	if (cmd >= DRV_CMD_GAME_ASSET_READ_A && cmd <= DRV_CMD_INSTALL_SIGSEGV_SUPPRESS)
		return do_hook_cmd(cmd, uarg);

	if (cmd >= DRV_CMD_INPUT_RANGE_FIRST && cmd <= DRV_CMD_INPUT_RANGE_LAST)
		return do_input_cmd(cmd, uarg);

	/* DEVIATION: binary's outer guard is `cmd-11 <= 0x58` so cmds in [0x16, 0x63] also copy_from_user 0x28 bytes then return 0 via the jump-table default. We return -ENOTTY for any cmd not matching a known range — a documented behavioural delta. */
	return -ENOTTY;
}

long dispatch_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	return dispatch_ioctl_unlocked(filp, cmd, arg);
}
