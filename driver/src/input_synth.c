// SPDX-License-Identifier: GPL-2.0-only
// synthetic multitouch event injection
#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/errno.h>
#include <linux/input.h>
#include <linux/input-event-codes.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>

#include <driver/types.h>
#include <driver/uapi.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#include <linux/cfi.h>
#endif
#ifndef __nocfi
#define __nocfi
#endif

#include "input_synth.h"
#include "kallsym.h"
#include "log.h"

/* Subsystem-private init guard for init_fingers. drv_state carries the final post-init flag (drv.init_fingers_done); this atomic gates the exactly-once memset transition. */
static atomic_t init_fingers_initialized = ATOMIC_INIT(0);

/* install_input_hooks is invoked from dispatch_ioctl on every touch ioctl in the [0x12D..0x18F] range. Serialise the lazy init so two concurrent ioctls cannot both kvzalloc pool / register kprobes / overwrite the resolved input_handle_event_ptr. */
static DEFINE_MUTEX(install_lock);

/* input_handle_event () is not exported (not in __ksymtab) on >= 6.6 — resolve via kallsyms at init. */
typedef void(*input_handle_event_fn_t)(struct input_dev *dev, unsigned int type, unsigned int code, int value);
static input_handle_event_fn_t input_handle_event_ptr;

static noinline __nocfi void drv_call_input_handle_event(input_handle_event_fn_t fn, struct input_dev *dev, unsigned int type, unsigned int code, int value) {
	fn(dev, type, code, value);
}

/* Caller must hold drv.pool->lock. */
static inline void pool_push(u32 type, u32 code, s32 value) {
	struct evpool *p = drv.pool;
	u64 idx;

	if (!p)
		return;

	idx = p->count;
	if (idx > DRV_EVPOOL_CAPACITY - 1)
		return;

	p->entries[idx].type = type;
	p->entries[idx].code = code;
	p->entries[idx].value = value;
	/* Write barrier: ensure the entry payload becomes visible before the count bump is observed. The pool->lock acquired by handle_cache_events on the consumer side pairs with this on every architecture, but make the producer ordering explicit for the (uncommon) case where a future caller drops the lock between fields and a barrier-only reader is added. */
	smp_wmb();
	p->count = idx + 1;
}

void handle_cache_events(struct input_dev *idev) {
	struct evpool *p = drv.pool;
	unsigned long flags_pool, flags_dev;
	u64 i;

	if (!p || !idev || !input_handle_event_ptr)
		return;

	spin_lock_irqsave(&p->lock, flags_pool);

	if (p->count == 0) {
		spin_unlock_irqrestore(&p->lock, flags_pool);
		return;
	}

	/* Pair with smp_wmb in pool_push: ensure entries[] reads observe the writes that preceded the count bump. spin_lock_irqsave provides an acquire on arm64 already, but make the consumer-side ordering explicit. */
	smp_rmb();

	/* dev->event_lock must be held around input_handle_event — kprobed input_event would re-enter our probe. */
	spin_lock_irqsave(&idev->event_lock, flags_dev);

	if (p->count == 0)
		goto unlock_dev;

	for (i = 0; i < p->count; i++) {
		struct drv_input_event *ev;

		if (i == DRV_EVPOOL_CAPACITY + 1)
			BUG();                 /* mirrors BRK #0x5512 */

		ev = &p->entries[i];

		if (ev->type > EV_MAX)
			continue;

		if (!test_bit(ev->type, idev->evbit))
			continue;

		/* kCFI: input_handle_event_ptr is kallsyms-resolved; Android ACK exposes __nocfi as a function attribute, so keep the indirect call inside a tiny wrapper. */
		drv_call_input_handle_event(input_handle_event_ptr, idev, ev->type, ev->code, ev->value);
	}

	p->count = 0;

unlock_dev:
	spin_unlock_irqrestore(&idev->event_lock, flags_dev);
	spin_unlock_irqrestore(&p->lock, flags_pool);
}

int input_handle_event_handler_pre(struct kprobe *p, struct pt_regs *regs) {
	/* arm64 calling convention: input_event(struct input_dev *dev, unsigned int type, unsigned int code, int value). Arg0 (dev) is in x0 -> regs->regs[0]; arg1 (type) is in x1 -> regs->regs[1]. CFI/kCFI does NOT add a "this"-style implicit argument for C calls, so the index does not shift. Dossier docs/analysis/input_synth.json @0x12d84 confirms pt_regs+0 -> dev, pt_regs+8 -> type for the original binary. */
	struct input_dev *idev = (struct input_dev *)regs->regs[0];
	unsigned int type = (unsigned int)regs->regs[1];

	(void)p;

	if (!idev || type != EV_SYN)
		return 0;

	handle_cache_events(idev);
	return 0;
}

int input_handle_event_handler2_pre(struct kprobe *p, struct pt_regs *regs) {
	/* input_inject_event(struct input_handle *handle, unsigned int type, unsigned int code, int value). Same x0/x1 layout — see comment in input_handle_event_handler_pre. Dossier docs/analysis/input_synth.json @0x12c48 confirms the original reads pt_regs+0 -> handle and pt_regs+8 -> type. */
	struct input_handle *handle = (struct input_handle *)regs->regs[0];
	unsigned int type = (unsigned int)regs->regs[1];

	(void)p;

	if (!handle || type != EV_SYN)
		return 0;

	handle_cache_events(handle->dev);
	return 0;
}

/* Caller must hold drv.pool->lock. */
int input_mt_report_slot_state_with_id_cache(int id) {
	pool_push(EV_ABS, ABS_MT_TRACKING_ID, id);
	pool_push(EV_ABS, ABS_MT_TOOL_TYPE, MT_TOOL_FINGER);
	return id;
}

static void init_fingers(void) {
	if (atomic_cmpxchg(&init_fingers_initialized, 0, 1) != 0)
		return;

	memset(drv.slots, 0, sizeof(drv.slots));
	drv.persistent_current_slot = 0;
	drv.init_fingers_done = 1;
}

/* DEVIATION: binary 0x12D/0x12E/0x12F always emits ABS_MT_SLOT unconditionally. We dedupe against drv.persistent_current_slot to cut ring pressure when the same finger is updated repeatedly — semantically equivalent because evdev caches the active slot, but it does drop redundant SLOT events the binary keeps. */
static void emit_slot_select_locked(int slot) {
	if (drv.persistent_current_slot == slot)
		return;

	pool_push(EV_ABS, ABS_MT_SLOT, slot);
	drv.persistent_current_slot = slot;
}

void touch_down(int slot, int x, int y, int pressure) {
	unsigned long flags_slot, flags_pool;

	if (slot < 0 || slot >= DRV_MT_NUM_SLOTS)
		return;

	if (!drv.pool)
		return;

	init_fingers();

	spin_lock_irqsave(&drv.slot_lock, flags_slot);
	spin_lock_irqsave(&drv.pool->lock, flags_pool);

	emit_slot_select_locked(slot);

	/* Binary 0x12D uses the raw slot index (0..9) as the tracking id; the slot+0x29A constant only appears on the legacy 0x136 fake-key path. */
	drv.slots[slot].id = slot;
	drv.slots[slot].x = x;
	drv.slots[slot].y = y;
	drv.slots[slot].pressure = pressure;
	drv.slots[slot].active = 1;

	input_mt_report_slot_state_with_id_cache(drv.slots[slot].id);
	pool_push(EV_ABS, ABS_MT_POSITION_X, x);
	pool_push(EV_ABS, ABS_MT_POSITION_Y, y);
	/* Binary emits ABS_MT_ORIENTATION(0x3A) between POSITION_Y and TOUCH_MAJOR carrying the pressure scalar — mirror it exactly. */
	pool_push(EV_ABS, ABS_MT_ORIENTATION, pressure);
	pool_push(EV_ABS, ABS_MT_TOUCH_MAJOR, pressure);
	pool_push(EV_ABS, ABS_MT_PRESSURE, pressure);
	/* Binary 0x12D pushes ONLY ABS_MT events; no BTN_TOUCH / BTN_TOOL_FINGER. */

	spin_unlock_irqrestore(&drv.pool->lock, flags_pool);
	spin_unlock_irqrestore(&drv.slot_lock, flags_slot);
}

void touch_move(int slot, int x, int y) {
	unsigned long flags_slot, flags_pool;

	if (slot < 0 || slot >= DRV_MT_NUM_SLOTS)
		return;

	if (!drv.pool)
		return;

	init_fingers();

	spin_lock_irqsave(&drv.slot_lock, flags_slot);
	spin_lock_irqsave(&drv.pool->lock, flags_pool);

	emit_slot_select_locked(slot);

	drv.slots[slot].x = x;
	drv.slots[slot].y = y;

	pool_push(EV_ABS, ABS_MT_POSITION_X, x);
	pool_push(EV_ABS, ABS_MT_POSITION_Y, y);

	spin_unlock_irqrestore(&drv.pool->lock, flags_pool);
	spin_unlock_irqrestore(&drv.slot_lock, flags_slot);
}

void touch_up(int slot) {
	unsigned long flags_slot, flags_pool;

	if (slot < 0 || slot >= DRV_MT_NUM_SLOTS)
		return;

	if (!drv.pool)
		return;

	init_fingers();

	spin_lock_irqsave(&drv.slot_lock, flags_slot);
	spin_lock_irqsave(&drv.pool->lock, flags_pool);

	emit_slot_select_locked(slot);

	/* Binary 0x12E pushes only ABS_MT_TRACKING_ID == -1; the BTN_TOUCH / BTN_TOOL_FINGER releases happen via the legitimate driver's frame. */
	pool_push(EV_ABS, ABS_MT_TRACKING_ID, -1);

	drv.slots[slot].id = -1;
	drv.slots[slot].active = 0;

	spin_unlock_irqrestore(&drv.pool->lock, flags_pool);
	spin_unlock_irqrestore(&drv.slot_lock, flags_slot);
}

int install_input_hooks(void) {
	int ret = 0;
	bool input_event_registered_now = false;

	/* Serialise the entire lazy-init body. dispatch_ioctl calls this from process context on every ioctl in [0x12D..0x18F] and is unlocked_ioctl (no BKL), so two CPUs can race here. Without this mutex they can both observe !drv.kp_input_event_armed, both register_kprobe, and one of the registrations will silently fail (or worse, leak the kprobe slot). The mutex is fine here because we are in process context — no kprobe pre-handler reaches this path. */
	mutex_lock(&install_lock);

	if (!input_handle_event_ptr) {
		/* input_handle_event is not exported on >= 6.6 (no __ksymtab entry); resolve via kallsyms. */
		input_handle_event_ptr = (input_handle_event_fn_t)kallsym_lookup("input_handle_event");
		if (!input_handle_event_ptr) {
			pr_drv_err("input_synth: failed to resolve input_handle_event via kallsyms\n");
			ret = -ENOENT;
			goto out_unlock;
		}
	}

	if (!drv.pool) {
		struct evpool *p;

		/* Binary uses kvmalloc_node with gfp 0xCC0 (GFP_KERNEL|__GFP_RETRY_MAYFAIL); mirror the retry hint so allocator behaviour matches under pressure. */
		p = kvzalloc(sizeof(*p), GFP_KERNEL | __GFP_RETRY_MAYFAIL);
		if (!p) {
			pr_drv_err("input_synth: failed to alloc event pool\n");
			ret = -ENOMEM;
			goto out_unlock;
		}

		spin_lock_init(&p->lock);
		p->count = 0;

		/* drv.slot_lock and the slots[] array are zero-initialised by BSS but spin_lock_init also primes the lockdep tracking; do it before publishing drv.pool so any reader that observes a non-NULL pool is guaranteed to see a usable slot_lock as well. */
		spin_lock_init(&drv.slot_lock);
		init_fingers();

		/* Publish the fully-initialised pool only after spin_lock_init, count=0, slot_lock init, and slot memset all complete. smp_store_release ensures any concurrent reader that loads drv.pool sees a usable evpool and a usable slot_lock, not half-initialised state. The install_lock makes this strictly unnecessary, but the explicit publishing barrier documents the invariant. */
		smp_store_release(&drv.pool, p);
	}

	if (!drv.kp_input_event_armed) {
		drv.kp_input_event.symbol_name = "input_event";
		drv.kp_input_event.pre_handler = input_handle_event_handler_pre;
		ret = register_kprobe(&drv.kp_input_event);
		if (ret) {
			pr_drv_err("Failed to register kprobe kp_input_event: %d\n", ret);
			/* register_kprobe() resolves symbol_name into addr before some
			 * later failures. Clear it so a retry does not present both. */
			drv.kp_input_event.addr = NULL;
			goto out_unlock;
		}
		drv.kp_input_event_armed = 1;
		input_event_registered_now = true;
	}

	if (!drv.kp_input_inject_armed) {
		drv.kp_input_inject_event.symbol_name = "input_inject_event";
		drv.kp_input_inject_event.pre_handler = input_handle_event_handler2_pre;
		ret = register_kprobe(&drv.kp_input_inject_event);
		if (ret) {
			pr_drv_err("Failed to register kprobe kp_input_inject_event: %d\n", ret);
			drv.kp_input_inject_event.addr = NULL;
			if (input_event_registered_now) {
				unregister_kprobe(&drv.kp_input_event);
				drv.kp_input_event_armed = 0;
				drv.kp_input_event.addr = NULL;
			}
			goto out_unlock;
		}
		drv.kp_input_inject_armed = 1;
	}

out_unlock:
	mutex_unlock(&install_lock);
	return ret;
}
