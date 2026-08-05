// SPDX-License-Identifier: GPL-2.0
/* Internal kernel-only types. The shared ABI is in uapi.h. */
#ifndef _DRIVER_TYPES_H
#define _DRIVER_TYPES_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/input.h>

#include <driver/uapi.h>

#ifndef DRIVER_NAME
#define DRIVER_NAME "my-driver"
#endif

#ifndef TARGET_PACKAGE
#define TARGET_PACKAGE "com.tencent.tmgp.sgame"
#endif

/* Binary layout requires 10 slots at offsets 0x1004..0x10C4. */
#define DRV_MT_NUM_SLOTS 10
#define DRV_EVPOOL_CAPACITY 0x400u
#define DRV_EVPOOL_BYTES (sizeof(struct evpool))

#define DRV_BIG_BUFFER_BYTES 0xA000u /* 40960 */
#define DRV_HOOK_SLOT_BYTES 0xE8u /* 232-byte hook slot */
#define DRV_HOOK_SLOT_COUNT (DRV_BIG_BUFFER_BYTES / DRV_HOOK_SLOT_BYTES)

#define DRV_WZ_HERO_ADDR_MAP_BYTES 0x640u /* 1600 */
#define DRV_WZ_HERO_OBJECTS_BYTES 0x190u /* 400 */

/* Exact 0x3000-byte event pool followed by count and lock. */
struct evpool {
	struct drv_input_event entries[DRV_EVPOOL_CAPACITY]; /* +0x0000 */
	__u64 count; /* +0x3000 */
	spinlock_t lock; /* +0x3008 */
};

/* Fixed touch-slot layout with a 20-byte naturally aligned stride. */
struct mt_slot {
	int id; /* -1 when the slot is empty */
	int x;
	int y;
	int pressure;
	int active;
};

/* 232-byte trampoline slot carved from big_buffer. */
struct hook_slot {
	__u64 orig_func; /* +0x00 */
	__u64 origin_offset; /* +0x08 after BTI/PACIASP */
	__u64 replace_func; /* +0x10 */
	__u64 chain_target; /* +0x18 jump-back slot + 72 */
	__u32 instr_count; /* +0x20, default 4 */
	__u32 max_capacity; /* +0x24, always 0x28 */
	__u32 relocated[0x28]; /* +0x28, 40 dwords */
	__u64 chain_landing; /* +0xC8, origin + 4 * count */
	__u8 _pad[0xE8 - 0xC8 - 8];
};

/* Shared driver state. Retained callbacks make module unload unsupported. */
struct drv_state {
	struct evpool *pool;
	struct input_dev *dev;

	struct mt_slot slots[DRV_MT_NUM_SLOTS];
	spinlock_t slot_lock;
	int persistent_current_slot;
	int init_fingers_done;

	__u8 touch_is_init;
	__u8 kp_input_event_armed;
	__u8 kp_input_inject_armed;

	struct kprobe kp_input_event;
	struct kprobe kp_input_inject_event;
	struct kprobe kp_vfs_read;
	__u8 vfs_read_hook_armed;

	/* Raw IEEE-754 binary32 bit patterns copied from userspace. */
	__u32 gyro_x;
	__u32 gyro_y;
	__u8 gyro_enable;
	__u8 sensor_hook_armed;
	struct kprobe kp_sensor_input_event;
	struct kprobe kp_sensor_input_inject_event;

	struct kprobe kp_reboot;

	struct hook_slot *big_buffer;
	__u32 hook_slot_used;
	__u8 hooks_installed;
	__u8 sigsegv_hook_armed;
	struct kprobe kp_arm64_force_sig_fault;

	/* Cached constants for write_ro_memory and the PGD walker. */
	__u64 m_pgd_va; /* swapper_pg_dir alias VA */
	__u32 m_page_level; /* (60 - T0SZ) / 9 */

	__u8 wz_hero_addr_map[DRV_WZ_HERO_ADDR_MAP_BYTES];
	__u8 wz_hero_objects[DRV_WZ_HERO_OBJECTS_BYTES];
};

extern struct drv_state drv;

#endif /* _DRIVER_TYPES_H */
