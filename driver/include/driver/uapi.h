// SPDX-License-Identifier: GPL-2.0
// Shared UAPI surface; included from BOTH kernel module AND userspace client.
#ifndef _DRIVER_UAPI_H
#define _DRIVER_UAPI_H

#ifdef __KERNEL__
#  include <linux/types.h>
#  include <linux/ioctl.h>
#else
#  include <stdint.h>
#  include <linux/types.h>
#  include <sys/types.h>
#endif

/* Per CLAUDE.md, the magic-handshake constants are configurable via Kbuild -DKCFG_* knobs (see driver/Kbuild). The DRIVER_* names here are the single shared source consumed by both kernel module and userspace client -- comm.c MUST NOT redefine them. */
#ifndef KCFG_REBOOT_MAGIC
#  define KCFG_REBOOT_MAGIC 0x123456u
#endif

/* reboot () handshake — the sole bootstrap path. The kprobe on
 * __arm64_sys_reboot matches (regs[0],regs[1]) == (MAGIC1,MAGIC2) on the
 * inner wrapped pt_regs; regs[3] is the userspace pointer where the
 * freshly-installed anon-inode fd is written back; regs[2] is ignored.
 * The IDA original binary uses the same magic on both slots. Reachable
 * from adb shell uid; bionic seccomp blocks __NR_reboot for app uids. */
#define DRIVER_REBOOT_MAGIC1 KCFG_REBOOT_MAGIC
#define DRIVER_REBOOT_MAGIC2 KCFG_REBOOT_MAGIC

/* Two reserved cmd codes handled OUTSIDE the main switch. PING: returns success unconditionally (userspace verifies the fd is ours). HELLO: echo-back probe used for protocol version negotiation. */
#define DRIVER_IOCTL_PING 0x9FBF1u
#define DRIVER_IOCTL_HELLO 0x1E240u

/* dispatch_ioctl is a switch keyed by the RAW cmd integer (NOT _IO/_IOR/_IOW/_IOWR macros — the binary uses naked integer compares). Sub-ranges: 0x0B..0x15  memory / process commands 0xD0..0xD5  game-asset / hook-install commands 0x12D..0x18F input-event synthesis commands (lazy-init range) / */
enum drv_cmd {
	DRV_CMD_READ_MEM_LINEAR         = 0x0B,
	DRV_CMD_WRITE_MEM_LINEAR        = 0x0C,
	/* vmap variants: used when the page falls outside the kernel direct map. */
	DRV_CMD_READ_MEM_VMAP           = 0x0D,
	DRV_CMD_WRITE_MEM_VMAP          = 0x0E,
	DRV_CMD_GET_MODULE_BASE         = 0x0F,
	DRV_CMD_FIND_TASK_BY_COMM       = 0x10,
	DRV_CMD_READ_VMA_COOKIE         = 0x11,
	/* TLS layout differs by SDK flag — see dispatch_ioctl case 18. */
	DRV_CMD_GET_TLS                 = 0x12,
	DRV_CMD_HIDE_KGSL               = 0x13,
	DRV_CMD_MULTI_READ              = 0x14,
	DRV_CMD_DUMP_VMAS               = 0x15,

	DRV_CMD_GAME_ASSET_READ_A       = 0xD0,
	DRV_CMD_INSTALL_HOOKS           = 0xD1,
	DRV_CMD_TEAR_DOWN               = 0xD2,
	DRV_CMD_GAME_ASSET_READ_B       = 0xD4,
	DRV_CMD_INSTALL_SIGSEGV_SUPPRESS = 0xD5,

	/* FIRST ioctl in [0x12D, 0x18F] silently registers input_event_kp + input_inject_event_kp and kvmalloc ()s the 12304-byte event pool. */
	DRV_CMD_TOUCH_DOWN              = 0x12D,
	DRV_CMD_TOUCH_UP                = 0x12E,
	DRV_CMD_TOUCH_MOVE              = 0x12F,

	/* First call lazily registers vfs_read_kp on /dev/input/event* reads. */
	DRV_CMD_TOUCH_SLOT_LEGACY       = 0x136,

	/* field0 == 100 binds the sensor kprobes; else sets gyro_x/gyro_y/enable. */
	DRV_CMD_SENSOR_BIND             = 0x140,

	/* Range guards: all cmd values in [FIRST, LAST] enter the lazy-init prelude even if no specific case matches. */
	DRV_CMD_INPUT_RANGE_FIRST       = 0x12D,
	DRV_CMD_INPUT_RANGE_LAST        = 0x18F,
};

/* 40-byte payload for every cmd in the 0x0B..0x15 range. copy_from_user pulls exactly 0x28 bytes from the userspace arg pointer. Field meaning is command-specific. */
struct drv_ioctl_req {
	__u64 pid;      /* +0x00 */
	__u64 addr;     /* +0x08 */
	__u64 buf;      /* +0x10 */
	__u64 size;     /* +0x18 */
	__u64 extra;    /* +0x20 */
};

/* Single element of the vectored DRV_CMD_MULTI_READ array (24 bytes each).
 *
 * DRV_CMD_MULTI_READ ABI inside drv_ioctl_req:
 *   req.pid   = target task pid (as for every read-mem family cmd)
 *   req.buf   = userspace pointer to the drv_multi_read_req[] descriptor array
 *   req.extra = element count
 *   req.size  = writeback slot — driver writes 1 on success, 0 on failure
 *
 * req.addr is unused for this cmd; do NOT put the array pointer there (the
 * driver only reads req.buf).  See comm.c case DRV_CMD_MULTI_READ. */
struct drv_multi_read_req {
	__u64 user_dst;
	__u64 src_va;
	__u64 len;
};

/* 16-byte payload for DRV_CMD_TOUCH_*. Some code paths pass via the embedded fields of drv_ioctl_req (addr=slot_id, buf=x|y, size=pressure); others via a dedicated copy_from_user — userspace MUST zero unused fields. */
struct drv_touch_inject_req {
	__u32 slot_id;
	__u32 x;
	__u32 y;
	__u32 pressure;  /* DOWN only */
};

/* In-pool element format (12 bytes); structurally identical to the type/code/value triple emitted by input_handle_event (). */
struct drv_input_event {
	__u32 type;      /* EV_KEY / EV_ABS / EV_SYN */
	__u32 code;      /* ABS_MT_*, BTN_TOUCH, SYN_REPORT, ... */
	__s32 value;     /* signed payload (tracking id may be -1) */
};

#endif /* _DRIVER_UAPI_H */
