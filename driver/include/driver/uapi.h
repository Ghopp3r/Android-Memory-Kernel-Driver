// SPDX-License-Identifier: GPL-2.0
/* Shared ABI for the kernel module and userspace client. */
#ifndef _DRIVER_UAPI_H
#define _DRIVER_UAPI_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <linux/types.h>
#include <sys/types.h>
#endif

/* Kbuild can override this value with -DKCFG_REBOOT_MAGIC. */
#ifndef KCFG_REBOOT_MAGIC
#define KCFG_REBOOT_MAGIC 0x123456u
#endif

/* reboot() handshake: x0/x1 carry magic, x3 points to fd output, x2 is unused. */
#define DRIVER_REBOOT_MAGIC1 KCFG_REBOOT_MAGIC
#define DRIVER_REBOOT_MAGIC2 KCFG_REBOOT_MAGIC

/* Reserved commands are handled before the main command switch. */
#define DRIVER_IOCTL_PING 0x9FBF1u
#define DRIVER_IOCTL_HELLO 0x1E240u

/* Maximum payload for one process-memory ioctl. */
#define DRV_MEM_CMD_MAX_SIZE (16ULL << 20)

/* Event layout selected by DRV_CMD_SENSOR_BIND. Values are ABI-stable. */
enum drv_sensor_layout {
	DRV_SENSOR_LAYOUT_HIDL_V1 = 0,
	DRV_SENSOR_LAYOUT_AIDL_V1 = 1,
	DRV_SENSOR_LAYOUT_COUNT,
};

/* Raw ioctl commands. */
enum drv_cmd {
	DRV_CMD_READ_MEM_LINEAR = 0x0B,
	DRV_CMD_WRITE_MEM_LINEAR = 0x0C,
	/* Uses vmap when the page is outside the kernel direct map. */
	DRV_CMD_READ_MEM_VMAP = 0x0D,
	DRV_CMD_WRITE_MEM_VMAP = 0x0E,
	DRV_CMD_GET_MODULE_BASE = 0x0F,
	DRV_CMD_FIND_TASK_BY_COMM = 0x10,
	DRV_CMD_READ_VMA_COOKIE = 0x11,
	/* TLS layout depends on the SDK selection in dispatch_ioctl(). */
	DRV_CMD_GET_TLS = 0x12,
	DRV_CMD_HIDE_KGSL = 0x13,
	DRV_CMD_MULTI_READ = 0x14,
	DRV_CMD_DUMP_VMAS = 0x15,
	/* Exact argv[0] lookup using drv_find_pid_req. */
	DRV_CMD_FIND_PID_BY_PACKAGE = 0x16,
	/* Writes APGA keys to req.size (lo) and req.extra (hi). */
	DRV_CMD_GET_APGA_KEYS = 0x17,

	DRV_CMD_GAME_ASSET_READ_A = 0xD0,
	DRV_CMD_INSTALL_HOOKS = 0xD1,
	DRV_CMD_TEAR_DOWN = 0xD2,
	DRV_CMD_GAME_ASSET_READ_B = 0xD4,
	DRV_CMD_INSTALL_SIGSEGV_SUPPRESS = 0xD5,

	/* The first input-range command allocates the pool and installs input kprobes. */
	DRV_CMD_TOUCH_DOWN = 0x12D,
	DRV_CMD_TOUCH_UP = 0x12E,
	DRV_CMD_TOUCH_MOVE = 0x12F,

	/* First call lazily registers the vfs_read kprobe for /dev/input/event*. */
	DRV_CMD_TOUCH_SLOT_LEGACY = 0x136,

	/* pid == 100 binds a sensor uprobe; otherwise this updates gyro values. */
	DRV_CMD_SENSOR_BIND = 0x140,

	/* These values enter the lazy input initialization path. */
	DRV_CMD_INPUT_RANGE_FIRST = 0x12D,
	DRV_CMD_INPUT_RANGE_LAST = 0x18F,

	DRV_CMD_HWBP_INSTALL = 0x40,
	DRV_CMD_HWBP_REMOVE = 0x41,
	DRV_CMD_HWBP_SET_OVERRIDE = 0x42,
	DRV_CMD_HWBP_GET_HITS = 0x43,
	DRV_CMD_HWBP_CLEAR_ALL = 0x44,
	DRV_CMD_HWBP_RANGE_FIRST = DRV_CMD_HWBP_INSTALL,
	DRV_CMD_HWBP_RANGE_LAST = DRV_CMD_HWBP_CLEAR_ALL,

	DRV_CMD_PTE_HOOK_INSTALL = 0x48,
	DRV_CMD_PTE_HOOK_REMOVE = 0x49,
	DRV_CMD_PTE_HOOK_CLEAR_ALL = 0x4A,
	DRV_CMD_PTE_HOOK_RANGE_FIRST = DRV_CMD_PTE_HOOK_INSTALL,
	DRV_CMD_PTE_HOOK_RANGE_LAST = DRV_CMD_PTE_HOOK_CLEAR_ALL,
};

/* Exact full argv[0] lookup request. flags is reserved and pid receives the target TGID. */
#define DRV_PACKAGE_NAME_MAX 255u
struct drv_find_pid_req {
	__s32 pid;
	__u32 flags;
	char package[DRV_PACKAGE_NAME_MAX + 1u];
};

/* Shared 40-byte payload for commands in the 0x0B..0x17 range. */
struct drv_ioctl_req {
	__u64 pid; /* +0x00 */
	__u64 addr; /* +0x08 */
	__u64 buf; /* +0x10 */
	__u64 size; /* +0x18 */
	__u64 extra; /* +0x20 */
};

/* 24-byte DRV_CMD_MULTI_READ descriptor; req.buf is its array and req.extra is its count. */
struct drv_multi_read_req {
	__u64 user_dst;
	__u64 src_va;
	__u64 len;
};

/* 16-byte payload for DRV_CMD_TOUCH_*; callers must zero unused fields. */
struct drv_touch_inject_req {
	__u32 slot_id;
	__u32 x;
	__u32 y;
	__u32 pressure; /* DOWN only */
};

/* In-pool input event with the type/code/value wire layout. */
struct drv_input_event {
	__u32 type; /* EV_KEY, EV_ABS, or EV_SYN */
	__u32 code; /* ABS_MT_*, BTN_TOUCH, SYN_REPORT, ... */
	__s32 value; /* Tracking ID can be -1. */
};

/* AArch64 per-thread hardware-breakpoint ABI. */
#define DRV_HWBP_TYPE_EXECUTE 4u
#define DRV_HWBP_LEN_EXECUTE 4u
#define DRV_HWBP_MAX_OVERRIDES 10u
#define DRV_HWBP_HIT_RING_SLOTS 32u

enum drv_hwbp_reg_kind {
	DRV_HWBP_REG_NONE = 0,
	DRV_HWBP_REG_X = 1,
	DRV_HWBP_REG_VLO = 2,
	DRV_HWBP_REG_VHI = 3,
	DRV_HWBP_REG_PC = 4,
};

struct drv_hwbp_reg_override {
	__u32 kind;
	__u32 index;
	__u64 value;
};

struct drv_hwbp_install_req {
	__s32 pid;
	__u32 bp_len;
	__u32 bp_type;
	__u32 override_count;
	__u64 addr;
	__u32 pass_through;
	__u32 _pad;
	struct drv_hwbp_reg_override overrides[DRV_HWBP_MAX_OVERRIDES];
};

struct drv_hwbp_hit {
	__u64 timestamp_ns;
	__u64 pc;
	__u64 sp;
	__u64 pstate;
	__u64 x[31];
};

/* AArch64 user-code return-stub ABI. TRAMPOLINE is reserved for v2. */
enum drv_pte_hook_kind {
	DRV_PTE_HOOK_CONST_U64 = 0,
	DRV_PTE_HOOK_TRAMPOLINE = 1,
	DRV_PTE_HOOK_CONST_FLOAT = 2,
	DRV_PTE_HOOK_CONST_DOUBLE = 3,
	DRV_PTE_HOOK_VOID_RET = 4,
	DRV_PTE_HOOK_CONST_INT = DRV_PTE_HOOK_CONST_U64,
};

struct drv_pte_hook_install_req {
	__s32 pid;
	__u32 kind;
	__u64 addr;
	__u64 ret_value;
	__u64 tramp_addr;
	__u64 replace_addr;
};

#endif /* _DRIVER_UAPI_H */
