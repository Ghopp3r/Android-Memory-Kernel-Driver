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

/* Maximum payload accepted by one process-memory ioctl. Userspace write
 * wrappers split larger buffers into requests of at most this size. */
#define DRV_MEM_CMD_MAX_SIZE (16ULL << 20)

/* ABI layout of the Event reference passed in x0 to the selected
 * convertToSensorEvent(const Event&, sensors_event_t*) implementation.
 * These values are carried in drv_ioctl_req.size for DRV_CMD_SENSOR_BIND;
 * keep them stable for existing userspace clients. */
enum drv_sensor_layout {
	DRV_SENSOR_LAYOUT_HIDL_V1 = 0,
	DRV_SENSOR_LAYOUT_AIDL_V1 = 1,
	DRV_SENSOR_LAYOUT_COUNT,
};

/* Raw ioctl values; 0x0B..0x17 are memory/process commands. */
enum drv_cmd {
	DRV_CMD_READ_MEM_LINEAR = 0x0B,
	DRV_CMD_WRITE_MEM_LINEAR = 0x0C,
	/* vmap variants: used when the page falls outside the kernel direct map. */
	DRV_CMD_READ_MEM_VMAP = 0x0D,
	DRV_CMD_WRITE_MEM_VMAP = 0x0E,
	DRV_CMD_GET_MODULE_BASE = 0x0F,
	DRV_CMD_FIND_TASK_BY_COMM = 0x10,
	DRV_CMD_READ_VMA_COOKIE = 0x11,
	/* TLS layout differs by SDK flag — see dispatch_ioctl case 18. */
	DRV_CMD_GET_TLS = 0x12,
	DRV_CMD_HIDE_KGSL = 0x13,
	DRV_CMD_MULTI_READ = 0x14,
	DRV_CMD_DUMP_VMAS = 0x15,
	/* Project extension: exact argv[0] lookup using struct drv_find_pid_req. */
	DRV_CMD_FIND_PID_BY_PACKAGE = 0x16,
	/* Writes target APGA keys to req.size (lo) and req.extra (hi). */
	DRV_CMD_GET_APGA_KEYS = 0x17,

	DRV_CMD_GAME_ASSET_READ_A = 0xD0,
	DRV_CMD_INSTALL_HOOKS = 0xD1,
	DRV_CMD_TEAR_DOWN = 0xD2,
	DRV_CMD_GAME_ASSET_READ_B = 0xD4,
	DRV_CMD_INSTALL_SIGSEGV_SUPPRESS = 0xD5,

	/* FIRST ioctl in [0x12D, 0x18F] silently registers input_event_kp + input_inject_event_kp and kvmalloc ()s the 12304-byte event pool. */
	DRV_CMD_TOUCH_DOWN = 0x12D,
	DRV_CMD_TOUCH_UP = 0x12E,
	DRV_CMD_TOUCH_MOVE = 0x12F,

	/* First call lazily registers vfs_read_kp on /dev/input/event* reads. */
	DRV_CMD_TOUCH_SLOT_LEGACY = 0x136,

	/* pid == 100 binds a sensor uprobe: addr=ELF file offset,
	 * size=enum drv_sensor_layout. Otherwise sets gyro_x/gyro_y/enable. */
	DRV_CMD_SENSOR_BIND = 0x140,

	/* Range guards: all cmd values in [FIRST, LAST] enter the lazy-init prelude even if no specific case matches. */
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

/* Fixed, compat-safe payload for DRV_CMD_FIND_PID_BY_PACKAGE.
 *
 * Input:
 *   package = NUL-terminated Android process name (the full argv[0])
 *   flags   = 0 (reserved for future matching modes)
 * Output on success:
 *   pid     = TGID visible in the caller's active PID namespace
 *
 * Matching is exact. "com.example.app" does not match
 * "com.example.app:remote"; pass the latter explicitly to select it.
 */
#define DRV_PACKAGE_NAME_MAX 255u
struct drv_find_pid_req {
	__s32 pid;
	__u32 flags;
	char package[DRV_PACKAGE_NAME_MAX + 1u];
};

/* 40-byte payload for every cmd in the 0x0B..0x17 range. */
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

/* AArch64 per-thread hardware-breakpoint API. */
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

/* AArch64 user-code return-stub API. TRAMPOLINE is reserved for v2. */
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
