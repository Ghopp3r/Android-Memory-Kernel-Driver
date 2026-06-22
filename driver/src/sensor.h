// SPDX-License-Identifier: GPL-2.0
// gyro/accelerometer sample spoofing via uprobe on libsensorservice.so.
#ifndef DRIVER_SENSOR_H
#define DRIVER_SENSOR_H

#include <linux/types.h>
#include <linux/uprobes.h>

#ifndef SENSOR_TARGET_SO
#define SENSOR_TARGET_SO "/system/lib64/libsensorservice.so"
#endif

/* @event_type: 1 => gyro layout (X@+0x18, Y@+0x1C); else accel (X@+0x10, Y@+0x14). Calls kern_path, optionally d_real ()-unwraps for overlayfs (gated by DCACHE_OP_REAL + CFI type-id check), then uprobe_register. */
int sensor_hook_init(unsigned long probe_offset, int event_type);

int handler_pre(struct uprobe_consumer *self, struct pt_regs *regs);

/* Pure-integer IEEE-754 binary32 add — kernel FPSIMD is unavailable in the uprobe pre-handler context (kernel_neon_begin may sleep). Quirks preserved: NaN -> +qNaN 0x7FFFFFFF, exact cancellation -> +0, RNE rounding. */
u32 fadd(u32 a, u32 b);

extern u8  gyro_enable;
extern u32 gyro_x;
extern u32 gyro_y;
extern int event_type;

#endif /* DRIVER_SENSOR_H */
