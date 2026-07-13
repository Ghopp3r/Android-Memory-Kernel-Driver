// SPDX-License-Identifier: GPL-2.0
// gyro/accelerometer sample spoofing via uprobe on libsensorservice.so.
#ifndef DRIVER_SENSOR_H
#define DRIVER_SENSOR_H

#include <linux/types.h>
#include <linux/uprobes.h>

#ifndef SENSOR_TARGET_SO
#define SENSOR_TARGET_SO "/system/lib64/libsensorservice.so"
#endif

/* @layout_profile is enum drv_sensor_layout: HIDL V1.0 uses Vec3 at +0x10;
 * AIDL V1 uses a tagged payload with Vec3 at +0x18. Calls kern_path,
 * optionally d_real()-unwraps overlayfs, then registers the uprobe. */
int sensor_hook_init(unsigned long probe_offset, int layout_profile);

int handler_pre(struct uprobe_consumer *self, struct pt_regs *regs);

/* Pure-integer IEEE-754 binary32 add — kernel FPSIMD is unavailable in the uprobe pre-handler context (kernel_neon_begin may sleep). Quirks preserved: NaN -> +qNaN 0x7FFFFFFF, exact cancellation -> +0, RNE rounding. */
u32 fadd(u32 a, u32 b);

extern u8  gyro_enable;
extern u32 gyro_x;
extern u32 gyro_y;

#endif /* DRIVER_SENSOR_H */
