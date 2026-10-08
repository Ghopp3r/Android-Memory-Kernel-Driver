// SPDX-License-Identifier: GPL-2.0
// gyro/accelerometer sample spoofing via uprobe on libsensorservice.so.
#ifndef DRIVER_SENSOR_H
#define DRIVER_SENSOR_H

#include <linux/types.h>
#include <linux/uprobes.h>
#include <driver/uapi.h>

#ifndef SENSOR_TARGET_SO
#define SENSOR_TARGET_SO "/system/lib64/libsensorserviceaidl.so"
#endif
void sensor_hook_write(u32 x_bits, u32 y_bits, u32 enable);
/* @layout_profile = enum drv_sensor_layout: HIDL Vec3 at +0x10, AIDL tagged payload at +0x18. */
/* Registers the uprobe via kern_path (+ d_real for overlayfs). */
int sensor_hook_init(const char *path, unsigned long probe_offset, int layout_profile);
int handler_pre(struct uprobe_consumer *self, struct pt_regs *regs);

/* Pure-integer IEEE-754 binary32 add — kernel FPSIMD is unavailable in the uprobe pre-handler context (kernel_neon_begin may sleep). Quirks preserved: NaN -> +qNaN 0x7FFFFFFF, exact cancellation -> +0, RNE rounding. */
u32 fadd(u32 a, u32 b);

extern u8 gyro_enable;
extern u32 gyro_x;
extern u32 gyro_y;

#endif /* DRIVER_SENSOR_H */
