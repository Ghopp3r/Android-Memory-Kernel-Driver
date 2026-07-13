// SPDX-License-Identifier: GPL-2.0-only
/* gyro/accelerometer sample spoofing via uprobe. */

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uprobes.h>
#include <linux/version.h>

#include <driver/types.h>
#include <driver/uapi.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
#include <linux/cfi.h>
#endif
#ifndef __nocfi
#define __nocfi
#endif

#include "kallsym.h"
#include "log.h"
#include "sensor.h"

/* x0 is const Event&, not sensors_event_t*. HIDL uses an untagged payload at
 * +0x10; the fixed-size AIDL union stores its tag at +0x10 and its aligned
 * value at +0x18. Both Event forms keep SensorType at +0x0c. */
struct sensor_abi_layout {
	u8 type_off;
	u8 data_off;
	u8 tag_off;
	u32 tag_value;
	bool has_tag;
};

static const struct sensor_abi_layout layouts[DRV_SENSOR_LAYOUT_COUNT] = {
	[DRV_SENSOR_LAYOUT_HIDL_V1] = {
		.type_off = 12,
		.data_off = 16,
		.has_tag = false,
	},
	[DRV_SENSOR_LAYOUT_AIDL_V1] = {
		.type_off = 12,
		.data_off = 24,
		.tag_off = 16,
		.tag_value = 0, /* EventPayload::Tag::vec3 */
		.has_tag = true,
	},
};

static int active_layout_profile = -1;

u8 gyro_enable;
u32 gyro_x;
u32 gyro_y;

static int handler_pre_thunk(struct uprobe_consumer *self, struct pt_regs *regs);

static struct uprobe_consumer uc = {
	.handler = handler_pre_thunk,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
typedef struct uprobe *(*uprobe_register_fn_t)(struct inode *inode, loff_t offset, loff_t ref_ctr_offset, struct uprobe_consumer *consumer);
static uprobe_register_fn_t uprobe_register_ptr;

static noinline __nocfi struct uprobe *drv_call_uprobe_register(uprobe_register_fn_t fn, struct inode *inode, loff_t offset, loff_t ref_ctr_offset, struct uprobe_consumer *consumer) {
	return fn(inode, offset, ref_ctr_offset, consumer);
}

static int drv_uprobe_register(struct inode *inode, loff_t offset, struct uprobe_consumer *consumer) {
	struct uprobe *uprobe;

	if (!uprobe_register_ptr) {
		uprobe_register_ptr = (uprobe_register_fn_t)kallsym_lookup("uprobe_register");
		if (!uprobe_register_ptr) {
			pr_drv_err("uprobe_register not found\n");
			return -ENOENT;
		}
	}

	uprobe = drv_call_uprobe_register(uprobe_register_ptr, inode, offset, 0, consumer);
	return PTR_ERR_OR_ZERO(uprobe);
}
#else
typedef int (*uprobe_register_fn_t)(struct inode *inode, loff_t offset, struct uprobe_consumer *consumer);
static uprobe_register_fn_t uprobe_register_ptr;

static noinline __nocfi int drv_call_uprobe_register(uprobe_register_fn_t fn, struct inode *inode, loff_t offset, struct uprobe_consumer *consumer) {
	return fn(inode, offset, consumer);
}

static int drv_uprobe_register(struct inode *inode, loff_t offset, struct uprobe_consumer *consumer) {
	if (!uprobe_register_ptr) {
		uprobe_register_ptr = (uprobe_register_fn_t)kallsym_lookup("uprobe_register");
		if (!uprobe_register_ptr) {
			pr_drv_err("uprobe_register not found\n");
			return -ENOENT;
		}
	}

	return drv_call_uprobe_register(uprobe_register_ptr, inode, offset, consumer);
}
#endif

/* Pure-integer IEEE-754 binary32 add; kernel FPSIMD unavailable in uprobe pre-handler. */
/* Quirks preserved: NaN -> +qNaN 0x7FFFFFFF, exact cancellation -> +0, RNE, implicit-1 at bit 30. */
u32 fadd(u32 a, u32 b) {
	u32 mant_a, mant_b;
	u32 sig_a, sig_b;
	u32 exp_a, exp_b;
	u32 sign_a, sign_b;
	u32 sum;
	u32 result_exp;
	u32 result;
	int leading_pos;
	int shift;
	int i;
	bool a_is_inf;
	bool b_is_inf;
	bool both_inf;

	if (a == 0)
		return b;
	if (b == 0)
		return a;

	mant_a = a & 0x7FFFFFu;
	mant_b = b & 0x7FFFFFu;

	sig_a = (((a >> 23) & 0xFFu) != 0) ? ((mant_a << 7) | 0x40000000u) : (mant_a << 7);
	sig_b = (((b >> 23) & 0xFFu) != 0) ? ((mant_b << 7) | 0x40000000u) : (mant_b << 7);

	/* Biased exponents clamped to >= 1 for gradual-underflow alignment. */
	exp_a = ((a >> 23) & 0xFFu);
	if (exp_a <= 1u)
		exp_a = 1u;
	exp_b = ((b >> 23) & 0xFFu);
	if (exp_b <= 1u)
		exp_b = 1u;

	if (mant_a != 0 && exp_a == 0xFFu)
		return 0x7FFFFFFFu;

	result = 0x7FFFFFFFu;

	if (mant_b == 0 || exp_b != 0xFFu) {
		sign_a = a >> 31;
		sign_b = b >> 31;
		a_is_inf = (mant_a == 0) && (exp_a == 0xFFu);
		b_is_inf = (mant_b == 0) && (exp_b == 0xFFu);
		both_inf = a_is_inf && b_is_inf;

		result = ((sign_a != sign_b) && both_inf) ? 0x7FFFFFFFu : a;

		if (!a_is_inf) {
			if (mant_b == 0 && exp_b == 0xFFu) {
				return b;
			}

			if (exp_a >= exp_b) {
				shift = (int)(exp_a - exp_b);
				if (shift >= 31)
					shift = 31;
				sig_b >>= shift;
				result_exp = exp_a;
			} else {
				shift = (int)(exp_b - exp_a);
				if (shift >= 31)
					shift = 31;
				sig_a >>= shift;
				result_exp = exp_b;
			}

			if (sign_a == sign_b) {
				sum = sig_a + sig_b;
			} else {
				if (sig_a > sig_b) {
					sum = sig_a - sig_b;
				} else if (sig_a < sig_b) {
					sum = sig_b - sig_a;
					sign_a = sign_b;
				} else {
					sum = 0;
					sign_a = 0;
				}
			}

			leading_pos = -1;
			for (i = 31; i >= 0; i--) {
				if ((sum >> i) != 0) {
					leading_pos = i;
					break;
				}
			}

			if (leading_pos < 23) {
				if (leading_pos == -1) {
					result_exp = (result_exp >= 0xFFu) ? result_exp : 0u;
				} else {
					int up = 22 - leading_pos;
					u32 new_exp = result_exp - (u32)up;

					if ((new_exp - 8u) > 0xFDu) {
						if ((int)new_exp > 7) {
							sum = 0x800000u;
							result_exp = 0xFFu;
						} else {
							sum = (sum >> 7) << (result_exp - 1);
							result_exp = 0u;
						}
					} else {
						sum <<= up;
						result_exp = new_exp - 7u;
					}
				}

				return (result_exp << 23) | (sign_a << 31) | (sum & 0x7FFFFFu);
			} else {
				int round_bit_pos = leading_pos - 23;
				int down_shift = leading_pos - 22;
				u32 sticky = 0;
				u32 round_bit;
				u32 pre_mant;
				u32 carry;
				u32 rounded;
				u32 final_exp;
				u32 base_exp;

				if (leading_pos >= 24) {
					/* Sticky = OR of mantissa bits below the round bit; unrolled-by-2 matches original codegen. */
					int bound = leading_pos - 23;

					if (bound > 1) {
						int j = 0;
						u32 acc_lo = 0;
						u32 acc_hi = 0;
						int pair_bound = bound & ~1;

						while (j != pair_bound) {
							u32 bit_lo = ((1u << j) & sum) >> j;
							u32 bit_hi = ((1u << (j + 1)) & sum) >> (j + 1);

							acc_lo |= bit_lo;
							acc_hi |= bit_hi;
							j += 2;
						}
						sticky = acc_lo | acc_hi;
						if (bound != pair_bound) {
							int k = j;
							while (k != bound) {
								sticky |= ((1u << k) & sum) >> k;
								k++;
							}
						}
					} else {
						int k = 0;
						while (k != bound) {
							sticky |= ((1u << k) & sum) >> k;
							k++;
						}
					}
				}

				base_exp = (u32)down_shift + result_exp;
				final_exp = base_exp - 7u;

				if ((base_exp - 8u) >= 0xFEu) {
					u32 sub_mant = (sum >> 7) << (result_exp - 1);

					if ((int)final_exp <= 0) {
						result_exp = 0u;
						sum = sub_mant;
					} else {
						result_exp = 0xFFu;
						sum = 0x800000u;
					}
				} else {
					round_bit = ((1u << round_bit_pos) & sum) >> round_bit_pos;
					pre_mant = sum >> down_shift;

					if (round_bit == 1 && sticky == 1) {
						carry = 1;
					} else if (round_bit == 1 && sticky == 0) {
						/* Halfway: ties to even. */
						carry = pre_mant & 1u;
					} else {
						carry = 0;
					}

					rounded = pre_mant + carry;

					if (((rounded >> 24) & 0xFFu) == 1u) {
						result_exp = base_exp - 6u;
						sum = rounded >> 1;
					} else {
						result_exp = final_exp;
						sum = rounded;
					}
				}

				return (result_exp << 23) | (sign_a << 31) | (sum & 0x7FFFFFu);
			}
		}
	}

	return result;
}

int handler_pre(struct uprobe_consumer *self, struct pt_regs *regs) {
	const struct sensor_abi_layout *layout;
	int layout_profile;
	unsigned long user_ptr;
	u32 sensor_type = 0;
	u32 payload_tag = 0;
	u32 xy[2] = { 0, 0 };
	u32 new_y;

	(void)self;

	if (gyro_enable == 0)
		return 0;
	if (gyro_x == 0 && gyro_y == 0)
		return 0;
	if (!regs)
		return 0;

	layout_profile = READ_ONCE(active_layout_profile);
	if (layout_profile < 0 || layout_profile >= DRV_SENSOR_LAYOUT_COUNT)
		return 0;
	layout = &layouts[layout_profile];

	/* On ARM64 pt_regs starts with the GPR array; regs[0] == x0. */
	user_ptr = regs->regs[0];
	if (!user_ptr)
		return 0;

	/* SensorType::GYROSCOPE == 4 in both HIDL V1.0 and sensors AIDL. */
	if (copy_from_user(&sensor_type,
			   (void __user *)(user_ptr + layout->type_off),
			   sizeof(sensor_type)) != 0) {
		pr_drv_err("sensor_hook copy_from_user failed\n");
		return 0;
	}
	if (sensor_type != 4)
		return 0;

	/* The AIDL EventPayload is a fixed tagged union. Do not interpret another
	 * active member as Vec3 even when a malformed Event claims gyro type. */
	if (layout->has_tag) {
		if (copy_from_user(&payload_tag,
				   (void __user *)(user_ptr + layout->tag_off),
				   sizeof(payload_tag)) != 0) {
			pr_drv_err("sensor_hook copy_from_user failed\n");
			return 0;
		}
		if (payload_tag != layout->tag_value)
			return 0;
	}

	if (copy_from_user(xy, (void __user *)(user_ptr + layout->data_off),
			   sizeof(xy)) != 0) {
		pr_drv_err("sensor_hook copy_from_user failed\n");
		return 0;
	}

	xy[0] = fadd(xy[0], gyro_x);
	new_y = fadd(xy[1], gyro_y);
	xy[1] = new_y;

	if (copy_to_user((void __user *)(user_ptr + layout->data_off), xy,
			 sizeof(xy)) != 0) {
		pr_drv_err("sensor_hook copy_to_user failed\n");
		return 0;
	}

	return 0;
}

static int handler_pre_thunk(struct uprobe_consumer *self, struct pt_regs *regs) {
	return handler_pre(self, regs);
}

/* Second invocation on the same (inode, offset) blocks indefinitely inside
 * uprobe_register on Android 6.6 kernels — the global consumer is already on
 * the per-uprobe list and the re-add path waits on a lock the first caller
 * still holds. Gate on first-success to keep userspace re-bind safe. */
static bool uprobe_armed;
static unsigned long armed_probe_offset;
static int armed_layout_profile = -1;
static DEFINE_MUTEX(sensor_bind_lock);

int sensor_hook_init(unsigned long probe_offset, int layout_profile) {
	struct path path;
	struct dentry *dentry;
	struct inode *inode;
	int ret;

	if (layout_profile < 0 || layout_profile >= DRV_SENSOR_LAYOUT_COUNT)
		return -EINVAL;

	mutex_lock(&sensor_bind_lock);

	if (uprobe_armed) {
		ret = (armed_probe_offset == probe_offset &&
		       armed_layout_profile == layout_profile) ? 0 : -EBUSY;
		goto out_unlock;
	}

	path.mnt = NULL;
	path.dentry = NULL;

	ret = kern_path(SENSOR_TARGET_SO, LOOKUP_FOLLOW, &path);
	if (ret != 0) {
		pr_drv_err("kern_path failed: %d\n", ret);
		goto out_unlock;
	}

	dentry = path.dentry;

	/* DCACHE_OP_REAL => overlayfs/union; ->d_real reaches the inode whose pages the uprobe patches. */
	if (dentry->d_flags & DCACHE_OP_REAL) {
		struct dentry *real;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
		real = d_real(dentry, D_REAL_DATA);
#else
		real = d_real(dentry, NULL);
#endif
		if (!IS_ERR_OR_NULL(real))
			dentry = real;
	}

	inode = dentry->d_inode;

	ret = drv_uprobe_register(inode, probe_offset, &uc);
	if (ret != 0)
		pr_drv_err("uprobe_register failed: %d\n", ret);
	else {
		/* Publish the layout only after the registration succeeds. A handler
		 * racing in the tiny interval before this store safely sees -1 and
		 * leaves that event untouched. */
		WRITE_ONCE(active_layout_profile, layout_profile);
		armed_probe_offset = probe_offset;
		armed_layout_profile = layout_profile;
		uprobe_armed = true;
	}

	path_put(&path);

out_unlock:
	mutex_unlock(&sensor_bind_lock);
	return ret;
}
