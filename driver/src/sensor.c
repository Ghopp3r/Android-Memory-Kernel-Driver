// SPDX-License-Identifier: GPL-2.0-only
/* gyro/accelerometer sample spoofing via uprobe. */

#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/uprobes.h>
#include <linux/version.h>

#include <driver/types.h>
#include <driver/uapi.h>

#include "log.h"
#include "sensor.h"

/* event_type == 1 selects gyro layout (X/Y at +0x18); else accel at +0x10. */
int event_type;

u8 gyro_enable;
u32 gyro_x;
u32 gyro_y;

static int handler_pre_thunk(struct uprobe_consumer *self, struct pt_regs *regs);

static struct uprobe_consumer uc = {
	.handler = handler_pre_thunk,
};

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
	unsigned long data_off;
	unsigned long user_ptr;
	u32 num_axes = 0;
	u32 xy[2] = { 0, 0 };
	u32 new_y;

	(void)self;

	/* Gyro layout has an extra 8-byte leading field. */
	data_off = (event_type == 1) ? 24UL : 16UL;

	if (gyro_enable == 0)
		return 0;
	if (gyro_x == 0 && gyro_y == 0)
		return 0;

	/* On ARM64 pt_regs starts with the GPR array; regs[0] == x0. */
	user_ptr = regs->regs[0];

	/* numAxes lives at +0x0C of the user-mode sensors_event_t. */
	if (copy_from_user(&num_axes, (void __user *)(user_ptr + 12), 4) != 0) {
		pr_drv_err("sensor_hook copy_from_user failed\n");
		return 0;
	}
	if (num_axes != 4)
		return 0;

	if (copy_from_user(xy, (void __user *)(user_ptr + data_off), 8) != 0) {
		pr_drv_err("sensor_hook copy_from_user failed\n");
		return 0;
	}

	xy[0] = fadd(xy[0], gyro_x);
	new_y = fadd(xy[1], gyro_y);
	xy[1] = new_y;

	if (copy_to_user((void __user *)(user_ptr + data_off), xy, 8) != 0) {
		pr_drv_err("sensor_hook copy_to_user failed\n");
		return 0;
	}

	return 0;
}

static int handler_pre_thunk(struct uprobe_consumer *self, struct pt_regs *regs) {
	return handler_pre(self, regs);
}

int sensor_hook_init(unsigned long probe_offset, int new_event_type) {
	struct path path;
	struct dentry *dentry;
	struct inode *inode;
	int ret;

	/* Stash the user-chosen layout selector in the module global. */
	event_type = new_event_type;

	path.mnt = NULL;
	path.dentry = NULL;

	ret = kern_path(SENSOR_TARGET_SO, LOOKUP_FOLLOW, &path);
	if (ret != 0) {
		pr_drv_err("kern_path failed: %d\n", ret);
		return ret;
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

	ret = uprobe_register(inode, probe_offset, &uc);
	if (ret != 0)
		pr_drv_err("uprobe_register failed: %d\n", ret);

	path_put(&path);
	return ret;
}
