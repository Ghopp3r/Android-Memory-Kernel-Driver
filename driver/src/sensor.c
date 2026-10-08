// SPDX-License-Identifier: GPL-2.0-only
/* gyro/accelerometer sample spoofing via uprobe. */

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/ptrace.h>
#include <linux/string.h>
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

/* x0 is const Event&, not sensors_event_t*. */
/* HIDL: untagged payload at +0x10. AIDL: tag at +0x10, aligned value at +0x18. */
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

#define SENSOR_MAX_PROBES 8

struct sensor_slot {
	struct uprobe_consumer uc;
	struct inode *inode;
	unsigned long offset;
	int layout_profile;
	bool armed;
};

static struct sensor_slot sensor_slots[SENSOR_MAX_PROBES];
static DEFINE_MUTEX(sensor_bind_lock);

u8 gyro_enable;
u32 gyro_x;
u32 gyro_y;

/* ---------------- kallsym-resolved kernel helpers ---------------- */

/* kern_path / path_put are not in __ksymtab; resolve at runtime like uprobe_register. */
typedef int  (*kern_path_fn_t)(const char *name, unsigned int flags, struct path *path);
typedef void (*path_put_fn_t)(const struct path *path);

static kern_path_fn_t kern_path_ptr;
static path_put_fn_t  path_put_ptr;

static noinline __nocfi int
drv_call_kern_path(kern_path_fn_t fn, const char *name, unsigned int flags,
		   struct path *path)
{
	return fn(name, flags, path);
}

static noinline __nocfi void
drv_call_path_put(path_put_fn_t fn, const struct path *path)
{
	fn(path);
}

static int drv_kern_path(const char *name, struct path *path)
{
	if (!kern_path_ptr) {
		kern_path_ptr = (kern_path_fn_t)kallsym_lookup("kern_path");
		if (!kern_path_ptr) {
			LOGE("kern_path not found\n");
			return -ENOENT;
		}
	}
	return drv_call_kern_path(kern_path_ptr, name, LOOKUP_FOLLOW, path);
}

static void drv_path_put(const struct path *path)
{
	if (!path_put_ptr) {
		path_put_ptr = (path_put_fn_t)kallsym_lookup("path_put");
		if (!path_put_ptr) {
			LOGE("path_put not found\n");
			return;
		}
	}
	drv_call_path_put(path_put_ptr, path);
}

/* ---------------- uprobe_register wrapper ---------------- */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
typedef struct uprobe *(*uprobe_register_fn_t)(struct inode *inode, loff_t offset,
					       loff_t ref_ctr_offset,
					       struct uprobe_consumer *consumer);
static uprobe_register_fn_t uprobe_register_ptr;

static noinline __nocfi struct uprobe *
drv_call_uprobe_register(uprobe_register_fn_t fn, struct inode *inode,
			 loff_t offset, loff_t ref_ctr_offset,
			 struct uprobe_consumer *consumer)
{
	return fn(inode, offset, ref_ctr_offset, consumer);
}

static int drv_uprobe_register(struct inode *inode, loff_t offset,
			       struct uprobe_consumer *consumer)
{
	struct uprobe *uprobe;

	if (!uprobe_register_ptr) {
		uprobe_register_ptr =
			(uprobe_register_fn_t)kallsym_lookup("uprobe_register");
		if (!uprobe_register_ptr) {
			LOGE("uprobe_register not found\n");
			return -ENOENT;
		}
	}

	uprobe = drv_call_uprobe_register(uprobe_register_ptr, inode, offset, 0,
					  consumer);
	return PTR_ERR_OR_ZERO(uprobe);
}
#else
typedef int (*uprobe_register_fn_t)(struct inode *inode, loff_t offset,
				    struct uprobe_consumer *consumer);
static uprobe_register_fn_t uprobe_register_ptr;

static noinline __nocfi int
drv_call_uprobe_register(uprobe_register_fn_t fn, struct inode *inode,
			 loff_t offset, struct uprobe_consumer *consumer)
{
	return fn(inode, offset, consumer);
}

static int drv_uprobe_register(struct inode *inode, loff_t offset,
			       struct uprobe_consumer *consumer)
{
	if (!uprobe_register_ptr) {
		uprobe_register_ptr =
			(uprobe_register_fn_t)kallsym_lookup("uprobe_register");
		if (!uprobe_register_ptr) {
			LOGE("uprobe_register not found\n");
			return -ENOENT;
		}
	}

	return drv_call_uprobe_register(uprobe_register_ptr, inode, offset,
					consumer);
}
#endif

/* ---------------- handler ---------------- */

int handler_pre(struct uprobe_consumer *self, struct pt_regs *regs)
{
	struct sensor_slot *slot = container_of(self, struct sensor_slot, uc);
	const struct sensor_abi_layout *layout;
	unsigned long user_ptr;
	u32 sensor_type = 0;
	u32 payload_tag = 0;
	u32 xy[2] = { 0, 0 };

	if (gyro_enable == 0)
		return 0;
	if (gyro_x == 0 && gyro_y == 0)
		return 0;
	if (!regs)
		return 0;

	if (slot->layout_profile < 0 ||
	    slot->layout_profile >= DRV_SENSOR_LAYOUT_COUNT)
		return 0;
	layout = &layouts[slot->layout_profile];

	/* On ARM64 pt_regs starts with the GPR array; regs[0] == x0. */
	user_ptr = regs->regs[0];
	if (!user_ptr)
		return 0;

	/* SensorType::GYROSCOPE == 4 in both HIDL V1.0 and sensors AIDL. */
	if (copy_from_user(&sensor_type,
			   (void __user *)(user_ptr + layout->type_off),
			   sizeof(sensor_type)) != 0) {

		return 0;
	}

	if (sensor_type != 4)
		return 0;

	/* AIDL EventPayload is a tagged union; refuse to reinterpret another
	 * active member as Vec3. */
	if (layout->has_tag) {
		if (copy_from_user(&payload_tag,
				   (void __user *)(user_ptr + layout->tag_off),
				   sizeof(payload_tag)) != 0)
			return 0;

		if (payload_tag != layout->tag_value)
			return 0;
	}

	if (copy_from_user(xy, (void __user *)(user_ptr + layout->data_off),
			   sizeof(xy)) != 0)
		return 0;

	xy[0] = fadd(xy[0], gyro_x);
	xy[1] = fadd(xy[1], gyro_y);

	if (copy_to_user((void __user *)(user_ptr + layout->data_off), xy,
			 sizeof(xy)) != 0) {
		return 0;
	}

	return 0;
}

/* ---------------- fadd (unchanged) ---------------- */

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
					/* Sticky = OR of mantissa bits below the round bit; unrolled-by-2 for original codegen. */
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

/* ---------------- write path ---------------- */

void sensor_hook_write(u32 x_bits, u32 y_bits, u32 enable)
{
	WRITE_ONCE(gyro_x, x_bits);
	WRITE_ONCE(gyro_y, y_bits);
	WRITE_ONCE(gyro_enable, enable ? 1u : 0u);
}

/* ---------------- slot management ---------------- */

static struct sensor_slot *sensor_find_free_slot(void)
{
	int i;
	for (i = 0; i < SENSOR_MAX_PROBES; i++)
		if (!sensor_slots[i].armed)
			return &sensor_slots[i];
	return NULL;
}

static struct sensor_slot *sensor_find_duplicate(struct inode *inode,
						 unsigned long offset)
{
	int i;
	for (i = 0; i < SENSOR_MAX_PROBES; i++)
		if (sensor_slots[i].armed &&
		    sensor_slots[i].inode == inode &&
		    sensor_slots[i].offset == offset)
			return &sensor_slots[i];
	return NULL;
}

int sensor_hook_init(const char *path, unsigned long probe_offset,
		     int layout_profile)
{
	struct path kpath;
	struct dentry *dentry;
	struct inode *inode;
	struct sensor_slot *slot;
	int ret;

	if (!path || layout_profile < 0 ||
	    layout_profile >= DRV_SENSOR_LAYOUT_COUNT)
		return -EINVAL;

	if (path[0] == '\0')
		return -EINVAL;

	mutex_lock(&sensor_bind_lock);

	kpath.mnt = NULL;
	kpath.dentry = NULL;

	ret = drv_kern_path(path, &kpath);
	if (ret != 0) {
		LOGE("kern_path(%s) failed: %d\n", path, ret);
		goto out_unlock;
	}

	dentry = kpath.dentry;

	/* DCACHE_OP_REAL => overlayfs/union; ->d_real reaches the inode whose
	 * pages the uprobe patches. */
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

	if (sensor_find_duplicate(inode, probe_offset)) {
		LOGE("sensor dup: %s+0x%lx already armed\n",
		     path, probe_offset);
		ret = 0;
		drv_path_put(&kpath);
		goto out_unlock;
	}

	slot = sensor_find_free_slot();
	if (!slot) {
		LOGE("sensor: no free slot for %s+0x%lx\n",
		     path, probe_offset);
		ret = -ENOSPC;
		drv_path_put(&kpath);
		goto out_unlock;
	}

	memset(slot, 0, sizeof(*slot));
	slot->uc.handler = handler_pre;
	slot->inode = inode;
	slot->offset = probe_offset;
	slot->layout_profile = layout_profile;

	ret = drv_uprobe_register(inode, probe_offset, &slot->uc);
	if (ret != 0) {
		LOGE("uprobe_register(%s, 0x%lx) failed: %d\n",
		     path, probe_offset, ret);
		drv_path_put(&kpath);
		goto out_unlock;
	}

	slot->armed = true;
	LOGE("sensor armed: %s+0x%lx layout=%d ino=%lu\n",
	     path, probe_offset, layout_profile,
	     (unsigned long)inode->i_ino);

	drv_path_put(&kpath);

out_unlock:
	mutex_unlock(&sensor_bind_lock);
	return ret;
}