// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2013 - 2020 Intel Corporation

#include <linux/compat.h>
#include <linux/errno.h>
#include <linux/uaccess.h>

#include <uapi/linux/ipu-psys.h>

#include "ipu-psys.h"

static long native_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = -ENOTTY;

	if (file->f_op->unlocked_ioctl)
		ret = file->f_op->unlocked_ioctl(file, cmd, arg);

	return ret;
}

struct ipu_psys_buffer32 {
	u64 len;
	union {
		int fd;
		compat_uptr_t userptr;
		u64 reserved;
	} base;
	u32 data_offset;
	u32 bytes_used;
	u32 flags;
	u32 reserved[2];
} __packed;

struct ipu_psys_command32 {
	u64 issue_id;
	u64 user_token;
	u32 priority;
	compat_uptr_t pg_manifest;
	compat_uptr_t buffers;
	int pg;
	u32 pg_manifest_size;
	u32 bufcount;
	u32 min_psys_freq;
	u32 frame_counter;
	u32 reserved[2];
} __packed;

struct ipu_psys_manifest32 {
	u32 index;
	u32 size;
	compat_uptr_t manifest;
	u32 reserved[5];
} __packed;

static int
get_ipu_psys_command32(struct ipu_psys_command *kp,
		       struct ipu_psys_command32 __user *up)
{
	compat_uptr_t pgm, bufs;
	bool access_ok;

	access_ok = access_ok(up, sizeof(struct ipu_psys_command32));
	if (!access_ok || get_user(kp->issue_id, &up->issue_id) ||
	    get_user(kp->user_token, &up->user_token) ||
	    get_user(kp->priority, &up->priority) ||
	    get_user(pgm, &up->pg_manifest) ||
	    get_user(bufs, &up->buffers) ||
	    get_user(kp->pg, &up->pg) ||
	    get_user(kp->pg_manifest_size, &up->pg_manifest_size) ||
	    get_user(kp->bufcount, &up->bufcount) ||
	    get_user(kp->min_psys_freq, &up->min_psys_freq) ||
	    get_user(kp->frame_counter, &up->frame_counter)
	    )
		return -EFAULT;

	kp->pg_manifest = compat_ptr(pgm);
	kp->buffers = compat_ptr(bufs);

	return 0;
}

static int
get_ipu_psys_buffer32(struct ipu_psys_buffer *kp,
		      struct ipu_psys_buffer32 __user *up)
{
	compat_uptr_t ptr;
	bool access_ok;

	access_ok = access_ok(up, sizeof(struct ipu_psys_buffer32));
	if (!access_ok || get_user(kp->len, &up->len) ||
	    get_user(ptr, &up->base.userptr) ||
	    get_user(kp->data_offset, &up->data_offset) ||
	    get_user(kp->bytes_used, &up->bytes_used) ||
	    get_user(kp->flags, &up->flags))
		return -EFAULT;

	kp->base.userptr = compat_ptr(ptr);

	return 0;
}

static int
put_ipu_psys_buffer32(struct ipu_psys_buffer *kp,
		      struct ipu_psys_buffer32 __user *up)
{
	bool access_ok;

	access_ok = access_ok(up, sizeof(struct ipu_psys_buffer32));
	if (!access_ok || put_user(kp->len, &up->len) ||
	    put_user(kp->base.fd, &up->base.fd) ||
	    put_user(kp->data_offset, &up->data_offset) ||
	    put_user(kp->bytes_used, &up->bytes_used) ||
	    put_user(kp->flags, &up->flags))
		return -EFAULT;

	return 0;
}

static int
get_ipu_psys_manifest32(struct ipu_psys_manifest *kp,
			struct ipu_psys_manifest32 __user *up)
{
	compat_uptr_t ptr;
	bool access_ok;

	access_ok = access_ok(up, sizeof(struct ipu_psys_manifest32));
	if (!access_ok || get_user(kp->index, &up->index) ||
	    get_user(kp->size, &up->size) || get_user(ptr, &up->manifest))
		return -EFAULT;

	kp->manifest = compat_ptr(ptr);

	return 0;
}

static int
put_ipu_psys_manifest32(struct ipu_psys_manifest *kp,
			struct ipu_psys_manifest32 __user *up)
{
	compat_uptr_t ptr = (u32)((unsigned long)kp->manifest);
	bool access_ok;

	access_ok = access_ok(up, sizeof(struct ipu_psys_manifest32));
	if (!access_ok || put_user(kp->index, &up->index) ||
	    put_user(kp->size, &up->size) || put_user(ptr, &up->manifest))
		return -EFAULT;

	return 0;
}

#define IPU_IOC_GETBUF32 _IOWR('A', 4, struct ipu_psys_buffer32)
#define IPU_IOC_PUTBUF32 _IOWR('A', 5, struct ipu_psys_buffer32)
#define IPU_IOC_QCMD32 _IOWR('A', 6, struct ipu_psys_command32)
#define IPU_IOC_CMD_CANCEL32 _IOWR('A', 8, struct ipu_psys_command32)
#define IPU_IOC_GET_MANIFEST32 _IOWR('A', 9, struct ipu_psys_manifest32)

long ipu_psys_compat_ioctl32(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	union {
		struct ipu_psys_buffer buf;
		struct ipu_psys_command cmd;
		struct ipu_psys_event ev;
		struct ipu_psys_manifest m;
	} karg;
	int compatible_arg = 1;
	int err = 0;
	void __user *up = compat_ptr(arg);

	switch (cmd) {
	case IPU_IOC_GETBUF32:
		cmd = IPU_IOC_GETBUF;
		break;
	case IPU_IOC_PUTBUF32:
		cmd = IPU_IOC_PUTBUF;
		break;
	case IPU_IOC_QCMD32:
		cmd = IPU_IOC_QCMD;
		break;
	case IPU_IOC_GET_MANIFEST32:
		cmd = IPU_IOC_GET_MANIFEST;
		break;
	}

	switch (cmd) {
	case IPU_IOC_GETBUF:
	case IPU_IOC_PUTBUF:
		err = get_ipu_psys_buffer32(&karg.buf, up);
		compatible_arg = 0;
		break;
	case IPU_IOC_QCMD:
		err = get_ipu_psys_command32(&karg.cmd, up);
		compatible_arg = 0;
		break;
	case IPU_IOC_GET_MANIFEST:
		err = get_ipu_psys_manifest32(&karg.m, up);
		compatible_arg = 0;
		break;
	}
	if (err)
		return err;

	if (compatible_arg) {
		err = native_ioctl(file, cmd, (unsigned long)up);
	} else {
		mm_segment_t old_fs = force_uaccess_begin();

		err = native_ioctl(file, cmd, (unsigned long)&karg);
		force_uaccess_end(old_fs);
	}

	if (err)
		return err;

	switch (cmd) {
	case IPU_IOC_GETBUF:
		err = put_ipu_psys_buffer32(&karg.buf, up);
		break;
	case IPU_IOC_GET_MANIFEST:
		err = put_ipu_psys_manifest32(&karg.m, up);
		break;
	}
	return err;
}
