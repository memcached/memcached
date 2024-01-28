/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016 - 2020 Intel Corporation */

#ifndef IPU_ISYS_MEDIA_H
#define IPU_ISYS_MEDIA_H

#include <linux/slab.h>
#include <media/media-entity.h>

struct __packed media_request_cmd {
	__u32 cmd;
	__u32 request;
	__u32 flags;
};

struct __packed media_event_request_complete {
	__u32 id;
};

#define MEDIA_EVENT_TYPE_REQUEST_COMPLETE	1

struct __packed media_event {
	__u32 type;
	__u32 sequence;
	__u32 reserved[4];

	union {
		struct media_event_request_complete req_complete;
	};
};

enum media_device_request_state {
	MEDIA_DEVICE_REQUEST_STATE_IDLE,
	MEDIA_DEVICE_REQUEST_STATE_QUEUED,
	MEDIA_DEVICE_REQUEST_STATE_DELETED,
	MEDIA_DEVICE_REQUEST_STATE_COMPLETE,
};

struct media_kevent {
	struct list_head list;
	struct media_event ev;
};

struct media_device_request {
	u32 id;
	struct media_device *mdev;
	struct file *filp;
	struct media_kevent *kev;
	struct kref kref;
	struct list_head list;
	struct list_head fh_list;
	enum media_device_request_state state;
	struct list_head data;
	u32 flags;
};

static inline struct media_device_request *
media_device_request_find(struct media_device *mdev, u16 reqid)
{
	return NULL;
}

static inline void media_device_request_get(struct media_device_request *req)
{
}

static inline void media_device_request_put(struct media_device_request *req)
{
}

static inline void
media_device_request_complete(struct media_device *mdev,
			      struct media_device_request *req)
{
}

#endif /* IPU_ISYS_MEDIA_H */
