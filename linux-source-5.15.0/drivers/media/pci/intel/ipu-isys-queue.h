/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2013 - 2020 Intel Corporation */

#ifndef IPU_ISYS_QUEUE_H
#define IPU_ISYS_QUEUE_H

#include <linux/list.h>
#include <linux/spinlock.h>

#include <media/videobuf2-v4l2.h>

#include "ipu-isys-media.h"

struct ipu_isys_video;
struct ipu_isys_pipeline;
struct ipu_fw_isys_resp_info_abi;
struct ipu_fw_isys_frame_buff_set_abi;

enum ipu_isys_buffer_type {
	IPU_ISYS_VIDEO_BUFFER,
	IPU_ISYS_SHORT_PACKET_BUFFER,
};

struct ipu_isys_queue {
	struct list_head node;	/* struct ipu_isys_pipeline.queues */
	struct vb2_queue vbq;
	struct device *dev;
	/*
	 * @lock: serialise access to queued and pre_streamon_queued
	 */
	spinlock_t lock;
	struct list_head active;
	struct list_head incoming;
	u32 css_pin_type;
	unsigned int fw_output;
	int (*buf_init)(struct vb2_buffer *vb);
	void (*buf_cleanup)(struct vb2_buffer *vb);
	int (*buf_prepare)(struct vb2_buffer *vb);
	void (*prepare_frame_buff_set)(struct vb2_buffer *vb);
	void (*fill_frame_buff_set_pin)(struct vb2_buffer *vb,
					struct ipu_fw_isys_frame_buff_set_abi *
					set);
	int (*link_fmt_validate)(struct ipu_isys_queue *aq);
};

struct ipu_isys_buffer {
	struct list_head head;
	enum ipu_isys_buffer_type type;
	struct list_head req_head;
	struct media_device_request *req;
	atomic_t str2mmio_flag;
};

struct ipu_isys_video_buffer {
	struct vb2_v4l2_buffer vb_v4l2;
	struct ipu_isys_buffer ib;
};

struct ipu_isys_private_buffer {
	struct ipu_isys_buffer ib;
	struct ipu_isys_pipeline *ip;
	unsigned int index;
	unsigned int bytesused;
	dma_addr_t dma_addr;
	void *buffer;
};

#define IPU_ISYS_BUFFER_LIST_FL_INCOMING	BIT(0)
#define IPU_ISYS_BUFFER_LIST_FL_ACTIVE	BIT(1)
#define IPU_ISYS_BUFFER_LIST_FL_SET_STATE	BIT(2)

struct ipu_isys_buffer_list {
	struct list_head head;
	unsigned int nbufs;
};

#define vb2_queue_to_ipu_isys_queue(__vb2) \
	container_of(__vb2, struct ipu_isys_queue, vbq)

#define ipu_isys_to_isys_video_buffer(__ib) \
	container_of(__ib, struct ipu_isys_video_buffer, ib)

#define vb2_buffer_to_ipu_isys_video_buffer(__vb) \
	container_of(to_vb2_v4l2_buffer(__vb), \
	struct ipu_isys_video_buffer, vb_v4l2)

#define ipu_isys_buffer_to_vb2_buffer(__ib) \
	(&ipu_isys_to_isys_video_buffer(__ib)->vb_v4l2.vb2_buf)

#define vb2_buffer_to_ipu_isys_buffer(__vb) \
	(&vb2_buffer_to_ipu_isys_video_buffer(__vb)->ib)

#define ipu_isys_buffer_to_private_buffer(__ib) \
	container_of(__ib, struct ipu_isys_private_buffer, ib)

struct ipu_isys_request {
	struct media_device_request req;
	/* serialise access to buffers */
	spinlock_t lock;
	struct list_head buffers;	/* struct ipu_isys_buffer.head */
	bool dispatched;
	/*
	 * struct ipu_isys.requests;
	 * struct ipu_isys_pipeline.struct.*
	 */
	struct list_head head;
};

#define to_ipu_isys_request(__req) \
	container_of(__req, struct ipu_isys_request, req)

int ipu_isys_buf_prepare(struct vb2_buffer *vb);

void ipu_isys_buffer_list_queue(struct ipu_isys_buffer_list *bl,
				unsigned long op_flags,
				enum vb2_buffer_state state);
struct ipu_isys_request *
ipu_isys_next_queued_request(struct ipu_isys_pipeline *ip);
void
ipu_isys_buffer_to_fw_frame_buff_pin(struct vb2_buffer *vb,
				     struct ipu_fw_isys_frame_buff_set_abi *
				     set);
void
ipu_isys_buffer_to_fw_frame_buff(struct ipu_fw_isys_frame_buff_set_abi *set,
				 struct ipu_isys_pipeline *ip,
				 struct ipu_isys_buffer_list *bl);
int ipu_isys_link_fmt_validate(struct ipu_isys_queue *aq);

void
ipu_isys_buf_calc_sequence_time(struct ipu_isys_buffer *ib,
				struct ipu_fw_isys_resp_info_abi *info);
void ipu_isys_queue_buf_done(struct ipu_isys_buffer *ib);
void ipu_isys_queue_buf_ready(struct ipu_isys_pipeline *ip,
			      struct ipu_fw_isys_resp_info_abi *info);
void
ipu_isys_queue_short_packet_ready(struct ipu_isys_pipeline *ip,
				  struct ipu_fw_isys_resp_info_abi *inf);

int ipu_isys_queue_init(struct ipu_isys_queue *aq);
void ipu_isys_queue_cleanup(struct ipu_isys_queue *aq);

#endif /* IPU_ISYS_QUEUE_H */
