/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2013 - 2020 Intel Corporation */

#ifndef IPU_ISYS_VIDEO_H
#define IPU_ISYS_VIDEO_H

#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/videodev2.h>
#include <media/media-entity.h>
#include <media/v4l2-device.h>
#include <media/v4l2-subdev.h>

#include "ipu-isys-queue.h"

#define IPU_ISYS_OUTPUT_PINS 11
#define IPU_NUM_CAPTURE_DONE 2
#define IPU_ISYS_MAX_PARALLEL_SOF 2

struct ipu_isys;
struct ipu_isys_csi2_be_soc;
struct ipu_fw_isys_stream_cfg_data_abi;

struct ipu_isys_pixelformat {
	u32 pixelformat;
	u32 bpp;
	u32 bpp_packed;
	u32 bpp_planar;
	u32 code;
	u32 css_pixelformat;
};

struct sequence_info {
	unsigned int sequence;
	u64 timestamp;
};

struct output_pin_data {
	void (*pin_ready)(struct ipu_isys_pipeline *ip,
			  struct ipu_fw_isys_resp_info_abi *info);
	struct ipu_isys_queue *aq;
};

struct ipu_isys_pipeline {
	struct media_pipeline pipe;
	struct media_pad *external;
	atomic_t sequence;
	unsigned int seq_index;
	struct sequence_info seq[IPU_ISYS_MAX_PARALLEL_SOF];
	int source;	/* SSI stream source */
	int stream_handle;	/* stream handle for CSS API */
	unsigned int nr_output_pins;	/* How many firmware pins? */
	enum ipu_isl_mode isl_mode;
	struct ipu_isys_csi2_be *csi2_be;
	struct ipu_isys_csi2_be_soc *csi2_be_soc;
	struct ipu_isys_csi2 *csi2;

	/*
	 * Number of capture queues, write access serialised using struct
	 * ipu_isys.stream_mutex
	 */
	int nr_queues;
	int nr_streaming;	/* Number of capture queues streaming */
	int streaming;	/* Has streaming been really started? */
	struct list_head queues;
	struct completion stream_open_completion;
	struct completion stream_close_completion;
	struct completion stream_start_completion;
	struct completion stream_stop_completion;
	struct ipu_isys *isys;

	void (*capture_done[IPU_NUM_CAPTURE_DONE])
	 (struct ipu_isys_pipeline *ip,
	  struct ipu_fw_isys_resp_info_abi *resp);
	struct output_pin_data output_pins[IPU_ISYS_OUTPUT_PINS];
	bool has_sof;
	bool interlaced;
	int error;
	struct ipu_isys_private_buffer *short_packet_bufs;
	size_t short_packet_buffer_size;
	unsigned int num_short_packet_lines;
	unsigned int short_packet_output_pin;
	unsigned int cur_field;
	struct list_head short_packet_incoming;
	struct list_head short_packet_active;
	/* Serialize access to short packet active and incoming lists */
	spinlock_t short_packet_queue_lock;
	struct list_head pending_interlaced_bufs;
	unsigned int short_packet_trace_index;
	struct media_graph graph;
	struct media_entity_enum entity_enum;
};

#define to_ipu_isys_pipeline(__pipe)				\
	container_of((__pipe), struct ipu_isys_pipeline, pipe)

struct video_stream_watermark {
	u32 width;
	u32 height;
	u32 vblank;
	u32 hblank;
	u32 frame_rate;
	u64 pixel_rate;
	u64 stream_data_rate;
	struct list_head stream_node;
};

struct ipu_isys_video {
	/* Serialise access to other fields in the struct. */
	struct mutex mutex;
	struct media_pad pad;
	struct video_device vdev;
	struct v4l2_pix_format_mplane mpix;
	const struct ipu_isys_pixelformat *pfmts;
	const struct ipu_isys_pixelformat *pfmt;
	struct ipu_isys_queue aq;
	struct ipu_isys *isys;
	struct ipu_isys_pipeline ip;
	unsigned int streaming;
	bool packed;
	bool compression;
	struct v4l2_ctrl_handler ctrl_handler;
	struct v4l2_ctrl *compression_ctrl;
	unsigned int ts_offsets[VIDEO_MAX_PLANES];
	unsigned int line_header_length;	/* bits */
	unsigned int line_footer_length;	/* bits */

	struct video_stream_watermark *watermark;

	const struct ipu_isys_pixelformat *
		(*try_fmt_vid_mplane)(struct ipu_isys_video *av,
				      struct v4l2_pix_format_mplane *mpix);
	void (*prepare_fw_stream)(struct ipu_isys_video *av,
				  struct ipu_fw_isys_stream_cfg_data_abi *cfg);
};

#define ipu_isys_queue_to_video(__aq) \
	container_of(__aq, struct ipu_isys_video, aq)

extern const struct ipu_isys_pixelformat ipu_isys_pfmts[];
extern const struct ipu_isys_pixelformat ipu_isys_pfmts_be_soc[];
extern const struct ipu_isys_pixelformat ipu_isys_pfmts_packed[];

const struct ipu_isys_pixelformat *
ipu_isys_get_pixelformat(struct ipu_isys_video *av, u32 pixelformat);

int ipu_isys_vidioc_querycap(struct file *file, void *fh,
			     struct v4l2_capability *cap);

int ipu_isys_vidioc_enum_fmt(struct file *file, void *fh,
			     struct v4l2_fmtdesc *f);

const struct ipu_isys_pixelformat *
ipu_isys_video_try_fmt_vid_mplane_default(struct ipu_isys_video *av,
					  struct v4l2_pix_format_mplane *mpix);

const struct ipu_isys_pixelformat *
ipu_isys_video_try_fmt_vid_mplane(struct ipu_isys_video *av,
				  struct v4l2_pix_format_mplane *mpix,
				  int store_csi2_header);

void
ipu_isys_prepare_fw_cfg_default(struct ipu_isys_video *av,
				struct ipu_fw_isys_stream_cfg_data_abi *cfg);
int ipu_isys_video_prepare_streaming(struct ipu_isys_video *av,
				     unsigned int state);
int ipu_isys_video_set_streaming(struct ipu_isys_video *av, unsigned int state,
				 struct ipu_isys_buffer_list *bl);
int ipu_isys_video_init(struct ipu_isys_video *av, struct media_entity *source,
			unsigned int source_pad, unsigned long pad_flags,
			unsigned int flags);
void ipu_isys_video_cleanup(struct ipu_isys_video *av);
void ipu_isys_video_add_capture_done(struct ipu_isys_pipeline *ip,
				     void (*capture_done)
				      (struct ipu_isys_pipeline *ip,
				       struct ipu_fw_isys_resp_info_abi *resp));

#endif /* IPU_ISYS_VIDEO_H */
