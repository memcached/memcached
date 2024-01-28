/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2013 - 2020 Intel Corporation */

#ifndef IPU_ISYS_CSI2_H
#define IPU_ISYS_CSI2_H

#include <media/media-entity.h>
#include <media/v4l2-device.h>

#include "ipu-isys-queue.h"
#include "ipu-isys-subdev.h"
#include "ipu-isys-video.h"
#include "ipu-platform-isys.h"

struct ipu_isys_csi2_timing;
struct ipu_isys_csi2_pdata;
struct ipu_isys;

#define NR_OF_CSI2_SINK_PADS		1
#define CSI2_PAD_SINK			0
#define NR_OF_CSI2_SOURCE_PADS		1
#define CSI2_PAD_SOURCE			1
#define NR_OF_CSI2_PADS	(NR_OF_CSI2_SINK_PADS + NR_OF_CSI2_SOURCE_PADS)

#define IPU_ISYS_SHORT_PACKET_BUFFER_NUM	VIDEO_MAX_FRAME
#define IPU_ISYS_SHORT_PACKET_WIDTH	32
#define IPU_ISYS_SHORT_PACKET_FRAME_PACKETS	2
#define IPU_ISYS_SHORT_PACKET_EXTRA_PACKETS	64
#define IPU_ISYS_SHORT_PACKET_UNITSIZE	8
#define IPU_ISYS_SHORT_PACKET_GENERAL_DT	0
#define IPU_ISYS_SHORT_PACKET_PT		0
#define IPU_ISYS_SHORT_PACKET_FT		0

#define IPU_ISYS_SHORT_PACKET_STRIDE \
	(IPU_ISYS_SHORT_PACKET_WIDTH * \
	IPU_ISYS_SHORT_PACKET_UNITSIZE)
#define IPU_ISYS_SHORT_PACKET_NUM(num_lines) \
	((num_lines) * 2 + IPU_ISYS_SHORT_PACKET_FRAME_PACKETS + \
	IPU_ISYS_SHORT_PACKET_EXTRA_PACKETS)
#define IPU_ISYS_SHORT_PACKET_PKT_LINES(num_lines) \
	DIV_ROUND_UP(IPU_ISYS_SHORT_PACKET_NUM(num_lines) * \
	IPU_ISYS_SHORT_PACKET_UNITSIZE, \
	IPU_ISYS_SHORT_PACKET_STRIDE)
#define IPU_ISYS_SHORT_PACKET_BUF_SIZE(num_lines) \
	(IPU_ISYS_SHORT_PACKET_WIDTH * \
	IPU_ISYS_SHORT_PACKET_PKT_LINES(num_lines) * \
	IPU_ISYS_SHORT_PACKET_UNITSIZE)

#define IPU_ISYS_SHORT_PACKET_TRACE_MSG_NUMBER	256
#define IPU_ISYS_SHORT_PACKET_TRACE_MSG_SIZE	16
#define IPU_ISYS_SHORT_PACKET_TRACE_BUFFER_SIZE \
	(IPU_ISYS_SHORT_PACKET_TRACE_MSG_NUMBER * \
	IPU_ISYS_SHORT_PACKET_TRACE_MSG_SIZE)

#define IPU_ISYS_SHORT_PACKET_FROM_RECEIVER	0
#define IPU_ISYS_SHORT_PACKET_FROM_TUNIT		1

#define IPU_ISYS_SHORT_PACKET_TRACE_MAX_TIMESHIFT 100
#define IPU_ISYS_SHORT_PACKET_TRACE_EVENT_MASK	0x2082
#define IPU_SKEW_CAL_LIMIT_HZ (1500000000ul / 2)

#define CSI2_CSI_RX_DLY_CNT_TERMEN_CLANE_A		0
#define CSI2_CSI_RX_DLY_CNT_TERMEN_CLANE_B		0
#define CSI2_CSI_RX_DLY_CNT_SETTLE_CLANE_A		95
#define CSI2_CSI_RX_DLY_CNT_SETTLE_CLANE_B		-8

#define CSI2_CSI_RX_DLY_CNT_TERMEN_DLANE_A		0
#define CSI2_CSI_RX_DLY_CNT_TERMEN_DLANE_B		0
#define CSI2_CSI_RX_DLY_CNT_SETTLE_DLANE_A		85
#define CSI2_CSI_RX_DLY_CNT_SETTLE_DLANE_B		-2

#define IPU_EOF_TIMEOUT 300
#define IPU_EOF_TIMEOUT_JIFFIES msecs_to_jiffies(IPU_EOF_TIMEOUT)

/*
 * struct ipu_isys_csi2
 *
 * @nlanes: number of lanes in the receiver
 */
struct ipu_isys_csi2 {
	struct ipu_isys_csi2_pdata *pdata;
	struct ipu_isys *isys;
	struct ipu_isys_subdev asd;
	struct ipu_isys_video av;
	struct completion eof_completion;

	void __iomem *base;
	u32 receiver_errors;
	unsigned int nlanes;
	unsigned int index;
	atomic_t sof_sequence;
	bool in_frame;
	bool wait_for_sync;

	struct v4l2_ctrl *store_csi2_header;
};

struct ipu_isys_csi2_timing {
	u32 ctermen;
	u32 csettle;
	u32 dtermen;
	u32 dsettle;
};

/*
 * This structure defines the MIPI packet header output
 * from IPU MIPI receiver. Due to hardware conversion,
 * this structure is not the same as defined in CSI-2 spec.
 */
struct ipu_isys_mipi_packet_header {
	u32 word_count:16, dtype:13, sync:2, stype:1;
	u32 sid:4, port_id:4, reserved:23, odd_even:1;
} __packed;

/*
 * This structure defines the trace message content
 * for CSI2 receiver monitor messages.
 */
struct ipu_isys_csi2_monitor_message {
	u64 fe:1,
	    fs:1,
	    pe:1,
	    ps:1,
	    le:1,
	    ls:1,
	    reserved1:2,
	    sequence:2,
	    reserved2:2,
	    flash_shutter:4,
	    error_cause:12,
	    fifo_overrun:1,
	    crc_error:2,
	    reserved3:1,
	    timestamp_l:16,
	    port:4, vc:2, reserved4:2, frame_sync:4, reserved5:4;
	u64 reserved6:3,
	    cmd:2, reserved7:1, monitor_id:7, reserved8:1, timestamp_h:50;
} __packed;

#define to_ipu_isys_csi2(sd) container_of(to_ipu_isys_subdev(sd), \
					struct ipu_isys_csi2, asd)

int ipu_isys_csi2_get_link_freq(struct ipu_isys_csi2 *csi2, __s64 *link_freq);
int ipu_isys_csi2_init(struct ipu_isys_csi2 *csi2,
		       struct ipu_isys *isys,
		       void __iomem *base, unsigned int index);
void ipu_isys_csi2_cleanup(struct ipu_isys_csi2 *csi2);
struct ipu_isys_buffer *
ipu_isys_csi2_get_short_packet_buffer(struct ipu_isys_pipeline *ip,
				      struct ipu_isys_buffer_list *bl);
void ipu_isys_csi2_sof_event(struct ipu_isys_csi2 *csi2);
void ipu_isys_csi2_eof_event(struct ipu_isys_csi2 *csi2);
void ipu_isys_csi2_wait_last_eof(struct ipu_isys_csi2 *csi2);

/* interface for platform specific */
int ipu_isys_csi2_set_stream(struct v4l2_subdev *sd,
			     struct ipu_isys_csi2_timing timing,
			     unsigned int nlanes, int enable);
unsigned int ipu_isys_csi2_get_current_field(struct ipu_isys_pipeline *ip,
					     unsigned int *timestamp);
void ipu_isys_csi2_isr(struct ipu_isys_csi2 *csi2);
void ipu_isys_csi2_error(struct ipu_isys_csi2 *csi2);

#endif /* IPU_ISYS_CSI2_H */
