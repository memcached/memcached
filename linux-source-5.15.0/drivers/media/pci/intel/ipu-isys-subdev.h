/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2013 - 2020 Intel Corporation */

#ifndef IPU_ISYS_SUBDEV_H
#define IPU_ISYS_SUBDEV_H

#include <linux/mutex.h>

#include <media/media-entity.h>
#include <media/v4l2-device.h>
#include <media/v4l2-ctrls.h>

#include "ipu-isys-queue.h"

#define IPU_ISYS_MIPI_CSI2_TYPE_NULL	0x10
#define IPU_ISYS_MIPI_CSI2_TYPE_BLANKING	0x11
#define IPU_ISYS_MIPI_CSI2_TYPE_EMBEDDED8	0x12
#define IPU_ISYS_MIPI_CSI2_TYPE_YUV422_8	0x1e
#define IPU_ISYS_MIPI_CSI2_TYPE_YUV422_10	0x1f
#define IPU_ISYS_MIPI_CSI2_TYPE_RGB565	0x22
#define IPU_ISYS_MIPI_CSI2_TYPE_RGB888	0x24
#define IPU_ISYS_MIPI_CSI2_TYPE_RAW6	0x28
#define IPU_ISYS_MIPI_CSI2_TYPE_RAW7	0x29
#define IPU_ISYS_MIPI_CSI2_TYPE_RAW8	0x2a
#define IPU_ISYS_MIPI_CSI2_TYPE_RAW10	0x2b
#define IPU_ISYS_MIPI_CSI2_TYPE_RAW12	0x2c
#define IPU_ISYS_MIPI_CSI2_TYPE_RAW14	0x2d
/* 1-8 */
#define IPU_ISYS_MIPI_CSI2_TYPE_USER_DEF(i)	(0x30 + (i) - 1)

#define FMT_ENTRY (struct ipu_isys_fmt_entry [])

enum isys_subdev_prop_tgt {
	IPU_ISYS_SUBDEV_PROP_TGT_SINK_FMT,
	IPU_ISYS_SUBDEV_PROP_TGT_SINK_CROP,
	IPU_ISYS_SUBDEV_PROP_TGT_SINK_COMPOSE,
	IPU_ISYS_SUBDEV_PROP_TGT_SOURCE_COMPOSE,
	IPU_ISYS_SUBDEV_PROP_TGT_SOURCE_CROP,
};

#define	IPU_ISYS_SUBDEV_PROP_TGT_NR_OF \
	(IPU_ISYS_SUBDEV_PROP_TGT_SOURCE_CROP + 1)

enum ipu_isl_mode {
	IPU_ISL_OFF = 0,	/* SOC BE */
	IPU_ISL_CSI2_BE,	/* RAW BE */
};

enum ipu_be_mode {
	IPU_BE_RAW = 0,
	IPU_BE_SOC
};

enum ipu_isys_subdev_pixelorder {
	IPU_ISYS_SUBDEV_PIXELORDER_BGGR = 0,
	IPU_ISYS_SUBDEV_PIXELORDER_GBRG,
	IPU_ISYS_SUBDEV_PIXELORDER_GRBG,
	IPU_ISYS_SUBDEV_PIXELORDER_RGGB,
};

struct ipu_isys;

struct ipu_isys_subdev {
	/* Serialise access to any other field in the struct */
	struct mutex mutex;
	struct v4l2_subdev sd;
	struct ipu_isys *isys;
	u32 const *const *supported_codes;
	struct media_pad *pad;
	struct v4l2_mbus_framefmt *ffmt;
	struct v4l2_rect *crop;
	struct v4l2_rect *compose;
	unsigned int nsinks;
	unsigned int nsources;
	struct v4l2_ctrl_handler ctrl_handler;
	void (*ctrl_init)(struct v4l2_subdev *sd);
	void (*set_ffmt)(struct v4l2_subdev *sd,
			 struct v4l2_subdev_state *sd_state,
			 struct v4l2_subdev_format *fmt);
	struct {
		bool crop;
		bool compose;
	} *valid_tgts;
	enum ipu_isl_mode isl_mode;
	enum ipu_be_mode be_mode;
	int source;	/* SSI stream source; -1 if unset */
};

#define to_ipu_isys_subdev(__sd) \
	container_of(__sd, struct ipu_isys_subdev, sd)

struct v4l2_mbus_framefmt *__ipu_isys_get_ffmt(struct v4l2_subdev *sd,
					       struct v4l2_subdev_state *sd_state,
					       unsigned int pad,
					       unsigned int which);

unsigned int ipu_isys_mbus_code_to_bpp(u32 code);
unsigned int ipu_isys_mbus_code_to_mipi(u32 code);
u32 ipu_isys_subdev_code_to_uncompressed(u32 sink_code);

enum ipu_isys_subdev_pixelorder ipu_isys_subdev_get_pixelorder(u32 code);

int ipu_isys_subdev_fmt_propagate(struct v4l2_subdev *sd,
				  struct v4l2_subdev_state *sd_state,
				  struct v4l2_mbus_framefmt *ffmt,
				  struct v4l2_rect *r,
				  enum isys_subdev_prop_tgt tgt,
				  unsigned int pad, unsigned int which);

int ipu_isys_subdev_set_ffmt_default(struct v4l2_subdev *sd,
				     struct v4l2_subdev_state *sd_state,
				     struct v4l2_subdev_format *fmt);
int __ipu_isys_subdev_set_ffmt(struct v4l2_subdev *sd,
			       struct v4l2_subdev_state *sd_state,
			       struct v4l2_subdev_format *fmt);
struct v4l2_rect *__ipu_isys_get_selection(struct v4l2_subdev *sd,
					   struct v4l2_subdev_state *sd_state,
					   unsigned int target,
					   unsigned int pad,
					   unsigned int which);
int ipu_isys_subdev_set_ffmt(struct v4l2_subdev *sd,
			     struct v4l2_subdev_state *sd_state,
			     struct v4l2_subdev_format *fmt);
int ipu_isys_subdev_get_ffmt(struct v4l2_subdev *sd,
			     struct v4l2_subdev_state *sd_state,
			     struct v4l2_subdev_format *fmt);
int ipu_isys_subdev_get_sel(struct v4l2_subdev *sd,
			    struct v4l2_subdev_state *sd_state,
			    struct v4l2_subdev_selection *sel);
int ipu_isys_subdev_set_sel(struct v4l2_subdev *sd,
			    struct v4l2_subdev_state *sd_state,
			    struct v4l2_subdev_selection *sel);
int ipu_isys_subdev_enum_mbus_code(struct v4l2_subdev *sd,
				   struct v4l2_subdev_state *sd_state,
				   struct v4l2_subdev_mbus_code_enum
				   *code);
int ipu_isys_subdev_link_validate(struct v4l2_subdev *sd,
				  struct media_link *link,
				  struct v4l2_subdev_format *source_fmt,
				  struct v4l2_subdev_format *sink_fmt);

int ipu_isys_subdev_open(struct v4l2_subdev *sd, struct v4l2_subdev_fh *fh);
int ipu_isys_subdev_close(struct v4l2_subdev *sd, struct v4l2_subdev_fh *fh);
int ipu_isys_subdev_init(struct ipu_isys_subdev *asd,
			 struct v4l2_subdev_ops *ops,
			 unsigned int nr_ctrls,
			 unsigned int num_pads,
			 unsigned int num_source,
			 unsigned int num_sink,
			 unsigned int sd_flags);
void ipu_isys_subdev_cleanup(struct ipu_isys_subdev *asd);
#endif /* IPU_ISYS_SUBDEV_H */
