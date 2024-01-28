// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2014 - 2020 Intel Corporation

#include <linux/device.h>
#include <linux/module.h>

#include <media/ipu-isys.h>
#include <media/media-entity.h>
#include <media/v4l2-device.h>

#include "ipu.h"
#include "ipu-bus.h"
#include "ipu-isys.h"
#include "ipu-isys-csi2-be.h"
#include "ipu-isys-subdev.h"
#include "ipu-isys-video.h"

/*
 * Raw bayer format pixel order MUST BE MAINTAINED in groups of four codes.
 * Otherwise pixel order calculation below WILL BREAK!
 */
static const u32 csi2_be_supported_codes_pad[] = {
	MEDIA_BUS_FMT_SBGGR12_1X12,
	MEDIA_BUS_FMT_SGBRG12_1X12,
	MEDIA_BUS_FMT_SGRBG12_1X12,
	MEDIA_BUS_FMT_SRGGB12_1X12,
	MEDIA_BUS_FMT_SBGGR10_1X10,
	MEDIA_BUS_FMT_SGBRG10_1X10,
	MEDIA_BUS_FMT_SGRBG10_1X10,
	MEDIA_BUS_FMT_SRGGB10_1X10,
	MEDIA_BUS_FMT_SBGGR8_1X8,
	MEDIA_BUS_FMT_SGBRG8_1X8,
	MEDIA_BUS_FMT_SGRBG8_1X8,
	MEDIA_BUS_FMT_SRGGB8_1X8,
	0,
};

static const u32 *csi2_be_supported_codes[] = {
	csi2_be_supported_codes_pad,
	csi2_be_supported_codes_pad,
};

static struct v4l2_subdev_internal_ops csi2_be_sd_internal_ops = {
	.open = ipu_isys_subdev_open,
	.close = ipu_isys_subdev_close,
};

static const struct v4l2_subdev_core_ops csi2_be_sd_core_ops = {
};

static const struct v4l2_ctrl_config compression_ctrl_cfg = {
	.ops = NULL,
	.id = V4L2_CID_IPU_ISYS_COMPRESSION,
	.name = "ISYS CSI-BE compression",
	.type = V4L2_CTRL_TYPE_BOOLEAN,
	.min = 0,
	.max = 1,
	.step = 1,
	.def = 0,
};

static int set_stream(struct v4l2_subdev *sd, int enable)
{
	return 0;
}

static const struct v4l2_subdev_video_ops csi2_be_sd_video_ops = {
	.s_stream = set_stream,
};

static int __subdev_link_validate(struct v4l2_subdev *sd,
				  struct media_link *link,
				  struct v4l2_subdev_format *source_fmt,
				  struct v4l2_subdev_format *sink_fmt)
{
	struct ipu_isys_pipeline *ip = container_of(sd->entity.pipe,
						    struct ipu_isys_pipeline,
						    pipe);

	ip->csi2_be = to_ipu_isys_csi2_be(sd);
	return ipu_isys_subdev_link_validate(sd, link, source_fmt, sink_fmt);
}

static int get_supported_code_index(u32 code)
{
	int i;

	for (i = 0; csi2_be_supported_codes_pad[i]; i++) {
		if (csi2_be_supported_codes_pad[i] == code)
			return i;
	}
	return -EINVAL;
}

static int ipu_isys_csi2_be_set_sel(struct v4l2_subdev *sd,
				    struct v4l2_subdev_state *sd_state,
				    struct v4l2_subdev_selection *sel)
{
	struct ipu_isys_subdev *asd = to_ipu_isys_subdev(sd);
	struct media_pad *pad = &asd->sd.entity.pads[sel->pad];

	if (sel->target == V4L2_SEL_TGT_CROP &&
	    pad->flags & MEDIA_PAD_FL_SOURCE &&
	    asd->valid_tgts[CSI2_BE_PAD_SOURCE].crop) {
		struct v4l2_mbus_framefmt *ffmt =
			__ipu_isys_get_ffmt(sd, sd_state, sel->pad, sel->which);
		struct v4l2_rect *r = __ipu_isys_get_selection
		    (sd, sd_state, sel->target, CSI2_BE_PAD_SINK, sel->which);

		if (get_supported_code_index(ffmt->code) < 0) {
			/* Non-bayer formats can't be single line cropped */
			sel->r.left &= ~1;
			sel->r.top &= ~1;

			/* Non-bayer formats can't pe padded at all */
			sel->r.width = clamp(sel->r.width,
					     IPU_ISYS_MIN_WIDTH, r->width);
		} else {
			sel->r.width = clamp(sel->r.width,
					     IPU_ISYS_MIN_WIDTH,
					     IPU_ISYS_MAX_WIDTH);
		}

		/*
		 * Vertical padding is not supported, height is
		 * restricted by sink pad resolution.
		 */
		sel->r.height = clamp(sel->r.height, IPU_ISYS_MIN_HEIGHT,
				      r->height);
		*__ipu_isys_get_selection(sd, sd_state, sel->target,
					sel->pad, sel->which) = sel->r;
		ipu_isys_subdev_fmt_propagate
		    (sd, sd_state, NULL, &sel->r,
		     IPU_ISYS_SUBDEV_PROP_TGT_SOURCE_CROP,
		     sel->pad, sel->which);
		return 0;
	}
	return ipu_isys_subdev_set_sel(sd, sd_state, sel);
}

static const struct v4l2_subdev_pad_ops csi2_be_sd_pad_ops = {
	.link_validate = __subdev_link_validate,
	.get_fmt = ipu_isys_subdev_get_ffmt,
	.set_fmt = ipu_isys_subdev_set_ffmt,
	.get_selection = ipu_isys_subdev_get_sel,
	.set_selection = ipu_isys_csi2_be_set_sel,
	.enum_mbus_code = ipu_isys_subdev_enum_mbus_code,
};

static struct v4l2_subdev_ops csi2_be_sd_ops = {
	.core = &csi2_be_sd_core_ops,
	.video = &csi2_be_sd_video_ops,
	.pad = &csi2_be_sd_pad_ops,
};

static struct media_entity_operations csi2_be_entity_ops = {
	.link_validate = v4l2_subdev_link_validate,
};

static void csi2_be_set_ffmt(struct v4l2_subdev *sd,
			     struct v4l2_subdev_state *sd_state,
			     struct v4l2_subdev_format *fmt)
{
	struct ipu_isys_csi2 *csi2 = to_ipu_isys_csi2(sd);
	struct v4l2_mbus_framefmt *ffmt =
		__ipu_isys_get_ffmt(sd, sd_state, fmt->pad, fmt->which);

	switch (fmt->pad) {
	case CSI2_BE_PAD_SINK:
		if (fmt->format.field != V4L2_FIELD_ALTERNATE)
			fmt->format.field = V4L2_FIELD_NONE;
		*ffmt = fmt->format;

		ipu_isys_subdev_fmt_propagate
		    (sd, sd_state, &fmt->format, NULL,
		     IPU_ISYS_SUBDEV_PROP_TGT_SINK_FMT, fmt->pad, fmt->which);
		return;
	case CSI2_BE_PAD_SOURCE: {
		struct v4l2_mbus_framefmt *sink_ffmt =
			__ipu_isys_get_ffmt(sd, sd_state, CSI2_BE_PAD_SINK,
					    fmt->which);
		struct v4l2_rect *r =
			__ipu_isys_get_selection(sd, sd_state, V4L2_SEL_TGT_CROP,
						 CSI2_BE_PAD_SOURCE,
						 fmt->which);
		struct ipu_isys_subdev *asd = to_ipu_isys_subdev(sd);
		u32 code = sink_ffmt->code;
		int idx = get_supported_code_index(code);

		if (asd->valid_tgts[CSI2_BE_PAD_SOURCE].crop && idx >= 0) {
			int crop_info = 0;

			if (r->top & 1)
				crop_info |= CSI2_BE_CROP_VER;
			if (r->left & 1)
				crop_info |= CSI2_BE_CROP_HOR;
			code = csi2_be_supported_codes_pad
				[((idx & CSI2_BE_CROP_MASK) ^ crop_info)
				+ (idx & ~CSI2_BE_CROP_MASK)];
		}
		ffmt->width = r->width;
		ffmt->height = r->height;
		ffmt->code = code;
		ffmt->field = sink_ffmt->field;
		return;
	}
	default:
		dev_err(&csi2->isys->adev->dev, "Unknown pad type\n");
		WARN_ON(1);
	}
}

void ipu_isys_csi2_be_cleanup(struct ipu_isys_csi2_be *csi2_be)
{
	v4l2_ctrl_handler_free(&csi2_be->av.ctrl_handler);
	v4l2_device_unregister_subdev(&csi2_be->asd.sd);
	ipu_isys_subdev_cleanup(&csi2_be->asd);
	ipu_isys_video_cleanup(&csi2_be->av);
}

int ipu_isys_csi2_be_init(struct ipu_isys_csi2_be *csi2_be,
			  struct ipu_isys *isys)
{
	struct v4l2_subdev_format fmt = {
		.which = V4L2_SUBDEV_FORMAT_ACTIVE,
		.pad = CSI2_BE_PAD_SINK,
		.format = {
			   .width = 4096,
			   .height = 3072,
			  },
	};
	struct v4l2_subdev_selection sel = {
		.which = V4L2_SUBDEV_FORMAT_ACTIVE,
		.pad = CSI2_BE_PAD_SOURCE,
		.target = V4L2_SEL_TGT_CROP,
		.r = {
		      .width = fmt.format.width,
		      .height = fmt.format.height,
		     },
	};
	int rval;

	csi2_be->asd.sd.entity.ops = &csi2_be_entity_ops;
	csi2_be->asd.isys = isys;

	rval = ipu_isys_subdev_init(&csi2_be->asd, &csi2_be_sd_ops, 0,
				    NR_OF_CSI2_BE_PADS,
				    NR_OF_CSI2_BE_SOURCE_PADS,
				    NR_OF_CSI2_BE_SINK_PADS, 0);
	if (rval)
		goto fail;

	csi2_be->asd.pad[CSI2_BE_PAD_SINK].flags = MEDIA_PAD_FL_SINK
	    | MEDIA_PAD_FL_MUST_CONNECT;
	csi2_be->asd.pad[CSI2_BE_PAD_SOURCE].flags = MEDIA_PAD_FL_SOURCE;
	csi2_be->asd.valid_tgts[CSI2_BE_PAD_SOURCE].crop = true;
	csi2_be->asd.set_ffmt = csi2_be_set_ffmt;

	BUILD_BUG_ON(ARRAY_SIZE(csi2_be_supported_codes) != NR_OF_CSI2_BE_PADS);
	csi2_be->asd.supported_codes = csi2_be_supported_codes;
	csi2_be->asd.be_mode = IPU_BE_RAW;
	csi2_be->asd.isl_mode = IPU_ISL_CSI2_BE;

	ipu_isys_subdev_set_ffmt(&csi2_be->asd.sd, NULL, &fmt);
	ipu_isys_csi2_be_set_sel(&csi2_be->asd.sd, NULL, &sel);

	csi2_be->asd.sd.internal_ops = &csi2_be_sd_internal_ops;
	snprintf(csi2_be->asd.sd.name, sizeof(csi2_be->asd.sd.name),
		 IPU_ISYS_ENTITY_PREFIX " CSI2 BE");
	snprintf(csi2_be->av.vdev.name, sizeof(csi2_be->av.vdev.name),
		 IPU_ISYS_ENTITY_PREFIX " CSI2 BE capture");
	csi2_be->av.aq.css_pin_type = IPU_FW_ISYS_PIN_TYPE_RAW_NS;
	v4l2_set_subdevdata(&csi2_be->asd.sd, &csi2_be->asd);
	rval = v4l2_device_register_subdev(&isys->v4l2_dev, &csi2_be->asd.sd);
	if (rval) {
		dev_info(&isys->adev->dev, "can't register v4l2 subdev\n");
		goto fail;
	}

	csi2_be->av.isys = isys;
	csi2_be->av.pfmts = ipu_isys_pfmts;
	csi2_be->av.try_fmt_vid_mplane =
	    ipu_isys_video_try_fmt_vid_mplane_default;
	csi2_be->av.prepare_fw_stream =
	    ipu_isys_prepare_fw_cfg_default;
	csi2_be->av.aq.buf_prepare = ipu_isys_buf_prepare;
	csi2_be->av.aq.fill_frame_buff_set_pin =
	    ipu_isys_buffer_to_fw_frame_buff_pin;
	csi2_be->av.aq.link_fmt_validate = ipu_isys_link_fmt_validate;
	csi2_be->av.aq.vbq.buf_struct_size =
	    sizeof(struct ipu_isys_video_buffer);

	/* create v4l2 ctrl for csi-be video node */
	rval = v4l2_ctrl_handler_init(&csi2_be->av.ctrl_handler, 0);
	if (rval) {
		dev_err(&isys->adev->dev,
			"failed to init v4l2 ctrl handler for csi2_be\n");
		goto fail;
	}

	csi2_be->av.compression_ctrl =
		v4l2_ctrl_new_custom(&csi2_be->av.ctrl_handler,
				     &compression_ctrl_cfg, NULL);
	if (!csi2_be->av.compression_ctrl) {
		dev_err(&isys->adev->dev,
			"failed to create CSI-BE cmprs ctrl\n");
		goto fail;
	}
	csi2_be->av.compression = 0;
	csi2_be->av.vdev.ctrl_handler = &csi2_be->av.ctrl_handler;

	rval = ipu_isys_video_init(&csi2_be->av, &csi2_be->asd.sd.entity,
				   CSI2_BE_PAD_SOURCE, MEDIA_PAD_FL_SINK, 0);
	if (rval) {
		dev_info(&isys->adev->dev, "can't init video node\n");
		goto fail;
	}

	return 0;

fail:
	ipu_isys_csi2_be_cleanup(csi2_be);

	return rval;
}
