// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2013 - 2020 Intel Corporation

#include <linux/types.h>
#include <linux/videodev2.h>

#include <media/media-entity.h>

#include <uapi/linux/media-bus-format.h>

#include "ipu-isys.h"
#include "ipu-isys-video.h"
#include "ipu-isys-subdev.h"

unsigned int ipu_isys_mbus_code_to_bpp(u32 code)
{
	switch (code) {
	case MEDIA_BUS_FMT_RGB888_1X24:
		return 24;
	case MEDIA_BUS_FMT_YUYV10_1X20:
		return 20;
	case MEDIA_BUS_FMT_Y10_1X10:
	case MEDIA_BUS_FMT_RGB565_1X16:
	case MEDIA_BUS_FMT_UYVY8_1X16:
	case MEDIA_BUS_FMT_YUYV8_1X16:
		return 16;
	case MEDIA_BUS_FMT_SBGGR12_1X12:
	case MEDIA_BUS_FMT_SGBRG12_1X12:
	case MEDIA_BUS_FMT_SGRBG12_1X12:
	case MEDIA_BUS_FMT_SRGGB12_1X12:
		return 12;
	case MEDIA_BUS_FMT_SBGGR10_1X10:
	case MEDIA_BUS_FMT_SGBRG10_1X10:
	case MEDIA_BUS_FMT_SGRBG10_1X10:
	case MEDIA_BUS_FMT_SRGGB10_1X10:
		return 10;
	case MEDIA_BUS_FMT_SBGGR8_1X8:
	case MEDIA_BUS_FMT_SGBRG8_1X8:
	case MEDIA_BUS_FMT_SGRBG8_1X8:
	case MEDIA_BUS_FMT_SRGGB8_1X8:
	case MEDIA_BUS_FMT_SBGGR10_DPCM8_1X8:
	case MEDIA_BUS_FMT_SGBRG10_DPCM8_1X8:
	case MEDIA_BUS_FMT_SGRBG10_DPCM8_1X8:
	case MEDIA_BUS_FMT_SRGGB10_DPCM8_1X8:
		return 8;
	default:
		WARN_ON(1);
		return -EINVAL;
	}
}

unsigned int ipu_isys_mbus_code_to_mipi(u32 code)
{
	switch (code) {
	case MEDIA_BUS_FMT_RGB565_1X16:
		return IPU_ISYS_MIPI_CSI2_TYPE_RGB565;
	case MEDIA_BUS_FMT_RGB888_1X24:
		return IPU_ISYS_MIPI_CSI2_TYPE_RGB888;
	case MEDIA_BUS_FMT_YUYV10_1X20:
		return IPU_ISYS_MIPI_CSI2_TYPE_YUV422_10;
	case MEDIA_BUS_FMT_UYVY8_1X16:
	case MEDIA_BUS_FMT_YUYV8_1X16:
		return IPU_ISYS_MIPI_CSI2_TYPE_YUV422_8;
	case MEDIA_BUS_FMT_SBGGR12_1X12:
	case MEDIA_BUS_FMT_SGBRG12_1X12:
	case MEDIA_BUS_FMT_SGRBG12_1X12:
	case MEDIA_BUS_FMT_SRGGB12_1X12:
		return IPU_ISYS_MIPI_CSI2_TYPE_RAW12;
	case MEDIA_BUS_FMT_Y10_1X10:
	case MEDIA_BUS_FMT_SBGGR10_1X10:
	case MEDIA_BUS_FMT_SGBRG10_1X10:
	case MEDIA_BUS_FMT_SGRBG10_1X10:
	case MEDIA_BUS_FMT_SRGGB10_1X10:
		return IPU_ISYS_MIPI_CSI2_TYPE_RAW10;
	case MEDIA_BUS_FMT_SBGGR8_1X8:
	case MEDIA_BUS_FMT_SGBRG8_1X8:
	case MEDIA_BUS_FMT_SGRBG8_1X8:
	case MEDIA_BUS_FMT_SRGGB8_1X8:
		return IPU_ISYS_MIPI_CSI2_TYPE_RAW8;
	case MEDIA_BUS_FMT_SBGGR10_DPCM8_1X8:
	case MEDIA_BUS_FMT_SGBRG10_DPCM8_1X8:
	case MEDIA_BUS_FMT_SGRBG10_DPCM8_1X8:
	case MEDIA_BUS_FMT_SRGGB10_DPCM8_1X8:
		return IPU_ISYS_MIPI_CSI2_TYPE_USER_DEF(1);
	default:
		WARN_ON(1);
		return -EINVAL;
	}
}

enum ipu_isys_subdev_pixelorder ipu_isys_subdev_get_pixelorder(u32 code)
{
	switch (code) {
	case MEDIA_BUS_FMT_SBGGR12_1X12:
	case MEDIA_BUS_FMT_SBGGR10_1X10:
	case MEDIA_BUS_FMT_SBGGR8_1X8:
	case MEDIA_BUS_FMT_SBGGR10_DPCM8_1X8:
		return IPU_ISYS_SUBDEV_PIXELORDER_BGGR;
	case MEDIA_BUS_FMT_SGBRG12_1X12:
	case MEDIA_BUS_FMT_SGBRG10_1X10:
	case MEDIA_BUS_FMT_SGBRG8_1X8:
	case MEDIA_BUS_FMT_SGBRG10_DPCM8_1X8:
		return IPU_ISYS_SUBDEV_PIXELORDER_GBRG;
	case MEDIA_BUS_FMT_SGRBG12_1X12:
	case MEDIA_BUS_FMT_SGRBG10_1X10:
	case MEDIA_BUS_FMT_SGRBG8_1X8:
	case MEDIA_BUS_FMT_SGRBG10_DPCM8_1X8:
		return IPU_ISYS_SUBDEV_PIXELORDER_GRBG;
	case MEDIA_BUS_FMT_SRGGB12_1X12:
	case MEDIA_BUS_FMT_SRGGB10_1X10:
	case MEDIA_BUS_FMT_SRGGB8_1X8:
	case MEDIA_BUS_FMT_SRGGB10_DPCM8_1X8:
		return IPU_ISYS_SUBDEV_PIXELORDER_RGGB;
	default:
		WARN_ON(1);
		return -EINVAL;
	}
}

u32 ipu_isys_subdev_code_to_uncompressed(u32 sink_code)
{
	switch (sink_code) {
	case MEDIA_BUS_FMT_SBGGR10_DPCM8_1X8:
		return MEDIA_BUS_FMT_SBGGR10_1X10;
	case MEDIA_BUS_FMT_SGBRG10_DPCM8_1X8:
		return MEDIA_BUS_FMT_SGBRG10_1X10;
	case MEDIA_BUS_FMT_SGRBG10_DPCM8_1X8:
		return MEDIA_BUS_FMT_SGRBG10_1X10;
	case MEDIA_BUS_FMT_SRGGB10_DPCM8_1X8:
		return MEDIA_BUS_FMT_SRGGB10_1X10;
	default:
		return sink_code;
	}
}

struct v4l2_mbus_framefmt *__ipu_isys_get_ffmt(struct v4l2_subdev *sd,
					       struct v4l2_subdev_state *sd_state,
					       unsigned int pad,
					       unsigned int which)
{
	struct ipu_isys_subdev *asd = to_ipu_isys_subdev(sd);

	if (which == V4L2_SUBDEV_FORMAT_ACTIVE)
		return &asd->ffmt[pad];
	else
		return v4l2_subdev_get_try_format(sd, sd_state, pad);
}

struct v4l2_rect *__ipu_isys_get_selection(struct v4l2_subdev *sd,
					   struct v4l2_subdev_state *sd_state,
					   unsigned int target,
					   unsigned int pad, unsigned int which)
{
	struct ipu_isys_subdev *asd = to_ipu_isys_subdev(sd);

	if (which == V4L2_SUBDEV_FORMAT_ACTIVE) {
		switch (target) {
		case V4L2_SEL_TGT_CROP:
			return &asd->crop[pad];
		case V4L2_SEL_TGT_COMPOSE:
			return &asd->compose[pad];
		}
	} else {
		switch (target) {
		case V4L2_SEL_TGT_CROP:
			return v4l2_subdev_get_try_crop(sd, sd_state, pad);
		case V4L2_SEL_TGT_COMPOSE:
			return v4l2_subdev_get_try_compose(sd, sd_state, pad);
		}
	}
	WARN_ON(1);
	return NULL;
}

static int target_valid(struct v4l2_subdev *sd, unsigned int target,
			unsigned int pad)
{
	struct ipu_isys_subdev *asd = to_ipu_isys_subdev(sd);

	switch (target) {
	case V4L2_SEL_TGT_CROP:
		return asd->valid_tgts[pad].crop;
	case V4L2_SEL_TGT_COMPOSE:
		return asd->valid_tgts[pad].compose;
	default:
		return 0;
	}
}

int ipu_isys_subdev_fmt_propagate(struct v4l2_subdev *sd,
				  struct v4l2_subdev_state *sd_state,
				  struct v4l2_mbus_framefmt *ffmt,
				  struct v4l2_rect *r,
				  enum isys_subdev_prop_tgt tgt,
				  unsigned int pad, unsigned int which)
{
	struct ipu_isys_subdev *asd = to_ipu_isys_subdev(sd);
	struct v4l2_mbus_framefmt **ffmts = NULL;
	struct v4l2_rect **crops = NULL;
	struct v4l2_rect **compose = NULL;
	unsigned int i;
	int rval = 0;

	if (tgt == IPU_ISYS_SUBDEV_PROP_TGT_NR_OF)
		return 0;

	if (WARN_ON(pad >= sd->entity.num_pads))
		return -EINVAL;

	ffmts = kcalloc(sd->entity.num_pads,
			sizeof(*ffmts), GFP_KERNEL);
	if (!ffmts) {
		rval = -ENOMEM;
		goto out_subdev_fmt_propagate;
	}
	crops = kcalloc(sd->entity.num_pads,
			sizeof(*crops), GFP_KERNEL);
	if (!crops) {
		rval = -ENOMEM;
		goto out_subdev_fmt_propagate;
	}
	compose = kcalloc(sd->entity.num_pads,
			  sizeof(*compose), GFP_KERNEL);
	if (!compose) {
		rval = -ENOMEM;
		goto out_subdev_fmt_propagate;
	}

	for (i = 0; i < sd->entity.num_pads; i++) {
		ffmts[i] = __ipu_isys_get_ffmt(sd, sd_state, i, which);
		crops[i] = __ipu_isys_get_selection(sd, sd_state,
						    V4L2_SEL_TGT_CROP, i, which);
		compose[i] = __ipu_isys_get_selection(sd, sd_state,
						      V4L2_SEL_TGT_COMPOSE, i, which);
	}

	switch (tgt) {
	case IPU_ISYS_SUBDEV_PROP_TGT_SINK_FMT:
		crops[pad]->left = 0;
		crops[pad]->top = 0;
		crops[pad]->width = ffmt->width;
		crops[pad]->height = ffmt->height;
		rval = ipu_isys_subdev_fmt_propagate(sd, sd_state, ffmt,
						     crops[pad], tgt + 1, pad, which);
		goto out_subdev_fmt_propagate;
	case IPU_ISYS_SUBDEV_PROP_TGT_SINK_CROP:
		if (WARN_ON(sd->entity.pads[pad].flags & MEDIA_PAD_FL_SOURCE))
			goto out_subdev_fmt_propagate;

		compose[pad]->left = 0;
		compose[pad]->top = 0;
		compose[pad]->width = r->width;
		compose[pad]->height = r->height;
		rval = ipu_isys_subdev_fmt_propagate(sd, sd_state, ffmt,
						     compose[pad], tgt + 1, pad, which);
		goto out_subdev_fmt_propagate;
	case IPU_ISYS_SUBDEV_PROP_TGT_SINK_COMPOSE:
		if (WARN_ON(sd->entity.pads[pad].flags & MEDIA_PAD_FL_SOURCE)) {
			rval = -EINVAL;
			goto out_subdev_fmt_propagate;
		}

		for (i = 1; i < sd->entity.num_pads; i++) {
			if (!(sd->entity.pads[i].flags &
					MEDIA_PAD_FL_SOURCE))
				continue;

			compose[i]->left = 0;
			compose[i]->top = 0;
			compose[i]->width = r->width;
			compose[i]->height = r->height;
			rval = ipu_isys_subdev_fmt_propagate(sd, sd_state,
							ffmt, compose[i], tgt + 1, i, which);
			if (rval)
				goto out_subdev_fmt_propagate;
		}
		goto out_subdev_fmt_propagate;
	case IPU_ISYS_SUBDEV_PROP_TGT_SOURCE_COMPOSE:
		if (WARN_ON(sd->entity.pads[pad].flags & MEDIA_PAD_FL_SINK)) {
			rval = -EINVAL;
			goto out_subdev_fmt_propagate;
		}

		crops[pad]->left = 0;
		crops[pad]->top = 0;
		crops[pad]->width = r->width;
		crops[pad]->height = r->height;
		rval = ipu_isys_subdev_fmt_propagate(sd, sd_state, ffmt,
						     crops[pad], tgt + 1, pad, which);
		goto out_subdev_fmt_propagate;
	case IPU_ISYS_SUBDEV_PROP_TGT_SOURCE_CROP:{
			struct v4l2_subdev_format fmt = {
				.which = which,
				.pad = pad,
				.format = {
					.width = r->width,
					.height = r->height,
					/*
					 * Either use the code from sink pad
					 * or the current one.
					 */
					.code = ffmt ? ffmt->code :
						       ffmts[pad]->code,
					.field = ffmt ? ffmt->field :
							ffmts[pad]->field,
				},
			};

			asd->set_ffmt(sd, sd_state, &fmt);
			goto out_subdev_fmt_propagate;
		}
	}

out_subdev_fmt_propagate:
	kfree(ffmts);
	kfree(crops);
	kfree(compose);
	return rval;
}

int ipu_isys_subdev_set_ffmt_default(struct v4l2_subdev *sd,
				     struct v4l2_subdev_state *sd_state,
				     struct v4l2_subdev_format *fmt)
{
	struct v4l2_mbus_framefmt *ffmt =
		__ipu_isys_get_ffmt(sd, sd_state, fmt->pad, fmt->which);

	/* No propagation for non-zero pads. */
	if (fmt->pad) {
		struct v4l2_mbus_framefmt *sink_ffmt =
			__ipu_isys_get_ffmt(sd, sd_state, 0, fmt->which);

		ffmt->width = sink_ffmt->width;
		ffmt->height = sink_ffmt->height;
		ffmt->code = sink_ffmt->code;
		ffmt->field = sink_ffmt->field;

		return 0;
	}

	ffmt->width = fmt->format.width;
	ffmt->height = fmt->format.height;
	ffmt->code = fmt->format.code;
	ffmt->field = fmt->format.field;

	return ipu_isys_subdev_fmt_propagate(sd, sd_state, &fmt->format, NULL,
					     IPU_ISYS_SUBDEV_PROP_TGT_SINK_FMT,
					     fmt->pad, fmt->which);
}

int __ipu_isys_subdev_set_ffmt(struct v4l2_subdev *sd,
			       struct v4l2_subdev_state *sd_state,
			       struct v4l2_subdev_format *fmt)
{
	struct ipu_isys_subdev *asd = to_ipu_isys_subdev(sd);
	struct v4l2_mbus_framefmt *ffmt =
		__ipu_isys_get_ffmt(sd, sd_state, fmt->pad, fmt->which);
	u32 code = asd->supported_codes[fmt->pad][0];
	unsigned int i;

	WARN_ON(!mutex_is_locked(&asd->mutex));

	fmt->format.width = clamp(fmt->format.width, IPU_ISYS_MIN_WIDTH,
				  IPU_ISYS_MAX_WIDTH);
	fmt->format.height = clamp(fmt->format.height,
				   IPU_ISYS_MIN_HEIGHT, IPU_ISYS_MAX_HEIGHT);

	for (i = 0; asd->supported_codes[fmt->pad][i]; i++) {
		if (asd->supported_codes[fmt->pad][i] == fmt->format.code) {
			code = asd->supported_codes[fmt->pad][i];
			break;
		}
	}

	fmt->format.code = code;

	asd->set_ffmt(sd, sd_state, fmt);

	fmt->format = *ffmt;

	return 0;
}

int ipu_isys_subdev_set_ffmt(struct v4l2_subdev *sd,
			     struct v4l2_subdev_state *sd_state,
			     struct v4l2_subdev_format *fmt)
{
	struct ipu_isys_subdev *asd = to_ipu_isys_subdev(sd);
	int rval;

	mutex_lock(&asd->mutex);
	rval = __ipu_isys_subdev_set_ffmt(sd, sd_state, fmt);
	mutex_unlock(&asd->mutex);

	return rval;
}

int ipu_isys_subdev_get_ffmt(struct v4l2_subdev *sd,
			     struct v4l2_subdev_state *sd_state,
			     struct v4l2_subdev_format *fmt)
{
	struct ipu_isys_subdev *asd = to_ipu_isys_subdev(sd);

	mutex_lock(&asd->mutex);
	fmt->format = *__ipu_isys_get_ffmt(sd, sd_state, fmt->pad,
					   fmt->which);
	mutex_unlock(&asd->mutex);

	return 0;
}

int ipu_isys_subdev_set_sel(struct v4l2_subdev *sd,
			    struct v4l2_subdev_state *sd_state,
			    struct v4l2_subdev_selection *sel)
{
	struct ipu_isys_subdev *asd = to_ipu_isys_subdev(sd);
	struct media_pad *pad = &asd->sd.entity.pads[sel->pad];
	struct v4l2_rect *r, __r = { 0 };
	unsigned int tgt;

	if (!target_valid(sd, sel->target, sel->pad))
		return -EINVAL;

	switch (sel->target) {
	case V4L2_SEL_TGT_CROP:
		if (pad->flags & MEDIA_PAD_FL_SINK) {
			struct v4l2_mbus_framefmt *ffmt =
				__ipu_isys_get_ffmt(sd, sd_state, sel->pad,
						    sel->which);

			__r.width = ffmt->width;
			__r.height = ffmt->height;
			r = &__r;
			tgt = IPU_ISYS_SUBDEV_PROP_TGT_SINK_CROP;
		} else {
			/* 0 is the sink pad. */
			r = __ipu_isys_get_selection(sd, sd_state, sel->target, 0,
						     sel->which);
			tgt = IPU_ISYS_SUBDEV_PROP_TGT_SOURCE_CROP;
		}

		break;
	case V4L2_SEL_TGT_COMPOSE:
		if (pad->flags & MEDIA_PAD_FL_SINK) {
			r = __ipu_isys_get_selection(sd, sd_state, V4L2_SEL_TGT_CROP,
						     sel->pad, sel->which);
			tgt = IPU_ISYS_SUBDEV_PROP_TGT_SINK_COMPOSE;
		} else {
			r = __ipu_isys_get_selection(sd, sd_state,
						     V4L2_SEL_TGT_COMPOSE, 0,
						     sel->which);
			tgt = IPU_ISYS_SUBDEV_PROP_TGT_SOURCE_COMPOSE;
		}
		break;
	default:
		return -EINVAL;
	}

	sel->r.width = clamp(sel->r.width, IPU_ISYS_MIN_WIDTH, r->width);
	sel->r.height = clamp(sel->r.height, IPU_ISYS_MIN_HEIGHT, r->height);
	*__ipu_isys_get_selection(sd, sd_state, sel->target, sel->pad,
				  sel->which) = sel->r;
	return ipu_isys_subdev_fmt_propagate(sd, sd_state, NULL, &sel->r, tgt,
					     sel->pad, sel->which);
}

int ipu_isys_subdev_get_sel(struct v4l2_subdev *sd,
			    struct v4l2_subdev_state *sd_state,
			    struct v4l2_subdev_selection *sel)
{
	if (!target_valid(sd, sel->target, sel->pad))
		return -EINVAL;

	sel->r = *__ipu_isys_get_selection(sd, sd_state, sel->target,
					   sel->pad, sel->which);

	return 0;
}

int ipu_isys_subdev_enum_mbus_code(struct v4l2_subdev *sd,
				   struct v4l2_subdev_state *sd_state,
				   struct v4l2_subdev_mbus_code_enum *code)
{
	struct ipu_isys_subdev *asd = to_ipu_isys_subdev(sd);
	const u32 *supported_codes = asd->supported_codes[code->pad];
	u32 index;

	for (index = 0; supported_codes[index]; index++) {
		if (index == code->index) {
			code->code = supported_codes[index];
			return 0;
		}
	}

	return -EINVAL;
}

/*
 * Besides validating the link, figure out the external pad and the
 * ISYS FW ABI source.
 */
int ipu_isys_subdev_link_validate(struct v4l2_subdev *sd,
				  struct media_link *link,
				  struct v4l2_subdev_format *source_fmt,
				  struct v4l2_subdev_format *sink_fmt)
{
	struct v4l2_subdev *source_sd =
	    media_entity_to_v4l2_subdev(link->source->entity);
	struct ipu_isys_pipeline *ip = container_of(sd->entity.pipe,
						    struct ipu_isys_pipeline,
						    pipe);
	struct ipu_isys_subdev *asd = to_ipu_isys_subdev(sd);

	if (!source_sd)
		return -ENODEV;
	if (strncmp(source_sd->name, IPU_ISYS_ENTITY_PREFIX,
		    strlen(IPU_ISYS_ENTITY_PREFIX)) != 0) {
		/*
		 * source_sd isn't ours --- sd must be the external
		 * sub-device.
		 */
		ip->external = link->source;
		ip->source = to_ipu_isys_subdev(sd)->source;
		dev_dbg(&asd->isys->adev->dev, "%s: using source %d\n",
			sd->entity.name, ip->source);
	} else if (source_sd->entity.num_pads == 1) {
		/* All internal sources have a single pad. */
		ip->external = link->source;
		ip->source = to_ipu_isys_subdev(source_sd)->source;

		dev_dbg(&asd->isys->adev->dev, "%s: using source %d\n",
			sd->entity.name, ip->source);
	}

	if (asd->isl_mode != IPU_ISL_OFF)
		ip->isl_mode = asd->isl_mode;

	return v4l2_subdev_link_validate_default(sd, link, source_fmt,
						 sink_fmt);
}

int ipu_isys_subdev_open(struct v4l2_subdev *sd, struct v4l2_subdev_fh *fh)
{
	struct ipu_isys_subdev *asd = to_ipu_isys_subdev(sd);
	unsigned int i;

	mutex_lock(&asd->mutex);

	for (i = 0; i < asd->sd.entity.num_pads; i++) {
		struct v4l2_mbus_framefmt *try_fmt =
			v4l2_subdev_get_try_format(sd, fh->state, i);
		struct v4l2_rect *try_crop =
			v4l2_subdev_get_try_crop(sd, fh->state, i);
		struct v4l2_rect *try_compose =
			v4l2_subdev_get_try_compose(sd, fh->state, i);

		*try_fmt = asd->ffmt[i];
		*try_crop = asd->crop[i];
		*try_compose = asd->compose[i];
	}

	mutex_unlock(&asd->mutex);

	return 0;
}

int ipu_isys_subdev_close(struct v4l2_subdev *sd, struct v4l2_subdev_fh *fh)
{
	return 0;
}

int ipu_isys_subdev_init(struct ipu_isys_subdev *asd,
			 struct v4l2_subdev_ops *ops,
			 unsigned int nr_ctrls,
			 unsigned int num_pads,
			 unsigned int num_source,
			 unsigned int num_sink,
			 unsigned int sd_flags)
{
	int rval = -EINVAL;

	mutex_init(&asd->mutex);

	v4l2_subdev_init(&asd->sd, ops);

	asd->sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE | sd_flags;
	asd->sd.owner = THIS_MODULE;
	asd->sd.entity.function = MEDIA_ENT_F_VID_IF_BRIDGE;

	asd->nsources = num_source;
	asd->nsinks = num_sink;

	asd->pad = devm_kcalloc(&asd->isys->adev->dev, num_pads,
				sizeof(*asd->pad), GFP_KERNEL);

	asd->ffmt = devm_kcalloc(&asd->isys->adev->dev, num_pads,
				 sizeof(*asd->ffmt), GFP_KERNEL);

	asd->crop = devm_kcalloc(&asd->isys->adev->dev, num_pads,
				 sizeof(*asd->crop), GFP_KERNEL);

	asd->compose = devm_kcalloc(&asd->isys->adev->dev, num_pads,
				    sizeof(*asd->compose), GFP_KERNEL);

	asd->valid_tgts = devm_kcalloc(&asd->isys->adev->dev, num_pads,
				       sizeof(*asd->valid_tgts), GFP_KERNEL);
	if (!asd->pad || !asd->ffmt || !asd->crop || !asd->compose ||
	    !asd->valid_tgts)
		return -ENOMEM;

	rval = media_entity_pads_init(&asd->sd.entity, num_pads, asd->pad);
	if (rval)
		goto out_mutex_destroy;

	if (asd->ctrl_init) {
		rval = v4l2_ctrl_handler_init(&asd->ctrl_handler, nr_ctrls);
		if (rval)
			goto out_media_entity_cleanup;

		asd->ctrl_init(&asd->sd);
		if (asd->ctrl_handler.error) {
			rval = asd->ctrl_handler.error;
			goto out_v4l2_ctrl_handler_free;
		}

		asd->sd.ctrl_handler = &asd->ctrl_handler;
	}

	asd->source = -1;

	return 0;

out_v4l2_ctrl_handler_free:
	v4l2_ctrl_handler_free(&asd->ctrl_handler);

out_media_entity_cleanup:
	media_entity_cleanup(&asd->sd.entity);

out_mutex_destroy:
	mutex_destroy(&asd->mutex);

	return rval;
}

void ipu_isys_subdev_cleanup(struct ipu_isys_subdev *asd)
{
	media_entity_cleanup(&asd->sd.entity);
	v4l2_ctrl_handler_free(&asd->ctrl_handler);
	mutex_destroy(&asd->mutex);
}
