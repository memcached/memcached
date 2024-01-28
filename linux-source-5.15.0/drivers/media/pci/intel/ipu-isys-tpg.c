// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2013 - 2020 Intel Corporation

#include <linux/device.h>
#include <linux/module.h>

#include <media/media-entity.h>
#include <media/v4l2-device.h>
#include <media/v4l2-event.h>

#include "ipu.h"
#include "ipu-bus.h"
#include "ipu-isys.h"
#include "ipu-isys-subdev.h"
#include "ipu-isys-tpg.h"
#include "ipu-isys-video.h"
#include "ipu-platform-isys-csi2-reg.h"

static const u32 tpg_supported_codes_pad[] = {
	MEDIA_BUS_FMT_SBGGR8_1X8,
	MEDIA_BUS_FMT_SGBRG8_1X8,
	MEDIA_BUS_FMT_SGRBG8_1X8,
	MEDIA_BUS_FMT_SRGGB8_1X8,
	MEDIA_BUS_FMT_SBGGR10_1X10,
	MEDIA_BUS_FMT_SGBRG10_1X10,
	MEDIA_BUS_FMT_SGRBG10_1X10,
	MEDIA_BUS_FMT_SRGGB10_1X10,
	0,
};

static const u32 *tpg_supported_codes[] = {
	tpg_supported_codes_pad,
};

static struct v4l2_subdev_internal_ops tpg_sd_internal_ops = {
	.open = ipu_isys_subdev_open,
	.close = ipu_isys_subdev_close,
};

static const struct v4l2_subdev_video_ops tpg_sd_video_ops = {
	.s_stream = tpg_set_stream,
};

static int ipu_isys_tpg_s_ctrl(struct v4l2_ctrl *ctrl)
{
	struct ipu_isys_tpg *tpg = container_of(container_of(ctrl->handler,
							     struct
							     ipu_isys_subdev,
							     ctrl_handler),
						struct ipu_isys_tpg, asd);

	switch (ctrl->id) {
	case V4L2_CID_HBLANK:
		writel(ctrl->val, tpg->base + MIPI_GEN_REG_SYNG_HBLANK_CYC);
		break;
	case V4L2_CID_VBLANK:
		writel(ctrl->val, tpg->base + MIPI_GEN_REG_SYNG_VBLANK_CYC);
		break;
	case V4L2_CID_TEST_PATTERN:
		writel(ctrl->val, tpg->base + MIPI_GEN_REG_TPG_MODE);
		break;
	}

	return 0;
}

static const struct v4l2_ctrl_ops ipu_isys_tpg_ctrl_ops = {
	.s_ctrl = ipu_isys_tpg_s_ctrl,
};

static s64 ipu_isys_tpg_rate(struct ipu_isys_tpg *tpg, unsigned int bpp)
{
	return MIPI_GEN_PPC * IPU_ISYS_FREQ / bpp;
}

static const char *const tpg_mode_items[] = {
	"Ramp",
	"Checkerboard",	/* Does not work, disabled. */
	"Frame Based Colour",
};

static struct v4l2_ctrl_config tpg_mode = {
	.ops = &ipu_isys_tpg_ctrl_ops,
	.id = V4L2_CID_TEST_PATTERN,
	.name = "Test Pattern",
	.type = V4L2_CTRL_TYPE_MENU,
	.min = 0,
	.max = ARRAY_SIZE(tpg_mode_items) - 1,
	.def = 0,
	.menu_skip_mask = 0x2,
	.qmenu = tpg_mode_items,
};

static const struct v4l2_ctrl_config csi2_header_cfg = {
	.id = V4L2_CID_IPU_STORE_CSI2_HEADER,
	.name = "Store CSI-2 Headers",
	.type = V4L2_CTRL_TYPE_BOOLEAN,
	.min = 0,
	.max = 1,
	.step = 1,
	.def = 1,
};

static void ipu_isys_tpg_init_controls(struct v4l2_subdev *sd)
{
	struct ipu_isys_tpg *tpg = to_ipu_isys_tpg(sd);
	int hblank;
	u64 default_pixel_rate;

	hblank = 1024;

	tpg->hblank = v4l2_ctrl_new_std(&tpg->asd.ctrl_handler,
					&ipu_isys_tpg_ctrl_ops,
					V4L2_CID_HBLANK, 8, 65535, 1, hblank);

	tpg->vblank = v4l2_ctrl_new_std(&tpg->asd.ctrl_handler,
					&ipu_isys_tpg_ctrl_ops,
					V4L2_CID_VBLANK, 8, 65535, 1, 1024);

	default_pixel_rate = ipu_isys_tpg_rate(tpg, 8);
	tpg->pixel_rate = v4l2_ctrl_new_std(&tpg->asd.ctrl_handler,
					    &ipu_isys_tpg_ctrl_ops,
					    V4L2_CID_PIXEL_RATE,
					    default_pixel_rate,
					    default_pixel_rate,
					    1, default_pixel_rate);
	if (tpg->pixel_rate) {
		tpg->pixel_rate->cur.val = default_pixel_rate;
		tpg->pixel_rate->flags |= V4L2_CTRL_FLAG_READ_ONLY;
	}

	v4l2_ctrl_new_custom(&tpg->asd.ctrl_handler, &tpg_mode, NULL);
	tpg->store_csi2_header =
		v4l2_ctrl_new_custom(&tpg->asd.ctrl_handler,
				     &csi2_header_cfg, NULL);
}

static void tpg_set_ffmt(struct v4l2_subdev *sd,
			 struct v4l2_subdev_state *sd_state,
			 struct v4l2_subdev_format *fmt)
{
	fmt->format.field = V4L2_FIELD_NONE;
	*__ipu_isys_get_ffmt(sd, sd_state, fmt->pad, fmt->which) = fmt->format;
}

static int ipu_isys_tpg_set_ffmt(struct v4l2_subdev *sd,
				 struct v4l2_subdev_state *sd_state,
				 struct v4l2_subdev_format *fmt)
{
	struct ipu_isys_tpg *tpg = to_ipu_isys_tpg(sd);
	__u32 code = tpg->asd.ffmt[TPG_PAD_SOURCE].code;
	unsigned int bpp = ipu_isys_mbus_code_to_bpp(code);
	s64 tpg_rate = ipu_isys_tpg_rate(tpg, bpp);
	int rval;

	mutex_lock(&tpg->asd.mutex);
	rval = __ipu_isys_subdev_set_ffmt(sd, sd_state, fmt);
	mutex_unlock(&tpg->asd.mutex);

	if (rval || fmt->which != V4L2_SUBDEV_FORMAT_ACTIVE)
		return rval;

	v4l2_ctrl_s_ctrl_int64(tpg->pixel_rate, tpg_rate);

	return 0;
}

static const struct ipu_isys_pixelformat *
ipu_isys_tpg_try_fmt(struct ipu_isys_video *av,
		     struct v4l2_pix_format_mplane *mpix)
{
	struct media_link *link = list_first_entry(&av->vdev.entity.links,
						   struct media_link, list);
	struct v4l2_subdev *sd =
		media_entity_to_v4l2_subdev(link->source->entity);
	struct ipu_isys_tpg *tpg;

	if (!sd)
		return NULL;

	tpg = to_ipu_isys_tpg(sd);

	return ipu_isys_video_try_fmt_vid_mplane(av, mpix,
		v4l2_ctrl_g_ctrl(tpg->store_csi2_header));
}

static const struct v4l2_subdev_pad_ops tpg_sd_pad_ops = {
	.get_fmt = ipu_isys_subdev_get_ffmt,
	.set_fmt = ipu_isys_tpg_set_ffmt,
	.enum_mbus_code = ipu_isys_subdev_enum_mbus_code,
};

static int subscribe_event(struct v4l2_subdev *sd, struct v4l2_fh *fh,
			   struct v4l2_event_subscription *sub)
{
	switch (sub->type) {
#ifdef IPU_TPG_FRAME_SYNC
	case V4L2_EVENT_FRAME_SYNC:
		return v4l2_event_subscribe(fh, sub, 10, NULL);
#endif
	case V4L2_EVENT_CTRL:
		return v4l2_ctrl_subscribe_event(fh, sub);
	default:
		return -EINVAL;
	}
};

/* V4L2 subdev core operations */
static const struct v4l2_subdev_core_ops tpg_sd_core_ops = {
	.subscribe_event = subscribe_event,
	.unsubscribe_event = v4l2_event_subdev_unsubscribe,
};

static struct v4l2_subdev_ops tpg_sd_ops = {
	.core = &tpg_sd_core_ops,
	.video = &tpg_sd_video_ops,
	.pad = &tpg_sd_pad_ops,
};

static struct media_entity_operations tpg_entity_ops = {
	.link_validate = v4l2_subdev_link_validate,
};

void ipu_isys_tpg_cleanup(struct ipu_isys_tpg *tpg)
{
	v4l2_device_unregister_subdev(&tpg->asd.sd);
	ipu_isys_subdev_cleanup(&tpg->asd);
	ipu_isys_video_cleanup(&tpg->av);
}

int ipu_isys_tpg_init(struct ipu_isys_tpg *tpg,
		      struct ipu_isys *isys,
		      void __iomem *base, void __iomem *sel,
		      unsigned int index)
{
	struct v4l2_subdev_format fmt = {
		.which = V4L2_SUBDEV_FORMAT_ACTIVE,
		.pad = TPG_PAD_SOURCE,
		.format = {
			   .width = 4096,
			   .height = 3072,
			   },
	};
	int rval;

	tpg->isys = isys;
	tpg->base = base;
	tpg->sel = sel;
	tpg->index = index;

	tpg->asd.sd.entity.ops = &tpg_entity_ops;
	tpg->asd.ctrl_init = ipu_isys_tpg_init_controls;
	tpg->asd.isys = isys;

	rval = ipu_isys_subdev_init(&tpg->asd, &tpg_sd_ops, 5,
				    NR_OF_TPG_PADS,
				    NR_OF_TPG_SOURCE_PADS,
				    NR_OF_TPG_SINK_PADS,
				    V4L2_SUBDEV_FL_HAS_EVENTS);
	if (rval)
		return rval;

	tpg->asd.sd.entity.function = MEDIA_ENT_F_CAM_SENSOR;
	tpg->asd.pad[TPG_PAD_SOURCE].flags = MEDIA_PAD_FL_SOURCE;

	tpg->asd.source = IPU_FW_ISYS_STREAM_SRC_MIPIGEN_PORT0 + index;
	tpg->asd.supported_codes = tpg_supported_codes;
	tpg->asd.set_ffmt = tpg_set_ffmt;
	ipu_isys_subdev_set_ffmt(&tpg->asd.sd, NULL, &fmt);

	tpg->asd.sd.internal_ops = &tpg_sd_internal_ops;
	snprintf(tpg->asd.sd.name, sizeof(tpg->asd.sd.name),
		 IPU_ISYS_ENTITY_PREFIX " TPG %u", index);
	v4l2_set_subdevdata(&tpg->asd.sd, &tpg->asd);
	rval = v4l2_device_register_subdev(&isys->v4l2_dev, &tpg->asd.sd);
	if (rval) {
		dev_info(&isys->adev->dev, "can't register v4l2 subdev\n");
		goto fail;
	}

	snprintf(tpg->av.vdev.name, sizeof(tpg->av.vdev.name),
		 IPU_ISYS_ENTITY_PREFIX " TPG %u capture", index);
	tpg->av.isys = isys;
	tpg->av.aq.css_pin_type = IPU_FW_ISYS_PIN_TYPE_MIPI;
	tpg->av.pfmts = ipu_isys_pfmts_packed;
	tpg->av.try_fmt_vid_mplane = ipu_isys_tpg_try_fmt;
	tpg->av.prepare_fw_stream =
	    ipu_isys_prepare_fw_cfg_default;
	tpg->av.packed = true;
	tpg->av.line_header_length = IPU_ISYS_CSI2_LONG_PACKET_HEADER_SIZE;
	tpg->av.line_footer_length = IPU_ISYS_CSI2_LONG_PACKET_FOOTER_SIZE;
	tpg->av.aq.buf_prepare = ipu_isys_buf_prepare;
	tpg->av.aq.fill_frame_buff_set_pin =
	    ipu_isys_buffer_to_fw_frame_buff_pin;
	tpg->av.aq.link_fmt_validate = ipu_isys_link_fmt_validate;
	tpg->av.aq.vbq.buf_struct_size = sizeof(struct ipu_isys_video_buffer);

	rval = ipu_isys_video_init(&tpg->av, &tpg->asd.sd.entity,
				   TPG_PAD_SOURCE, MEDIA_PAD_FL_SINK, 0);
	if (rval) {
		dev_info(&isys->adev->dev, "can't init video node\n");
		goto fail;
	}

	return 0;

fail:
	ipu_isys_tpg_cleanup(tpg);

	return rval;
}
