// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Intel Corporation.

#include <asm/unaligned.h>
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/version.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-device.h>
#include <media/v4l2-fwnode.h>
#include <linux/vsc.h>

#define OV02C10_LINK_FREQ_400MHZ	400000000ULL
#define OV02C10_SCLK			80000000LL
#define OV02C10_MCLK			19200000
#define OV02C10_DATA_LANES		1
#define OV02C10_RGB_DEPTH		10

#define OV02C10_REG_CHIP_ID		0x300a
#define OV02C10_CHIP_ID			0x560243

#define OV02C10_REG_MODE_SELECT		0x0100
#define OV02C10_MODE_STANDBY		0x00
#define OV02C10_MODE_STREAMING		0x01

/* vertical-timings from sensor */
#define OV02C10_REG_VTS			0x380e
#define OV02C10_VTS_DEF			0x048c
#define OV02C10_VTS_MIN			0x048c
#define OV02C10_VTS_MAX			0x7fff

/* Exposure controls from sensor */
#define OV02C10_REG_EXPOSURE		0x3501
#define OV02C10_EXPOSURE_MIN		4
#define OV02C10_EXPOSURE_MAX_MARGIN	8
#define OV02C10_EXPOSURE_STEP		1

/* Analog gain controls from sensor */
#define OV02C10_REG_ANALOG_GAIN		0x3508
#define OV02C10_ANAL_GAIN_MIN		0x10
#define OV02C10_ANAL_GAIN_MAX		0xf8
#define OV02C10_ANAL_GAIN_STEP		1
#define OV02C10_ANAL_GAIN_DEFAULT	0x80

/* Digital gain controls from sensor */
#define OV02C10_REG_DIGILAL_GAIN	0x350a
#define OV02C10_DGTL_GAIN_MIN		0x0400
#define OV02C10_DGTL_GAIN_MAX		0x3fff
#define OV02C10_DGTL_GAIN_STEP		1
#define OV02C10_DGTL_GAIN_DEFAULT	0x0400

/* Test Pattern Control */
#define OV02C10_REG_TEST_PATTERN		0x4503
#define OV02C10_TEST_PATTERN_ENABLE	BIT(7)
#define OV02C10_TEST_PATTERN_BAR_SHIFT	0

enum {
	OV02C10_LINK_FREQ_400MHZ_INDEX,
};

struct ov02c10_reg {
	u16 address;
	u8 val;
};

struct ov02c10_reg_list {
	u32 num_of_regs;
	const struct ov02c10_reg *regs;
};

struct ov02c10_link_freq_config {
	const struct ov02c10_reg_list reg_list;
};

struct ov02c10_mode {
	/* Frame width in pixels */
	u32 width;

	/* Frame height in pixels */
	u32 height;

	/* Horizontal timining size */
	u32 hts;

	/* Default vertical timining size */
	u32 vts_def;

	/* Min vertical timining size */
	u32 vts_min;

	/* Link frequency needed for this resolution */
	u32 link_freq_index;

	/* Sensor register settings for this resolution */
	const struct ov02c10_reg_list reg_list;
};

static const struct ov02c10_reg mipi_data_rate_960mbps[] = {
};

static const struct ov02c10_reg sensor_1932x1092_1lane_30fps_setting[] = {
	// 1932x1092_GRBG_MIPI_MCLK19.2MHz_30fps_1Lane
	{0x0301, 0x08},
	// {0x0303, 0x06},
	{0x0304, 0x01},
	// {0x0305, 0xe0},
	{0x0313, 0x40},
	{0x031c, 0x4f},
	{0x301b, 0xd2},
	{0x3020, 0x97},
	{0x3022, 0x01},
	{0x3026, 0xb4},
	{0x3027, 0xe1},
	{0x303b, 0x00},
	{0x303c, 0x4f},
	{0x303d, 0xe6},
	{0x303e, 0x00},
	{0x303f, 0x03},
	{0x3021, 0x23},
	{0x3501, 0x04},
	{0x3502, 0x6c},
	{0x3504, 0x0c},
	{0x3507, 0x00},
	{0x3508, 0x08},
	{0x3509, 0x00},
	{0x350a, 0x01},
	{0x350b, 0x00},
	{0x350c, 0x41},
	{0x3600, 0x84},
	{0x3611, 0x1b},
	{0x3613, 0x78},
	{0x3623, 0x00},
	{0x3632, 0xa0},
	{0x3642, 0xe8},
	{0x364c, 0x70},
	{0x365f, 0x0f},
	{0x3708, 0x30},
	{0x3714, 0x24},
	{0x3725, 0x02},
	{0x3737, 0x08},
	{0x3739, 0x28},
	{0x3749, 0x32},
	{0x374a, 0x32},
	{0x374b, 0x32},
	{0x374c, 0x32},
	{0x374d, 0x81},
	{0x374e, 0x81},
	{0x374f, 0x81},
	{0x3752, 0x36},
	{0x3753, 0x36},
	{0x3754, 0x36},
	{0x3761, 0x00},
	{0x376c, 0x81},
	{0x377c, 0x81},
	{0x377d, 0x81},
	{0x377e, 0x81},
	{0x37a0, 0x44},
	{0x37a6, 0x44},
	{0x37aa, 0x0d},
	{0x37ae, 0x00},
	{0x37cb, 0x03},
	{0x37cc, 0x01},
	{0x37d8, 0x02},
	{0x37d9, 0x10},
	{0x37e1, 0x10},
	{0x37e2, 0x18},
	{0x37e3, 0x08},
	{0x37e4, 0x08},
	{0x37e5, 0x02},
	{0x37e6, 0x08},
	{0x3800, 0x00},
	{0x3801, 0x00},
	{0x3802, 0x00},
	// {0x3803, 0x04},
	// {0x3804, 0x07},
	// {0x3805, 0x8f},
	// {0x3806, 0x04},
	// {0x3807, 0x43},
	// {0x3808, 0x07},
	// {0x3809, 0x80},
	// {0x380a, 0x04},
	// {0x380b, 0x38},
	// {0x380c, 0x04},
	// {0x380d, 0x74},
	// {0x380e, 0x04},
	// {0x380f, 0x8c},
	// {0x3810, 0x00},
	// {0x3811, 0x07},
	// {0x3812, 0x00},
	// {0x3813, 0x04},
	{0x3814, 0x01},
	{0x3815, 0x01},
	{0x3816, 0x01},
	{0x3817, 0x01},
	{0x3820, 0xa8},
	{0x3821, 0x00},
	{0x3822, 0x80},
	{0x3823, 0x08},
	{0x3824, 0x00},
	{0x3825, 0x20},
	{0x3826, 0x00},
	{0x3827, 0x08},
	{0x382a, 0x00},
	{0x382b, 0x08},
	{0x382d, 0x00},
	{0x382e, 0x00},
	{0x382f, 0x23},
	{0x3834, 0x00},
	{0x3839, 0x00},
	{0x383a, 0xd1},
	{0x383e, 0x03},
	{0x393d, 0x29},
	{0x393f, 0x6e},
	{0x394b, 0x01},
	{0x394c, 0x01},
	{0x394d, 0x01},
	{0x394e, 0x01},
	{0x394f, 0x01},
	{0x3950, 0x01},
	{0x3951, 0x01},
	{0x3952, 0x01},
	{0x3953, 0x01},
	{0x3954, 0x01},
	{0x3955, 0x01},
	{0x3956, 0x01},
	{0x3957, 0x0e},
	{0x3958, 0x08},
	{0x3959, 0x08},
	{0x395a, 0x08},
	{0x395b, 0x00},
	{0x395c, 0x00},
	{0x395d, 0x00},
	{0x395e, 0x00},
	{0x395f, 0x00},
	{0x395f, 0x00},
	{0x3960, 0x00},
	{0x3961, 0x00},
	{0x3962, 0x00},
	{0x3963, 0x00},
	{0x3964, 0x00},
	{0x3965, 0x00},
	{0x3966, 0x00},
	{0x3967, 0x00},
	{0x3968, 0x01},
	{0x3969, 0x01},
	{0x396a, 0x01},
	{0x396b, 0x01},
	{0x396c, 0x00},
	{0x396d, 0xf0},
	{0x396e, 0x11},
	{0x396f, 0x00},
	{0x3970, 0x37},
	{0x3971, 0x37},
	{0x3972, 0x37},
	{0x3973, 0x37},
	{0x3974, 0x00},
	{0x3975, 0x3c},
	{0x3976, 0x3c},
	{0x3977, 0x3c},
	{0x3978, 0x3c},
	{0x3c00, 0x0f},
	{0x3c20, 0x01},
	{0x3c21, 0x08},
	{0x3f00, 0x8b},
	{0x3f02, 0x0f},
	{0x4000, 0xc3},
	{0x4001, 0xe0},
	{0x4002, 0x00},
	{0x4003, 0x40},
	{0x4008, 0x04},
	{0x4009, 0x23},
	{0x400a, 0x04},
	{0x400b, 0x01},
	{0x4077, 0x06},
	{0x4078, 0x00},
	{0x4079, 0x1a},
	{0x407a, 0x7f},
	{0x407b, 0x01},
	{0x4080, 0x03},
	{0x4081, 0x84},
	{0x4308, 0x03},
	{0x4309, 0xff},
	{0x430d, 0x00},
	{0x4806, 0x00},
	{0x4813, 0x00},
	{0x4837, 0x10},
	{0x4857, 0x05},
	{0x4500, 0x07},
	{0x4501, 0x00},
	{0x4503, 0x00},
	{0x450a, 0x04},
	{0x450e, 0x00},
	{0x450f, 0x00},
	{0x4800, 0x24},
	{0x4900, 0x00},
	{0x4901, 0x00},
	{0x4902, 0x01},
	{0x5000, 0xf5},
	{0x5001, 0x50},
	{0x5006, 0x00},
	{0x5080, 0x40},
	{0x5181, 0x2b},
	{0x5202, 0xa3},
	{0x5206, 0x01},
	{0x5207, 0x00},
	{0x520a, 0x01},
	{0x520b, 0x00},
	// {0x3016, 0x32},
	{0x365d, 0x00},
	{0x4815, 0x40},
	{0x4816, 0x12},
	{0x4f00, 0x01},
	{0x396c, 0x10},
	{0x3603, 0x08},
	{0x395b, 0x13},
	{0x395c, 0x09},
	{0x395d, 0x05},
	{0x395e, 0x02},
	{0x3610, 0x57},
	{0x394e, 0x0b},
	{0x394d, 0x08},
	{0x394c, 0x06},
	{0x394b, 0x06},
	// key setting for MCLK=19.2MCLK 1932x1092 GRBG 1 lane 30fps
	{0x0303, 0x05},
	{0x0305, 0x90},
	{0x0316, 0x90},
	{0x3016, 0x12},
	{0x3803, 0x00},
	{0x3804, 0x07},
	{0x3805, 0x8f},
	{0x3806, 0x04},
	{0x3807, 0x47},
	{0x3808, 0x07},
	{0x3809, 0x8c},
	{0x380a, 0x04},
	{0x380b, 0x44},
	{0x380c, 0x08},
	{0x380d, 0xe8},
	{0x380e, 0x04},
	{0x380f, 0x8c},
	{0x3810, 0x00},
	{0x3811, 0x03},
	{0x3812, 0x00},
	{0x3813, 0x03},
};

static const char * const ov02c10_test_pattern_menu[] = {
	"Disabled",
	"Color Bar",
	"Top-Bottom Darker Color Bar",
	"Right-Left Darker Color Bar",
	"Color Bar type 4",
};

static const s64 link_freq_menu_items[] = {
	OV02C10_LINK_FREQ_400MHZ,
};

static const struct ov02c10_link_freq_config link_freq_configs[] = {
	[OV02C10_LINK_FREQ_400MHZ_INDEX] = {
		.reg_list = {
			.num_of_regs = ARRAY_SIZE(mipi_data_rate_960mbps),
			.regs = mipi_data_rate_960mbps,
		}
	},
};

static const struct ov02c10_mode supported_modes[] = {
	{
		.width = 1932,
		.height = 1092,
		.hts = 2280,
		.vts_def = OV02C10_VTS_DEF,
		.vts_min = OV02C10_VTS_MIN,
		.reg_list = {
			.num_of_regs = ARRAY_SIZE(sensor_1932x1092_1lane_30fps_setting),
			.regs = sensor_1932x1092_1lane_30fps_setting,
		},
		.link_freq_index = OV02C10_LINK_FREQ_400MHZ_INDEX,
	},
};

struct ov02c10 {
	struct v4l2_subdev sd;
	struct media_pad pad;
	struct v4l2_ctrl_handler ctrl_handler;

	/* V4L2 Controls */
	struct v4l2_ctrl *link_freq;
	struct v4l2_ctrl *pixel_rate;
	struct v4l2_ctrl *vblank;
	struct v4l2_ctrl *hblank;
	struct v4l2_ctrl *exposure;
	struct v4l2_ctrl *privacy_status;
	/* Current mode */
	const struct ov02c10_mode *cur_mode;

	/* To serialize asynchronus callbacks */
	struct mutex mutex;

	/* Streaming on/off */
	bool streaming;
};

static inline struct ov02c10 *to_ov02c10(struct v4l2_subdev *subdev)
{
	return container_of(subdev, struct ov02c10, sd);
}

static int ov02c10_read_reg(struct ov02c10 *ov02c10, u16 reg, u16 len, u32 *val)
{
	struct i2c_client *client = v4l2_get_subdevdata(&ov02c10->sd);
	struct i2c_msg msgs[2];
	u8 addr_buf[2];
	u8 data_buf[4] = {0};
	int ret = 0;

	if (len > sizeof(data_buf))
		return -EINVAL;

	put_unaligned_be16(reg, addr_buf);
	msgs[0].addr = client->addr;
	msgs[0].flags = 0;
	msgs[0].len = sizeof(addr_buf);
	msgs[0].buf = addr_buf;
	msgs[1].addr = client->addr;
	msgs[1].flags = I2C_M_RD;
	msgs[1].len = len;
	msgs[1].buf = &data_buf[sizeof(data_buf) - len];

	ret = i2c_transfer(client->adapter, msgs, ARRAY_SIZE(msgs));

	if (ret != ARRAY_SIZE(msgs))
		return ret < 0 ? ret : -EIO;

	*val = get_unaligned_be32(data_buf);

	return 0;
}

static int ov02c10_write_reg(struct ov02c10 *ov02c10, u16 reg, u16 len, u32 val)
{
	struct i2c_client *client = v4l2_get_subdevdata(&ov02c10->sd);
	u8 buf[6];
	int ret = 0;

	if (len > 4)
		return -EINVAL;

	put_unaligned_be16(reg, buf);
	put_unaligned_be32(val << 8 * (4 - len), buf + 2);

	ret = i2c_master_send(client, buf, len + 2);
	if (ret != len + 2)
		return ret < 0 ? ret : -EIO;

	return 0;
}

static int ov02c10_write_reg_list(struct ov02c10 *ov02c10,
				  const struct ov02c10_reg_list *r_list)
{
	struct i2c_client *client = v4l2_get_subdevdata(&ov02c10->sd);
	unsigned int i;
	int ret = 0;

	for (i = 0; i < r_list->num_of_regs; i++) {
		ret = ov02c10_write_reg(ov02c10, r_list->regs[i].address, 1,
					r_list->regs[i].val);
		if (ret) {
			dev_err_ratelimited(&client->dev,
					    "write reg 0x%4.4x return err = %d",
					    r_list->regs[i].address, ret);
			return ret;
		}
	}

	return 0;
}

static int ov02c10_test_pattern(struct ov02c10 *ov02c10, u32 pattern)
{
	if (pattern)
		pattern = (pattern - 1) << OV02C10_TEST_PATTERN_BAR_SHIFT |
			  OV02C10_TEST_PATTERN_ENABLE;

	return ov02c10_write_reg(ov02c10, OV02C10_REG_TEST_PATTERN, 1, pattern);
}

static int ov02c10_set_ctrl(struct v4l2_ctrl *ctrl)
{
	struct ov02c10 *ov02c10 = container_of(ctrl->handler,
					     struct ov02c10, ctrl_handler);
	struct i2c_client *client = v4l2_get_subdevdata(&ov02c10->sd);
	s64 exposure_max;
	int ret = 0;

	/* Propagate change of current control to all related controls */
	if (ctrl->id == V4L2_CID_VBLANK) {
		/* Update max exposure while meeting expected vblanking */
		exposure_max = ov02c10->cur_mode->height + ctrl->val -
			       OV02C10_EXPOSURE_MAX_MARGIN;
		__v4l2_ctrl_modify_range(ov02c10->exposure,
					 ov02c10->exposure->minimum,
					 exposure_max, ov02c10->exposure->step,
					 exposure_max);
	}

	/* V4L2 controls values will be applied only when power is already up */
	if (!pm_runtime_get_if_in_use(&client->dev))
		return 0;

	switch (ctrl->id) {
	case V4L2_CID_ANALOGUE_GAIN:
		ret = ov02c10_write_reg(ov02c10, OV02C10_REG_ANALOG_GAIN, 2,
					ctrl->val << 4);
		break;

	case V4L2_CID_DIGITAL_GAIN:
		ret = ov02c10_write_reg(ov02c10, OV02C10_REG_DIGILAL_GAIN, 3,
					ctrl->val << 6);
		break;

	case V4L2_CID_EXPOSURE:
		ret = ov02c10_write_reg(ov02c10, OV02C10_REG_EXPOSURE, 2,
					ctrl->val);
		break;

	case V4L2_CID_VBLANK:
		ret = ov02c10_write_reg(ov02c10, OV02C10_REG_VTS, 2,
					ov02c10->cur_mode->height + ctrl->val);
		break;

	case V4L2_CID_TEST_PATTERN:
		ret = ov02c10_test_pattern(ov02c10, ctrl->val);
		break;

	case V4L2_CID_PRIVACY:
		dev_dbg(&client->dev, "set privacy to %d", ctrl->val);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	pm_runtime_put(&client->dev);

	return ret;
}

static const struct v4l2_ctrl_ops ov02c10_ctrl_ops = {
	.s_ctrl = ov02c10_set_ctrl,
};

static int ov02c10_init_controls(struct ov02c10 *ov02c10)
{
	struct v4l2_ctrl_handler *ctrl_hdlr;
	const struct ov02c10_mode *cur_mode;
	s64 exposure_max, h_blank;
	u32 vblank_min, vblank_max, vblank_default;
	int size;
	int ret = 0;

	ctrl_hdlr = &ov02c10->ctrl_handler;
	ret = v4l2_ctrl_handler_init(ctrl_hdlr, 9);
	if (ret)
		return ret;

	ctrl_hdlr->lock = &ov02c10->mutex;
	cur_mode = ov02c10->cur_mode;
	size = ARRAY_SIZE(link_freq_menu_items);

	ov02c10->link_freq = v4l2_ctrl_new_int_menu(ctrl_hdlr,
						    &ov02c10_ctrl_ops,
						    V4L2_CID_LINK_FREQ,
						    size - 1, 0,
						    link_freq_menu_items);
	if (ov02c10->link_freq)
		ov02c10->link_freq->flags |= V4L2_CTRL_FLAG_READ_ONLY;

	ov02c10->pixel_rate = v4l2_ctrl_new_std(ctrl_hdlr, &ov02c10_ctrl_ops,
						V4L2_CID_PIXEL_RATE, 0,
						OV02C10_SCLK, 1, OV02C10_SCLK);

	vblank_min = cur_mode->vts_min - cur_mode->height;
	vblank_max = OV02C10_VTS_MAX - cur_mode->height;
	vblank_default = cur_mode->vts_def - cur_mode->height;
	ov02c10->vblank = v4l2_ctrl_new_std(ctrl_hdlr, &ov02c10_ctrl_ops,
					    V4L2_CID_VBLANK, vblank_min,
					    vblank_max, 1, vblank_default);

	h_blank = cur_mode->hts - cur_mode->width;
	ov02c10->hblank = v4l2_ctrl_new_std(ctrl_hdlr, &ov02c10_ctrl_ops,
					    V4L2_CID_HBLANK, h_blank, h_blank,
					    1, h_blank);
	if (ov02c10->hblank)
		ov02c10->hblank->flags |= V4L2_CTRL_FLAG_READ_ONLY;
	ov02c10->privacy_status = v4l2_ctrl_new_std(ctrl_hdlr, &ov02c10_ctrl_ops,
								V4L2_CID_PRIVACY, 0, 1, 1, 0);

	v4l2_ctrl_new_std(ctrl_hdlr, &ov02c10_ctrl_ops, V4L2_CID_ANALOGUE_GAIN,
			  OV02C10_ANAL_GAIN_MIN, OV02C10_ANAL_GAIN_MAX,
			  OV02C10_ANAL_GAIN_STEP, OV02C10_ANAL_GAIN_DEFAULT);
	v4l2_ctrl_new_std(ctrl_hdlr, &ov02c10_ctrl_ops, V4L2_CID_DIGITAL_GAIN,
			  OV02C10_DGTL_GAIN_MIN, OV02C10_DGTL_GAIN_MAX,
			  OV02C10_DGTL_GAIN_STEP, OV02C10_DGTL_GAIN_DEFAULT);
	exposure_max = cur_mode->vts_def - OV02C10_EXPOSURE_MAX_MARGIN;
	ov02c10->exposure = v4l2_ctrl_new_std(ctrl_hdlr, &ov02c10_ctrl_ops,
					      V4L2_CID_EXPOSURE,
					      OV02C10_EXPOSURE_MIN,
					      exposure_max,
					      OV02C10_EXPOSURE_STEP,
					      exposure_max);
	v4l2_ctrl_new_std_menu_items(ctrl_hdlr, &ov02c10_ctrl_ops,
				     V4L2_CID_TEST_PATTERN,
				     ARRAY_SIZE(ov02c10_test_pattern_menu) - 1,
				     0, 0, ov02c10_test_pattern_menu);
	if (ctrl_hdlr->error)
		return ctrl_hdlr->error;

	ov02c10->sd.ctrl_handler = ctrl_hdlr;

	return 0;
}

static void ov02c10_update_pad_format(const struct ov02c10_mode *mode,
				      struct v4l2_mbus_framefmt *fmt)
{
	fmt->width = mode->width;
	fmt->height = mode->height;
	fmt->code = MEDIA_BUS_FMT_SGRBG10_1X10;
	fmt->field = V4L2_FIELD_NONE;
}

static void ov02c10_vsc_privacy_callback(void *handle,
				       enum vsc_privacy_status status)
{
	struct ov02c10 *ov02c10 = handle;

	v4l2_ctrl_s_ctrl(ov02c10->privacy_status, !status);
}

static int ov02c10_start_streaming(struct ov02c10 *ov02c10)
{
	struct i2c_client *client = v4l2_get_subdevdata(&ov02c10->sd);
	const struct ov02c10_reg_list *reg_list;
	int link_freq_index;
	int ret = 0;
	struct vsc_mipi_config conf;
	struct vsc_camera_status status;

	conf.lane_num = OV02C10_DATA_LANES;
	/* frequency unit 100k */
	conf.freq = OV02C10_LINK_FREQ_400MHZ / 100000;
	ret = vsc_acquire_camera_sensor(&conf, ov02c10_vsc_privacy_callback,
									ov02c10, &status);
	if (ret) {
		dev_err(&client->dev, "Acquire VSC failed");
		return ret;
	}
	__v4l2_ctrl_s_ctrl(ov02c10->privacy_status, !(status.status));
	link_freq_index = ov02c10->cur_mode->link_freq_index;
	reg_list = &link_freq_configs[link_freq_index].reg_list;
	ret = ov02c10_write_reg_list(ov02c10, reg_list);
	if (ret) {
		dev_err(&client->dev, "failed to set plls");
		return ret;
	}

	reg_list = &ov02c10->cur_mode->reg_list;
	ret = ov02c10_write_reg_list(ov02c10, reg_list);
	if (ret) {
		dev_err(&client->dev, "failed to set mode");
		return ret;
	}

	ret = __v4l2_ctrl_handler_setup(ov02c10->sd.ctrl_handler);
	if (ret)
		return ret;

	ret = ov02c10_write_reg(ov02c10, OV02C10_REG_MODE_SELECT, 1,
				OV02C10_MODE_STREAMING);
	if (ret)
		dev_err(&client->dev, "failed to start streaming");

	return ret;
}

static void ov02c10_stop_streaming(struct ov02c10 *ov02c10)
{
	struct i2c_client *client = v4l2_get_subdevdata(&ov02c10->sd);
	int ret = 0;
	struct vsc_camera_status status;

	ret = ov02c10_write_reg(ov02c10, OV02C10_REG_MODE_SELECT, 1,
				OV02C10_MODE_STANDBY);
	if (ret)
		dev_err(&client->dev, "failed to stop streaming");
	ret = vsc_release_camera_sensor(&status);
	if (ret)
		dev_err(&client->dev, "Release VSC failed");
}

static int ov02c10_set_stream(struct v4l2_subdev *sd, int enable)
{
	struct ov02c10 *ov02c10 = to_ov02c10(sd);
	struct i2c_client *client = v4l2_get_subdevdata(sd);
	int ret = 0;

	if (ov02c10->streaming == enable)
		return 0;

	mutex_lock(&ov02c10->mutex);
	if (enable) {
		ret = pm_runtime_get_sync(&client->dev);
		if (ret < 0) {
			pm_runtime_put_noidle(&client->dev);
			mutex_unlock(&ov02c10->mutex);
			return ret;
		}

		ret = ov02c10_start_streaming(ov02c10);
		if (ret) {
			enable = 0;
			ov02c10_stop_streaming(ov02c10);
			pm_runtime_put(&client->dev);
		}
	} else {
		ov02c10_stop_streaming(ov02c10);
		pm_runtime_put(&client->dev);
	}

	ov02c10->streaming = enable;
	mutex_unlock(&ov02c10->mutex);

	return ret;
}

static int __maybe_unused ov02c10_suspend(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct ov02c10 *ov02c10 = to_ov02c10(sd);

	mutex_lock(&ov02c10->mutex);
	if (ov02c10->streaming)
		ov02c10_stop_streaming(ov02c10);

	mutex_unlock(&ov02c10->mutex);

	return 0;
}

static int __maybe_unused ov02c10_resume(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct ov02c10 *ov02c10 = to_ov02c10(sd);
	int ret = 0;

	mutex_lock(&ov02c10->mutex);
	if (!ov02c10->streaming)
		goto exit;

	ret = ov02c10_start_streaming(ov02c10);
	if (ret) {
		ov02c10->streaming = false;
		ov02c10_stop_streaming(ov02c10);
	}

exit:
	mutex_unlock(&ov02c10->mutex);
	return ret;
}

static int ov02c10_set_format(struct v4l2_subdev *sd,
			      struct v4l2_subdev_state *sd_state,
			      struct v4l2_subdev_format *fmt)
{
	struct ov02c10 *ov02c10 = to_ov02c10(sd);
	const struct ov02c10_mode *mode;
	s32 vblank_def, h_blank;

	mode = v4l2_find_nearest_size(supported_modes,
				      ARRAY_SIZE(supported_modes), width,
				      height, fmt->format.width,
				      fmt->format.height);

	mutex_lock(&ov02c10->mutex);
	ov02c10_update_pad_format(mode, &fmt->format);
	if (fmt->which == V4L2_SUBDEV_FORMAT_TRY) {
		*v4l2_subdev_get_try_format(sd, sd_state, fmt->pad) = fmt->format;
	} else {
		ov02c10->cur_mode = mode;
		__v4l2_ctrl_s_ctrl(ov02c10->link_freq, mode->link_freq_index);
		__v4l2_ctrl_s_ctrl_int64(ov02c10->pixel_rate, OV02C10_SCLK);

		/* Update limits and set FPS to default */
		vblank_def = mode->vts_def - mode->height;
		__v4l2_ctrl_modify_range(ov02c10->vblank,
					 mode->vts_min - mode->height,
					 OV02C10_VTS_MAX - mode->height, 1,
					 vblank_def);
		__v4l2_ctrl_s_ctrl(ov02c10->vblank, vblank_def);
		h_blank = mode->hts - mode->width;
		__v4l2_ctrl_modify_range(ov02c10->hblank, h_blank, h_blank, 1,
					 h_blank);
	}
	mutex_unlock(&ov02c10->mutex);

	return 0;
}

static int ov02c10_get_format(struct v4l2_subdev *sd,
			      struct v4l2_subdev_state *sd_state,
			      struct v4l2_subdev_format *fmt)
{
	struct ov02c10 *ov02c10 = to_ov02c10(sd);

	mutex_lock(&ov02c10->mutex);
	if (fmt->which == V4L2_SUBDEV_FORMAT_TRY)
		fmt->format = *v4l2_subdev_get_try_format(&ov02c10->sd,
							  sd_state, fmt->pad);
	else
		ov02c10_update_pad_format(ov02c10->cur_mode, &fmt->format);

	mutex_unlock(&ov02c10->mutex);

	return 0;
}

static int ov02c10_enum_mbus_code(struct v4l2_subdev *sd,
				  struct v4l2_subdev_state *sd_state,
				  struct v4l2_subdev_mbus_code_enum *code)
{
	if (code->index > 0)
		return -EINVAL;

	code->code = MEDIA_BUS_FMT_SGRBG10_1X10;

	return 0;
}

static int ov02c10_enum_frame_size(struct v4l2_subdev *sd,
				   struct v4l2_subdev_state *sd_state,
				   struct v4l2_subdev_frame_size_enum *fse)
{
	if (fse->index >= ARRAY_SIZE(supported_modes))
		return -EINVAL;

	if (fse->code != MEDIA_BUS_FMT_SGRBG10_1X10)
		return -EINVAL;

	fse->min_width = supported_modes[fse->index].width;
	fse->max_width = fse->min_width;
	fse->min_height = supported_modes[fse->index].height;
	fse->max_height = fse->min_height;

	return 0;
}

static int ov02c10_open(struct v4l2_subdev *sd, struct v4l2_subdev_fh *fh)
{
	struct ov02c10 *ov02c10 = to_ov02c10(sd);

	mutex_lock(&ov02c10->mutex);
	ov02c10_update_pad_format(&supported_modes[0],
				  v4l2_subdev_get_try_format(sd, fh->state, 0));
	mutex_unlock(&ov02c10->mutex);

	return 0;
}

static const struct v4l2_subdev_video_ops ov02c10_video_ops = {
	.s_stream = ov02c10_set_stream,
};

static const struct v4l2_subdev_pad_ops ov02c10_pad_ops = {
	.set_fmt = ov02c10_set_format,
	.get_fmt = ov02c10_get_format,
	.enum_mbus_code = ov02c10_enum_mbus_code,
	.enum_frame_size = ov02c10_enum_frame_size,
};

static const struct v4l2_subdev_ops ov02c10_subdev_ops = {
	.video = &ov02c10_video_ops,
	.pad = &ov02c10_pad_ops,
};

static const struct media_entity_operations ov02c10_subdev_entity_ops = {
	.link_validate = v4l2_subdev_link_validate,
};

static const struct v4l2_subdev_internal_ops ov02c10_internal_ops = {
	.open = ov02c10_open,
};

static int ov02c10_identify_module(struct ov02c10 *ov02c10)
{
	struct i2c_client *client = v4l2_get_subdevdata(&ov02c10->sd);
	int ret;
	u32 val;

	ret = ov02c10_read_reg(ov02c10, OV02C10_REG_CHIP_ID, 3, &val);
	if (ret)
		return ret;

	if (val != OV02C10_CHIP_ID) {
		dev_err(&client->dev, "chip id mismatch: %x!=%x",
			OV02C10_CHIP_ID, val);
		return -ENXIO;
	}

	return 0;
}

static int ov02c10_remove(struct i2c_client *client)
{
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct ov02c10 *ov02c10 = to_ov02c10(sd);

	v4l2_async_unregister_subdev(sd);
	media_entity_cleanup(&sd->entity);
	v4l2_ctrl_handler_free(sd->ctrl_handler);
	pm_runtime_disable(&client->dev);
	mutex_destroy(&ov02c10->mutex);

	return 0;
}

static int ov02c10_probe(struct i2c_client *client)
{
	struct ov02c10 *ov02c10;
	int ret = 0;
	struct vsc_mipi_config conf;
	struct vsc_camera_status status;

	conf.lane_num = OV02C10_DATA_LANES;
	/* frequency unit 100k */
	conf.freq = OV02C10_LINK_FREQ_400MHZ / 100000;
	ret = vsc_acquire_camera_sensor(&conf, NULL, NULL, &status);
	if (ret == -EAGAIN) {
		dev_dbg(&client->dev, "VSC not ready, will re-probe");
		return -EPROBE_DEFER;
	} else if (ret) {
		dev_err(&client->dev, "Acquire VSC failed");
		return ret;
	}
	ov02c10 = devm_kzalloc(&client->dev, sizeof(*ov02c10), GFP_KERNEL);
	if (!ov02c10) {
		ret = -ENOMEM;
		goto probe_error_ret;
	}

	v4l2_i2c_subdev_init(&ov02c10->sd, client, &ov02c10_subdev_ops);

	ret = ov02c10_identify_module(ov02c10);
	if (ret) {
		dev_err(&client->dev, "failed to find sensor: %d", ret);
		goto probe_error_ret;
	}

	mutex_init(&ov02c10->mutex);
	ov02c10->cur_mode = &supported_modes[0];
	ret = ov02c10_init_controls(ov02c10);
	if (ret) {
		dev_err(&client->dev, "failed to init controls: %d", ret);
		goto probe_error_v4l2_ctrl_handler_free;
	}

	ov02c10->sd.internal_ops = &ov02c10_internal_ops;
	ov02c10->sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	ov02c10->sd.entity.ops = &ov02c10_subdev_entity_ops;
	ov02c10->sd.entity.function = MEDIA_ENT_F_CAM_SENSOR;
	ov02c10->pad.flags = MEDIA_PAD_FL_SOURCE;
	ret = media_entity_pads_init(&ov02c10->sd.entity, 1, &ov02c10->pad);
	if (ret) {
		dev_err(&client->dev, "failed to init entity pads: %d", ret);
		goto probe_error_v4l2_ctrl_handler_free;
	}

	ret = v4l2_async_register_subdev_sensor(&ov02c10->sd);
	if (ret < 0) {
		dev_err(&client->dev, "failed to register V4L2 subdev: %d",
			ret);
		goto probe_error_media_entity_cleanup;
	}

	vsc_release_camera_sensor(&status);
	/*
	 * Device is already turned on by i2c-core with ACPI domain PM.
	 * Enable runtime PM and turn off the device.
	 */
	pm_runtime_set_active(&client->dev);
	pm_runtime_enable(&client->dev);
	pm_runtime_idle(&client->dev);

	return 0;

probe_error_media_entity_cleanup:
	media_entity_cleanup(&ov02c10->sd.entity);

probe_error_v4l2_ctrl_handler_free:
	v4l2_ctrl_handler_free(ov02c10->sd.ctrl_handler);
	mutex_destroy(&ov02c10->mutex);

probe_error_ret:
	vsc_release_camera_sensor(&status);
	return ret;
}

static const struct dev_pm_ops ov02c10_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(ov02c10_suspend, ov02c10_resume)
};

#ifdef CONFIG_ACPI
static const struct acpi_device_id ov02c10_acpi_ids[] = {
	{"OVTI02C1"},
	{}
};

MODULE_DEVICE_TABLE(acpi, ov02c10_acpi_ids);
#endif

static struct i2c_driver ov02c10_i2c_driver = {
	.driver = {
		.name = "ov02c10",
		.pm = &ov02c10_pm_ops,
		.acpi_match_table = ACPI_PTR(ov02c10_acpi_ids),
	},
	.probe_new = ov02c10_probe,
	.remove = ov02c10_remove,
};

module_i2c_driver(ov02c10_i2c_driver);

MODULE_AUTHOR("Hao Yao <hao.yao@intel.com>");
MODULE_DESCRIPTION("OmniVision OV02C10 sensor driver");
MODULE_LICENSE("GPL v2");
