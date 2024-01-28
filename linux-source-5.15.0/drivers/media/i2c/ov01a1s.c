// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020-2021 Intel Corporation.

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
#include "power_ctrl_logic.h"

#define OV01A1S_LINK_FREQ_400MHZ	400000000ULL
#define OV01A1S_SCLK			40000000LL
#define OV01A1S_MCLK			19200000
#define OV01A1S_DATA_LANES		1
#define OV01A1S_RGB_DEPTH		10

#define OV01A1S_REG_CHIP_ID		0x300a
#define OV01A1S_CHIP_ID			0x560141

#define OV01A1S_REG_MODE_SELECT		0x0100
#define OV01A1S_MODE_STANDBY		0x00
#define OV01A1S_MODE_STREAMING		0x01

/* vertical-timings from sensor */
#define OV01A1S_REG_VTS			0x380e
#define OV01A1S_VTS_DEF			0x0380
#define OV01A1S_VTS_MIN			0x0380
#define OV01A1S_VTS_MAX			0xffff

/* Exposure controls from sensor */
#define OV01A1S_REG_EXPOSURE		0x3501
#define OV01A1S_EXPOSURE_MIN		4
#define OV01A1S_EXPOSURE_MAX_MARGIN	8
#define OV01A1S_EXPOSURE_STEP		1

/* Analog gain controls from sensor */
#define OV01A1S_REG_ANALOG_GAIN		0x3508
#define OV01A1S_ANAL_GAIN_MIN		0x100
#define OV01A1S_ANAL_GAIN_MAX		0xffff
#define OV01A1S_ANAL_GAIN_STEP		1

/* Digital gain controls from sensor */
#define OV01A1S_REG_DIGILAL_GAIN_B	0x350A
#define OV01A1S_REG_DIGITAL_GAIN_GB	0x3510
#define OV01A1S_REG_DIGITAL_GAIN_GR	0x3513
#define OV01A1S_REG_DIGITAL_GAIN_R	0x3516
#define OV01A1S_DGTL_GAIN_MIN		0
#define OV01A1S_DGTL_GAIN_MAX		0x3ffff
#define OV01A1S_DGTL_GAIN_STEP		1
#define OV01A1S_DGTL_GAIN_DEFAULT	1024

/* Test Pattern Control */
#define OV01A1S_REG_TEST_PATTERN		0x4503
#define OV01A1S_TEST_PATTERN_ENABLE	BIT(7)
#define OV01A1S_TEST_PATTERN_BAR_SHIFT	0

enum {
	OV01A1S_LINK_FREQ_400MHZ_INDEX,
};

struct ov01a1s_reg {
	u16 address;
	u8 val;
};

struct ov01a1s_reg_list {
	u32 num_of_regs;
	const struct ov01a1s_reg *regs;
};

struct ov01a1s_link_freq_config {
	const struct ov01a1s_reg_list reg_list;
};

struct ov01a1s_mode {
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
	const struct ov01a1s_reg_list reg_list;
};

static const struct ov01a1s_reg mipi_data_rate_720mbps[] = {
};

static const struct ov01a1s_reg sensor_1296x800_setting[] = {
	{0x0103, 0x01},
	{0x0302, 0x00},
	{0x0303, 0x06},
	{0x0304, 0x01},
	{0x0305, 0x90},
	{0x0306, 0x00},
	{0x0308, 0x01},
	{0x0309, 0x00},
	{0x030c, 0x01},
	{0x0322, 0x01},
	{0x0323, 0x06},
	{0x0324, 0x01},
	{0x0325, 0x68},
	{0x3002, 0xa1},
	{0x301e, 0xf0},
	{0x3022, 0x01},
	{0x3501, 0x03},
	{0x3502, 0x78},
	{0x3504, 0x0c},
	{0x3508, 0x01},
	{0x3509, 0x00},
	{0x3601, 0xc0},
	{0x3603, 0x71},
	{0x3610, 0x68},
	{0x3611, 0x86},
	{0x3640, 0x10},
	{0x3641, 0x80},
	{0x3642, 0xdc},
	{0x3646, 0x55},
	{0x3647, 0x57},
	{0x364b, 0x00},
	{0x3653, 0x10},
	{0x3655, 0x00},
	{0x3656, 0x00},
	{0x365f, 0x0f},
	{0x3661, 0x45},
	{0x3662, 0x24},
	{0x3663, 0x11},
	{0x3664, 0x07},
	{0x3709, 0x34},
	{0x370b, 0x6f},
	{0x3714, 0x22},
	{0x371b, 0x27},
	{0x371c, 0x67},
	{0x371d, 0xa7},
	{0x371e, 0xe7},
	{0x3730, 0x81},
	{0x3733, 0x10},
	{0x3734, 0x40},
	{0x3737, 0x04},
	{0x3739, 0x1c},
	{0x3767, 0x00},
	{0x376c, 0x81},
	{0x3772, 0x14},
	{0x37c2, 0x04},
	{0x37d8, 0x03},
	{0x37d9, 0x0c},
	{0x37e0, 0x00},
	{0x37e1, 0x08},
	{0x37e2, 0x10},
	{0x37e3, 0x04},
	{0x37e4, 0x04},
	{0x37e5, 0x03},
	{0x37e6, 0x04},
	{0x3800, 0x00},
	{0x3801, 0x00},
	{0x3802, 0x00},
	{0x3803, 0x00},
	{0x3804, 0x05},
	{0x3805, 0x0f},
	{0x3806, 0x03},
	{0x3807, 0x2f},
	{0x3808, 0x05},
	{0x3809, 0x00},
	{0x380a, 0x03},
	{0x380b, 0x1e},
	{0x380c, 0x05},
	{0x380d, 0xd0},
	{0x380e, 0x03},
	{0x380f, 0x80},
	{0x3810, 0x00},
	{0x3811, 0x09},
	{0x3812, 0x00},
	{0x3813, 0x08},
	{0x3814, 0x01},
	{0x3815, 0x01},
	{0x3816, 0x01},
	{0x3817, 0x01},
	{0x3820, 0xa8},
	{0x3822, 0x03},
	{0x3832, 0x28},
	{0x3833, 0x10},
	{0x3b00, 0x00},
	{0x3c80, 0x00},
	{0x3c88, 0x02},
	{0x3c8c, 0x07},
	{0x3c8d, 0x40},
	{0x3cc7, 0x80},
	{0x4000, 0xc3},
	{0x4001, 0xe0},
	{0x4003, 0x40},
	{0x4008, 0x02},
	{0x4009, 0x19},
	{0x400a, 0x01},
	{0x400b, 0x6c},
	{0x4011, 0x00},
	{0x4041, 0x00},
	{0x4300, 0xff},
	{0x4301, 0x00},
	{0x4302, 0x0f},
	{0x4503, 0x00},
	{0x4601, 0x50},
	{0x481f, 0x34},
	{0x4825, 0x33},
	{0x4837, 0x14},
	{0x4881, 0x40},
	{0x4883, 0x01},
	{0x4890, 0x00},
	{0x4901, 0x00},
	{0x4902, 0x00},
	{0x4b00, 0x2a},
	{0x4b0d, 0x00},
	{0x450a, 0x04},
	{0x450b, 0x00},
	{0x5000, 0x65},
	{0x5004, 0x00},
	{0x5080, 0x40},
	{0x5200, 0x18},
	{0x4837, 0x14},
	{0x0305, 0xf4},
	{0x0325, 0xc2},
	{0x3808, 0x05},
	{0x3809, 0x10},
	{0x380a, 0x03},
	{0x380b, 0x1e},
	{0x3810, 0x00},
	{0x3811, 0x00},
	{0x3812, 0x00},
	{0x3813, 0x09},
	{0x3820, 0x88},
	{0x373d, 0x24},
};

static const char * const ov01a1s_test_pattern_menu[] = {
	"Disabled",
	"Color Bar",
	"Top-Bottom Darker Color Bar",
	"Right-Left Darker Color Bar",
	"Color Bar type 4",
};

static const s64 link_freq_menu_items[] = {
	OV01A1S_LINK_FREQ_400MHZ,
};

static const struct ov01a1s_link_freq_config link_freq_configs[] = {
	[OV01A1S_LINK_FREQ_400MHZ_INDEX] = {
		.reg_list = {
			.num_of_regs = ARRAY_SIZE(mipi_data_rate_720mbps),
			.regs = mipi_data_rate_720mbps,
		}
	},
};

static const struct ov01a1s_mode supported_modes[] = {
	{
		.width = 1296,
		.height = 798,
		.hts = 1488,
		.vts_def = OV01A1S_VTS_DEF,
		.vts_min = OV01A1S_VTS_MIN,
		.reg_list = {
			.num_of_regs = ARRAY_SIZE(sensor_1296x800_setting),
			.regs = sensor_1296x800_setting,
		},
		.link_freq_index = OV01A1S_LINK_FREQ_400MHZ_INDEX,
	},
};

struct ov01a1s {
	struct v4l2_subdev sd;
	struct media_pad pad;
	struct v4l2_ctrl_handler ctrl_handler;

	/* V4L2 Controls */
	struct v4l2_ctrl *link_freq;
	struct v4l2_ctrl *pixel_rate;
	struct v4l2_ctrl *vblank;
	struct v4l2_ctrl *hblank;
	struct v4l2_ctrl *exposure;

	/* Current mode */
	const struct ov01a1s_mode *cur_mode;

	/* To serialize asynchronus callbacks */
	struct mutex mutex;

	/* Streaming on/off */
	bool streaming;
};

static inline struct ov01a1s *to_ov01a1s(struct v4l2_subdev *subdev)
{
	return container_of(subdev, struct ov01a1s, sd);
}

static int ov01a1s_read_reg(struct ov01a1s *ov01a1s, u16 reg, u16 len, u32 *val)
{
	struct i2c_client *client = v4l2_get_subdevdata(&ov01a1s->sd);
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

static int ov01a1s_write_reg(struct ov01a1s *ov01a1s, u16 reg, u16 len, u32 val)
{
	struct i2c_client *client = v4l2_get_subdevdata(&ov01a1s->sd);
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

static int ov01a1s_write_reg_list(struct ov01a1s *ov01a1s,
				  const struct ov01a1s_reg_list *r_list)
{
	struct i2c_client *client = v4l2_get_subdevdata(&ov01a1s->sd);
	unsigned int i;
	int ret = 0;

	for (i = 0; i < r_list->num_of_regs; i++) {
		ret = ov01a1s_write_reg(ov01a1s, r_list->regs[i].address, 1,
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

static int ov01a1s_update_digital_gain(struct ov01a1s *ov01a1s, u32 d_gain)
{
	struct i2c_client *client = v4l2_get_subdevdata(&ov01a1s->sd);
	u32 real = d_gain << 6;
	int ret = 0;

	ret = ov01a1s_write_reg(ov01a1s, OV01A1S_REG_DIGILAL_GAIN_B, 3, real);
	if (ret) {
		dev_err(&client->dev, "failed to set OV01A1S_REG_DIGITAL_GAIN_B");
		return ret;
	}
	ret = ov01a1s_write_reg(ov01a1s, OV01A1S_REG_DIGITAL_GAIN_GB, 3, real);
	if (ret) {
		dev_err(&client->dev, "failed to set OV01A1S_REG_DIGITAL_GAIN_GB");
		return ret;
	}
	ret = ov01a1s_write_reg(ov01a1s, OV01A1S_REG_DIGITAL_GAIN_GR, 3, real);
	if (ret) {
		dev_err(&client->dev, "failed to set OV01A1S_REG_DIGITAL_GAIN_GR");
		return ret;
	}

	ret = ov01a1s_write_reg(ov01a1s, OV01A1S_REG_DIGITAL_GAIN_R, 3, real);
	if (ret) {
		dev_err(&client->dev, "failed to set OV01A1S_REG_DIGITAL_GAIN_R");
		return ret;
	}
	return ret;
}

static int ov01a1s_test_pattern(struct ov01a1s *ov01a1s, u32 pattern)
{
	if (pattern)
		pattern = (pattern - 1) << OV01A1S_TEST_PATTERN_BAR_SHIFT |
			  OV01A1S_TEST_PATTERN_ENABLE;

	return ov01a1s_write_reg(ov01a1s, OV01A1S_REG_TEST_PATTERN, 1, pattern);
}

static int ov01a1s_set_ctrl(struct v4l2_ctrl *ctrl)
{
	struct ov01a1s *ov01a1s = container_of(ctrl->handler,
					     struct ov01a1s, ctrl_handler);
	struct i2c_client *client = v4l2_get_subdevdata(&ov01a1s->sd);
	s64 exposure_max;
	int ret = 0;

	/* Propagate change of current control to all related controls */
	if (ctrl->id == V4L2_CID_VBLANK) {
		/* Update max exposure while meeting expected vblanking */
		exposure_max = ov01a1s->cur_mode->height + ctrl->val -
			       OV01A1S_EXPOSURE_MAX_MARGIN;
		__v4l2_ctrl_modify_range(ov01a1s->exposure,
					 ov01a1s->exposure->minimum,
					 exposure_max, ov01a1s->exposure->step,
					 exposure_max);
	}

	/* V4L2 controls values will be applied only when power is already up */
	if (!pm_runtime_get_if_in_use(&client->dev))
		return 0;

	switch (ctrl->id) {
	case V4L2_CID_ANALOGUE_GAIN:
		ret = ov01a1s_write_reg(ov01a1s, OV01A1S_REG_ANALOG_GAIN, 2,
					ctrl->val);
		break;

	case V4L2_CID_DIGITAL_GAIN:
		ret = ov01a1s_update_digital_gain(ov01a1s, ctrl->val);
		break;

	case V4L2_CID_EXPOSURE:
		ret = ov01a1s_write_reg(ov01a1s, OV01A1S_REG_EXPOSURE, 2,
					ctrl->val);
		break;

	case V4L2_CID_VBLANK:
		ret = ov01a1s_write_reg(ov01a1s, OV01A1S_REG_VTS, 2,
					ov01a1s->cur_mode->height + ctrl->val);
		break;

	case V4L2_CID_TEST_PATTERN:
		ret = ov01a1s_test_pattern(ov01a1s, ctrl->val);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	pm_runtime_put(&client->dev);

	return ret;
}

static const struct v4l2_ctrl_ops ov01a1s_ctrl_ops = {
	.s_ctrl = ov01a1s_set_ctrl,
};

static int ov01a1s_init_controls(struct ov01a1s *ov01a1s)
{
	struct v4l2_ctrl_handler *ctrl_hdlr;
	const struct ov01a1s_mode *cur_mode;
	s64 exposure_max, h_blank;
	u32 vblank_min, vblank_max, vblank_default;
	int size;
	int ret = 0;

	ctrl_hdlr = &ov01a1s->ctrl_handler;
	ret = v4l2_ctrl_handler_init(ctrl_hdlr, 8);
	if (ret)
		return ret;

	ctrl_hdlr->lock = &ov01a1s->mutex;
	cur_mode = ov01a1s->cur_mode;
	size = ARRAY_SIZE(link_freq_menu_items);

	ov01a1s->link_freq = v4l2_ctrl_new_int_menu(ctrl_hdlr,
						    &ov01a1s_ctrl_ops,
						    V4L2_CID_LINK_FREQ,
						    size - 1, 0,
						    link_freq_menu_items);
	if (ov01a1s->link_freq)
		ov01a1s->link_freq->flags |= V4L2_CTRL_FLAG_READ_ONLY;

	ov01a1s->pixel_rate = v4l2_ctrl_new_std(ctrl_hdlr, &ov01a1s_ctrl_ops,
						V4L2_CID_PIXEL_RATE, 0,
						OV01A1S_SCLK, 1, OV01A1S_SCLK);

	vblank_min = cur_mode->vts_min - cur_mode->height;
	vblank_max = OV01A1S_VTS_MAX - cur_mode->height;
	vblank_default = cur_mode->vts_def - cur_mode->height;
	ov01a1s->vblank = v4l2_ctrl_new_std(ctrl_hdlr, &ov01a1s_ctrl_ops,
					    V4L2_CID_VBLANK, vblank_min,
					    vblank_max, 1, vblank_default);

	h_blank = cur_mode->hts - cur_mode->width;
	ov01a1s->hblank = v4l2_ctrl_new_std(ctrl_hdlr, &ov01a1s_ctrl_ops,
					    V4L2_CID_HBLANK, h_blank, h_blank,
					    1, h_blank);
	if (ov01a1s->hblank)
		ov01a1s->hblank->flags |= V4L2_CTRL_FLAG_READ_ONLY;

	v4l2_ctrl_new_std(ctrl_hdlr, &ov01a1s_ctrl_ops, V4L2_CID_ANALOGUE_GAIN,
			  OV01A1S_ANAL_GAIN_MIN, OV01A1S_ANAL_GAIN_MAX,
			  OV01A1S_ANAL_GAIN_STEP, OV01A1S_ANAL_GAIN_MIN);
	v4l2_ctrl_new_std(ctrl_hdlr, &ov01a1s_ctrl_ops, V4L2_CID_DIGITAL_GAIN,
			  OV01A1S_DGTL_GAIN_MIN, OV01A1S_DGTL_GAIN_MAX,
			  OV01A1S_DGTL_GAIN_STEP, OV01A1S_DGTL_GAIN_DEFAULT);
	exposure_max = cur_mode->vts_def - OV01A1S_EXPOSURE_MAX_MARGIN;
	ov01a1s->exposure = v4l2_ctrl_new_std(ctrl_hdlr, &ov01a1s_ctrl_ops,
					      V4L2_CID_EXPOSURE,
					      OV01A1S_EXPOSURE_MIN,
					      exposure_max,
					      OV01A1S_EXPOSURE_STEP,
					      exposure_max);
	v4l2_ctrl_new_std_menu_items(ctrl_hdlr, &ov01a1s_ctrl_ops,
				     V4L2_CID_TEST_PATTERN,
				     ARRAY_SIZE(ov01a1s_test_pattern_menu) - 1,
				     0, 0, ov01a1s_test_pattern_menu);
	if (ctrl_hdlr->error)
		return ctrl_hdlr->error;

	ov01a1s->sd.ctrl_handler = ctrl_hdlr;

	return 0;
}

static void ov01a1s_update_pad_format(const struct ov01a1s_mode *mode,
				      struct v4l2_mbus_framefmt *fmt)
{
	fmt->width = mode->width;
	fmt->height = mode->height;
	fmt->code = MEDIA_BUS_FMT_SGRBG10_1X10;
	fmt->field = V4L2_FIELD_NONE;
}

static int ov01a1s_start_streaming(struct ov01a1s *ov01a1s)
{
	struct i2c_client *client = v4l2_get_subdevdata(&ov01a1s->sd);
	const struct ov01a1s_reg_list *reg_list;
	int link_freq_index;
	int ret = 0;

	power_ctrl_logic_set_power(1);
	link_freq_index = ov01a1s->cur_mode->link_freq_index;
	reg_list = &link_freq_configs[link_freq_index].reg_list;
	ret = ov01a1s_write_reg_list(ov01a1s, reg_list);
	if (ret) {
		dev_err(&client->dev, "failed to set plls");
		return ret;
	}

	reg_list = &ov01a1s->cur_mode->reg_list;
	ret = ov01a1s_write_reg_list(ov01a1s, reg_list);
	if (ret) {
		dev_err(&client->dev, "failed to set mode");
		return ret;
	}

	ret = __v4l2_ctrl_handler_setup(ov01a1s->sd.ctrl_handler);
	if (ret)
		return ret;

	ret = ov01a1s_write_reg(ov01a1s, OV01A1S_REG_MODE_SELECT, 1,
				OV01A1S_MODE_STREAMING);
	if (ret)
		dev_err(&client->dev, "failed to start streaming");

	return ret;
}

static void ov01a1s_stop_streaming(struct ov01a1s *ov01a1s)
{
	struct i2c_client *client = v4l2_get_subdevdata(&ov01a1s->sd);
	int ret = 0;

	ret = ov01a1s_write_reg(ov01a1s, OV01A1S_REG_MODE_SELECT, 1,
				OV01A1S_MODE_STANDBY);
	if (ret)
		dev_err(&client->dev, "failed to stop streaming");
	power_ctrl_logic_set_power(0);
}

static int ov01a1s_set_stream(struct v4l2_subdev *sd, int enable)
{
	struct ov01a1s *ov01a1s = to_ov01a1s(sd);
	struct i2c_client *client = v4l2_get_subdevdata(sd);
	int ret = 0;

	if (ov01a1s->streaming == enable)
		return 0;

	mutex_lock(&ov01a1s->mutex);
	if (enable) {
		ret = pm_runtime_get_sync(&client->dev);
		if (ret < 0) {
			pm_runtime_put_noidle(&client->dev);
			mutex_unlock(&ov01a1s->mutex);
			return ret;
		}

		ret = ov01a1s_start_streaming(ov01a1s);
		if (ret) {
			enable = 0;
			ov01a1s_stop_streaming(ov01a1s);
			pm_runtime_put(&client->dev);
		}
	} else {
		ov01a1s_stop_streaming(ov01a1s);
		pm_runtime_put(&client->dev);
	}

	ov01a1s->streaming = enable;
	mutex_unlock(&ov01a1s->mutex);

	return ret;
}

static int __maybe_unused ov01a1s_suspend(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct ov01a1s *ov01a1s = to_ov01a1s(sd);

	mutex_lock(&ov01a1s->mutex);
	if (ov01a1s->streaming)
		ov01a1s_stop_streaming(ov01a1s);

	mutex_unlock(&ov01a1s->mutex);

	return 0;
}

static int __maybe_unused ov01a1s_resume(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct ov01a1s *ov01a1s = to_ov01a1s(sd);
	int ret = 0;

	mutex_lock(&ov01a1s->mutex);
	if (!ov01a1s->streaming)
		goto exit;

	ret = ov01a1s_start_streaming(ov01a1s);
	if (ret) {
		ov01a1s->streaming = false;
		ov01a1s_stop_streaming(ov01a1s);
	}

exit:
	mutex_unlock(&ov01a1s->mutex);
	return ret;
}

static int ov01a1s_set_format(struct v4l2_subdev *sd,
			      struct v4l2_subdev_state *sd_state,
			      struct v4l2_subdev_format *fmt)
{
	struct ov01a1s *ov01a1s = to_ov01a1s(sd);
	const struct ov01a1s_mode *mode;
	s32 vblank_def, h_blank;

	mode = v4l2_find_nearest_size(supported_modes,
				      ARRAY_SIZE(supported_modes), width,
				      height, fmt->format.width,
				      fmt->format.height);

	mutex_lock(&ov01a1s->mutex);
	ov01a1s_update_pad_format(mode, &fmt->format);
	if (fmt->which == V4L2_SUBDEV_FORMAT_TRY) {
		*v4l2_subdev_get_try_format(sd, sd_state, fmt->pad) = fmt->format;
	} else {
		ov01a1s->cur_mode = mode;
		__v4l2_ctrl_s_ctrl(ov01a1s->link_freq, mode->link_freq_index);
		__v4l2_ctrl_s_ctrl_int64(ov01a1s->pixel_rate, OV01A1S_SCLK);

		/* Update limits and set FPS to default */
		vblank_def = mode->vts_def - mode->height;
		__v4l2_ctrl_modify_range(ov01a1s->vblank,
					 mode->vts_min - mode->height,
					 OV01A1S_VTS_MAX - mode->height, 1,
					 vblank_def);
		__v4l2_ctrl_s_ctrl(ov01a1s->vblank, vblank_def);
		h_blank = mode->hts - mode->width;
		__v4l2_ctrl_modify_range(ov01a1s->hblank, h_blank, h_blank, 1,
					 h_blank);
	}
	mutex_unlock(&ov01a1s->mutex);

	return 0;
}

static int ov01a1s_get_format(struct v4l2_subdev *sd,
			      struct v4l2_subdev_state *sd_state,
			      struct v4l2_subdev_format *fmt)
{
	struct ov01a1s *ov01a1s = to_ov01a1s(sd);

	mutex_lock(&ov01a1s->mutex);
	if (fmt->which == V4L2_SUBDEV_FORMAT_TRY)
		fmt->format = *v4l2_subdev_get_try_format(&ov01a1s->sd,
							  sd_state, fmt->pad);
	else
		ov01a1s_update_pad_format(ov01a1s->cur_mode, &fmt->format);

	mutex_unlock(&ov01a1s->mutex);

	return 0;
}

static int ov01a1s_enum_mbus_code(struct v4l2_subdev *sd,
				  struct v4l2_subdev_state *sd_state,
				  struct v4l2_subdev_mbus_code_enum *code)
{
	if (code->index > 0)
		return -EINVAL;

	code->code = MEDIA_BUS_FMT_SGRBG10_1X10;

	return 0;
}

static int ov01a1s_enum_frame_size(struct v4l2_subdev *sd,
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

static int ov01a1s_open(struct v4l2_subdev *sd, struct v4l2_subdev_fh *fh)
{
	struct ov01a1s *ov01a1s = to_ov01a1s(sd);

	mutex_lock(&ov01a1s->mutex);
	ov01a1s_update_pad_format(&supported_modes[0],
				  v4l2_subdev_get_try_format(sd, fh->state, 0));
	mutex_unlock(&ov01a1s->mutex);

	return 0;
}

static const struct v4l2_subdev_video_ops ov01a1s_video_ops = {
	.s_stream = ov01a1s_set_stream,
};

static const struct v4l2_subdev_pad_ops ov01a1s_pad_ops = {
	.set_fmt = ov01a1s_set_format,
	.get_fmt = ov01a1s_get_format,
	.enum_mbus_code = ov01a1s_enum_mbus_code,
	.enum_frame_size = ov01a1s_enum_frame_size,
};

static const struct v4l2_subdev_ops ov01a1s_subdev_ops = {
	.video = &ov01a1s_video_ops,
	.pad = &ov01a1s_pad_ops,
};

static const struct media_entity_operations ov01a1s_subdev_entity_ops = {
	.link_validate = v4l2_subdev_link_validate,
};

static const struct v4l2_subdev_internal_ops ov01a1s_internal_ops = {
	.open = ov01a1s_open,
};

static int ov01a1s_identify_module(struct ov01a1s *ov01a1s)
{
	struct i2c_client *client = v4l2_get_subdevdata(&ov01a1s->sd);
	int ret;
	u32 val;

	ret = ov01a1s_read_reg(ov01a1s, OV01A1S_REG_CHIP_ID, 3, &val);
	if (ret)
		return ret;

	if (val != OV01A1S_CHIP_ID) {
		dev_err(&client->dev, "chip id mismatch: %x!=%x",
			OV01A1S_CHIP_ID, val);
		return -ENXIO;
	}

	return 0;
}

static int ov01a1s_remove(struct i2c_client *client)
{
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct ov01a1s *ov01a1s = to_ov01a1s(sd);

	v4l2_async_unregister_subdev(sd);
	media_entity_cleanup(&sd->entity);
	v4l2_ctrl_handler_free(sd->ctrl_handler);
	pm_runtime_disable(&client->dev);
	mutex_destroy(&ov01a1s->mutex);

	return 0;
}

static int ov01a1s_probe(struct i2c_client *client)
{
	struct ov01a1s *ov01a1s;
	int ret = 0;

	if (power_ctrl_logic_set_power(1)) {
		dev_dbg(&client->dev, "power control driver not ready.\n");
		return -EPROBE_DEFER;
	}
	ov01a1s = devm_kzalloc(&client->dev, sizeof(*ov01a1s), GFP_KERNEL);
	if (!ov01a1s) {
		ret = -ENOMEM;
		goto probe_error_ret;
	}

	v4l2_i2c_subdev_init(&ov01a1s->sd, client, &ov01a1s_subdev_ops);
	ret = ov01a1s_identify_module(ov01a1s);
	if (ret) {
		dev_err(&client->dev, "failed to find sensor: %d", ret);
		goto probe_error_ret;
	}

	mutex_init(&ov01a1s->mutex);
	ov01a1s->cur_mode = &supported_modes[0];
	ret = ov01a1s_init_controls(ov01a1s);
	if (ret) {
		dev_err(&client->dev, "failed to init controls: %d", ret);
		goto probe_error_v4l2_ctrl_handler_free;
	}

	ov01a1s->sd.internal_ops = &ov01a1s_internal_ops;
	ov01a1s->sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	ov01a1s->sd.entity.ops = &ov01a1s_subdev_entity_ops;
	ov01a1s->sd.entity.function = MEDIA_ENT_F_CAM_SENSOR;
	ov01a1s->pad.flags = MEDIA_PAD_FL_SOURCE;
	ret = media_entity_pads_init(&ov01a1s->sd.entity, 1, &ov01a1s->pad);
	if (ret) {
		dev_err(&client->dev, "failed to init entity pads: %d", ret);
		goto probe_error_v4l2_ctrl_handler_free;
	}

	ret = v4l2_async_register_subdev_sensor(&ov01a1s->sd);
	if (ret < 0) {
		dev_err(&client->dev, "failed to register V4L2 subdev: %d",
			ret);
		goto probe_error_media_entity_cleanup;
	}

	/*
	 * Device is already turned on by i2c-core with ACPI domain PM.
	 * Enable runtime PM and turn off the device.
	 */
	pm_runtime_set_active(&client->dev);
	pm_runtime_enable(&client->dev);
	pm_runtime_idle(&client->dev);

	power_ctrl_logic_set_power(0);
	return 0;

probe_error_media_entity_cleanup:
	media_entity_cleanup(&ov01a1s->sd.entity);

probe_error_v4l2_ctrl_handler_free:
	v4l2_ctrl_handler_free(ov01a1s->sd.ctrl_handler);
	mutex_destroy(&ov01a1s->mutex);

probe_error_ret:
	power_ctrl_logic_set_power(0);
	return ret;
}

static const struct dev_pm_ops ov01a1s_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(ov01a1s_suspend, ov01a1s_resume)
};

#ifdef CONFIG_ACPI
static const struct acpi_device_id ov01a1s_acpi_ids[] = {
	{ "OVTI01AS" },
	{}
};

MODULE_DEVICE_TABLE(acpi, ov01a1s_acpi_ids);
#endif

static struct i2c_driver ov01a1s_i2c_driver = {
	.driver = {
		.name = "ov01a1s",
		.pm = &ov01a1s_pm_ops,
		.acpi_match_table = ACPI_PTR(ov01a1s_acpi_ids),
	},
	.probe_new = ov01a1s_probe,
	.remove = ov01a1s_remove,
};

module_i2c_driver(ov01a1s_i2c_driver);

MODULE_AUTHOR("Xu, Chongyang <chongyang.xu@intel.com>");
MODULE_AUTHOR("Lai, Jim <jim.lai@intel.com>");
MODULE_AUTHOR("Qiu, Tianshu <tian.shu.qiu@intel.com>");
MODULE_AUTHOR("Shawn Tu <shawnx.tu@intel.com>");
MODULE_AUTHOR("Bingbu Cao <bingbu.cao@intel.com>");
MODULE_DESCRIPTION("OmniVision OV01A1S sensor driver");
MODULE_LICENSE("GPL v2");
