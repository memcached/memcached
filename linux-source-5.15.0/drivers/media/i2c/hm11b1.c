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

#define HM11B1_LINK_FREQ_384MHZ		384000000ULL
#define HM11B1_SCLK			72000000LL
#define HM11B1_MCLK			19200000
#define HM11B1_DATA_LANES		1
#define HM11B1_RGB_DEPTH		10

#define HM11B1_REG_CHIP_ID		0x0000
#define HM11B1_CHIP_ID			0x11B1

#define HM11B1_REG_MODE_SELECT		0x0100
#define HM11B1_MODE_STANDBY		0x00
#define HM11B1_MODE_STREAMING		0x01

/* vertical-timings from sensor */
#define HM11B1_REG_VTS			0x3402
#define HM11B1_VTS_DEF			0x037d
#define HM11B1_VTS_MIN			0x0346
#define HM11B1_VTS_MAX			0xffff

/* horizontal-timings from sensor */
#define HM11B1_REG_HTS			0x3404

/* Exposure controls from sensor */
#define HM11B1_REG_EXPOSURE		0x0202
#define HM11B1_EXPOSURE_MIN		2
#define HM11B1_EXPOSURE_MAX_MARGIN	2
#define HM11B1_EXPOSURE_STEP		1

/* Analog gain controls from sensor */
#define HM11B1_REG_ANALOG_GAIN		0x0205
#define HM11B1_REG_ANALOG_GAIN_IR	0x0206
#define HM11B1_ANAL_GAIN_MIN		0
#define HM11B1_ANAL_GAIN_MAX		0xFF
#define HM11B1_ANAL_GAIN_STEP		1

/* Digital gain controls from sensor */
#define HM11B1_REG_DGTL_GAIN		0x0207
#define HM11B1_REG_DGTL_GAIN_IR		0x0209
#define HM11B1_DGTL_GAIN_MIN		0x0
#define HM11B1_DGTL_GAIN_MAX		0x3FF
#define HM11B1_DGTL_GAIN_STEP		1
#define HM11B1_DGTL_GAIN_DEFAULT	0x100
/* register update control */
#define HM11B1_REG_COMMAND_UPDATE	0x104

/* Test Pattern Control */
#define HM11B1_REG_TEST_PATTERN		0x0601
#define HM11B1_TEST_PATTERN_ENABLE	1
#define HM11B1_TEST_PATTERN_BAR_SHIFT	1

enum {
	HM11B1_LINK_FREQ_384MHZ_INDEX,
};

struct hm11b1_reg {
	u16 address;
	u8 val;
};

struct hm11b1_reg_list {
	u32 num_of_regs;
	const struct hm11b1_reg *regs;
};

struct hm11b1_link_freq_config {
	const struct hm11b1_reg_list reg_list;
};

struct hm11b1_mode {
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
	const struct hm11b1_reg_list reg_list;
};

static const struct hm11b1_reg mipi_data_rate_384mbps[] = {
};

//RAW 10bit 1292x800_30fps_MIPI 384Mbps/lane
static const struct hm11b1_reg sensor_1292x800_30fps_setting[] = {
	{0x0103, 0x00},
	{0x0102, 0x01},
	{0x0202, 0x03},
	{0x0203, 0x7C},
	{0x0205, 0x20},
	{0x0207, 0x01},
	{0x0208, 0x00},
	{0x0209, 0x01},
	{0x020A, 0x00},
	{0x0300, 0x91},
	{0x0301, 0x0A},
	{0x0302, 0x02},
	{0x0303, 0x2E},
	{0x0304, 0x43},
	{0x0306, 0x00},
	{0x0307, 0x00},
	{0x0340, 0x03},
	{0x0341, 0x60},
	{0x0342, 0x05},
	{0x0343, 0xA0},
	{0x0344, 0x00},
	{0x0345, 0x00},
	{0x0346, 0x03},
	{0x0347, 0x2F},
	{0x0350, 0xFF},
	{0x0351, 0x00},
	{0x0352, 0x00},
	{0x0370, 0x00},
	{0x0371, 0x00},
	{0x0380, 0x00},
	{0x0381, 0x00},
	{0x0382, 0x00},
	{0x1000, 0xC3},
	{0x1001, 0xD0},
	{0x100A, 0x13},
	{0x2000, 0x00},
	{0x2061, 0x01},
	{0x2062, 0x00},
	{0x2063, 0xC8},
	{0x2100, 0x03},
	{0x2101, 0xF0},
	{0x2102, 0xF0},
	{0x2103, 0x01},
	{0x2104, 0x10},
	{0x2105, 0x10},
	{0x2106, 0x02},
	{0x2107, 0x0A},
	{0x2108, 0x10},
	{0x2109, 0x15},
	{0x210A, 0x1A},
	{0x210B, 0x20},
	{0x210C, 0x08},
	{0x210D, 0x0A},
	{0x210E, 0x0F},
	{0x210F, 0x12},
	{0x2110, 0x1C},
	{0x2111, 0x20},
	{0x2112, 0x23},
	{0x2113, 0x2A},
	{0x2114, 0x30},
	{0x2115, 0x10},
	{0x2116, 0x00},
	{0x2117, 0x01},
	{0x2118, 0x00},
	{0x2119, 0x06},
	{0x211A, 0x00},
	{0x211B, 0x00},
	{0x2615, 0x08},
	{0x2616, 0x00},
	{0x2700, 0x01},
	{0x2711, 0x01},
	{0x272F, 0x01},
	{0x2800, 0x29},
	{0x2821, 0xCE},
	{0x2839, 0x27},
	{0x283A, 0x01},
	{0x2842, 0x01},
	{0x2843, 0x00},
	{0x3022, 0x11},
	{0x3024, 0x30},
	{0x3025, 0x12},
	{0x3026, 0x00},
	{0x3027, 0x81},
	{0x3028, 0x01},
	{0x3029, 0x00},
	{0x302A, 0x30},
	{0x3030, 0x00},
	{0x3032, 0x00},
	{0x3035, 0x01},
	{0x303E, 0x00},
	{0x3051, 0x00},
	{0x3082, 0x0E},
	{0x3084, 0x0D},
	{0x30A8, 0x03},
	{0x30C4, 0xA0},
	{0x30D5, 0xC1},
	{0x30D8, 0x00},
	{0x30D9, 0x0D},
	{0x30DB, 0xC2},
	{0x30DE, 0x25},
	{0x30E1, 0xC3},
	{0x30E4, 0x25},
	{0x30E7, 0xC4},
	{0x30EA, 0x25},
	{0x30ED, 0xC5},
	{0x30F0, 0x25},
	{0x30F2, 0x0C},
	{0x30F3, 0x85},
	{0x30F6, 0x25},
	{0x30F8, 0x0C},
	{0x30F9, 0x05},
	{0x30FB, 0x40},
	{0x30FC, 0x25},
	{0x30FD, 0x54},
	{0x30FE, 0x0C},
	{0x3100, 0xC2},
	{0x3103, 0x00},
	{0x3104, 0x2B},
	{0x3106, 0xC3},
	{0x3109, 0x25},
	{0x310C, 0xC4},
	{0x310F, 0x25},
	{0x3112, 0xC5},
	{0x3115, 0x25},
	{0x3117, 0x0C},
	{0x3118, 0x85},
	{0x311B, 0x25},
	{0x311D, 0x0C},
	{0x311E, 0x05},
	{0x3121, 0x25},
	{0x3123, 0x0C},
	{0x3124, 0x0D},
	{0x3126, 0x40},
	{0x3127, 0x25},
	{0x3128, 0x54},
	{0x3129, 0x0C},
	{0x3130, 0x20},
	{0x3134, 0x60},
	{0x3135, 0xC2},
	{0x3139, 0x12},
	{0x313A, 0x07},
	{0x313F, 0x52},
	{0x3140, 0x34},
	{0x3141, 0x2E},
	{0x314F, 0x07},
	{0x3151, 0x47},
	{0x3153, 0xB0},
	{0x3154, 0x4A},
	{0x3155, 0xC0},
	{0x3157, 0x55},
	{0x3158, 0x01},
	{0x3165, 0xFF},
	{0x316B, 0x12},
	{0x316E, 0x12},
	{0x3176, 0x12},
	{0x3178, 0x01},
	{0x317C, 0x10},
	{0x317D, 0x05},
	{0x317F, 0x07},
	{0x3182, 0x07},
	{0x3183, 0x11},
	{0x3184, 0x88},
	{0x3186, 0x28},
	{0x3191, 0x00},
	{0x3192, 0x20},
	{0x3400, 0x48},
	{0x3401, 0x00},
	{0x3402, 0x06},
	{0x3403, 0xFA},
	{0x3404, 0x05},
	{0x3405, 0x40},
	{0x3406, 0x00},
	{0x3407, 0x00},
	{0x3408, 0x03},
	{0x3409, 0x2F},
	{0x340A, 0x00},
	{0x340B, 0x00},
	{0x340C, 0x00},
	{0x340D, 0x00},
	{0x340E, 0x00},
	{0x340F, 0x00},
	{0x3410, 0x00},
	{0x3411, 0x01},
	{0x3412, 0x00},
	{0x3413, 0x03},
	{0x3414, 0xB0},
	{0x3415, 0x4A},
	{0x3416, 0xC0},
	{0x3418, 0x55},
	{0x3419, 0x03},
	{0x341B, 0x7D},
	{0x341C, 0x00},
	{0x341F, 0x03},
	{0x3420, 0x00},
	{0x3421, 0x02},
	{0x3422, 0x00},
	{0x3423, 0x02},
	{0x3424, 0x01},
	{0x3425, 0x02},
	{0x3426, 0x00},
	{0x3427, 0xA2},
	{0x3428, 0x01},
	{0x3429, 0x06},
	{0x342A, 0xF8},
	{0x3440, 0x01},
	{0x3441, 0xBE},
	{0x3442, 0x02},
	{0x3443, 0x18},
	{0x3444, 0x03},
	{0x3445, 0x0C},
	{0x3446, 0x06},
	{0x3447, 0x18},
	{0x3448, 0x09},
	{0x3449, 0x24},
	{0x344A, 0x08},
	{0x344B, 0x08},
	{0x345C, 0x00},
	{0x345D, 0x44},
	{0x345E, 0x02},
	{0x345F, 0x43},
	{0x3460, 0x04},
	{0x3461, 0x3B},
	{0x3466, 0xF8},
	{0x3467, 0x43},
	{0x347D, 0x02},
	{0x3483, 0x05},
	{0x3484, 0x0C},
	{0x3485, 0x03},
	{0x3486, 0x20},
	{0x3487, 0x00},
	{0x3488, 0x00},
	{0x3489, 0x00},
	{0x348A, 0x09},
	{0x348B, 0x00},
	{0x348C, 0x00},
	{0x348D, 0x02},
	{0x348E, 0x01},
	{0x348F, 0x40},
	{0x3490, 0x00},
	{0x3491, 0xC8},
	{0x3492, 0x00},
	{0x3493, 0x02},
	{0x3494, 0x00},
	{0x3495, 0x02},
	{0x3496, 0x02},
	{0x3497, 0x06},
	{0x3498, 0x05},
	{0x3499, 0x04},
	{0x349A, 0x09},
	{0x349B, 0x05},
	{0x349C, 0x17},
	{0x349D, 0x05},
	{0x349E, 0x00},
	{0x349F, 0x00},
	{0x34A0, 0x00},
	{0x34A1, 0x00},
	{0x34A2, 0x08},
	{0x34A3, 0x08},
	{0x34A4, 0x00},
	{0x34A5, 0x0B},
	{0x34A6, 0x0C},
	{0x34A7, 0x32},
	{0x34A8, 0x10},
	{0x34A9, 0xE0},
	{0x34AA, 0x52},
	{0x34AB, 0x00},
	{0x34AC, 0x60},
	{0x34AD, 0x2B},
	{0x34AE, 0x25},
	{0x34AF, 0x48},
	{0x34B1, 0x06},
	{0x34B2, 0xF8},
	{0x34C3, 0xB0},
	{0x34C4, 0x4A},
	{0x34C5, 0xC0},
	{0x34C7, 0x55},
	{0x34C8, 0x03},
	{0x34CB, 0x00},
	{0x353A, 0x00},
	{0x355E, 0x48},
	{0x3572, 0xB0},
	{0x3573, 0x4A},
	{0x3574, 0xC0},
	{0x3576, 0x55},
	{0x3577, 0x03},
	{0x357A, 0x00},
	{0x35DA, 0x00},
	{0x4003, 0x02},
	{0x4004, 0x02},
};

static const char * const hm11b1_test_pattern_menu[] = {
	"Disabled",
	"Solid Color",
	"Color Bar",
	"Color Bar Blending",
	"PN11",
};

static const s64 link_freq_menu_items[] = {
	HM11B1_LINK_FREQ_384MHZ,
};

static const struct hm11b1_link_freq_config link_freq_configs[] = {
	[HM11B1_LINK_FREQ_384MHZ_INDEX] = {
		.reg_list = {
			.num_of_regs = ARRAY_SIZE(mipi_data_rate_384mbps),
			.regs = mipi_data_rate_384mbps,
		}
	},
};

static const struct hm11b1_mode supported_modes[] = {
	{
		.width = 1292,
		.height = 800,
		.hts = 1344,
		.vts_def = HM11B1_VTS_DEF,
		.vts_min = HM11B1_VTS_MIN,
		.reg_list = {
			.num_of_regs =
				ARRAY_SIZE(sensor_1292x800_30fps_setting),
			.regs = sensor_1292x800_30fps_setting,
		},
		.link_freq_index = HM11B1_LINK_FREQ_384MHZ_INDEX,
	},
};

struct hm11b1 {
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
	const struct hm11b1_mode *cur_mode;

	/* To serialize asynchronus callbacks */
	struct mutex mutex;

	/* Streaming on/off */
	bool streaming;
};

static inline struct hm11b1 *to_hm11b1(struct v4l2_subdev *subdev)
{
	return container_of(subdev, struct hm11b1, sd);
}

static u64 to_pixel_rate(u32 f_index)
{
	u64 pixel_rate = link_freq_menu_items[f_index] * 2 * HM11B1_DATA_LANES;

	do_div(pixel_rate, HM11B1_RGB_DEPTH);

	return pixel_rate;
}

static u64 to_pixels_per_line(u32 hts, u32 f_index)
{
	u64 ppl = hts * to_pixel_rate(f_index);

	do_div(ppl, HM11B1_SCLK);

	return ppl;
}

static int hm11b1_read_reg(struct hm11b1 *hm11b1, u16 reg, u16 len, u32 *val)
{
	struct i2c_client *client = v4l2_get_subdevdata(&hm11b1->sd);
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

static int hm11b1_write_reg(struct hm11b1 *hm11b1, u16 reg, u16 len, u32 val)
{
	struct i2c_client *client = v4l2_get_subdevdata(&hm11b1->sd);
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

static int hm11b1_write_reg_list(struct hm11b1 *hm11b1,
				 const struct hm11b1_reg_list *r_list)
{
	struct i2c_client *client = v4l2_get_subdevdata(&hm11b1->sd);
	unsigned int i;
	int ret = 0;

	for (i = 0; i < r_list->num_of_regs; i++) {
		ret = hm11b1_write_reg(hm11b1, r_list->regs[i].address, 1,
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

static int hm11b1_update_digital_gain(struct hm11b1 *hm11b1, u32 d_gain)
{
	struct i2c_client *client = v4l2_get_subdevdata(&hm11b1->sd);
	int ret = 0;

	ret = hm11b1_write_reg(hm11b1, HM11B1_REG_DGTL_GAIN, 2, d_gain);
	if (ret) {
		dev_err(&client->dev, "failed to set HM11B1_REG_DGTL_GAIN");
		return ret;
	}

	ret = hm11b1_write_reg(hm11b1, HM11B1_REG_DGTL_GAIN_IR, 2, d_gain);
	if (ret) {
		dev_err(&client->dev, "failed to set HM11B1_REG_DGTL_GAIN_IR");
		return ret;
	}

	return ret;
}

static int hm11b1_test_pattern(struct hm11b1 *hm11b1, u32 pattern)
{
	if (pattern)
		pattern = pattern << HM11B1_TEST_PATTERN_BAR_SHIFT |
			  HM11B1_TEST_PATTERN_ENABLE;

	return hm11b1_write_reg(hm11b1, HM11B1_REG_TEST_PATTERN, 1, pattern);
}

static int hm11b1_set_ctrl(struct v4l2_ctrl *ctrl)
{
	struct hm11b1 *hm11b1 = container_of(ctrl->handler,
					     struct hm11b1, ctrl_handler);
	struct i2c_client *client = v4l2_get_subdevdata(&hm11b1->sd);
	s64 exposure_max;
	int ret = 0;

	/* Propagate change of current control to all related controls */
	if (ctrl->id == V4L2_CID_VBLANK) {
		/* Update max exposure while meeting expected vblanking */
		exposure_max = hm11b1->cur_mode->height + ctrl->val -
			       HM11B1_EXPOSURE_MAX_MARGIN;
		__v4l2_ctrl_modify_range(hm11b1->exposure,
					 hm11b1->exposure->minimum,
					 exposure_max, hm11b1->exposure->step,
					 exposure_max);
	}

	/* V4L2 controls values will be applied only when power is already up */
	if (!pm_runtime_get_if_in_use(&client->dev))
		return 0;

	ret = hm11b1_write_reg(hm11b1, HM11B1_REG_COMMAND_UPDATE, 1, 1);
	if (ret) {
		dev_err(&client->dev, "failed to enable HM11B1_REG_COMMAND_UPDATE");
		pm_runtime_put(&client->dev);
		return ret;
	}
	switch (ctrl->id) {
	case V4L2_CID_ANALOGUE_GAIN:
		ret = hm11b1_write_reg(hm11b1, HM11B1_REG_ANALOG_GAIN, 1,
				       ctrl->val);
		ret |= hm11b1_write_reg(hm11b1, HM11B1_REG_ANALOG_GAIN_IR, 1,
					ctrl->val);
		break;

	case V4L2_CID_DIGITAL_GAIN:
		ret = hm11b1_update_digital_gain(hm11b1, ctrl->val);
		break;

	case V4L2_CID_EXPOSURE:
		/* 4 least significant bits of expsoure are fractional part */
		ret = hm11b1_write_reg(hm11b1, HM11B1_REG_EXPOSURE, 2,
				       ctrl->val);
		break;

	case V4L2_CID_VBLANK:
		ret = hm11b1_write_reg(hm11b1, HM11B1_REG_VTS, 2,
				       hm11b1->cur_mode->height + ctrl->val);
		break;

	case V4L2_CID_TEST_PATTERN:
		ret = hm11b1_test_pattern(hm11b1, ctrl->val);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	ret |= hm11b1_write_reg(hm11b1, HM11B1_REG_COMMAND_UPDATE, 1, 0);
	pm_runtime_put(&client->dev);

	return ret;
}

static const struct v4l2_ctrl_ops hm11b1_ctrl_ops = {
	.s_ctrl = hm11b1_set_ctrl,
};

static int hm11b1_init_controls(struct hm11b1 *hm11b1)
{
	struct v4l2_ctrl_handler *ctrl_hdlr;
	const struct hm11b1_mode *cur_mode;
	s64 exposure_max, h_blank, pixel_rate;
	u32 vblank_min, vblank_max, vblank_default;
	int size;
	int ret = 0;

	ctrl_hdlr = &hm11b1->ctrl_handler;
	ret = v4l2_ctrl_handler_init(ctrl_hdlr, 8);
	if (ret)
		return ret;

	ctrl_hdlr->lock = &hm11b1->mutex;
	cur_mode = hm11b1->cur_mode;
	size = ARRAY_SIZE(link_freq_menu_items);

	hm11b1->link_freq = v4l2_ctrl_new_int_menu(ctrl_hdlr, &hm11b1_ctrl_ops,
						   V4L2_CID_LINK_FREQ,
						   size - 1, 0,
						   link_freq_menu_items);
	if (hm11b1->link_freq)
		hm11b1->link_freq->flags |= V4L2_CTRL_FLAG_READ_ONLY;

	pixel_rate = to_pixel_rate(HM11B1_LINK_FREQ_384MHZ_INDEX);
	hm11b1->pixel_rate = v4l2_ctrl_new_std(ctrl_hdlr, &hm11b1_ctrl_ops,
					       V4L2_CID_PIXEL_RATE, 0,
					       pixel_rate, 1, pixel_rate);

	vblank_min = cur_mode->vts_min - cur_mode->height;
	vblank_max = HM11B1_VTS_MAX - cur_mode->height;
	vblank_default = cur_mode->vts_def - cur_mode->height;
	hm11b1->vblank = v4l2_ctrl_new_std(ctrl_hdlr, &hm11b1_ctrl_ops,
					   V4L2_CID_VBLANK, vblank_min,
					   vblank_max, 1, vblank_default);

	h_blank = to_pixels_per_line(cur_mode->hts, cur_mode->link_freq_index);
	h_blank -= cur_mode->width;
	hm11b1->hblank = v4l2_ctrl_new_std(ctrl_hdlr, &hm11b1_ctrl_ops,
					   V4L2_CID_HBLANK, h_blank, h_blank, 1,
					   h_blank);
	if (hm11b1->hblank)
		hm11b1->hblank->flags |= V4L2_CTRL_FLAG_READ_ONLY;

	v4l2_ctrl_new_std(ctrl_hdlr, &hm11b1_ctrl_ops, V4L2_CID_ANALOGUE_GAIN,
			  HM11B1_ANAL_GAIN_MIN, HM11B1_ANAL_GAIN_MAX,
			  HM11B1_ANAL_GAIN_STEP, HM11B1_ANAL_GAIN_MIN);
	v4l2_ctrl_new_std(ctrl_hdlr, &hm11b1_ctrl_ops, V4L2_CID_DIGITAL_GAIN,
			  HM11B1_DGTL_GAIN_MIN, HM11B1_DGTL_GAIN_MAX,
			  HM11B1_DGTL_GAIN_STEP, HM11B1_DGTL_GAIN_DEFAULT);
	exposure_max = cur_mode->vts_def - HM11B1_EXPOSURE_MAX_MARGIN;
	hm11b1->exposure = v4l2_ctrl_new_std(ctrl_hdlr, &hm11b1_ctrl_ops,
					     V4L2_CID_EXPOSURE,
					     HM11B1_EXPOSURE_MIN, exposure_max,
					     HM11B1_EXPOSURE_STEP,
					     exposure_max);
	v4l2_ctrl_new_std_menu_items(ctrl_hdlr, &hm11b1_ctrl_ops,
				     V4L2_CID_TEST_PATTERN,
				     ARRAY_SIZE(hm11b1_test_pattern_menu) - 1,
				     0, 0, hm11b1_test_pattern_menu);
	if (ctrl_hdlr->error)
		return ctrl_hdlr->error;

	hm11b1->sd.ctrl_handler = ctrl_hdlr;

	return 0;
}

static void hm11b1_update_pad_format(const struct hm11b1_mode *mode,
				     struct v4l2_mbus_framefmt *fmt)
{
	fmt->width = mode->width;
	fmt->height = mode->height;
	fmt->code = MEDIA_BUS_FMT_SGRBG10_1X10;
	fmt->field = V4L2_FIELD_NONE;
}

static int hm11b1_start_streaming(struct hm11b1 *hm11b1)
{
	struct i2c_client *client = v4l2_get_subdevdata(&hm11b1->sd);
	const struct hm11b1_reg_list *reg_list;
	int link_freq_index;
	int ret = 0;

	power_ctrl_logic_set_power(1);
	link_freq_index = hm11b1->cur_mode->link_freq_index;
	reg_list = &link_freq_configs[link_freq_index].reg_list;
	ret = hm11b1_write_reg_list(hm11b1, reg_list);
	if (ret) {
		dev_err(&client->dev, "failed to set plls");
		return ret;
	}

	reg_list = &hm11b1->cur_mode->reg_list;
	ret = hm11b1_write_reg_list(hm11b1, reg_list);
	if (ret) {
		dev_err(&client->dev, "failed to set mode");
		return ret;
	}

	ret = __v4l2_ctrl_handler_setup(hm11b1->sd.ctrl_handler);
	if (ret)
		return ret;

	ret = hm11b1_write_reg(hm11b1, HM11B1_REG_MODE_SELECT, 1,
			       HM11B1_MODE_STREAMING);
	if (ret)
		dev_err(&client->dev, "failed to start streaming");

	return ret;
}

static void hm11b1_stop_streaming(struct hm11b1 *hm11b1)
{
	struct i2c_client *client = v4l2_get_subdevdata(&hm11b1->sd);

	if (hm11b1_write_reg(hm11b1, HM11B1_REG_MODE_SELECT, 1,
			     HM11B1_MODE_STANDBY))
		dev_err(&client->dev, "failed to stop streaming");
	power_ctrl_logic_set_power(0);
}

static int hm11b1_set_stream(struct v4l2_subdev *sd, int enable)
{
	struct hm11b1 *hm11b1 = to_hm11b1(sd);
	struct i2c_client *client = v4l2_get_subdevdata(sd);
	int ret = 0;

	if (hm11b1->streaming == enable)
		return 0;

	mutex_lock(&hm11b1->mutex);
	if (enable) {
		ret = pm_runtime_get_sync(&client->dev);
		if (ret < 0) {
			pm_runtime_put_noidle(&client->dev);
			mutex_unlock(&hm11b1->mutex);
			return ret;
		}

		ret = hm11b1_start_streaming(hm11b1);
		if (ret) {
			enable = 0;
			hm11b1_stop_streaming(hm11b1);
			pm_runtime_put(&client->dev);
		}
	} else {
		hm11b1_stop_streaming(hm11b1);
		pm_runtime_put(&client->dev);
	}

	hm11b1->streaming = enable;
	mutex_unlock(&hm11b1->mutex);

	return ret;
}

static int __maybe_unused hm11b1_suspend(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct hm11b1 *hm11b1 = to_hm11b1(sd);

	mutex_lock(&hm11b1->mutex);
	if (hm11b1->streaming)
		hm11b1_stop_streaming(hm11b1);

	mutex_unlock(&hm11b1->mutex);

	return 0;
}

static int __maybe_unused hm11b1_resume(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct hm11b1 *hm11b1 = to_hm11b1(sd);
	int ret = 0;

	mutex_lock(&hm11b1->mutex);
	if (!hm11b1->streaming)
		goto exit;

	ret = hm11b1_start_streaming(hm11b1);
	if (ret) {
		hm11b1->streaming = false;
		hm11b1_stop_streaming(hm11b1);
	}

exit:
	mutex_unlock(&hm11b1->mutex);
	return ret;
}

static int hm11b1_set_format(struct v4l2_subdev *sd,
			     struct v4l2_subdev_state *sd_state,
			     struct v4l2_subdev_format *fmt)
{
	struct hm11b1 *hm11b1 = to_hm11b1(sd);
	const struct hm11b1_mode *mode;
	s32 vblank_def, h_blank;

	mode = v4l2_find_nearest_size(supported_modes,
				      ARRAY_SIZE(supported_modes), width,
				      height, fmt->format.width,
				      fmt->format.height);

	mutex_lock(&hm11b1->mutex);
	hm11b1_update_pad_format(mode, &fmt->format);
	if (fmt->which == V4L2_SUBDEV_FORMAT_TRY) {
		*v4l2_subdev_get_try_format(sd, sd_state, fmt->pad) = fmt->format;
	} else {
		hm11b1->cur_mode = mode;
		__v4l2_ctrl_s_ctrl(hm11b1->link_freq, mode->link_freq_index);
		__v4l2_ctrl_s_ctrl_int64(hm11b1->pixel_rate,
					 to_pixel_rate(mode->link_freq_index));

		/* Update limits and set FPS to default */
		vblank_def = mode->vts_def - mode->height;
		__v4l2_ctrl_modify_range(hm11b1->vblank,
					 mode->vts_min - mode->height,
					 HM11B1_VTS_MAX - mode->height, 1,
					 vblank_def);
		__v4l2_ctrl_s_ctrl(hm11b1->vblank, vblank_def);
		h_blank = to_pixels_per_line(mode->hts, mode->link_freq_index) -
			  mode->width;
		__v4l2_ctrl_modify_range(hm11b1->hblank, h_blank, h_blank, 1,
					 h_blank);
	}
	mutex_unlock(&hm11b1->mutex);

	return 0;
}

static int hm11b1_get_format(struct v4l2_subdev *sd,
			     struct v4l2_subdev_state *sd_state,
			     struct v4l2_subdev_format *fmt)
{
	struct hm11b1 *hm11b1 = to_hm11b1(sd);

	mutex_lock(&hm11b1->mutex);
	if (fmt->which == V4L2_SUBDEV_FORMAT_TRY)
		fmt->format = *v4l2_subdev_get_try_format(&hm11b1->sd,
							  sd_state, fmt->pad);
	else
		hm11b1_update_pad_format(hm11b1->cur_mode, &fmt->format);

	mutex_unlock(&hm11b1->mutex);

	return 0;
}

static int hm11b1_enum_mbus_code(struct v4l2_subdev *sd,
				 struct v4l2_subdev_state *sd_state,
				 struct v4l2_subdev_mbus_code_enum *code)
{
	if (code->index > 0)
		return -EINVAL;

	code->code = MEDIA_BUS_FMT_SGRBG10_1X10;

	return 0;
}

static int hm11b1_enum_frame_size(struct v4l2_subdev *sd,
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

static int hm11b1_open(struct v4l2_subdev *sd, struct v4l2_subdev_fh *fh)
{
	struct hm11b1 *hm11b1 = to_hm11b1(sd);

	mutex_lock(&hm11b1->mutex);
	hm11b1_update_pad_format(&supported_modes[0],
				 v4l2_subdev_get_try_format(sd, fh->state, 0));
	mutex_unlock(&hm11b1->mutex);

	return 0;
}

static const struct v4l2_subdev_video_ops hm11b1_video_ops = {
	.s_stream = hm11b1_set_stream,
};

static const struct v4l2_subdev_pad_ops hm11b1_pad_ops = {
	.set_fmt = hm11b1_set_format,
	.get_fmt = hm11b1_get_format,
	.enum_mbus_code = hm11b1_enum_mbus_code,
	.enum_frame_size = hm11b1_enum_frame_size,
};

static const struct v4l2_subdev_ops hm11b1_subdev_ops = {
	.video = &hm11b1_video_ops,
	.pad = &hm11b1_pad_ops,
};

static const struct media_entity_operations hm11b1_subdev_entity_ops = {
	.link_validate = v4l2_subdev_link_validate,
};

static const struct v4l2_subdev_internal_ops hm11b1_internal_ops = {
	.open = hm11b1_open,
};

static int hm11b1_identify_module(struct hm11b1 *hm11b1)
{
	struct i2c_client *client = v4l2_get_subdevdata(&hm11b1->sd);
	int ret;
	u32 val;

	ret = hm11b1_read_reg(hm11b1, HM11B1_REG_CHIP_ID, 2, &val);
	if (ret)
		return ret;

	if (val != HM11B1_CHIP_ID) {
		dev_err(&client->dev, "chip id mismatch: %x!=%x",
			HM11B1_CHIP_ID, val);
		return -ENXIO;
	}

	return 0;
}

static int hm11b1_remove(struct i2c_client *client)
{
	struct v4l2_subdev *sd = i2c_get_clientdata(client);
	struct hm11b1 *hm11b1 = to_hm11b1(sd);

	v4l2_async_unregister_subdev(sd);
	media_entity_cleanup(&sd->entity);
	v4l2_ctrl_handler_free(sd->ctrl_handler);
	pm_runtime_disable(&client->dev);
	mutex_destroy(&hm11b1->mutex);

	return 0;
}

static int hm11b1_probe(struct i2c_client *client)
{
	struct hm11b1 *hm11b1;
	int ret = 0;

	hm11b1 = devm_kzalloc(&client->dev, sizeof(*hm11b1), GFP_KERNEL);
	if (!hm11b1)
		return -ENOMEM;

	v4l2_i2c_subdev_init(&hm11b1->sd, client, &hm11b1_subdev_ops);
	power_ctrl_logic_set_power(0);
	power_ctrl_logic_set_power(1);
	ret = hm11b1_identify_module(hm11b1);
	if (ret) {
		dev_err(&client->dev, "failed to find sensor: %d", ret);
		return ret;
	}

	mutex_init(&hm11b1->mutex);
	hm11b1->cur_mode = &supported_modes[0];
	ret = hm11b1_init_controls(hm11b1);
	if (ret) {
		dev_err(&client->dev, "failed to init controls: %d", ret);
		goto probe_error_v4l2_ctrl_handler_free;
	}

	hm11b1->sd.internal_ops = &hm11b1_internal_ops;
	hm11b1->sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	hm11b1->sd.entity.ops = &hm11b1_subdev_entity_ops;
	hm11b1->sd.entity.function = MEDIA_ENT_F_CAM_SENSOR;
	hm11b1->pad.flags = MEDIA_PAD_FL_SOURCE;
	ret = media_entity_pads_init(&hm11b1->sd.entity, 1, &hm11b1->pad);
	if (ret) {
		dev_err(&client->dev, "failed to init entity pads: %d", ret);
		goto probe_error_v4l2_ctrl_handler_free;
	}

	ret = v4l2_async_register_subdev_sensor(&hm11b1->sd);
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
	media_entity_cleanup(&hm11b1->sd.entity);

probe_error_v4l2_ctrl_handler_free:
	v4l2_ctrl_handler_free(hm11b1->sd.ctrl_handler);
	mutex_destroy(&hm11b1->mutex);

	return ret;
}

static const struct dev_pm_ops hm11b1_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(hm11b1_suspend, hm11b1_resume)
};

#ifdef CONFIG_ACPI
static const struct acpi_device_id hm11b1_acpi_ids[] = {
	{"HIMX11B1"},
	{}
};

MODULE_DEVICE_TABLE(acpi, hm11b1_acpi_ids);
#endif

static struct i2c_driver hm11b1_i2c_driver = {
	.driver = {
		.name = "hm11b1",
		.pm = &hm11b1_pm_ops,
		.acpi_match_table = ACPI_PTR(hm11b1_acpi_ids),
	},
	.probe_new = hm11b1_probe,
	.remove = hm11b1_remove,
};

module_i2c_driver(hm11b1_i2c_driver);

MODULE_AUTHOR("Qiu, Tianshu <tian.shu.qiu@intel.com>");
MODULE_AUTHOR("Shawn Tu <shawnx.tu@intel.com>");
MODULE_AUTHOR("Bingbu Cao <bingbu.cao@intel.com>");
MODULE_AUTHOR("Lai, Jim <jim.lai@intel.com>");
MODULE_DESCRIPTION("Himax HM11B1 sensor driver");
MODULE_LICENSE("GPL v2");
