/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2014 - 2020 Intel Corporation */

#ifndef MEDIA_IPU_H
#define MEDIA_IPU_H

#include <linux/i2c.h>
#include <linux/clkdev.h>
#include <media/v4l2-async.h>

#define IPU_ISYS_MAX_CSI2_LANES		4

struct ipu_isys_csi2_config {
	unsigned int nlanes;
	unsigned int port;
};

struct ipu_isys_subdev_i2c_info {
	struct i2c_board_info board_info;
	int i2c_adapter_id;
	char i2c_adapter_bdf[32];
};

struct ipu_isys_subdev_info {
	struct ipu_isys_csi2_config *csi2;
	struct ipu_isys_subdev_i2c_info i2c;
};

struct ipu_isys_clk_mapping {
	struct clk_lookup clkdev_data;
	char *platform_clock_name;
};

struct ipu_isys_subdev_pdata {
	struct ipu_isys_subdev_info **subdevs;
	struct ipu_isys_clk_mapping *clk_map;
};

struct sensor_async_subdev {
	struct v4l2_async_subdev asd;
	struct ipu_isys_csi2_config csi2;
};

#endif /* MEDIA_IPU_H */
