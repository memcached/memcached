// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2013 - 2020 Intel Corporation
 */

#include <linux/delay.h>
#include <media/ipu-isys.h>
#include <media/v4l2-device.h>
#include "ipu.h"
#include "ipu-buttress.h"
#include "ipu-isys.h"
#include "ipu-isys-csi2.h"
#include "ipu-platform-regs.h"
#include "ipu-platform-isys-csi2-reg.h"
#include "ipu6-isys-csi2.h"
#include "ipu6-isys-phy.h"

#define LOOP (2000)

#define PHY_REG_INIT_CTL	     0x00000694
#define PHY_REG_INIT_CTL_PORT_OFFSET 0x00000600

struct phy_reg {
	u32 reg;
	u32 val;
};

static const struct phy_reg common_init_regs[] = {
	/* for TGL-U, use 0x80000000 */
	{0x00000040, 0x80000000},
	{0x00000044, 0x00a80880},
	{0x00000044, 0x00b80880},
	{0x00000010, 0x0000078c},
	{0x00000344, 0x2f4401e2},
	{0x00000544, 0x924401e2},
	{0x00000744, 0x594401e2},
	{0x00000944, 0x624401e2},
	{0x00000b44, 0xfc4401e2},
	{0x00000d44, 0xc54401e2},
	{0x00000f44, 0x034401e2},
	{0x00001144, 0x8f4401e2},
	{0x00001344, 0x754401e2},
	{0x00001544, 0xe94401e2},
	{0x00001744, 0xcb4401e2},
	{0x00001944, 0xfa4401e2}
};

static const struct phy_reg x1_port0_config_regs[] = {
	{0x00000694, 0xc80060fa},
	{0x00000680, 0x3d4f78ea},
	{0x00000690, 0x10a0140b},
	{0x000006a8, 0xdf04010a},
	{0x00000700, 0x57050060},
	{0x00000710, 0x0030001c},
	{0x00000738, 0x5f004444},
	{0x0000073c, 0x78464204},
	{0x00000748, 0x7821f940},
	{0x0000074c, 0xb2000433},
	{0x00000494, 0xfe6030fa},
	{0x00000480, 0x29ef5ed0},
	{0x00000490, 0x10a0540b},
	{0x000004a8, 0x7a01010a},
	{0x00000500, 0xef053460},
	{0x00000510, 0xe030101c},
	{0x00000538, 0xdf808444},
	{0x0000053c, 0xc8422204},
	{0x00000540, 0x0180088c},
	{0x00000574, 0x00000000},
	{0x00000000, 0x00000000}
};

static const struct phy_reg x1_port1_config_regs[] = {
	{0x00000c94, 0xc80060fa},
	{0x00000c80, 0xcf47abea},
	{0x00000c90, 0x10a0840b},
	{0x00000ca8, 0xdf04010a},
	{0x00000d00, 0x57050060},
	{0x00000d10, 0x0030001c},
	{0x00000d38, 0x5f004444},
	{0x00000d3c, 0x78464204},
	{0x00000d48, 0x7821f940},
	{0x00000d4c, 0xb2000433},
	{0x00000a94, 0xc91030fa},
	{0x00000a80, 0x5a166ed0},
	{0x00000a90, 0x10a0540b},
	{0x00000aa8, 0x5d060100},
	{0x00000b00, 0xef053460},
	{0x00000b10, 0xa030101c},
	{0x00000b38, 0xdf808444},
	{0x00000b3c, 0xc8422204},
	{0x00000b40, 0x0180088c},
	{0x00000b74, 0x00000000},
	{0x00000000, 0x00000000}
};

static const struct phy_reg x1_port2_config_regs[] = {
	{0x00001294, 0x28f000fa},
	{0x00001280, 0x08130cea},
	{0x00001290, 0x10a0140b},
	{0x000012a8, 0xd704010a},
	{0x00001300, 0x8d050060},
	{0x00001310, 0x0030001c},
	{0x00001338, 0xdf008444},
	{0x0000133c, 0x78422204},
	{0x00001348, 0x7821f940},
	{0x0000134c, 0x5a000433},
	{0x00001094, 0x2d20b0fa},
	{0x00001080, 0xade75dd0},
	{0x00001090, 0x10a0540b},
	{0x000010a8, 0xb101010a},
	{0x00001100, 0x33053460},
	{0x00001110, 0x0030101c},
	{0x00001138, 0xdf808444},
	{0x0000113c, 0xc8422204},
	{0x00001140, 0x8180088c},
	{0x00001174, 0x00000000},
	{0x00000000, 0x00000000}
};

static const struct phy_reg x1_port3_config_regs[] = {
	{0x00001894, 0xc80060fa},
	{0x00001880, 0x0f90fd6a},
	{0x00001890, 0x10a0840b},
	{0x000018a8, 0xdf04010a},
	{0x00001900, 0x57050060},
	{0x00001910, 0x0030001c},
	{0x00001938, 0x5f004444},
	{0x0000193c, 0x78464204},
	{0x00001948, 0x7821f940},
	{0x0000194c, 0xb2000433},
	{0x00001694, 0x3050d0fa},
	{0x00001680, 0x0ef6d050},
	{0x00001690, 0x10a0540b},
	{0x000016a8, 0xe301010a},
	{0x00001700, 0x69053460},
	{0x00001710, 0xa030101c},
	{0x00001738, 0xdf808444},
	{0x0000173c, 0xc8422204},
	{0x00001740, 0x0180088c},
	{0x00001774, 0x00000000},
	{0x00000000, 0x00000000}
};

static const struct phy_reg x2_port0_config_regs[] = {
	{0x00000694, 0xc80060fa},
	{0x00000680, 0x3d4f78ea},
	{0x00000690, 0x10a0140b},
	{0x000006a8, 0xdf04010a},
	{0x00000700, 0x57050060},
	{0x00000710, 0x0030001c},
	{0x00000738, 0x5f004444},
	{0x0000073c, 0x78464204},
	{0x00000748, 0x7821f940},
	{0x0000074c, 0xb2000433},
	{0x00000494, 0xc80060fa},
	{0x00000480, 0x29ef5ed8},
	{0x00000490, 0x10a0540b},
	{0x000004a8, 0x7a01010a},
	{0x00000500, 0xef053460},
	{0x00000510, 0xe030101c},
	{0x00000538, 0xdf808444},
	{0x0000053c, 0xc8422204},
	{0x00000540, 0x0180088c},
	{0x00000574, 0x00000000},
	{0x00000294, 0xc80060fa},
	{0x00000280, 0xcb45b950},
	{0x00000290, 0x10a0540b},
	{0x000002a8, 0x8c01010a},
	{0x00000300, 0xef053460},
	{0x00000310, 0x8030101c},
	{0x00000338, 0x41808444},
	{0x0000033c, 0x32422204},
	{0x00000340, 0x0180088c},
	{0x00000374, 0x00000000},
	{0x00000000, 0x00000000}
};

static const struct phy_reg x2_port1_config_regs[] = {
	{0x00000c94, 0xc80060fa},
	{0x00000c80, 0xcf47abea},
	{0x00000c90, 0x10a0840b},
	{0x00000ca8, 0xdf04010a},
	{0x00000d00, 0x57050060},
	{0x00000d10, 0x0030001c},
	{0x00000d38, 0x5f004444},
	{0x00000d3c, 0x78464204},
	{0x00000d48, 0x7821f940},
	{0x00000d4c, 0xb2000433},
	{0x00000a94, 0xc80060fa},
	{0x00000a80, 0x5a166ed8},
	{0x00000a90, 0x10a0540b},
	{0x00000aa8, 0x7a01010a},
	{0x00000b00, 0xef053460},
	{0x00000b10, 0xa030101c},
	{0x00000b38, 0xdf808444},
	{0x00000b3c, 0xc8422204},
	{0x00000b40, 0x0180088c},
	{0x00000b74, 0x00000000},
	{0x00000894, 0xc80060fa},
	{0x00000880, 0x4d4f21d0},
	{0x00000890, 0x10a0540b},
	{0x000008a8, 0x5601010a},
	{0x00000900, 0xef053460},
	{0x00000910, 0x8030101c},
	{0x00000938, 0xdf808444},
	{0x0000093c, 0xc8422204},
	{0x00000940, 0x0180088c},
	{0x00000974, 0x00000000},
	{0x00000000, 0x00000000}
};

static const struct phy_reg x2_port2_config_regs[] = {
	{0x00001294, 0xc80060fa},
	{0x00001280, 0x08130cea},
	{0x00001290, 0x10a0140b},
	{0x000012a8, 0xd704010a},
	{0x00001300, 0x8d050060},
	{0x00001310, 0x0030001c},
	{0x00001338, 0xdf008444},
	{0x0000133c, 0x78422204},
	{0x00001348, 0x7821f940},
	{0x0000134c, 0x5a000433},
	{0x00001094, 0xc80060fa},
	{0x00001080, 0xade75dd8},
	{0x00001090, 0x10a0540b},
	{0x000010a8, 0xb101010a},
	{0x00001100, 0x33053460},
	{0x00001110, 0x0030101c},
	{0x00001138, 0xdf808444},
	{0x0000113c, 0xc8422204},
	{0x00001140, 0x8180088c},
	{0x00001174, 0x00000000},
	{0x00000e94, 0xc80060fa},
	{0x00000e80, 0x0fbf16d0},
	{0x00000e90, 0x10a0540b},
	{0x00000ea8, 0x7a01010a},
	{0x00000f00, 0xf5053460},
	{0x00000f10, 0xc030101c},
	{0x00000f38, 0xdf808444},
	{0x00000f3c, 0xc8422204},
	{0x00000f40, 0x8180088c},
	{0x00000000, 0x00000000}
};

static const struct phy_reg x2_port3_config_regs[] = {
	{0x00001894, 0xc80060fa},
	{0x00001880, 0x0f90fd6a},
	{0x00001890, 0x10a0840b},
	{0x000018a8, 0xdf04010a},
	{0x00001900, 0x57050060},
	{0x00001910, 0x0030001c},
	{0x00001938, 0x5f004444},
	{0x0000193c, 0x78464204},
	{0x00001948, 0x7821f940},
	{0x0000194c, 0xb2000433},
	{0x00001694, 0xc80060fa},
	{0x00001680, 0x0ef6d058},
	{0x00001690, 0x10a0540b},
	{0x000016a8, 0x7a01010a},
	{0x00001700, 0x69053460},
	{0x00001710, 0xa030101c},
	{0x00001738, 0xdf808444},
	{0x0000173c, 0xc8422204},
	{0x00001740, 0x0180088c},
	{0x00001774, 0x00000000},
	{0x00001494, 0xc80060fa},
	{0x00001480, 0xf9d34bd0},
	{0x00001490, 0x10a0540b},
	{0x000014a8, 0x7a01010a},
	{0x00001500, 0x1b053460},
	{0x00001510, 0x0030101c},
	{0x00001538, 0xdf808444},
	{0x0000153c, 0xc8422204},
	{0x00001540, 0x8180088c},
	{0x00001574, 0x00000000},
	{0x00000000, 0x00000000}
};

static const struct phy_reg x4_port0_config_regs[] = {
	{0x00000694, 0xc80060fa},
	{0x00000680, 0x3d4f78fa},
	{0x00000690, 0x10a0140b},
	{0x000006a8, 0xdf04010a},
	{0x00000700, 0x57050060},
	{0x00000710, 0x0030001c},
	{0x00000738, 0x5f004444},
	{0x0000073c, 0x78464204},
	{0x00000748, 0x7821f940},
	{0x0000074c, 0xb2000433},
	{0x00000494, 0xfe6030fa},
	{0x00000480, 0x29ef5ed8},
	{0x00000490, 0x10a0540b},
	{0x000004a8, 0x7a01010a},
	{0x00000500, 0xef053460},
	{0x00000510, 0xe030101c},
	{0x00000538, 0xdf808444},
	{0x0000053c, 0xc8422204},
	{0x00000540, 0x0180088c},
	{0x00000574, 0x00000004},
	{0x00000294, 0x23e030fa},
	{0x00000280, 0xcb45b950},
	{0x00000290, 0x10a0540b},
	{0x000002a8, 0x8c01010a},
	{0x00000300, 0xef053460},
	{0x00000310, 0x8030101c},
	{0x00000338, 0x41808444},
	{0x0000033c, 0x32422204},
	{0x00000340, 0x0180088c},
	{0x00000374, 0x00000004},
	{0x00000894, 0x5620b0fa},
	{0x00000880, 0x4d4f21dc},
	{0x00000890, 0x10a0540b},
	{0x000008a8, 0x5601010a},
	{0x00000900, 0xef053460},
	{0x00000910, 0x8030101c},
	{0x00000938, 0xdf808444},
	{0x0000093c, 0xc8422204},
	{0x00000940, 0x0180088c},
	{0x00000974, 0x00000004},
	{0x00000a94, 0xc91030fa},
	{0x00000a80, 0x5a166ecc},
	{0x00000a90, 0x10a0540b},
	{0x00000aa8, 0x5d01010a},
	{0x00000b00, 0xef053460},
	{0x00000b10, 0xa030101c},
	{0x00000b38, 0xdf808444},
	{0x00000b3c, 0xc8422204},
	{0x00000b40, 0x0180088c},
	{0x00000b74, 0x00000004},
	{0x00000000, 0x00000000}
};

static const struct phy_reg x4_port1_config_regs[] = {
	{0x00000000, 0x00000000}
};

static const struct phy_reg x4_port2_config_regs[] = {
	{0x00001294, 0x28f000fa},
	{0x00001280, 0x08130cfa},
	{0x00001290, 0x10c0140b},
	{0x000012a8, 0xd704010a},
	{0x00001300, 0x8d050060},
	{0x00001310, 0x0030001c},
	{0x00001338, 0xdf008444},
	{0x0000133c, 0x78422204},
	{0x00001348, 0x7821f940},
	{0x0000134c, 0x5a000433},
	{0x00001094, 0x2d20b0fa},
	{0x00001080, 0xade75dd8},
	{0x00001090, 0x10a0540b},
	{0x000010a8, 0xb101010a},
	{0x00001100, 0x33053460},
	{0x00001110, 0x0030101c},
	{0x00001138, 0xdf808444},
	{0x0000113c, 0xc8422204},
	{0x00001140, 0x8180088c},
	{0x00001174, 0x00000004},
	{0x00000e94, 0xd308d0fa},
	{0x00000e80, 0x0fbf16d0},
	{0x00000e90, 0x10a0540b},
	{0x00000ea8, 0x2c01010a},
	{0x00000f00, 0xf5053460},
	{0x00000f10, 0xc030101c},
	{0x00000f38, 0xdf808444},
	{0x00000f3c, 0xc8422204},
	{0x00000f40, 0x8180088c},
	{0x00000f74, 0x00000004},
	{0x00001494, 0x136850fa},
	{0x00001480, 0xf9d34bdc},
	{0x00001490, 0x10a0540b},
	{0x000014a8, 0x5a01010a},
	{0x00001500, 0x1b053460},
	{0x00001510, 0x0030101c},
	{0x00001538, 0xdf808444},
	{0x0000153c, 0xc8422204},
	{0x00001540, 0x8180088c},
	{0x00001574, 0x00000004},
	{0x00001694, 0x3050d0fa},
	{0x00001680, 0x0ef6d04c},
	{0x00001690, 0x10a0540b},
	{0x000016a8, 0xe301010a},
	{0x00001700, 0x69053460},
	{0x00001710, 0xa030101c},
	{0x00001738, 0xdf808444},
	{0x0000173c, 0xc8422204},
	{0x00001740, 0x0180088c},
	{0x00001774, 0x00000004},
	{0x00000000, 0x00000000}
};

static const struct phy_reg x4_port3_config_regs[] = {
	{0x00000000, 0x00000000}
};

static const struct phy_reg *x1_config_regs[4] = {
	x1_port0_config_regs,
	x1_port1_config_regs,
	x1_port2_config_regs,
	x1_port3_config_regs
};

static const struct phy_reg *x2_config_regs[4] = {
	x2_port0_config_regs,
	x2_port1_config_regs,
	x2_port2_config_regs,
	x2_port3_config_regs
};

static const struct phy_reg *x4_config_regs[4] = {
	x4_port0_config_regs,
	x4_port1_config_regs,
	x4_port2_config_regs,
	x4_port3_config_regs
};

static const struct phy_reg **config_regs[3] = {
	x1_config_regs,
	x2_config_regs,
	x4_config_regs,
};

int ipu6_isys_phy_powerup_ack(struct ipu_isys *isys, unsigned int phy_id)
{
	unsigned int i;
	u32 val;
	void __iomem *isys_base = isys->pdata->base;

	val = readl(isys_base + CSI_REG_HUB_GPREG_PHY_CONTROL(phy_id));
	val |= CSI_REG_HUB_GPREG_PHY_CONTROL_PWR_EN;
	writel(val, isys_base + CSI_REG_HUB_GPREG_PHY_CONTROL(phy_id));

	for (i = 0; i < LOOP; i++) {
		if (readl(isys_base + CSI_REG_HUB_GPREG_PHY_STATUS(phy_id)) &
		    CSI_REG_HUB_GPREG_PHY_STATUS_POWER_ACK)
			return 0;
		usleep_range(100, 200);
	}

	dev_warn(&isys->adev->dev, "PHY%d powerup ack timeout", phy_id);

	return -ETIMEDOUT;
}

int ipu6_isys_phy_powerdown_ack(struct ipu_isys *isys, unsigned int phy_id)
{
	unsigned int i;
	u32 val;
	void __iomem *isys_base = isys->pdata->base;

	writel(0, isys_base + CSI_REG_HUB_GPREG_PHY_CONTROL(phy_id));
	for (i = 0; i < LOOP; i++) {
		usleep_range(10, 20);
		val = readl(isys_base + CSI_REG_HUB_GPREG_PHY_STATUS(phy_id));
		if (!(val & CSI_REG_HUB_GPREG_PHY_STATUS_POWER_ACK))
			return 0;
	}

	dev_warn(&isys->adev->dev, "PHY %d poweroff ack timeout.\n", phy_id);

	return -ETIMEDOUT;
}

int ipu6_isys_phy_reset(struct ipu_isys *isys, unsigned int phy_id,
			bool assert)
{
	void __iomem *isys_base = isys->pdata->base;
	u32 val;

	val = readl(isys_base + CSI_REG_HUB_GPREG_PHY_CONTROL(phy_id));
	if (assert)
		val |= CSI_REG_HUB_GPREG_PHY_CONTROL_RESET;
	else
		val &= ~(CSI_REG_HUB_GPREG_PHY_CONTROL_RESET);

	writel(val, isys_base + CSI_REG_HUB_GPREG_PHY_CONTROL(phy_id));

	return 0;
}

int ipu6_isys_phy_ready(struct ipu_isys *isys, unsigned int phy_id)
{
	unsigned int i;
	u32 val;
	void __iomem *isys_base = isys->pdata->base;

	for (i = 0; i < LOOP; i++) {
		val = readl(isys_base + CSI_REG_HUB_GPREG_PHY_STATUS(phy_id));
		dev_dbg(&isys->adev->dev, "PHY%d ready status 0x%x\n",
			phy_id, val);
		if (val & CSI_REG_HUB_GPREG_PHY_STATUS_PHY_READY)
			return 0;
		usleep_range(10, 20);
	}

	dev_warn(&isys->adev->dev, "PHY%d ready timeout\n", phy_id);

	return -ETIMEDOUT;
}

int ipu6_isys_phy_common_init(struct ipu_isys *isys)
{
	unsigned int phy_id;
	void __iomem *phy_base;
	struct ipu_bus_device *adev = to_ipu_bus_device(&isys->adev->dev);
	struct ipu_device *isp = adev->isp;
	void __iomem *isp_base = isp->base;
	struct v4l2_async_subdev *asd;
	struct sensor_async_subdev *s_asd;
	unsigned int i;

	list_for_each_entry(asd, &isys->notifier.asd_list, asd_list) {
		s_asd = container_of(asd, struct sensor_async_subdev, asd);
		phy_id = s_asd->csi2.port / 4;
		phy_base = isp_base + IPU6_ISYS_PHY_BASE(phy_id);

		for (i = 0 ; i < ARRAY_SIZE(common_init_regs); i++) {
			writel(common_init_regs[i].val,
				phy_base + common_init_regs[i].reg);
		}
	}

	return 0;
}

static int ipu6_isys_driver_port_to_phy_port(struct ipu_isys_csi2_config *cfg)
{
	int phy_port;
	int ret;

	if (!(cfg->nlanes == 4 || cfg->nlanes == 2 || cfg->nlanes == 1))
		return -EINVAL;

	/* B,F -> C0 A,E -> C1 C,G -> C2 D,H -> C4 */
	/* normalize driver port number */
	phy_port = cfg->port % 4;

	/* swap port number only for A and B */
	if (phy_port == 0)
		phy_port = 1;
	else if (phy_port == 1)
		phy_port = 0;

	ret = phy_port;

	/* check validity per lane configuration */
	if ((cfg->nlanes == 4) &&
		 !(phy_port == 0 || phy_port == 2))
		ret = -EINVAL;
	else if ((cfg->nlanes == 2 || cfg->nlanes == 1) &&
		 !(phy_port >= 0 && phy_port <= 3))
		ret = -EINVAL;

	return ret;
}

int ipu6_isys_phy_config(struct ipu_isys *isys)
{
	int phy_port;
	unsigned int phy_id;
	void __iomem *phy_base;
	struct ipu_bus_device *adev = to_ipu_bus_device(&isys->adev->dev);
	struct ipu_device *isp = adev->isp;
	void __iomem *isp_base = isp->base;
	const struct phy_reg **phy_config_regs;
	struct v4l2_async_subdev *asd;
	struct sensor_async_subdev *s_asd;
	struct ipu_isys_csi2_config cfg;
	int i;

	list_for_each_entry(asd, &isys->notifier.asd_list, asd_list) {
		s_asd = container_of(asd, struct sensor_async_subdev, asd);
		cfg.port = s_asd->csi2.port;
		cfg.nlanes = s_asd->csi2.nlanes;
		phy_port = ipu6_isys_driver_port_to_phy_port(&cfg);
		if (phy_port < 0) {
			dev_err(&isys->adev->dev, "invalid port %d for lane %d",
				cfg.port, cfg.nlanes);
			return -ENXIO;
		}

		phy_id = cfg.port / 4;
		phy_base = isp_base + IPU6_ISYS_PHY_BASE(phy_id);
		dev_dbg(&isys->adev->dev, "port%d PHY%u lanes %u\n",
			cfg.port, phy_id, cfg.nlanes);

		phy_config_regs = config_regs[cfg.nlanes/2];
		cfg.port = phy_port;
		for (i = 0; phy_config_regs[cfg.port][i].reg; i++) {
			writel(phy_config_regs[cfg.port][i].val,
				phy_base + phy_config_regs[cfg.port][i].reg);
		}
	}

	return 0;
}
