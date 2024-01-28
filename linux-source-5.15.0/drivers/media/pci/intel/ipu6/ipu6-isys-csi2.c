// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2020 Intel Corporation

#include <linux/delay.h>
#include <linux/spinlock.h>
#include <media/ipu-isys.h>
#include "ipu.h"
#include "ipu-buttress.h"
#include "ipu-isys.h"
#include "ipu-platform-buttress-regs.h"
#include "ipu-platform-regs.h"
#include "ipu-platform-isys-csi2-reg.h"
#include "ipu6-isys-csi2.h"
#include "ipu6-isys-phy.h"
#include "ipu-isys-csi2.h"

struct ipu6_csi2_error {
	const char *error_string;
	bool is_info_only;
};

struct ipu6_csi_irq_info_map {
	u32 irq_error_mask;
	u32 irq_num;
	unsigned int irq_base;
	unsigned int irq_base_ctrl2;
	struct ipu6_csi2_error *errors;
};

/*
 * Strings corresponding to CSI-2 receiver errors are here.
 * Corresponding macros are defined in the header file.
 */
static struct ipu6_csi2_error dphy_rx_errors[] = {
	{"Single packet header error corrected", true},
	{"Multiple packet header errors detected", true},
	{"Payload checksum (CRC) error", true},
	{"Transfer FIFO overflow", false},
	{"Reserved short packet data type detected", true},
	{"Reserved long packet data type detected", true},
	{"Incomplete long packet detected", false},
	{"Frame sync error", false},
	{"Line sync error", false},
	{"DPHY recoverable synchronization error", true},
	{"DPHY fatal error", false},
	{"DPHY elastic FIFO overflow", false},
	{"Inter-frame short packet discarded", true},
	{"Inter-frame long packet discarded", true},
	{"MIPI pktgen overflow", false},
	{"MIPI pktgen data loss", false},
	{"FIFO overflow", false},
	{"Lane deskew", false},
	{"SOT sync error", false},
	{"HSIDLE detected", false}
};

static refcount_t phy_power_ref_count[IPU_ISYS_CSI_PHY_NUM];

static int ipu6_csi2_phy_power_set(struct ipu_isys *isys,
				   struct ipu_isys_csi2_config *cfg, bool on)
{
	int ret = 0;
	unsigned int port, phy_id;
	refcount_t *ref;
	void __iomem *isys_base = isys->pdata->base;
	unsigned int nr;

	port = cfg->port;
	phy_id = port / 4;
	ref = &phy_power_ref_count[phy_id];
	dev_dbg(&isys->adev->dev, "for phy %d port %d, lanes: %d\n",
		phy_id, port, cfg->nlanes);

	nr = (ipu_ver == IPU_VER_6 || ipu_ver == IPU_VER_6EP) ?
		IPU6_ISYS_CSI_PORT_NUM : IPU6SE_ISYS_CSI_PORT_NUM;

	if (!isys_base || port >= nr) {
		dev_warn(&isys->adev->dev, "invalid port ID %d\n", port);
		return -EINVAL;
	}

	if (on) {
		if (refcount_read(ref)) {
			/* already up */
			dev_warn(&isys->adev->dev, "for phy %d is already UP",
				 phy_id);
			refcount_inc(ref);
			return 0;
		}

		ret = ipu6_isys_phy_powerup_ack(isys, phy_id);
		if (ret)
			return ret;

		ipu6_isys_phy_reset(isys, phy_id, 0);
		ipu6_isys_phy_common_init(isys);

		ret = ipu6_isys_phy_config(isys);
		if (ret)
			return ret;

		ipu6_isys_phy_reset(isys, phy_id, 1);
		ret = ipu6_isys_phy_ready(isys, phy_id);
		if (ret)
			return ret;

		refcount_set(ref, 1);
		return 0;
	}

	/* power off process */
	if (refcount_dec_and_test(ref))
		ret = ipu6_isys_phy_powerdown_ack(isys, phy_id);
	if (ret)
		dev_err(&isys->adev->dev, "phy poweroff failed!");

	return ret;
}

static void ipu6_isys_register_errors(struct ipu_isys_csi2 *csi2)
{
	u32 mask = 0;
	u32 irq = readl(csi2->base + CSI_PORT_REG_BASE_IRQ_CSI +
			CSI_PORT_REG_BASE_IRQ_STATUS_OFFSET);

	mask = (ipu_ver == IPU_VER_6 || ipu_ver == IPU_VER_6EP) ?
		IPU6_CSI_RX_ERROR_IRQ_MASK : IPU6SE_CSI_RX_ERROR_IRQ_MASK;

	writel(irq & mask,
	       csi2->base + CSI_PORT_REG_BASE_IRQ_CSI +
	       CSI_PORT_REG_BASE_IRQ_CLEAR_OFFSET);
	csi2->receiver_errors |= irq & mask;
}

void ipu_isys_csi2_error(struct ipu_isys_csi2 *csi2)
{
	struct ipu6_csi2_error *errors;
	u32 status;
	unsigned int i;

	/* Register errors once more in case of error interrupts are disabled */
	ipu6_isys_register_errors(csi2);
	status = csi2->receiver_errors;
	csi2->receiver_errors = 0;
	errors = dphy_rx_errors;

	for (i = 0; i < CSI_RX_NUM_ERRORS_IN_IRQ; i++) {
		if (status & BIT(i))
			dev_err_ratelimited(&csi2->isys->adev->dev,
					    "csi2-%i error: %s\n",
					    csi2->index,
					    errors[i].error_string);
	}
}

const unsigned int csi2_port_cfg[][3] = {
	{0, 0, 0x1f}, /* no link */
	{4, 0, 0x10}, /* x4 + x4 config */
	{2, 0, 0x12}, /* x2 + x2 config */
	{1, 0, 0x13}, /* x1 + x1 config */
	{2, 1, 0x15}, /* x2x1 + x2x1 config */
	{1, 1, 0x16}, /* x1x1 + x1x1 config */
	{2, 2, 0x18}, /* x2x2 + x2x2 config */
	{1, 2, 0x19}, /* x1x2 + x1x2 config */
};

const unsigned int phy_port_cfg[][4] = {
	/* port, nlanes, bbindex, portcfg */
	/* sip0 */
	{0, 1, 0, 0x15},
	{0, 2, 0, 0x15},
	{0, 4, 0, 0x15},
	{0, 4, 2, 0x22},
	/* sip1 */
	{2, 1, 4, 0x15},
	{2, 2, 4, 0x15},
	{2, 4, 4, 0x15},
	{2, 4, 6, 0x22},
};

static int ipu_isys_csi2_phy_config_by_port(struct ipu_isys *isys,
					    unsigned int port,
					    unsigned int nlanes)
{
	void __iomem *base = isys->adev->isp->base;
	u32 val, reg, i;
	unsigned int bbnum;

	dev_dbg(&isys->adev->dev, "%s port %u with %u lanes", __func__,
		port, nlanes);

	/* hard code for x2x2 + x2x2 with <1.5Gbps */
	for (i = 0; i < IPU6SE_ISYS_PHY_BB_NUM; i++) {
		/* cphy_dll_ovrd.crcdc_fsm_dlane0 = 13 */
		reg = IPU6SE_ISYS_PHY_0_BASE + PHY_CPHY_DLL_OVRD(i);
		val = readl(base + reg);
		val |= 13 << 1;
		/* val &= ~0x1; */
		writel(val, base + reg);

		/* cphy_rx_control1.en_crc1 = 1 */
		reg = IPU6SE_ISYS_PHY_0_BASE + PHY_CPHY_RX_CONTROL1(i);
		val = readl(base + reg);
		val |= 0x1 << 31;
		writel(val, base + reg);

		/* dphy_cfg.reserved = 1
		 * dphy_cfg.lden_from_dll_ovrd_0 = 1
		 */
		reg = IPU6SE_ISYS_PHY_0_BASE + PHY_DPHY_CFG(i);
		val = readl(base + reg);
		val |= 0x1 << 25;
		val |= 0x1 << 26;
		writel(val, base + reg);

		/* cphy_dll_ovrd.lden_crcdc_fsm_dlane0 = 1 */
		reg = IPU6SE_ISYS_PHY_0_BASE + PHY_CPHY_DLL_OVRD(i);
		val = readl(base + reg);
		val |= 1;
		writel(val, base + reg);
	}

	/* bb afe config, use minimal channel loss */
	for (i = 0; i < ARRAY_SIZE(phy_port_cfg); i++) {
		if (phy_port_cfg[i][0] == port &&
		    phy_port_cfg[i][1] == nlanes) {
			bbnum = phy_port_cfg[i][2] / 2;
			reg = IPU6SE_ISYS_PHY_0_BASE + PHY_BB_AFE_CONFIG(bbnum);
			val = readl(base + reg);
			val |= phy_port_cfg[i][3];
			writel(val, base + reg);
		}
	}

	return 0;
}

static void ipu_isys_csi2_rx_control(struct ipu_isys *isys)
{
	void __iomem *base = isys->adev->isp->base;
	u32 val, reg;

	/* lp11 release */
	reg = CSI2_HUB_GPREG_SIP0_CSI_RX_A_CONTROL;
	val = readl(base + reg);
	val |= 0x1;
	writel(0x1, base + CSI2_HUB_GPREG_SIP0_CSI_RX_A_CONTROL);

	reg = CSI2_HUB_GPREG_SIP0_CSI_RX_B_CONTROL;
	val = readl(base + reg);
	val |= 0x1;
	writel(0x1, base + CSI2_HUB_GPREG_SIP0_CSI_RX_B_CONTROL);

	reg = CSI2_HUB_GPREG_SIP1_CSI_RX_A_CONTROL;
	val = readl(base + reg);
	val |= 0x1;
	writel(0x1, base + CSI2_HUB_GPREG_SIP1_CSI_RX_A_CONTROL);

	reg = CSI2_HUB_GPREG_SIP1_CSI_RX_B_CONTROL;
	val = readl(base + reg);
	val |= 0x1;
	writel(0x1, base + CSI2_HUB_GPREG_SIP1_CSI_RX_B_CONTROL);
}

static int ipu_isys_csi2_set_port_cfg(struct v4l2_subdev *sd, unsigned int port,
				      unsigned int nlanes)
{
	struct ipu_isys_csi2 *csi2 = to_ipu_isys_csi2(sd);
	struct ipu_isys *isys = csi2->isys;
	unsigned int sip = port / 2;
	unsigned int index;

	switch (nlanes) {
	case 1:
		index = 5;
		break;
	case 2:
		index = 6;
		break;
	case 4:
		index = 1;
		break;
	default:
		dev_err(&isys->adev->dev, "lanes nr %u is unsupported\n",
			nlanes);
		return -EINVAL;
	}

	dev_dbg(&isys->adev->dev, "port config for port %u with %u lanes\n",
		port, nlanes);
	writel(csi2_port_cfg[index][2],
	       isys->pdata->base + CSI2_HUB_GPREG_SIP_FB_PORT_CFG(sip));

	return 0;
}

static void ipu_isys_csi2_set_timing(struct v4l2_subdev *sd,
				     struct ipu_isys_csi2_timing timing,
				     unsigned int port,
				     unsigned int nlanes)
{
	u32 port_base;
	void __iomem *reg;
	struct ipu_isys_csi2 *csi2 = to_ipu_isys_csi2(sd);
	struct ipu_isys *isys = csi2->isys;
	unsigned int i;

	port_base = (port % 2) ? CSI2_SIP_TOP_CSI_RX_PORT_BASE_1(port) :
		CSI2_SIP_TOP_CSI_RX_PORT_BASE_0(port);

	dev_dbg(&isys->adev->dev,
		"set timing for port %u base 0x%x with %u lanes\n",
		port, port_base, nlanes);

	reg = isys->pdata->base + port_base;
	reg += CSI2_SIP_TOP_CSI_RX_DLY_CNT_TERMEN_CLANE;

	writel(timing.ctermen, reg);

	reg = isys->pdata->base + port_base;
	reg += CSI2_SIP_TOP_CSI_RX_DLY_CNT_SETTLE_CLANE;
	writel(timing.csettle, reg);

	for (i = 0; i < nlanes; i++) {
		reg = isys->pdata->base + port_base;
		reg += CSI2_SIP_TOP_CSI_RX_DLY_CNT_TERMEN_DLANE(i);
		writel(timing.dtermen, reg);

		reg = isys->pdata->base + port_base;
		reg += CSI2_SIP_TOP_CSI_RX_DLY_CNT_SETTLE_DLANE(i);
		writel(timing.dsettle, reg);
	}
}

int ipu_isys_csi2_set_stream(struct v4l2_subdev *sd,
			     struct ipu_isys_csi2_timing timing,
			     unsigned int nlanes, int enable)
{
	struct ipu_isys_csi2 *csi2 = to_ipu_isys_csi2(sd);
	struct ipu_isys *isys = csi2->isys;
	struct ipu_isys_pipeline *ip = container_of(sd->entity.pipe,
						    struct ipu_isys_pipeline,
						    pipe);
	struct ipu_isys_csi2_config *cfg =
		v4l2_get_subdev_hostdata(media_entity_to_v4l2_subdev
					 (ip->external->entity));
	unsigned int port;
	int ret;
	u32 mask = 0;

	port = cfg->port;
	dev_dbg(&isys->adev->dev, "for port %u\n", port);

	mask = (ipu_ver == IPU_VER_6 || ipu_ver == IPU_VER_6EP) ?
		IPU6_CSI_RX_ERROR_IRQ_MASK : IPU6SE_CSI_RX_ERROR_IRQ_MASK;

	if (!enable) {

		writel(0, csi2->base + CSI_REG_CSI_FE_ENABLE);
		writel(0, csi2->base + CSI_REG_PPI2CSI_ENABLE);

		/* Disable interrupts */
		writel(0,
		       csi2->base + CSI_PORT_REG_BASE_IRQ_CSI +
		       CSI_PORT_REG_BASE_IRQ_ENABLE_OFFSET);
		writel(mask,
		       csi2->base + CSI_PORT_REG_BASE_IRQ_CSI +
		       CSI_PORT_REG_BASE_IRQ_CLEAR_OFFSET);
		writel(0,
		       csi2->base + CSI_PORT_REG_BASE_IRQ_CSI_SYNC +
		       CSI_PORT_REG_BASE_IRQ_ENABLE_OFFSET);
		writel(0xffffffff,
		       csi2->base + CSI_PORT_REG_BASE_IRQ_CSI_SYNC +
		       CSI_PORT_REG_BASE_IRQ_CLEAR_OFFSET);

		/* Disable clock */
		writel(0, isys->pdata->base +
		       CSI_REG_HUB_FW_ACCESS_PORT(port));
		writel(0, isys->pdata->base +
		       CSI_REG_HUB_DRV_ACCESS_PORT(port));

		if (ipu_ver == IPU_VER_6SE)
			return 0;

		/* power down */
		return ipu6_csi2_phy_power_set(isys, cfg, false);
	}

	if (ipu_ver == IPU_VER_6 || ipu_ver == IPU_VER_6EP) {
		/* Enable DPHY power */
		ret = ipu6_csi2_phy_power_set(isys, cfg, true);
		if (ret) {
			dev_err(&isys->adev->dev,
				"CSI-%d PHY power up failed %d\n",
				cfg->port, ret);
			return ret;
		}
	}

	/* reset port reset */
	writel(0x1, csi2->base + CSI_REG_PORT_GPREG_SRST);
	usleep_range(100, 200);
	writel(0x0, csi2->base + CSI_REG_PORT_GPREG_SRST);

	/* Enable port clock */
	writel(1, isys->pdata->base + CSI_REG_HUB_DRV_ACCESS_PORT(port));
	writel(1, isys->pdata->base + CSI_REG_HUB_FW_ACCESS_PORT(port));

	if (ipu_ver == IPU_VER_6SE) {
		ipu_isys_csi2_phy_config_by_port(isys, port, nlanes);

		/* 9'b00010.1000 for 400Mhz isys freqency */
		writel(0x28,
		       isys->pdata->base + CSI2_HUB_GPREG_DPHY_TIMER_INCR);
		/* set port cfg and rx timing */
		ipu_isys_csi2_set_timing(sd, timing, port, nlanes);

		ret = ipu_isys_csi2_set_port_cfg(sd, port, nlanes);
		if (ret)
			return ret;

		ipu_isys_csi2_rx_control(isys);
	}

	/* enable all error related irq */
	writel(mask,
	       csi2->base + CSI_PORT_REG_BASE_IRQ_CSI +
	       CSI_PORT_REG_BASE_IRQ_STATUS_OFFSET);
	writel(mask,
	       csi2->base + CSI_PORT_REG_BASE_IRQ_CSI +
	       CSI_PORT_REG_BASE_IRQ_MASK_OFFSET);
	writel(mask,
	       csi2->base + CSI_PORT_REG_BASE_IRQ_CSI +
	       CSI_PORT_REG_BASE_IRQ_CLEAR_OFFSET);
	writel(mask,
	       csi2->base + CSI_PORT_REG_BASE_IRQ_CSI +
	       CSI_PORT_REG_BASE_IRQ_LEVEL_NOT_PULSE_OFFSET);
	writel(mask,
	       csi2->base + CSI_PORT_REG_BASE_IRQ_CSI +
	       CSI_PORT_REG_BASE_IRQ_ENABLE_OFFSET);

	/* To save CPU wakeups, disable CSI SOF/EOF irq */
	writel(0xffffffff, csi2->base + CSI_PORT_REG_BASE_IRQ_CSI_SYNC +
	       CSI_PORT_REG_BASE_IRQ_STATUS_OFFSET);
	writel(0, csi2->base + CSI_PORT_REG_BASE_IRQ_CSI_SYNC +
	       CSI_PORT_REG_BASE_IRQ_MASK_OFFSET);
	writel(0xffffffff, csi2->base + CSI_PORT_REG_BASE_IRQ_CSI_SYNC +
	       CSI_PORT_REG_BASE_IRQ_CLEAR_OFFSET);
	writel(0, csi2->base + CSI_PORT_REG_BASE_IRQ_CSI_SYNC +
	       CSI_PORT_REG_BASE_IRQ_LEVEL_NOT_PULSE_OFFSET);
	writel(0xffffffff, csi2->base + CSI_PORT_REG_BASE_IRQ_CSI_SYNC +
	       CSI_PORT_REG_BASE_IRQ_ENABLE_OFFSET);

	/* Configure FE/PPI2CSI and enable FE/ PPI2CSI */
	writel(0, csi2->base + CSI_REG_CSI_FE_MODE);
	writel(CSI_SENSOR_INPUT, csi2->base + CSI_REG_CSI_FE_MUX_CTRL);
	writel(CSI_CNTR_SENSOR_LINE_ID | CSI_CNTR_SENSOR_FRAME_ID,
	       csi2->base + CSI_REG_CSI_FE_SYNC_CNTR_SEL);
	writel(((nlanes - 1) <<
		PPI_INTF_CONFIG_NOF_ENABLED_DATALANES_SHIFT) |
	       (0 << PPI_INTF_CONFIG_RX_AUTO_CLKGATING_SHIFT),
	       csi2->base + CSI_REG_PPI2CSI_CONFIG_PPI_INTF);
	writel(0x06, csi2->base + CSI_REG_PPI2CSI_CONFIG_CSI_FEATURE);
	writel(1, csi2->base + CSI_REG_PPI2CSI_ENABLE);
	writel(1, csi2->base + CSI_REG_CSI_FE_ENABLE);

	return 0;
}

void ipu_isys_csi2_isr(struct ipu_isys_csi2 *csi2)
{
	u32 status;

	ipu6_isys_register_errors(csi2);

	status = readl(csi2->base + CSI_PORT_REG_BASE_IRQ_CSI_SYNC +
		       CSI_PORT_REG_BASE_IRQ_STATUS_OFFSET);

	writel(status, csi2->base + CSI_PORT_REG_BASE_IRQ_CSI_SYNC +
	       CSI_PORT_REG_BASE_IRQ_CLEAR_OFFSET);

	if (status & IPU_CSI_RX_IRQ_FS_VC)
		ipu_isys_csi2_sof_event(csi2);
	if (status & IPU_CSI_RX_IRQ_FE_VC)
		ipu_isys_csi2_eof_event(csi2);
}

unsigned int ipu_isys_csi2_get_current_field(struct ipu_isys_pipeline *ip,
					     unsigned int *timestamp)
{
	struct ipu_isys_video *av = container_of(ip, struct ipu_isys_video, ip);
	struct ipu_isys *isys = av->isys;
	unsigned int field = V4L2_FIELD_TOP;

	struct ipu_isys_buffer *short_packet_ib =
		list_last_entry(&ip->short_packet_active,
				struct ipu_isys_buffer, head);
	struct ipu_isys_private_buffer *pb =
		ipu_isys_buffer_to_private_buffer(short_packet_ib);
	struct ipu_isys_mipi_packet_header *ph =
		(struct ipu_isys_mipi_packet_header *)
		pb->buffer;

	/* Check if the first SOF packet is received. */
	if ((ph->dtype & IPU_ISYS_SHORT_PACKET_DTYPE_MASK) != 0)
		dev_warn(&isys->adev->dev, "First short packet is not SOF.\n");
	field = (ph->word_count % 2) ? V4L2_FIELD_TOP : V4L2_FIELD_BOTTOM;
	dev_dbg(&isys->adev->dev,
		"Interlaced field ready. frame_num = %d field = %d\n",
		ph->word_count, field);

	return field;
}
