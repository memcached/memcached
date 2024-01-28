// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2020 Intel Corporation

#include <linux/module.h>
#include <media/v4l2-event.h>

#include "ipu.h"
#include "ipu-platform-regs.h"
#include "ipu-trace.h"
#include "ipu-isys.h"
#include "ipu-platform-isys-csi2-reg.h"

const struct ipu_isys_pixelformat ipu_isys_pfmts[] = {
	{V4L2_PIX_FMT_SBGGR12, 16, 12, 0, MEDIA_BUS_FMT_SBGGR12_1X12,
	 IPU_FW_ISYS_FRAME_FORMAT_RAW16},
	{V4L2_PIX_FMT_SGBRG12, 16, 12, 0, MEDIA_BUS_FMT_SGBRG12_1X12,
	 IPU_FW_ISYS_FRAME_FORMAT_RAW16},
	{V4L2_PIX_FMT_SGRBG12, 16, 12, 0, MEDIA_BUS_FMT_SGRBG12_1X12,
	 IPU_FW_ISYS_FRAME_FORMAT_RAW16},
	{V4L2_PIX_FMT_SRGGB12, 16, 12, 0, MEDIA_BUS_FMT_SRGGB12_1X12,
	 IPU_FW_ISYS_FRAME_FORMAT_RAW16},
	{V4L2_PIX_FMT_SBGGR10, 16, 10, 0, MEDIA_BUS_FMT_SBGGR10_1X10,
	 IPU_FW_ISYS_FRAME_FORMAT_RAW16},
	{V4L2_PIX_FMT_SGBRG10, 16, 10, 0, MEDIA_BUS_FMT_SGBRG10_1X10,
	 IPU_FW_ISYS_FRAME_FORMAT_RAW16},
	{V4L2_PIX_FMT_SGRBG10, 16, 10, 0, MEDIA_BUS_FMT_SGRBG10_1X10,
	 IPU_FW_ISYS_FRAME_FORMAT_RAW16},
	{V4L2_PIX_FMT_SRGGB10, 16, 10, 0, MEDIA_BUS_FMT_SRGGB10_1X10,
	 IPU_FW_ISYS_FRAME_FORMAT_RAW16},
	{V4L2_PIX_FMT_SBGGR8, 8, 8, 0, MEDIA_BUS_FMT_SBGGR8_1X8,
	 IPU_FW_ISYS_FRAME_FORMAT_RAW8},
	{V4L2_PIX_FMT_SGBRG8, 8, 8, 0, MEDIA_BUS_FMT_SGBRG8_1X8,
	 IPU_FW_ISYS_FRAME_FORMAT_RAW8},
	{V4L2_PIX_FMT_SGRBG8, 8, 8, 0, MEDIA_BUS_FMT_SGRBG8_1X8,
	 IPU_FW_ISYS_FRAME_FORMAT_RAW8},
	{V4L2_PIX_FMT_SRGGB8, 8, 8, 0, MEDIA_BUS_FMT_SRGGB8_1X8,
	 IPU_FW_ISYS_FRAME_FORMAT_RAW8},
	{}
};

struct ipu_trace_block isys_trace_blocks[] = {
	{
		.offset = IPU_TRACE_REG_IS_TRACE_UNIT_BASE,
		.type = IPU_TRACE_BLOCK_TUN,
	},
	{
		.offset = IPU_TRACE_REG_IS_SP_EVQ_BASE,
		.type = IPU_TRACE_BLOCK_TM,
	},
	{
		.offset = IPU_TRACE_REG_IS_SP_GPC_BASE,
		.type = IPU_TRACE_BLOCK_GPC,
	},
	{
		.offset = IPU_TRACE_REG_IS_ISL_GPC_BASE,
		.type = IPU_TRACE_BLOCK_GPC,
	},
	{
		.offset = IPU_TRACE_REG_IS_MMU_GPC_BASE,
		.type = IPU_TRACE_BLOCK_GPC,
	},
	{
		/* Note! this covers all 8 blocks */
		.offset = IPU_TRACE_REG_CSI2_TM_BASE(0),
		.type = IPU_TRACE_CSI2,
	},
	{
		/* Note! this covers all 11 blocks */
		.offset = IPU_TRACE_REG_CSI2_PORT_SIG2SIO_GR_BASE(0),
		.type = IPU_TRACE_SIG2CIOS,
	},
	{
		.offset = IPU_TRACE_REG_IS_GPREG_TRACE_TIMER_RST_N,
		.type = IPU_TRACE_TIMER_RST,
	},
	{
		.type = IPU_TRACE_BLOCK_END,
	}
};

void isys_setup_hw(struct ipu_isys *isys)
{
	void __iomem *base = isys->pdata->base;
	const u8 *thd = isys->pdata->ipdata->hw_variant.cdc_fifo_threshold;
	u32 irqs = 0;
	unsigned int i, nr;

	nr = (ipu_ver == IPU_VER_6 || ipu_ver == IPU_VER_6EP) ?
		IPU6_ISYS_CSI_PORT_NUM : IPU6SE_ISYS_CSI_PORT_NUM;

	/* Enable irqs for all MIPI ports */
	for (i = 0; i < nr; i++)
		irqs |= IPU_ISYS_UNISPART_IRQ_CSI2(i);

	writel(irqs, base + IPU_REG_ISYS_CSI_TOP_CTRL0_IRQ_EDGE);
	writel(irqs, base + IPU_REG_ISYS_CSI_TOP_CTRL0_IRQ_LEVEL_NOT_PULSE);
	writel(0xffffffff, base + IPU_REG_ISYS_CSI_TOP_CTRL0_IRQ_CLEAR);
	writel(irqs, base + IPU_REG_ISYS_CSI_TOP_CTRL0_IRQ_MASK);
	writel(irqs, base + IPU_REG_ISYS_CSI_TOP_CTRL0_IRQ_ENABLE);

	irqs = ISYS_UNISPART_IRQS;
	writel(irqs, base + IPU_REG_ISYS_UNISPART_IRQ_EDGE);
	writel(irqs, base + IPU_REG_ISYS_UNISPART_IRQ_LEVEL_NOT_PULSE);
	writel(0xffffffff, base + IPU_REG_ISYS_UNISPART_IRQ_CLEAR);
	writel(irqs, base + IPU_REG_ISYS_UNISPART_IRQ_MASK);
	writel(irqs, base + IPU_REG_ISYS_UNISPART_IRQ_ENABLE);

	writel(0, base + IPU_REG_ISYS_UNISPART_SW_IRQ_REG);
	writel(0, base + IPU_REG_ISYS_UNISPART_SW_IRQ_MUX_REG);

	/* Write CDC FIFO threshold values for isys */
	for (i = 0; i < isys->pdata->ipdata->hw_variant.cdc_fifos; i++)
		writel(thd[i], base + IPU_REG_ISYS_CDC_THRESHOLD(i));
}

irqreturn_t isys_isr(struct ipu_bus_device *adev)
{
	struct ipu_isys *isys = ipu_bus_get_drvdata(adev);
	void __iomem *base = isys->pdata->base;
	u32 status_sw, status_csi;

	spin_lock(&isys->power_lock);
	if (!isys->power) {
		spin_unlock(&isys->power_lock);
		return IRQ_NONE;
	}

	status_csi = readl(isys->pdata->base +
			   IPU_REG_ISYS_CSI_TOP_CTRL0_IRQ_STATUS);
	status_sw = readl(isys->pdata->base + IPU_REG_ISYS_UNISPART_IRQ_STATUS);

	writel(ISYS_UNISPART_IRQS & ~IPU_ISYS_UNISPART_IRQ_SW,
	       base + IPU_REG_ISYS_UNISPART_IRQ_MASK);

	do {
		writel(status_csi, isys->pdata->base +
			   IPU_REG_ISYS_CSI_TOP_CTRL0_IRQ_CLEAR);
		writel(status_sw, isys->pdata->base +
			   IPU_REG_ISYS_UNISPART_IRQ_CLEAR);

		if (isys->isr_csi2_bits & status_csi) {
			unsigned int i;

			for (i = 0; i < isys->pdata->ipdata->csi2.nports; i++) {
				/* irq from not enabled port */
				if (!isys->csi2[i].base)
					continue;
				if (status_csi & IPU_ISYS_UNISPART_IRQ_CSI2(i))
					ipu_isys_csi2_isr(&isys->csi2[i]);
			}
		}

		writel(0, base + IPU_REG_ISYS_UNISPART_SW_IRQ_REG);

		if (!isys_isr_one(adev))
			status_sw = IPU_ISYS_UNISPART_IRQ_SW;
		else
			status_sw = 0;

		status_csi = readl(isys->pdata->base +
				       IPU_REG_ISYS_CSI_TOP_CTRL0_IRQ_STATUS);
		status_sw |= readl(isys->pdata->base +
				       IPU_REG_ISYS_UNISPART_IRQ_STATUS);
	} while (((status_csi & isys->isr_csi2_bits) ||
		  (status_sw & IPU_ISYS_UNISPART_IRQ_SW)) &&
		 !isys->adev->isp->flr_done);

	writel(ISYS_UNISPART_IRQS, base + IPU_REG_ISYS_UNISPART_IRQ_MASK);

	spin_unlock(&isys->power_lock);

	return IRQ_HANDLED;
}

