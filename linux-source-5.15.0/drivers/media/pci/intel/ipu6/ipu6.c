// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2018 - 2021 Intel Corporation

#include <linux/device.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>

#include "ipu.h"
#include "ipu-cpd.h"
#include "ipu-isys.h"
#include "ipu-psys.h"
#include "ipu-platform.h"
#include "ipu-platform-regs.h"
#include "ipu-platform-buttress-regs.h"
#include "ipu-platform-isys-csi2-reg.h"

struct ipu_cell_program_t {
	unsigned int magic_number;

	unsigned int blob_offset;
	unsigned int blob_size;

	unsigned int start[3];

	unsigned int icache_source;
	unsigned int icache_target;
	unsigned int icache_size;

	unsigned int pmem_source;
	unsigned int pmem_target;
	unsigned int pmem_size;

	unsigned int data_source;
	unsigned int data_target;
	unsigned int data_size;

	unsigned int bss_target;
	unsigned int bss_size;

	unsigned int cell_id;
	unsigned int regs_addr;

	unsigned int cell_pmem_data_bus_address;
	unsigned int cell_dmem_data_bus_address;
	unsigned int cell_pmem_control_bus_address;
	unsigned int cell_dmem_control_bus_address;

	unsigned int next;
	unsigned int dummy[2];
};

static unsigned int ipu6se_csi_offsets[] = {
	IPU_CSI_PORT_A_ADDR_OFFSET,
	IPU_CSI_PORT_B_ADDR_OFFSET,
	IPU_CSI_PORT_C_ADDR_OFFSET,
	IPU_CSI_PORT_D_ADDR_OFFSET,
};

static unsigned int ipu6_csi_offsets[] = {
	IPU_CSI_PORT_A_ADDR_OFFSET,
	IPU_CSI_PORT_B_ADDR_OFFSET,
	IPU_CSI_PORT_C_ADDR_OFFSET,
	IPU_CSI_PORT_D_ADDR_OFFSET,
	IPU_CSI_PORT_E_ADDR_OFFSET,
	IPU_CSI_PORT_F_ADDR_OFFSET,
	IPU_CSI_PORT_G_ADDR_OFFSET,
	IPU_CSI_PORT_H_ADDR_OFFSET
};

struct ipu_isys_internal_pdata isys_ipdata = {
	.hw_variant = {
		       .offset = IPU_UNIFIED_OFFSET,
		       .nr_mmus = 3,
		       .mmu_hw = {
				{
				   .offset = IPU_ISYS_IOMMU0_OFFSET,
				   .info_bits =
				   IPU_INFO_REQUEST_DESTINATION_IOSF,
				   .nr_l1streams = 16,
				   .l1_block_sz = {
						   3, 8, 2, 2, 2, 2, 2, 2, 1, 1,
						   1, 1, 1, 1, 1, 1
				   },
				   .nr_l2streams = 16,
				   .l2_block_sz = {
						   2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
						   2, 2, 2, 2, 2, 2
				   },
				   .insert_read_before_invalidate = false,
				   .l1_stream_id_reg_offset =
				   IPU_MMU_L1_STREAM_ID_REG_OFFSET,
				   .l2_stream_id_reg_offset =
				   IPU_MMU_L2_STREAM_ID_REG_OFFSET,
				},
				{
				   .offset = IPU_ISYS_IOMMU1_OFFSET,
				   .info_bits = IPU_INFO_STREAM_ID_SET(0),
				   .nr_l1streams = 16,
				   .l1_block_sz = {
						   2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
						   2, 2, 2, 1, 1, 4
				   },
				   .nr_l2streams = 16,
				   .l2_block_sz = {
						   2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
						   2, 2, 2, 2, 2, 2
				   },
				   .insert_read_before_invalidate = false,
				   .l1_stream_id_reg_offset =
				   IPU_MMU_L1_STREAM_ID_REG_OFFSET,
				   .l2_stream_id_reg_offset =
				   IPU_MMU_L2_STREAM_ID_REG_OFFSET,
				},
				{
				   .offset = IPU_ISYS_IOMMUI_OFFSET,
				   .info_bits = IPU_INFO_STREAM_ID_SET(0),
				   .nr_l1streams = 0,
				   .nr_l2streams = 0,
				   .insert_read_before_invalidate = false,
				},
			},
		       .cdc_fifos = 3,
		       .cdc_fifo_threshold = {6, 8, 2},
		       .dmem_offset = IPU_ISYS_DMEM_OFFSET,
		       .spc_offset = IPU_ISYS_SPC_OFFSET,
	},
	.isys_dma_overshoot = IPU_ISYS_OVERALLOC_MIN,
};

struct ipu_psys_internal_pdata psys_ipdata = {
	.hw_variant = {
		       .offset = IPU_UNIFIED_OFFSET,
		       .nr_mmus = 4,
		       .mmu_hw = {
				{
				   .offset = IPU_PSYS_IOMMU0_OFFSET,
				   .info_bits =
				   IPU_INFO_REQUEST_DESTINATION_IOSF,
				   .nr_l1streams = 16,
				   .l1_block_sz = {
						   2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
						   2, 2, 2, 2, 2, 2
				   },
				   .nr_l2streams = 16,
				   .l2_block_sz = {
						   2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
						   2, 2, 2, 2, 2, 2
				   },
				   .insert_read_before_invalidate = false,
				   .l1_stream_id_reg_offset =
				   IPU_MMU_L1_STREAM_ID_REG_OFFSET,
				   .l2_stream_id_reg_offset =
				   IPU_MMU_L2_STREAM_ID_REG_OFFSET,
				},
				{
				   .offset = IPU_PSYS_IOMMU1_OFFSET,
				   .info_bits = IPU_INFO_STREAM_ID_SET(0),
				   .nr_l1streams = 32,
				   .l1_block_sz = {
						   1, 2, 2, 2, 2, 2, 2, 2, 2, 2,
						   2, 2, 2, 2, 2, 10,
						   5, 4, 14, 6, 4, 14, 6, 4, 8,
						   4, 2, 1, 1, 1, 1, 14
				   },
				   .nr_l2streams = 32,
				   .l2_block_sz = {
						   2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
						   2, 2, 2, 2, 2, 2,
						   2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
						   2, 2, 2, 2, 2, 2
				   },
				   .insert_read_before_invalidate = false,
				   .l1_stream_id_reg_offset =
				   IPU_MMU_L1_STREAM_ID_REG_OFFSET,
				   .l2_stream_id_reg_offset =
				   IPU_PSYS_MMU1W_L2_STREAM_ID_REG_OFFSET,
				},
				{
				   .offset = IPU_PSYS_IOMMU1R_OFFSET,
				   .info_bits = IPU_INFO_STREAM_ID_SET(0),
				   .nr_l1streams = 16,
				   .l1_block_sz = {
						   1, 4, 4, 4, 4, 16, 8, 4, 32,
						   16, 16, 2, 2, 2, 1, 12
				   },
				   .nr_l2streams = 16,
				   .l2_block_sz = {
						   2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
						   2, 2, 2, 2, 2, 2
				   },
				   .insert_read_before_invalidate = false,
				   .l1_stream_id_reg_offset =
				   IPU_MMU_L1_STREAM_ID_REG_OFFSET,
				   .l2_stream_id_reg_offset =
				   IPU_MMU_L2_STREAM_ID_REG_OFFSET,
				},
				{
				   .offset = IPU_PSYS_IOMMUI_OFFSET,
				   .info_bits = IPU_INFO_STREAM_ID_SET(0),
				   .nr_l1streams = 0,
				   .nr_l2streams = 0,
				   .insert_read_before_invalidate = false,
				},
		},
	       .dmem_offset = IPU_PSYS_DMEM_OFFSET,
	},
};

const struct ipu_buttress_ctrl isys_buttress_ctrl = {
	.ratio = IPU_IS_FREQ_CTL_DEFAULT_RATIO,
	.qos_floor = IPU_IS_FREQ_CTL_DEFAULT_QOS_FLOOR_RATIO,
	.freq_ctl = IPU_BUTTRESS_REG_IS_FREQ_CTL,
	.pwr_sts_shift = IPU_BUTTRESS_PWR_STATE_IS_PWR_SHIFT,
	.pwr_sts_mask = IPU_BUTTRESS_PWR_STATE_IS_PWR_MASK,
	.pwr_sts_on = IPU_BUTTRESS_PWR_STATE_UP_DONE,
	.pwr_sts_off = IPU_BUTTRESS_PWR_STATE_DN_DONE,
};

const struct ipu_buttress_ctrl psys_buttress_ctrl = {
	.ratio = IPU_PS_FREQ_CTL_DEFAULT_RATIO,
	.qos_floor = IPU_PS_FREQ_CTL_DEFAULT_QOS_FLOOR_RATIO,
	.freq_ctl = IPU_BUTTRESS_REG_PS_FREQ_CTL,
	.pwr_sts_shift = IPU_BUTTRESS_PWR_STATE_PS_PWR_SHIFT,
	.pwr_sts_mask = IPU_BUTTRESS_PWR_STATE_PS_PWR_MASK,
	.pwr_sts_on = IPU_BUTTRESS_PWR_STATE_UP_DONE,
	.pwr_sts_off = IPU_BUTTRESS_PWR_STATE_DN_DONE,
};

static void ipu6_pkg_dir_configure_spc(struct ipu_device *isp,
				       const struct ipu_hw_variants *hw_variant,
				       int pkg_dir_idx, void __iomem *base,
				       u64 *pkg_dir,
				       dma_addr_t pkg_dir_vied_address)
{
	struct ipu_psys *psys = ipu_bus_get_drvdata(isp->psys);
	struct ipu_isys *isys = ipu_bus_get_drvdata(isp->isys);
	unsigned int server_fw_virtaddr;
	struct ipu_cell_program_t *prog;
	void __iomem *spc_base;
	dma_addr_t dma_addr;

	if (!pkg_dir || !isp->cpd_fw) {
		dev_err(&isp->pdev->dev, "invalid addr\n");
		return;
	}

	server_fw_virtaddr = *(pkg_dir + (pkg_dir_idx + 1) * 2);
	if (pkg_dir_idx == IPU_CPD_PKG_DIR_ISYS_SERVER_IDX) {
		dma_addr = sg_dma_address(isys->fw_sgt.sgl);
		prog = (struct ipu_cell_program_t *)((u64)isp->cpd_fw->data +
							(server_fw_virtaddr -
							 dma_addr));
	} else {
		dma_addr = sg_dma_address(psys->fw_sgt.sgl);
		prog = (struct ipu_cell_program_t *)((u64)isp->cpd_fw->data +
							(server_fw_virtaddr -
							 dma_addr));
	}

	spc_base = base + prog->regs_addr;
	if (spc_base != (base + hw_variant->spc_offset))
		dev_warn(&isp->pdev->dev,
			 "SPC reg addr 0x%p not matching value from CPD 0x%p\n",
			 base + hw_variant->spc_offset, spc_base);
	writel(server_fw_virtaddr + prog->blob_offset +
	       prog->icache_source, spc_base + IPU_PSYS_REG_SPC_ICACHE_BASE);
	writel(IPU_INFO_REQUEST_DESTINATION_IOSF,
	       spc_base + IPU_REG_PSYS_INFO_SEG_0_CONFIG_ICACHE_MASTER);
	writel(prog->start[1], spc_base + IPU_PSYS_REG_SPC_START_PC);
	writel(pkg_dir_vied_address, base + hw_variant->dmem_offset);
}

void ipu_configure_spc(struct ipu_device *isp,
		       const struct ipu_hw_variants *hw_variant,
		       int pkg_dir_idx, void __iomem *base, u64 *pkg_dir,
		       dma_addr_t pkg_dir_dma_addr)
{
	u32 val;
	void __iomem *dmem_base = base + hw_variant->dmem_offset;
	void __iomem *spc_regs_base = base + hw_variant->spc_offset;

	val = readl(spc_regs_base + IPU_PSYS_REG_SPC_STATUS_CTRL);
	val |= IPU_PSYS_SPC_STATUS_CTRL_ICACHE_INVALIDATE;
	writel(val, spc_regs_base + IPU_PSYS_REG_SPC_STATUS_CTRL);

	if (isp->secure_mode)
		writel(IPU_PKG_DIR_IMR_OFFSET, dmem_base);
	else
		ipu6_pkg_dir_configure_spc(isp, hw_variant, pkg_dir_idx, base,
					   pkg_dir, pkg_dir_dma_addr);
}
EXPORT_SYMBOL(ipu_configure_spc);

int ipu_buttress_psys_freq_get(void *data, u64 *val)
{
	struct ipu_device *isp = data;
	u32 reg_val;
	int rval;

	rval = pm_runtime_get_sync(&isp->psys->dev);
	if (rval < 0) {
		pm_runtime_put(&isp->psys->dev);
		dev_err(&isp->pdev->dev, "Runtime PM failed (%d)\n", rval);
		return rval;
	}

	reg_val = readl(isp->base + BUTTRESS_REG_PS_FREQ_CTL);

	pm_runtime_put(&isp->psys->dev);

	*val = IPU_PS_FREQ_RATIO_BASE *
	    (reg_val & IPU_BUTTRESS_PS_FREQ_CTL_DIVISOR_MASK);

	return 0;
}

void ipu_internal_pdata_init(void)
{
	if (ipu_ver == IPU_VER_6 || ipu_ver == IPU_VER_6EP) {
		isys_ipdata.csi2.nports = ARRAY_SIZE(ipu6_csi_offsets);
		isys_ipdata.csi2.offsets = ipu6_csi_offsets;
		isys_ipdata.num_parallel_streams = IPU6_ISYS_NUM_STREAMS;
		psys_ipdata.hw_variant.spc_offset = IPU6_PSYS_SPC_OFFSET;

	} else if (ipu_ver == IPU_VER_6SE) {
		isys_ipdata.csi2.nports = ARRAY_SIZE(ipu6se_csi_offsets);
		isys_ipdata.csi2.offsets = ipu6se_csi_offsets;
		isys_ipdata.num_parallel_streams = IPU6SE_ISYS_NUM_STREAMS;
		psys_ipdata.hw_variant.spc_offset = IPU6SE_PSYS_SPC_OFFSET;
	}
}
