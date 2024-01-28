// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2015 - 2021 Intel Corporation

#include <linux/err.h>
#include <linux/string.h>

#include "ipu-psys.h"
#include "ipu-fw-psys.h"
#include "ipu6-platform-resources.h"

/* resources table */

/*
 * Cell types by cell IDs
 */
static const u8 ipu6_fw_psys_cell_types[IPU6_FW_PSYS_N_CELL_ID] = {
	IPU6_FW_PSYS_SP_CTRL_TYPE_ID,
	IPU6_FW_PSYS_VP_TYPE_ID,
	IPU6_FW_PSYS_ACC_PSA_TYPE_ID,
	IPU6_FW_PSYS_ACC_PSA_TYPE_ID,
	IPU6_FW_PSYS_ACC_PSA_TYPE_ID,
	IPU6_FW_PSYS_ACC_PSA_TYPE_ID,
	IPU6_FW_PSYS_ACC_OSA_TYPE_ID,
	IPU6_FW_PSYS_ACC_OSA_TYPE_ID,
	IPU6_FW_PSYS_ACC_OSA_TYPE_ID,
	IPU6_FW_PSYS_ACC_PSA_TYPE_ID,
	IPU6_FW_PSYS_ACC_PSA_TYPE_ID,
	IPU6_FW_PSYS_ACC_PSA_TYPE_ID,
	IPU6_FW_PSYS_ACC_PSA_TYPE_ID,
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID,
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID,
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID,
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID,
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID,
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID,
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID,
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID,
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID,
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID,
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID,
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID,
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID,
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID, /* X2B_MD */
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID, /* ICA_MEDIUM */
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID, /* X2B_SVE_RGBIR */
	IPU6_FW_PSYS_ACC_ISA_TYPE_ID, /* PAF */
	IPU6_FW_PSYS_GDC_TYPE_ID,
	IPU6_FW_PSYS_TNR_TYPE_ID,
};

static const u16 ipu6_fw_num_dev_channels[IPU6_FW_PSYS_N_DEV_CHN_ID] = {
	IPU6_FW_PSYS_DEV_CHN_DMA_EXT0_MAX_SIZE,
	IPU6_FW_PSYS_DEV_CHN_DMA_EXT1_READ_MAX_SIZE,
	IPU6_FW_PSYS_DEV_CHN_DMA_EXT1_WRITE_MAX_SIZE,
	IPU6_FW_PSYS_DEV_CHN_DMA_INTERNAL_MAX_SIZE,
	IPU6_FW_PSYS_DEV_CHN_DMA_ISA_MAX_SIZE,
};

static const u16 ipu6_fw_psys_mem_size[IPU6_FW_PSYS_N_MEM_ID] = {
	IPU6_FW_PSYS_VMEM0_MAX_SIZE,
	IPU6_FW_PSYS_TRANSFER_VMEM0_MAX_SIZE,
	IPU6_FW_PSYS_TRANSFER_VMEM1_MAX_SIZE,
	IPU6_FW_PSYS_LB_VMEM_MAX_SIZE,
	IPU6_FW_PSYS_BAMEM0_MAX_SIZE,
	IPU6_FW_PSYS_DMEM0_MAX_SIZE,
	IPU6_FW_PSYS_DMEM1_MAX_SIZE,
	IPU6_FW_PSYS_DMEM2_MAX_SIZE,
	IPU6_FW_PSYS_DMEM3_MAX_SIZE,
	IPU6_FW_PSYS_PMEM0_MAX_SIZE
};

static const u16 ipu6_fw_psys_dfms[IPU6_FW_PSYS_N_DEV_DFM_ID] = {
	IPU6_FW_PSYS_DEV_DFM_BB_FULL_PORT_ID_MAX_SIZE,
	IPU6_FW_PSYS_DEV_DFM_BB_EMPTY_PORT_ID_MAX_SIZE,
	IPU6_FW_PSYS_DEV_DFM_ISL_FULL_PORT_ID_MAX_SIZE,
	IPU6_FW_PSYS_DEV_DFM_ISL_EMPTY_PORT_ID_MAX_SIZE,
	IPU6_FW_PSYS_DEV_DFM_LB_FULL_PORT_ID_MAX_SIZE,
	IPU6_FW_PSYS_DEV_DFM_LB_EMPTY_PORT_ID_MAX_SIZE,
};

static const u8
ipu6_fw_psys_c_mem[IPU6_FW_PSYS_N_CELL_ID][IPU6_FW_PSYS_N_MEM_TYPE_ID] = {
	{
		/* IPU6_FW_PSYS_SP0_ID */
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_DMEM0_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_SP1_ID */
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_DMEM1_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_VP0_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_DMEM3_ID,
		IPU6_FW_PSYS_VMEM0_ID,
		IPU6_FW_PSYS_BAMEM0_ID,
		IPU6_FW_PSYS_PMEM0_ID,
	},
	{
		/* IPU6_FW_PSYS_ACC1_ID BNLM */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ACC2_ID DM */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ACC3_ID ACM */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ACC4_ID GTC YUV1 */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ACC5_ID OFS pin main */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ACC6_ID OFS pin display */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ACC7_ID OFS pin pp */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ACC8_ID GAMMASTAR */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ACC9_ID GLTM */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ACC10_ID XNR */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_ICA_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_LSC_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_DPC_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_SIS_A_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_SIS_B_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_B2B_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_B2R_ID and ISA_R2I_SIE */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_R2I_DS_A_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_R2I_DS_B_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_AWB_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_AE_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_AF_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_DOL_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_X2B_MD_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_ICA_MEDIUM_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_X2B_SVE_RGBIR_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_ISA_PAF_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_LB_VMEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_BB_ACC_GDC0_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	},
	{
		/* IPU6_FW_PSYS_BB_ACC_TNR_ID */
		IPU6_FW_PSYS_TRANSFER_VMEM0_ID,
		IPU6_FW_PSYS_TRANSFER_VMEM1_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
		IPU6_FW_PSYS_N_MEM_ID,
	}
};

static const struct ipu_fw_resource_definitions ipu6_defs = {
	.cells = ipu6_fw_psys_cell_types,
	.num_cells = IPU6_FW_PSYS_N_CELL_ID,
	.num_cells_type = IPU6_FW_PSYS_N_CELL_TYPE_ID,

	.dev_channels = ipu6_fw_num_dev_channels,
	.num_dev_channels = IPU6_FW_PSYS_N_DEV_CHN_ID,

	.num_ext_mem_types = IPU6_FW_PSYS_N_DATA_MEM_TYPE_ID,
	.num_ext_mem_ids = IPU6_FW_PSYS_N_MEM_ID,
	.ext_mem_ids = ipu6_fw_psys_mem_size,

	.num_dfm_ids = IPU6_FW_PSYS_N_DEV_DFM_ID,

	.dfms = ipu6_fw_psys_dfms,

	.cell_mem_row = IPU6_FW_PSYS_N_MEM_TYPE_ID,
	.cell_mem = &ipu6_fw_psys_c_mem[0][0],
};

const struct ipu_fw_resource_definitions *ipu6_res_defs = &ipu6_defs;

/********** Generic resource handling **********/

int ipu6_fw_psys_set_proc_dev_chn(struct ipu_fw_psys_process *ptr, u16 offset,
				  u16 value)
{
	struct ipu6_fw_psys_process_ext *pm_ext;
	u8 ps_ext_offset;

	ps_ext_offset = ptr->process_extension_offset;
	if (!ps_ext_offset)
		return -EINVAL;

	pm_ext = (struct ipu6_fw_psys_process_ext *)((u8 *)ptr + ps_ext_offset);

	pm_ext->dev_chn_offset[offset] = value;

	return 0;
}

int ipu6_fw_psys_set_proc_dfm_bitmap(struct ipu_fw_psys_process *ptr,
				     u16 id, u32 bitmap,
				     u32 active_bitmap)
{
	struct ipu6_fw_psys_process_ext *pm_ext;
	u8 ps_ext_offset;

	ps_ext_offset = ptr->process_extension_offset;
	if (!ps_ext_offset)
		return -EINVAL;

	pm_ext = (struct ipu6_fw_psys_process_ext *)((u8 *)ptr + ps_ext_offset);

	pm_ext->dfm_port_bitmap[id] = bitmap;
	pm_ext->dfm_active_port_bitmap[id] = active_bitmap;

	return 0;
}

int ipu6_fw_psys_set_process_ext_mem(struct ipu_fw_psys_process *ptr,
				     u16 type_id, u16 mem_id, u16 offset)
{
	struct ipu6_fw_psys_process_ext *pm_ext;
	u8 ps_ext_offset;

	ps_ext_offset = ptr->process_extension_offset;
	if (!ps_ext_offset)
		return -EINVAL;

	pm_ext = (struct ipu6_fw_psys_process_ext *)((u8 *)ptr + ps_ext_offset);

	pm_ext->ext_mem_offset[type_id] = offset;
	pm_ext->ext_mem_id[type_id] = mem_id;

	return 0;
}

static struct ipu_fw_psys_program_manifest *
get_program_manifest(const struct ipu_fw_psys_program_group_manifest *manifest,
		     const unsigned int program_index)
{
	struct ipu_fw_psys_program_manifest *prg_manifest_base;
	u8 *program_manifest = NULL;
	u8 program_count;
	unsigned int i;

	program_count = manifest->program_count;

	prg_manifest_base = (struct ipu_fw_psys_program_manifest *)
		((char *)manifest + manifest->program_manifest_offset);
	if (program_index < program_count) {
		program_manifest = (u8 *)prg_manifest_base;
		for (i = 0; i < program_index; i++)
			program_manifest +=
				((struct ipu_fw_psys_program_manifest *)
				 program_manifest)->size;
	}

	return (struct ipu_fw_psys_program_manifest *)program_manifest;
}

int ipu6_fw_psys_get_program_manifest_by_process(
	struct ipu_fw_generic_program_manifest *gen_pm,
	const struct ipu_fw_psys_program_group_manifest *pg_manifest,
	struct ipu_fw_psys_process *process)
{
	u32 program_id = process->program_idx;
	struct ipu_fw_psys_program_manifest *pm;
	struct ipu6_fw_psys_program_manifest_ext *pm_ext;

	pm = get_program_manifest(pg_manifest, program_id);

	if (!pm)
		return -ENOENT;

	if (pm->program_extension_offset) {
		pm_ext = (struct ipu6_fw_psys_program_manifest_ext *)
			((u8 *)pm + pm->program_extension_offset);

		gen_pm->dev_chn_size = pm_ext->dev_chn_size;
		gen_pm->dev_chn_offset = pm_ext->dev_chn_offset;
		gen_pm->ext_mem_size = pm_ext->ext_mem_size;
		gen_pm->ext_mem_offset = (u16 *)pm_ext->ext_mem_offset;
		gen_pm->is_dfm_relocatable = pm_ext->is_dfm_relocatable;
		gen_pm->dfm_port_bitmap = pm_ext->dfm_port_bitmap;
		gen_pm->dfm_active_port_bitmap =
			pm_ext->dfm_active_port_bitmap;
	}

	memcpy(gen_pm->cells, pm->cells, sizeof(pm->cells));
	gen_pm->cell_id = pm->cells[0];
	gen_pm->cell_type_id = pm->cell_type_id;

	return 0;
}

#if defined(DEBUG) || defined(CONFIG_DYNAMIC_DEBUG) || \
	(defined(CONFIG_DYNAMIC_DEBUG_CORE) && defined(DYNAMIC_DEBUG_MODULE))
void ipu6_fw_psys_pg_dump(struct ipu_psys *psys,
			  struct ipu_psys_kcmd *kcmd, const char *note)
{
	struct ipu_fw_psys_process_group *pg = kcmd->kpg->pg;
	u32 pgid = pg->ID;
	u8 processes = pg->process_count;
	u16 *process_offset_table = (u16 *)((char *)pg + pg->processes_offset);
	unsigned int p, chn, mem, mem_id;
	unsigned int mem_type, max_mem_id, dev_chn;

	if (ipu_ver == IPU_VER_6SE) {
		mem_type = IPU6SE_FW_PSYS_N_DATA_MEM_TYPE_ID;
		max_mem_id = IPU6SE_FW_PSYS_N_MEM_ID;
		dev_chn = IPU6SE_FW_PSYS_N_DEV_CHN_ID;
	} else if (ipu_ver == IPU_VER_6 || ipu_ver == IPU_VER_6EP) {
		mem_type = IPU6_FW_PSYS_N_DATA_MEM_TYPE_ID;
		max_mem_id = IPU6_FW_PSYS_N_MEM_ID;
		dev_chn = IPU6_FW_PSYS_N_DEV_CHN_ID;
	} else {
		WARN(1, "%s ipu_ver:[%u] is unsupported!\n", __func__, ipu_ver);
		return;
	}

	dev_dbg(&psys->adev->dev, "%s %s pgid %i has %i processes:\n",
		__func__, note, pgid, processes);

	for (p = 0; p < processes; p++) {
		struct ipu_fw_psys_process *process =
		    (struct ipu_fw_psys_process *)
		    ((char *)pg + process_offset_table[p]);
		struct ipu6_fw_psys_process_ext *pm_ext =
		    (struct ipu6_fw_psys_process_ext *)((u8 *)process
		    + process->process_extension_offset);
		dev_dbg(&psys->adev->dev, "\t process %i size=%u",
			p, process->size);
		if (!process->process_extension_offset)
			continue;

		for (mem = 0; mem < mem_type; mem++) {
			mem_id = pm_ext->ext_mem_id[mem];
			if (mem_id != max_mem_id)
				dev_dbg(&psys->adev->dev,
					"\t mem type %u id %d offset=0x%x",
					mem, mem_id,
					pm_ext->ext_mem_offset[mem]);
		}
		for (chn = 0; chn < dev_chn; chn++) {
			if (pm_ext->dev_chn_offset[chn] != (u16)(-1))
				dev_dbg(&psys->adev->dev,
					"\t dev_chn[%u]=0x%x\n",
					chn, pm_ext->dev_chn_offset[chn]);
		}
	}
}
#else
void ipu6_fw_psys_pg_dump(struct ipu_psys *psys,
			  struct ipu_psys_kcmd *kcmd, const char *note)
{
	if (ipu_ver == IPU_VER_6SE || ipu_ver == IPU_VER_6 ||
	    ipu_ver == IPU_VER_6EP)
		return;

	WARN(1, "%s ipu_ver:[%u] is unsupported!\n", __func__, ipu_ver);
}
#endif
