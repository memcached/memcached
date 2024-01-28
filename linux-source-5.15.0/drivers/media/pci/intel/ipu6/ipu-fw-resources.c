// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2015 - 2019 Intel Corporation

#include <linux/err.h>
#include <linux/string.h>

#include "ipu-psys.h"
#include "ipu-fw-psys.h"
#include "ipu6-platform-resources.h"
#include "ipu6se-platform-resources.h"

/********** Generic resource handling **********/

/*
 * Extension library gives byte offsets to its internal structures.
 * use those offsets to update fields. Without extension lib access
 * structures directly.
 */
const struct ipu6_psys_hw_res_variant *var = &hw_var;

int ipu_fw_psys_set_process_cell_id(struct ipu_fw_psys_process *ptr, u8 index,
				    u8 value)
{
	struct ipu_fw_psys_process_group *parent =
		(struct ipu_fw_psys_process_group *)((char *)ptr +
						      ptr->parent_offset);

	ptr->cells[index] = value;
	parent->resource_bitmap |= 1 << value;

	return 0;
}

u8 ipu_fw_psys_get_process_cell_id(struct ipu_fw_psys_process *ptr, u8 index)
{
	return ptr->cells[index];
}

int ipu_fw_psys_clear_process_cell(struct ipu_fw_psys_process *ptr)
{
	struct ipu_fw_psys_process_group *parent;
	u8 cell_id = ipu_fw_psys_get_process_cell_id(ptr, 0);
	int retval = -1;
	u8 value;

	parent = (struct ipu_fw_psys_process_group *)((char *)ptr +
						       ptr->parent_offset);

	value = var->cell_num;
	if ((1 << cell_id) != 0 &&
	    ((1 << cell_id) & parent->resource_bitmap)) {
		ipu_fw_psys_set_process_cell_id(ptr, 0, value);
		parent->resource_bitmap &= ~(1 << cell_id);
		retval = 0;
	}

	return retval;
}

int ipu_fw_psys_set_proc_dev_chn(struct ipu_fw_psys_process *ptr, u16 offset,
				 u16 value)
{
	if (var->set_proc_dev_chn)
		return var->set_proc_dev_chn(ptr, offset, value);

	WARN(1, "ipu6 psys res var is not initialised correctly.");
	return 0;
}

int ipu_fw_psys_set_proc_dfm_bitmap(struct ipu_fw_psys_process *ptr,
				    u16 id, u32 bitmap,
				    u32 active_bitmap)
{
	if (var->set_proc_dfm_bitmap)
		return var->set_proc_dfm_bitmap(ptr, id, bitmap,
						active_bitmap);

	WARN(1, "ipu6 psys res var is not initialised correctly.");
	return 0;
}

int ipu_fw_psys_set_process_ext_mem(struct ipu_fw_psys_process *ptr,
				    u16 type_id, u16 mem_id, u16 offset)
{
	if (var->set_proc_ext_mem)
		return var->set_proc_ext_mem(ptr, type_id, mem_id, offset);

	WARN(1, "ipu6 psys res var is not initialised correctly.");
	return 0;
}

int ipu_fw_psys_get_program_manifest_by_process(
	struct ipu_fw_generic_program_manifest *gen_pm,
	const struct ipu_fw_psys_program_group_manifest *pg_manifest,
	struct ipu_fw_psys_process *process)
{
	if (var->get_pgm_by_proc)
		return var->get_pgm_by_proc(gen_pm, pg_manifest, process);

	WARN(1, "ipu6 psys res var is not initialised correctly.");
	return 0;
}

