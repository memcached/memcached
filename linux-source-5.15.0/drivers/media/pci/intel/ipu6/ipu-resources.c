// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2015 - 2020 Intel Corporation

#include <linux/bitmap.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/device.h>

#include <uapi/linux/ipu-psys.h>

#include "ipu-fw-psys.h"
#include "ipu-psys.h"

struct ipu6_psys_hw_res_variant hw_var;
void ipu6_psys_hw_res_variant_init(void)
{
	if (ipu_ver == IPU_VER_6SE) {
		hw_var.queue_num = IPU6SE_FW_PSYS_N_PSYS_CMD_QUEUE_ID;
		hw_var.cell_num = IPU6SE_FW_PSYS_N_CELL_ID;
	} else if (ipu_ver == IPU_VER_6) {
		hw_var.queue_num = IPU6_FW_PSYS_N_PSYS_CMD_QUEUE_ID;
		hw_var.cell_num = IPU6_FW_PSYS_N_CELL_ID;
	} else if (ipu_ver == IPU_VER_6EP) {
		hw_var.queue_num = IPU6_FW_PSYS_N_PSYS_CMD_QUEUE_ID;
		hw_var.cell_num = IPU6EP_FW_PSYS_N_CELL_ID;
	} else {
		WARN(1, "ipu6 psys res var is not initialised correctly.");
	}

	hw_var.set_proc_dev_chn = ipu6_fw_psys_set_proc_dev_chn;
	hw_var.set_proc_dfm_bitmap = ipu6_fw_psys_set_proc_dfm_bitmap;
	hw_var.set_proc_ext_mem = ipu6_fw_psys_set_process_ext_mem;
	hw_var.get_pgm_by_proc =
		ipu6_fw_psys_get_program_manifest_by_process;
	return;
}

static const struct ipu_fw_resource_definitions *get_res(void)
{
	if (ipu_ver == IPU_VER_6SE)
		return ipu6se_res_defs;

	if (ipu_ver == IPU_VER_6EP)
		return ipu6ep_res_defs;

	return ipu6_res_defs;
}

static int ipu_resource_init(struct ipu_resource *res, u32 id, int elements)
{
	if (elements <= 0) {
		res->bitmap = NULL;
		return 0;
	}

	res->bitmap = bitmap_zalloc(elements, GFP_KERNEL);
	if (!res->bitmap)
		return -ENOMEM;
	res->elements = elements;
	res->id = id;
	return 0;
}

static unsigned long
ipu_resource_alloc_with_pos(struct ipu_resource *res, int n,
			    int pos,
			    struct ipu_resource_alloc *alloc,
			    enum ipu_resource_type type)
{
	unsigned long p;

	if (n <= 0) {
		alloc->elements = 0;
		return 0;
	}

	if (!res->bitmap || pos >= res->elements)
		return (unsigned long)(-ENOSPC);

	p = bitmap_find_next_zero_area(res->bitmap, res->elements, pos, n, 0);
	alloc->resource = NULL;

	if (p != pos)
		return (unsigned long)(-ENOSPC);
	bitmap_set(res->bitmap, p, n);
	alloc->resource = res;
	alloc->elements = n;
	alloc->pos = p;
	alloc->type = type;

	return pos;
}

static unsigned long
ipu_resource_alloc(struct ipu_resource *res, int n,
		   struct ipu_resource_alloc *alloc,
		   enum ipu_resource_type type)
{
	unsigned long p;

	if (n <= 0) {
		alloc->elements = 0;
		return 0;
	}

	if (!res->bitmap)
		return (unsigned long)(-ENOSPC);

	p = bitmap_find_next_zero_area(res->bitmap, res->elements, 0, n, 0);
	alloc->resource = NULL;

	if (p >= res->elements)
		return (unsigned long)(-ENOSPC);
	bitmap_set(res->bitmap, p, n);
	alloc->resource = res;
	alloc->elements = n;
	alloc->pos = p;
	alloc->type = type;

	return p;
}

static void ipu_resource_free(struct ipu_resource_alloc *alloc)
{
	if (alloc->elements <= 0)
		return;

	if (alloc->type == IPU_RESOURCE_DFM)
		*alloc->resource->bitmap &= ~(unsigned long)(alloc->elements);
	else
		bitmap_clear(alloc->resource->bitmap, alloc->pos,
			     alloc->elements);
	alloc->resource = NULL;
}

static void ipu_resource_cleanup(struct ipu_resource *res)
{
	bitmap_free(res->bitmap);
	res->bitmap = NULL;
}

/********** IPU PSYS-specific resource handling **********/
int ipu_psys_resource_pool_init(struct ipu_psys_resource_pool *pool)
{
	int i, j, k, ret;
	const struct ipu_fw_resource_definitions *res_defs;

	res_defs = get_res();

	spin_lock_init(&pool->queues_lock);
	pool->cells = 0;

	for (i = 0; i < res_defs->num_dev_channels; i++) {
		ret = ipu_resource_init(&pool->dev_channels[i], i,
					res_defs->dev_channels[i]);
		if (ret)
			goto error;
	}

	for (j = 0; j < res_defs->num_ext_mem_ids; j++) {
		ret = ipu_resource_init(&pool->ext_memory[j], j,
					res_defs->ext_mem_ids[j]);
		if (ret)
			goto memory_error;
	}

	for (k = 0; k < res_defs->num_dfm_ids; k++) {
		ret = ipu_resource_init(&pool->dfms[k], k, res_defs->dfms[k]);
		if (ret)
			goto dfm_error;
	}

	spin_lock(&pool->queues_lock);
	if (ipu_ver == IPU_VER_6SE)
		bitmap_zero(pool->cmd_queues,
			    IPU6SE_FW_PSYS_N_PSYS_CMD_QUEUE_ID);
	else
		bitmap_zero(pool->cmd_queues,
			    IPU6_FW_PSYS_N_PSYS_CMD_QUEUE_ID);
	spin_unlock(&pool->queues_lock);

	return 0;

dfm_error:
	for (k--; k >= 0; k--)
		ipu_resource_cleanup(&pool->dfms[k]);

memory_error:
	for (j--; j >= 0; j--)
		ipu_resource_cleanup(&pool->ext_memory[j]);

error:
	for (i--; i >= 0; i--)
		ipu_resource_cleanup(&pool->dev_channels[i]);
	return ret;
}

void ipu_psys_resource_copy(struct ipu_psys_resource_pool *src,
			    struct ipu_psys_resource_pool *dest)
{
	int i;
	const struct ipu_fw_resource_definitions *res_defs;

	res_defs = get_res();

	dest->cells = src->cells;
	for (i = 0; i < res_defs->num_dev_channels; i++)
		*dest->dev_channels[i].bitmap = *src->dev_channels[i].bitmap;

	for (i = 0; i < res_defs->num_ext_mem_ids; i++)
		*dest->ext_memory[i].bitmap = *src->ext_memory[i].bitmap;

	for (i = 0; i < res_defs->num_dfm_ids; i++)
		*dest->dfms[i].bitmap = *src->dfms[i].bitmap;
}

void ipu_psys_resource_pool_cleanup(struct ipu_psys_resource_pool
				    *pool)
{
	u32 i;
	const struct ipu_fw_resource_definitions *res_defs;

	res_defs = get_res();
	for (i = 0; i < res_defs->num_dev_channels; i++)
		ipu_resource_cleanup(&pool->dev_channels[i]);

	for (i = 0; i < res_defs->num_ext_mem_ids; i++)
		ipu_resource_cleanup(&pool->ext_memory[i]);

	for (i = 0; i < res_defs->num_dfm_ids; i++)
		ipu_resource_cleanup(&pool->dfms[i]);
}

static int __alloc_one_resrc(const struct device *dev,
			     struct ipu_fw_psys_process *process,
			     struct ipu_resource *resource,
			     struct ipu_fw_generic_program_manifest *pm,
			     u32 resource_id,
			     struct ipu_psys_resource_alloc *alloc)
{
	const u16 resource_req = pm->dev_chn_size[resource_id];
	const u16 resource_offset_req = pm->dev_chn_offset[resource_id];
	unsigned long retl;

	if (resource_req <= 0)
		return -ENXIO;

	if (alloc->resources >= IPU_MAX_RESOURCES) {
		dev_err(dev, "out of resource handles\n");
		return -ENOSPC;
	}
	if (resource_offset_req != (u16)(-1))
		retl = ipu_resource_alloc_with_pos
		    (resource,
		     resource_req,
		     resource_offset_req,
		     &alloc->resource_alloc[alloc->resources],
		     IPU_RESOURCE_DEV_CHN);
	else
		retl = ipu_resource_alloc
		    (resource, resource_req,
		     &alloc->resource_alloc[alloc->resources],
		     IPU_RESOURCE_DEV_CHN);
	if (IS_ERR_VALUE(retl)) {
		dev_dbg(dev, "out of device channel resources\n");
		return (int)retl;
	}
	alloc->resources++;

	return 0;
}

static int ipu_psys_allocate_one_dfm(const struct device *dev,
				     struct ipu_fw_psys_process *process,
				     struct ipu_resource *resource,
				     struct ipu_fw_generic_program_manifest *pm,
				     u32 resource_id,
				     struct ipu_psys_resource_alloc *alloc)
{
	u32 dfm_bitmap_req = pm->dfm_port_bitmap[resource_id];
	u32 active_dfm_bitmap_req = pm->dfm_active_port_bitmap[resource_id];
	const u8 is_relocatable = pm->is_dfm_relocatable[resource_id];
	struct ipu_resource_alloc *alloc_resource;
	unsigned long p = 0;

	if (dfm_bitmap_req == 0)
		return -ENXIO;

	if (alloc->resources >= IPU_MAX_RESOURCES) {
		dev_err(dev, "out of resource handles\n");
		return -ENOSPC;
	}

	if (!resource->bitmap)
		return -ENOSPC;

	if (!is_relocatable) {
		if (*resource->bitmap & dfm_bitmap_req) {
			dev_warn(dev,
				 "out of dfm resources, req 0x%x, get 0x%lx\n",
				 dfm_bitmap_req, *resource->bitmap);
			return -ENOSPC;
		}
		*resource->bitmap |= dfm_bitmap_req;
	} else {
		unsigned int n = hweight32(dfm_bitmap_req);

		p = bitmap_find_next_zero_area(resource->bitmap,
					       resource->elements, 0, n, 0);

		if (p >= resource->elements)
			return -ENOSPC;

		bitmap_set(resource->bitmap, p, n);
		dfm_bitmap_req = dfm_bitmap_req << p;
		active_dfm_bitmap_req = active_dfm_bitmap_req << p;
	}

	alloc_resource = &alloc->resource_alloc[alloc->resources];
	alloc_resource->resource = resource;
	/* Using elements to indicate the bitmap */
	alloc_resource->elements = dfm_bitmap_req;
	alloc_resource->pos = p;
	alloc_resource->type = IPU_RESOURCE_DFM;

	alloc->resources++;

	return 0;
}

/*
 * ext_mem_type_id is a generic type id for memory (like DMEM, VMEM)
 * ext_mem_bank_id is detailed type id for  memory (like DMEM0, DMEM1 etc.)
 */
static int __alloc_mem_resrc(const struct device *dev,
			     struct ipu_fw_psys_process *process,
			     struct ipu_resource *resource,
			     struct ipu_fw_generic_program_manifest *pm,
			     u32 ext_mem_type_id, u32 ext_mem_bank_id,
			     struct ipu_psys_resource_alloc *alloc)
{
	const u16 memory_resource_req = pm->ext_mem_size[ext_mem_type_id];
	const u16 memory_offset_req = pm->ext_mem_offset[ext_mem_type_id];

	unsigned long retl;

	if (memory_resource_req <= 0)
		return -ENXIO;

	if (alloc->resources >= IPU_MAX_RESOURCES) {
		dev_err(dev, "out of resource handles\n");
		return -ENOSPC;
	}
	if (memory_offset_req != (u16)(-1))
		retl = ipu_resource_alloc_with_pos
		    (resource,
		     memory_resource_req, memory_offset_req,
		     &alloc->resource_alloc[alloc->resources],
		     IPU_RESOURCE_EXT_MEM);
	else
		retl = ipu_resource_alloc
		    (resource, memory_resource_req,
		     &alloc->resource_alloc[alloc->resources],
		     IPU_RESOURCE_EXT_MEM);
	if (IS_ERR_VALUE(retl)) {
		dev_dbg(dev, "out of memory resources\n");
		return (int)retl;
	}

	alloc->resources++;

	return 0;
}

int ipu_psys_allocate_cmd_queue_resource(struct ipu_psys_resource_pool *pool)
{
	unsigned long p;
	int size, start;

	size = IPU6_FW_PSYS_N_PSYS_CMD_QUEUE_ID;
	start = IPU6_FW_PSYS_CMD_QUEUE_PPG0_COMMAND_ID;

	if (ipu_ver == IPU_VER_6SE) {
		size = IPU6SE_FW_PSYS_N_PSYS_CMD_QUEUE_ID;
		start = IPU6SE_FW_PSYS_CMD_QUEUE_PPG0_COMMAND_ID;
	}

	spin_lock(&pool->queues_lock);
	/* find available cmd queue from ppg0_cmd_id */
	p = bitmap_find_next_zero_area(pool->cmd_queues, size, start, 1, 0);

	if (p >= size) {
		spin_unlock(&pool->queues_lock);
		return -ENOSPC;
	}

	bitmap_set(pool->cmd_queues, p, 1);
	spin_unlock(&pool->queues_lock);

	return p;
}

void ipu_psys_free_cmd_queue_resource(struct ipu_psys_resource_pool *pool,
				      u8 queue_id)
{
	spin_lock(&pool->queues_lock);
	bitmap_clear(pool->cmd_queues, queue_id, 1);
	spin_unlock(&pool->queues_lock);
}

int ipu_psys_try_allocate_resources(struct device *dev,
				    struct ipu_fw_psys_process_group *pg,
				    void *pg_manifest,
				    struct ipu_psys_resource_pool *pool)
{
	u32 id, idx;
	u32 mem_type_id;
	int ret, i;
	u16 *process_offset_table;
	u8 processes;
	u32 cells = 0;
	struct ipu_psys_resource_alloc *alloc;
	const struct ipu_fw_resource_definitions *res_defs;

	if (!pg)
		return -EINVAL;
	process_offset_table = (u16 *)((u8 *)pg + pg->processes_offset);
	processes = pg->process_count;

	alloc = kzalloc(sizeof(*alloc), GFP_KERNEL);
	if (!alloc)
		return -ENOMEM;

	res_defs = get_res();
	for (i = 0; i < processes; i++) {
		u32 cell;
		struct ipu_fw_psys_process *process =
			(struct ipu_fw_psys_process *)
			((char *)pg + process_offset_table[i]);
		struct ipu_fw_generic_program_manifest pm;

		memset(&pm, 0, sizeof(pm));

		if (!process) {
			dev_err(dev, "can not get process\n");
			ret = -ENOENT;
			goto free_out;
		}

		ret = ipu_fw_psys_get_program_manifest_by_process
			(&pm, pg_manifest, process);
		if (ret < 0) {
			dev_err(dev, "can not get manifest\n");
			goto free_out;
		}

		if (pm.cell_id == res_defs->num_cells &&
		    pm.cell_type_id == res_defs->num_cells_type) {
			cell = res_defs->num_cells;
		} else if ((pm.cell_id != res_defs->num_cells &&
			    pm.cell_type_id == res_defs->num_cells_type)) {
			cell = pm.cell_id;
		} else {
			/* Find a free cell of desired type */
			u32 type = pm.cell_type_id;

			for (cell = 0; cell < res_defs->num_cells; cell++)
				if (res_defs->cells[cell] == type &&
				    ((pool->cells | cells) & (1 << cell)) == 0)
					break;
			if (cell >= res_defs->num_cells) {
				dev_dbg(dev, "no free cells of right type\n");
				ret = -ENOSPC;
				goto free_out;
			}
		}
		if (cell < res_defs->num_cells)
			cells |= 1 << cell;
		if (pool->cells & cells) {
			dev_dbg(dev, "out of cell resources\n");
			ret = -ENOSPC;
			goto free_out;
		}

		if (pm.dev_chn_size) {
			for (id = 0; id < res_defs->num_dev_channels; id++) {
				ret = __alloc_one_resrc(dev, process,
							&pool->dev_channels[id],
							&pm, id, alloc);
				if (ret && ret != -ENXIO)
					goto free_out;
			}
		}

		if (pm.dfm_port_bitmap) {
			for (id = 0; id < res_defs->num_dfm_ids; id++) {
				ret = ipu_psys_allocate_one_dfm
					(dev, process,
					 &pool->dfms[id], &pm, id, alloc);
				if (ret && ret != -ENXIO)
					goto free_out;
			}
		}

		if (pm.ext_mem_size) {
			for (mem_type_id = 0;
			     mem_type_id < res_defs->num_ext_mem_types;
			     mem_type_id++) {
				u32 bank = res_defs->num_ext_mem_ids;

				if (cell != res_defs->num_cells) {
					idx = res_defs->cell_mem_row * cell +
						mem_type_id;
					bank = res_defs->cell_mem[idx];
				}

				if (bank == res_defs->num_ext_mem_ids)
					continue;

				ret = __alloc_mem_resrc(dev, process,
							&pool->ext_memory[bank],
							&pm, mem_type_id, bank,
							alloc);
				if (ret && ret != -ENXIO)
					goto free_out;
			}
		}
	}
	alloc->cells |= cells;
	pool->cells |= cells;

	kfree(alloc);
	return 0;

free_out:
	dev_dbg(dev, "failed to try_allocate resource\n");
	kfree(alloc);
	return ret;
}

/*
 * Allocate resources for pg from `pool'. Mark the allocated
 * resources into `alloc'. Returns 0 on success, -ENOSPC
 * if there are no enough resources, in which cases resources
 * are not allocated at all, or some other error on other conditions.
 */
int ipu_psys_allocate_resources(const struct device *dev,
				struct ipu_fw_psys_process_group *pg,
				void *pg_manifest,
				struct ipu_psys_resource_alloc
				*alloc, struct ipu_psys_resource_pool
				*pool)
{
	u32 id;
	u32 mem_type_id;
	int ret, i;
	u16 *process_offset_table;
	u8 processes;
	u32 cells = 0;
	int p, idx;
	u32 bmp, a_bmp;
	const struct ipu_fw_resource_definitions *res_defs;

	if (!pg)
		return -EINVAL;

	res_defs = get_res();
	process_offset_table = (u16 *)((u8 *)pg + pg->processes_offset);
	processes = pg->process_count;

	for (i = 0; i < processes; i++) {
		u32 cell;
		struct ipu_fw_psys_process *process =
		    (struct ipu_fw_psys_process *)
		    ((char *)pg + process_offset_table[i]);
		struct ipu_fw_generic_program_manifest pm;

		memset(&pm, 0, sizeof(pm));
		if (!process) {
			dev_err(dev, "can not get process\n");
			ret = -ENOENT;
			goto free_out;
		}

		ret = ipu_fw_psys_get_program_manifest_by_process
		    (&pm, pg_manifest, process);
		if (ret < 0) {
			dev_err(dev, "can not get manifest\n");
			goto free_out;
		}

		if (pm.cell_id == res_defs->num_cells &&
		    pm.cell_type_id == res_defs->num_cells_type) {
			cell = res_defs->num_cells;
		} else if ((pm.cell_id != res_defs->num_cells &&
			    pm.cell_type_id == res_defs->num_cells_type)) {
			cell = pm.cell_id;
		} else {
			/* Find a free cell of desired type */
			u32 type = pm.cell_type_id;

			for (cell = 0; cell < res_defs->num_cells; cell++)
				if (res_defs->cells[cell] == type &&
				    ((pool->cells | cells) & (1 << cell)) == 0)
					break;
			if (cell >= res_defs->num_cells) {
				dev_dbg(dev, "no free cells of right type\n");
				ret = -ENOSPC;
				goto free_out;
			}
			ret = ipu_fw_psys_set_process_cell_id(process, 0, cell);
			if (ret)
				goto free_out;
		}
		if (cell < res_defs->num_cells)
			cells |= 1 << cell;
		if (pool->cells & cells) {
			dev_dbg(dev, "out of cell resources\n");
			ret = -ENOSPC;
			goto free_out;
		}

		if (pm.dev_chn_size) {
			for (id = 0; id < res_defs->num_dev_channels; id++) {
				ret = __alloc_one_resrc(dev, process,
							&pool->dev_channels[id],
							&pm, id, alloc);
				if (ret == -ENXIO)
					continue;

				if (ret)
					goto free_out;

				idx = alloc->resources - 1;
				p = alloc->resource_alloc[idx].pos;
				ret = ipu_fw_psys_set_proc_dev_chn(process, id,
								   p);
				if (ret)
					goto free_out;
			}
		}

		if (pm.dfm_port_bitmap) {
			for (id = 0; id < res_defs->num_dfm_ids; id++) {
				ret = ipu_psys_allocate_one_dfm(dev, process,
								&pool->dfms[id],
								&pm, id, alloc);
				if (ret == -ENXIO)
					continue;

				if (ret)
					goto free_out;

				idx = alloc->resources - 1;
				p = alloc->resource_alloc[idx].pos;
				bmp = pm.dfm_port_bitmap[id];
				bmp = bmp << p;
				a_bmp = pm.dfm_active_port_bitmap[id];
				a_bmp = a_bmp << p;
				ret = ipu_fw_psys_set_proc_dfm_bitmap(process,
								      id, bmp,
								      a_bmp);
				if (ret)
					goto free_out;
			}
		}

		if (pm.ext_mem_size) {
			for (mem_type_id = 0;
			     mem_type_id < res_defs->num_ext_mem_types;
			     mem_type_id++) {
				u32 bank = res_defs->num_ext_mem_ids;

				if (cell != res_defs->num_cells) {
					idx = res_defs->cell_mem_row * cell +
						mem_type_id;
					bank = res_defs->cell_mem[idx];
				}
				if (bank == res_defs->num_ext_mem_ids)
					continue;

				ret = __alloc_mem_resrc(dev, process,
							&pool->ext_memory[bank],
							&pm, mem_type_id,
							bank, alloc);
				if (ret == -ENXIO)
					continue;

				if (ret)
					goto free_out;

				/* no return value check here because fw api
				 * will do some checks, and would return
				 * non-zero except mem_type_id == 0.
				 * This maybe caused by that above flow of
				 * allocating mem_bank_id is improper.
				 */
				idx = alloc->resources - 1;
				p = alloc->resource_alloc[idx].pos;
				ipu_fw_psys_set_process_ext_mem(process,
								mem_type_id,
								bank, p);
			}
		}
	}
	alloc->cells |= cells;
	pool->cells |= cells;
	return 0;

free_out:
	dev_err(dev, "failed to allocate resources, ret %d\n", ret);
	ipu_psys_reset_process_cell(dev, pg, pg_manifest, i + 1);
	ipu_psys_free_resources(alloc, pool);
	return ret;
}

int ipu_psys_move_resources(const struct device *dev,
			    struct ipu_psys_resource_alloc *alloc,
			    struct ipu_psys_resource_pool
			    *source_pool, struct ipu_psys_resource_pool
			    *target_pool)
{
	int i;

	if (target_pool->cells & alloc->cells) {
		dev_dbg(dev, "out of cell resources\n");
		return -ENOSPC;
	}

	for (i = 0; i < alloc->resources; i++) {
		unsigned long bitmap = 0;
		unsigned int id = alloc->resource_alloc[i].resource->id;
		unsigned long fbit, end;

		switch (alloc->resource_alloc[i].type) {
		case IPU_RESOURCE_DEV_CHN:
			bitmap_set(&bitmap, alloc->resource_alloc[i].pos,
				   alloc->resource_alloc[i].elements);
			if (*target_pool->dev_channels[id].bitmap & bitmap)
				return -ENOSPC;
			break;
		case IPU_RESOURCE_EXT_MEM:
			end = alloc->resource_alloc[i].elements +
			    alloc->resource_alloc[i].pos;

			fbit = find_next_bit(target_pool->ext_memory[id].bitmap,
					     end, alloc->resource_alloc[i].pos);
			/* if find_next_bit returns "end" it didn't find 1bit */
			if (end != fbit)
				return -ENOSPC;
			break;
		case IPU_RESOURCE_DFM:
			bitmap = alloc->resource_alloc[i].elements;
			if (*target_pool->dfms[id].bitmap & bitmap)
				return -ENOSPC;
			break;
		default:
			dev_err(dev, "Illegal resource type\n");
			return -EINVAL;
		}
	}

	for (i = 0; i < alloc->resources; i++) {
		u32 id = alloc->resource_alloc[i].resource->id;

		switch (alloc->resource_alloc[i].type) {
		case IPU_RESOURCE_DEV_CHN:
			bitmap_set(target_pool->dev_channels[id].bitmap,
				   alloc->resource_alloc[i].pos,
				   alloc->resource_alloc[i].elements);
			ipu_resource_free(&alloc->resource_alloc[i]);
			alloc->resource_alloc[i].resource =
			    &target_pool->dev_channels[id];
			break;
		case IPU_RESOURCE_EXT_MEM:
			bitmap_set(target_pool->ext_memory[id].bitmap,
				   alloc->resource_alloc[i].pos,
				   alloc->resource_alloc[i].elements);
			ipu_resource_free(&alloc->resource_alloc[i]);
			alloc->resource_alloc[i].resource =
			    &target_pool->ext_memory[id];
			break;
		case IPU_RESOURCE_DFM:
			*target_pool->dfms[id].bitmap |=
			    alloc->resource_alloc[i].elements;
			*alloc->resource_alloc[i].resource->bitmap &=
			    ~(alloc->resource_alloc[i].elements);
			alloc->resource_alloc[i].resource =
			    &target_pool->dfms[id];
			break;
		default:
			/*
			 * Just keep compiler happy. This case failed already
			 * in above loop.
			 */
			break;
		}
	}

	target_pool->cells |= alloc->cells;
	source_pool->cells &= ~alloc->cells;

	return 0;
}

void ipu_psys_reset_process_cell(const struct device *dev,
				 struct ipu_fw_psys_process_group *pg,
				 void *pg_manifest,
				 int process_count)
{
	int i;
	u16 *process_offset_table;
	const struct ipu_fw_resource_definitions *res_defs;

	if (!pg)
		return;

	res_defs = get_res();
	process_offset_table = (u16 *)((u8 *)pg + pg->processes_offset);
	for (i = 0; i < process_count; i++) {
		struct ipu_fw_psys_process *process =
		    (struct ipu_fw_psys_process *)
		    ((char *)pg + process_offset_table[i]);
		struct ipu_fw_generic_program_manifest pm;
		int ret;

		if (!process)
			break;

		ret = ipu_fw_psys_get_program_manifest_by_process(&pm,
								  pg_manifest,
								  process);
		if (ret < 0) {
			dev_err(dev, "can not get manifest\n");
			break;
		}
		if ((pm.cell_id != res_defs->num_cells &&
		     pm.cell_type_id == res_defs->num_cells_type))
			continue;
		/* no return value check here because if finding free cell
		 * failed, process cell would not set then calling clear_cell
		 * will return non-zero.
		 */
		ipu_fw_psys_clear_process_cell(process);
	}
}

/* Free resources marked in `alloc' from `resources' */
void ipu_psys_free_resources(struct ipu_psys_resource_alloc
			     *alloc, struct ipu_psys_resource_pool *pool)
{
	unsigned int i;

	pool->cells &= ~alloc->cells;
	alloc->cells = 0;
	for (i = 0; i < alloc->resources; i++)
		ipu_resource_free(&alloc->resource_alloc[i]);
	alloc->resources = 0;
}
