/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2018 - 2020 Intel Corporation */

#ifndef IPU_PLATFORM_RESOURCES_COMMON_H
#define IPU_PLATFORM_RESOURCES_COMMON_H

#define IPU_FW_PSYS_N_PADDING_UINT8_IN_PROGRAM_MANIFEST                 0

#define	IPU_FW_PSYS_N_PADDING_UINT8_IN_PROCESS_STRUCT			0
#define	IPU_FW_PSYS_N_PADDING_UINT8_IN_PROCESS_GROUP_STRUCT		2
#define	IPU_FW_PSYS_N_PADDING_UINT8_IN_PROGRAM_MANIFEST_EXT		2

#define IPU_FW_PSYS_N_PADDING_UINT8_IN_TERMINAL_STRUCT			5

#define IPU_FW_PSYS_N_PADDING_UINT8_IN_PARAM_TERMINAL_STRUCT		6

#define	IPU_FW_PSYS_N_PADDING_UINT8_IN_DATA_TERMINAL_STRUCT		3

#define	IPU_FW_PSYS_N_PADDING_UINT8_IN_FRAME_DESC_STRUCT		3
#define IPU_FW_PSYS_N_FRAME_PLANES					6
#define IPU_FW_PSYS_N_PADDING_UINT8_IN_FRAME_STRUCT			4

#define IPU_FW_PSYS_N_PADDING_UINT8_IN_BUFFER_SET_STRUCT		1

#define IPU_FW_PSYS_MAX_INPUT_DEC_RESOURCES		4
#define IPU_FW_PSYS_MAX_OUTPUT_DEC_RESOURCES		4

#define IPU_FW_PSYS_PROCESS_MAX_CELLS			1
#define IPU_FW_PSYS_KERNEL_BITMAP_NOF_ELEMS		4
#define IPU_FW_PSYS_RBM_NOF_ELEMS			5
#define IPU_FW_PSYS_KBM_NOF_ELEMS			4

struct ipu_fw_psys_process {
	s16 parent_offset;
	u8 size;
	u8 cell_dependencies_offset;
	u8 terminal_dependencies_offset;
	u8 process_extension_offset;
	u8 ID;
	u8 program_idx;
	u8 state;
	u8 cells[IPU_FW_PSYS_PROCESS_MAX_CELLS];
	u8 cell_dependency_count;
	u8 terminal_dependency_count;
};

struct ipu_fw_psys_program_manifest {
	u32 kernel_bitmap[IPU_FW_PSYS_KERNEL_BITMAP_NOF_ELEMS];
	s16 parent_offset;
	u8  program_dependency_offset;
	u8  terminal_dependency_offset;
	u8  size;
	u8  program_extension_offset;
	u8 program_type;
	u8 ID;
	u8 cells[IPU_FW_PSYS_PROCESS_MAX_CELLS];
	u8 cell_type_id;
	u8 program_dependency_count;
	u8 terminal_dependency_count;
};

/* platform specific resource interface */
struct ipu_psys_resource_pool;
struct ipu_psys_resource_alloc;
struct ipu_fw_psys_process_group;
int ipu_psys_allocate_resources(const struct device *dev,
				struct ipu_fw_psys_process_group *pg,
				void *pg_manifest,
				struct ipu_psys_resource_alloc *alloc,
				struct ipu_psys_resource_pool *pool);
int ipu_psys_move_resources(const struct device *dev,
			    struct ipu_psys_resource_alloc *alloc,
			    struct ipu_psys_resource_pool *source_pool,
			    struct ipu_psys_resource_pool *target_pool);

void ipu_psys_resource_copy(struct ipu_psys_resource_pool *src,
			    struct ipu_psys_resource_pool *dest);

int ipu_psys_try_allocate_resources(struct device *dev,
				    struct ipu_fw_psys_process_group *pg,
				    void *pg_manifest,
				    struct ipu_psys_resource_pool *pool);

void ipu_psys_reset_process_cell(const struct device *dev,
				 struct ipu_fw_psys_process_group *pg,
				 void *pg_manifest,
				 int process_count);
void ipu_psys_free_resources(struct ipu_psys_resource_alloc *alloc,
			     struct ipu_psys_resource_pool *pool);

int ipu_fw_psys_set_proc_dfm_bitmap(struct ipu_fw_psys_process *ptr,
				    u16 id, u32 bitmap,
				    u32 active_bitmap);

int ipu_psys_allocate_cmd_queue_resource(struct ipu_psys_resource_pool *pool);
void ipu_psys_free_cmd_queue_resource(struct ipu_psys_resource_pool *pool,
				      u8 queue_id);

extern const struct ipu_fw_resource_definitions *ipu6_res_defs;
extern const struct ipu_fw_resource_definitions *ipu6se_res_defs;
extern const struct ipu_fw_resource_definitions *ipu6ep_res_defs;
extern struct ipu6_psys_hw_res_variant hw_var;
#endif /* IPU_PLATFORM_RESOURCES_COMMON_H */
