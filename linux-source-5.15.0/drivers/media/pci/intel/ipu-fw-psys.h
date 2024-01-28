/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2016 - 2020 Intel Corporation */

#ifndef IPU_FW_PSYS_H
#define IPU_FW_PSYS_H

#include "ipu6-platform-resources.h"
#include "ipu6se-platform-resources.h"
#include "ipu6ep-platform-resources.h"

#define IPU_FW_PSYS_CMD_QUEUE_SIZE 0x20
#define IPU_FW_PSYS_EVENT_QUEUE_SIZE 0x40

#define IPU_FW_PSYS_CMD_BITS 64
#define IPU_FW_PSYS_EVENT_BITS 128

enum {
	IPU_FW_PSYS_EVENT_TYPE_SUCCESS = 0,
	IPU_FW_PSYS_EVENT_TYPE_UNKNOWN_ERROR = 1,
	IPU_FW_PSYS_EVENT_TYPE_RET_REM_OBJ_NOT_FOUND = 2,
	IPU_FW_PSYS_EVENT_TYPE_RET_REM_OBJ_TOO_BIG = 3,
	IPU_FW_PSYS_EVENT_TYPE_RET_REM_OBJ_DDR_TRANS_ERR = 4,
	IPU_FW_PSYS_EVENT_TYPE_RET_REM_OBJ_NULL_PKG_DIR_ADDR = 5,
	IPU_FW_PSYS_EVENT_TYPE_PROC_GRP_LOAD_FRAME_ERR = 6,
	IPU_FW_PSYS_EVENT_TYPE_PROC_GRP_LOAD_FRAGMENT_ERR = 7,
	IPU_FW_PSYS_EVENT_TYPE_PROC_GRP_PROCESS_COUNT_ZERO = 8,
	IPU_FW_PSYS_EVENT_TYPE_PROC_GRP_PROCESS_INIT_ERR = 9,
	IPU_FW_PSYS_EVENT_TYPE_PROC_GRP_ABORT = 10,
	IPU_FW_PSYS_EVENT_TYPE_PROC_GRP_NULL = 11,
	IPU_FW_PSYS_EVENT_TYPE_PROC_GRP_VALIDATION_ERR = 12,
	IPU_FW_PSYS_EVENT_TYPE_PROC_GRP_INVALID_FRAME = 13
};

enum {
	IPU_FW_PSYS_EVENT_QUEUE_MAIN_ID,
	IPU_FW_PSYS_N_PSYS_EVENT_QUEUE_ID
};

enum {
	IPU_FW_PSYS_PROCESS_GROUP_ERROR = 0,
	IPU_FW_PSYS_PROCESS_GROUP_CREATED,
	IPU_FW_PSYS_PROCESS_GROUP_READY,
	IPU_FW_PSYS_PROCESS_GROUP_BLOCKED,
	IPU_FW_PSYS_PROCESS_GROUP_STARTED,
	IPU_FW_PSYS_PROCESS_GROUP_RUNNING,
	IPU_FW_PSYS_PROCESS_GROUP_STALLED,
	IPU_FW_PSYS_PROCESS_GROUP_STOPPED,
	IPU_FW_PSYS_N_PROCESS_GROUP_STATES
};

enum {
	IPU_FW_PSYS_CONNECTION_MEMORY = 0,
	IPU_FW_PSYS_CONNECTION_MEMORY_STREAM,
	IPU_FW_PSYS_CONNECTION_STREAM,
	IPU_FW_PSYS_N_CONNECTION_TYPES
};

enum {
	IPU_FW_PSYS_BUFFER_NULL = 0,
	IPU_FW_PSYS_BUFFER_UNDEFINED,
	IPU_FW_PSYS_BUFFER_EMPTY,
	IPU_FW_PSYS_BUFFER_NONEMPTY,
	IPU_FW_PSYS_BUFFER_FULL,
	IPU_FW_PSYS_N_BUFFER_STATES
};

enum {
	IPU_FW_PSYS_TERMINAL_TYPE_DATA_IN = 0,
	IPU_FW_PSYS_TERMINAL_TYPE_DATA_OUT,
	IPU_FW_PSYS_TERMINAL_TYPE_PARAM_STREAM,
	IPU_FW_PSYS_TERMINAL_TYPE_PARAM_CACHED_IN,
	IPU_FW_PSYS_TERMINAL_TYPE_PARAM_CACHED_OUT,
	IPU_FW_PSYS_TERMINAL_TYPE_PARAM_SPATIAL_IN,
	IPU_FW_PSYS_TERMINAL_TYPE_PARAM_SPATIAL_OUT,
	IPU_FW_PSYS_TERMINAL_TYPE_PARAM_SLICED_IN,
	IPU_FW_PSYS_TERMINAL_TYPE_PARAM_SLICED_OUT,
	IPU_FW_PSYS_TERMINAL_TYPE_STATE_IN,
	IPU_FW_PSYS_TERMINAL_TYPE_STATE_OUT,
	IPU_FW_PSYS_TERMINAL_TYPE_PROGRAM,
	IPU_FW_PSYS_TERMINAL_TYPE_PROGRAM_CONTROL_INIT,
	IPU_FW_PSYS_N_TERMINAL_TYPES
};

enum {
	IPU_FW_PSYS_COL_DIMENSION = 0,
	IPU_FW_PSYS_ROW_DIMENSION = 1,
	IPU_FW_PSYS_N_DATA_DIMENSION = 2
};

enum {
	IPU_FW_PSYS_PROCESS_GROUP_CMD_NOP = 0,
	IPU_FW_PSYS_PROCESS_GROUP_CMD_SUBMIT,
	IPU_FW_PSYS_PROCESS_GROUP_CMD_ATTACH,
	IPU_FW_PSYS_PROCESS_GROUP_CMD_DETACH,
	IPU_FW_PSYS_PROCESS_GROUP_CMD_START,
	IPU_FW_PSYS_PROCESS_GROUP_CMD_DISOWN,
	IPU_FW_PSYS_PROCESS_GROUP_CMD_RUN,
	IPU_FW_PSYS_PROCESS_GROUP_CMD_STOP,
	IPU_FW_PSYS_PROCESS_GROUP_CMD_SUSPEND,
	IPU_FW_PSYS_PROCESS_GROUP_CMD_RESUME,
	IPU_FW_PSYS_PROCESS_GROUP_CMD_ABORT,
	IPU_FW_PSYS_PROCESS_GROUP_CMD_RESET,
	IPU_FW_PSYS_N_PROCESS_GROUP_CMDS
};

enum {
	IPU_FW_PSYS_PROCESS_GROUP_PROTOCOL_LEGACY = 0,
	IPU_FW_PSYS_PROCESS_GROUP_PROTOCOL_PPG,
	IPU_FW_PSYS_PROCESS_GROUP_N_PROTOCOLS
};

struct __packed ipu_fw_psys_process_group {
	u64 token;
	u64 private_token;
	u32 routing_bitmap[IPU_FW_PSYS_RBM_NOF_ELEMS];
	u32 kernel_bitmap[IPU_FW_PSYS_KBM_NOF_ELEMS];
	u32 size;
	u32 psys_server_init_cycles;
	u32 pg_load_start_ts;
	u32 pg_load_cycles;
	u32 pg_init_cycles;
	u32 pg_processing_cycles;
	u32 pg_next_frame_init_cycles;
	u32 pg_complete_cycles;
	u32 ID;
	u32 state;
	u32 ipu_virtual_address;
	u32 resource_bitmap;
	u16 fragment_count;
	u16 fragment_state;
	u16 fragment_limit;
	u16 processes_offset;
	u16 terminals_offset;
	u8 process_count;
	u8 terminal_count;
	u8 subgraph_count;
	u8 protocol_version;
	u8 base_queue_id;
	u8 num_queues;
	u8 mask_irq;
	u8 error_handling_enable;
	u8 padding[IPU_FW_PSYS_N_PADDING_UINT8_IN_PROCESS_GROUP_STRUCT];
};

struct ipu_fw_psys_srv_init {
	void *host_ddr_pkg_dir;
	u32 ddr_pkg_dir_address;
	u32 pkg_dir_size;

	u32 icache_prefetch_sp;
	u32 icache_prefetch_isp;
};

struct __packed ipu_fw_psys_cmd {
	u16 command;
	u16 msg;
	u32 context_handle;
};

struct __packed ipu_fw_psys_event {
	u16 status;
	u16 command;
	u32 context_handle;
	u64 token;
};

struct ipu_fw_psys_terminal {
	u32 terminal_type;
	s16 parent_offset;
	u16 size;
	u16 tm_index;
	u8 ID;
	u8 padding[IPU_FW_PSYS_N_PADDING_UINT8_IN_TERMINAL_STRUCT];
};

struct ipu_fw_psys_param_payload {
	u64 host_buffer;
	u32 buffer;
	u32 terminal_index;
};

struct ipu_fw_psys_param_terminal {
	struct ipu_fw_psys_terminal base;
	struct ipu_fw_psys_param_payload param_payload;
	u16 param_section_desc_offset;
	u8 padding[IPU_FW_PSYS_N_PADDING_UINT8_IN_PARAM_TERMINAL_STRUCT];
};

struct ipu_fw_psys_frame {
	u32 buffer_state;
	u32 access_type;
	u32 pointer_state;
	u32 access_scope;
	u32 data;
	u32 data_index;
	u32 data_bytes;
	u8 padding[IPU_FW_PSYS_N_PADDING_UINT8_IN_FRAME_STRUCT];
};

struct ipu_fw_psys_frame_descriptor {
	u32 frame_format_type;
	u32 plane_count;
	u32 plane_offsets[IPU_FW_PSYS_N_FRAME_PLANES];
	u32 stride[1];
	u32 ts_offsets[IPU_FW_PSYS_N_FRAME_PLANES];
	u16 dimension[2];
	u16 size;
	u8 bpp;
	u8 bpe;
	u8 is_compressed;
	u8 padding[IPU_FW_PSYS_N_PADDING_UINT8_IN_FRAME_DESC_STRUCT];
};

struct ipu_fw_psys_stream {
	u64 dummy;
};

struct ipu_fw_psys_data_terminal {
	struct ipu_fw_psys_terminal base;
	struct ipu_fw_psys_frame_descriptor frame_descriptor;
	struct ipu_fw_psys_frame frame;
	struct ipu_fw_psys_stream stream;
	u32 reserved;
	u32 connection_type;
	u16 fragment_descriptor_offset;
	u8 kernel_id;
	u8 subgraph_id;
	u8 padding[IPU_FW_PSYS_N_PADDING_UINT8_IN_DATA_TERMINAL_STRUCT];
};

struct ipu_fw_psys_buffer_set {
	u64 token;
	u32 kernel_enable_bitmap[IPU_FW_PSYS_KERNEL_BITMAP_NOF_ELEMS];
	u32 terminal_enable_bitmap[IPU_FW_PSYS_KERNEL_BITMAP_NOF_ELEMS];
	u32 routing_enable_bitmap[IPU_FW_PSYS_KERNEL_BITMAP_NOF_ELEMS];
	u32 rbm[IPU_FW_PSYS_RBM_NOF_ELEMS];
	u32 ipu_virtual_address;
	u32 process_group_handle;
	u16 terminal_count;
	u8 frame_counter;
	u8 padding[IPU_FW_PSYS_N_PADDING_UINT8_IN_BUFFER_SET_STRUCT];
};

struct ipu_fw_psys_program_group_manifest {
	u32 kernel_bitmap[IPU_FW_PSYS_KERNEL_BITMAP_NOF_ELEMS];
	u32 ID;
	u16 program_manifest_offset;
	u16 terminal_manifest_offset;
	u16 private_data_offset;
	u16 rbm_manifest_offset;
	u16 size;
	u8 alignment;
	u8 kernel_count;
	u8 program_count;
	u8 terminal_count;
	u8 subgraph_count;
	u8 reserved[5];
};

struct ipu_fw_generic_program_manifest {
	u16 *dev_chn_size;
	u16 *dev_chn_offset;
	u16 *ext_mem_size;
	u16 *ext_mem_offset;
	u8 cell_id;
	u8 cells[IPU_FW_PSYS_PROCESS_MAX_CELLS];
	u8 cell_type_id;
	u8 *is_dfm_relocatable;
	u32 *dfm_port_bitmap;
	u32 *dfm_active_port_bitmap;
};

struct ipu_fw_resource_definitions {
	u32 num_cells;
	u32 num_cells_type;
	const u8 *cells;
	u32 num_dev_channels;
	const u16 *dev_channels;

	u32 num_ext_mem_types;
	u32 num_ext_mem_ids;
	const u16 *ext_mem_ids;

	u32 num_dfm_ids;
	const u16 *dfms;

	u32 cell_mem_row;
	const u8 *cell_mem;
};

struct ipu6_psys_hw_res_variant {
	unsigned int queue_num;
	unsigned int cell_num;
	int (*set_proc_dev_chn)(struct ipu_fw_psys_process *ptr, u16 offset,
				u16 value);
	int (*set_proc_dfm_bitmap)(struct ipu_fw_psys_process *ptr,
				   u16 id, u32 bitmap, u32 active_bitmap);
	int (*set_proc_ext_mem)(struct ipu_fw_psys_process *ptr,
				u16 type_id, u16 mem_id, u16 offset);
	int (*get_pgm_by_proc)(struct ipu_fw_generic_program_manifest *gen_pm,
			       const struct ipu_fw_psys_program_group_manifest
			       *pg_manifest,
			       struct ipu_fw_psys_process *process);
};
struct ipu_psys_kcmd;
struct ipu_psys;
int ipu_fw_psys_pg_start(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_pg_disown(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_pg_abort(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_pg_submit(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_ppg_suspend(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_ppg_resume(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_pg_load_cycles(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_pg_init_cycles(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_pg_processing_cycles(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_pg_server_init_cycles(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_pg_next_frame_init_cycles(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_pg_complete_cycles(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_rcv_event(struct ipu_psys *psys,
			  struct ipu_fw_psys_event *event);
int ipu_fw_psys_terminal_set(struct ipu_fw_psys_terminal *terminal,
			     int terminal_idx,
			     struct ipu_psys_kcmd *kcmd,
			     u32 buffer, unsigned int size);
void ipu_fw_psys_pg_dump(struct ipu_psys *psys,
			 struct ipu_psys_kcmd *kcmd, const char *note);
int ipu_fw_psys_pg_get_id(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_pg_get_terminal_count(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_pg_get_size(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_pg_set_ipu_vaddress(struct ipu_psys_kcmd *kcmd,
				    dma_addr_t vaddress);
struct ipu_fw_psys_terminal *ipu_fw_psys_pg_get_terminal(struct ipu_psys_kcmd
							 *kcmd, int index);
void ipu_fw_psys_pg_set_token(struct ipu_psys_kcmd *kcmd, u64 token);
u64 ipu_fw_psys_pg_get_token(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_ppg_set_buffer_set(struct ipu_psys_kcmd *kcmd,
				   struct ipu_fw_psys_terminal *terminal,
				   int terminal_idx, u32 buffer);
size_t ipu_fw_psys_ppg_get_buffer_set_size(struct ipu_psys_kcmd *kcmd);
int
ipu_fw_psys_ppg_buffer_set_vaddress(struct ipu_fw_psys_buffer_set *buf_set,
				    u32 vaddress);
int ipu_fw_psys_ppg_buffer_set_set_kernel_enable_bitmap(
	struct ipu_fw_psys_buffer_set *buf_set, u32 *kernel_enable_bitmap);
struct ipu_fw_psys_buffer_set *
ipu_fw_psys_ppg_create_buffer_set(struct ipu_psys_kcmd *kcmd,
				  void *kaddr, u32 frame_counter);
int ipu_fw_psys_ppg_enqueue_bufs(struct ipu_psys_kcmd *kcmd);
u8 ipu_fw_psys_ppg_get_base_queue_id(struct ipu_psys_kcmd *kcmd);
void ipu_fw_psys_ppg_set_base_queue_id(struct ipu_psys_kcmd *kcmd, u8 queue_id);
int ipu_fw_psys_pg_get_protocol(struct ipu_psys_kcmd *kcmd);
int ipu_fw_psys_open(struct ipu_psys *psys);
int ipu_fw_psys_close(struct ipu_psys *psys);

/* common resource interface for both abi and api mode */
int ipu_fw_psys_set_process_cell_id(struct ipu_fw_psys_process *ptr, u8 index,
				    u8 value);
u8 ipu_fw_psys_get_process_cell_id(struct ipu_fw_psys_process *ptr, u8 index);
int ipu_fw_psys_clear_process_cell(struct ipu_fw_psys_process *ptr);
int ipu_fw_psys_set_proc_dev_chn(struct ipu_fw_psys_process *ptr, u16 offset,
				 u16 value);
int ipu_fw_psys_set_process_ext_mem(struct ipu_fw_psys_process *ptr,
				    u16 type_id, u16 mem_id, u16 offset);
int ipu_fw_psys_get_program_manifest_by_process(
	struct ipu_fw_generic_program_manifest *gen_pm,
	const struct ipu_fw_psys_program_group_manifest *pg_manifest,
	struct ipu_fw_psys_process *process);
int ipu6_fw_psys_set_proc_dev_chn(struct ipu_fw_psys_process *ptr, u16 offset,
				  u16 value);
int ipu6_fw_psys_set_proc_dfm_bitmap(struct ipu_fw_psys_process *ptr,
				     u16 id, u32 bitmap,
				     u32 active_bitmap);
int ipu6_fw_psys_set_process_ext_mem(struct ipu_fw_psys_process *ptr,
				     u16 type_id, u16 mem_id, u16 offset);
int ipu6_fw_psys_get_program_manifest_by_process(
	struct ipu_fw_generic_program_manifest *gen_pm,
	const struct ipu_fw_psys_program_group_manifest *pg_manifest,
	struct ipu_fw_psys_process *process);
void ipu6_fw_psys_pg_dump(struct ipu_psys *psys,
			  struct ipu_psys_kcmd *kcmd, const char *note);
void ipu6_psys_hw_res_variant_init(void);
#endif /* IPU_FW_PSYS_H */
