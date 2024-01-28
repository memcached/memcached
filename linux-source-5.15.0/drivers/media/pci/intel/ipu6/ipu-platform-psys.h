/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020 Intel Corporation */

#ifndef IPU_PLATFORM_PSYS_H
#define IPU_PLATFORM_PSYS_H

#include "ipu-psys.h"
#include <uapi/linux/ipu-psys.h>

#define IPU_PSYS_BUF_SET_POOL_SIZE 8
#define IPU_PSYS_BUF_SET_MAX_SIZE 1024

struct ipu_fw_psys_buffer_set;

enum ipu_psys_cmd_state {
	KCMD_STATE_PPG_NEW,
	KCMD_STATE_PPG_START,
	KCMD_STATE_PPG_ENQUEUE,
	KCMD_STATE_PPG_STOP,
	KCMD_STATE_PPG_COMPLETE
};

struct ipu_psys_scheduler {
	struct list_head ppgs;
	struct mutex bs_mutex;  /* Protects buf_set field */
	struct list_head buf_sets;
};

enum ipu_psys_ppg_state {
	PPG_STATE_START = (1 << 0),
	PPG_STATE_STARTING = (1 << 1),
	PPG_STATE_STARTED = (1 << 2),
	PPG_STATE_RUNNING = (1 << 3),
	PPG_STATE_SUSPEND = (1 << 4),
	PPG_STATE_SUSPENDING = (1 << 5),
	PPG_STATE_SUSPENDED = (1 << 6),
	PPG_STATE_RESUME = (1 << 7),
	PPG_STATE_RESUMING = (1 << 8),
	PPG_STATE_RESUMED = (1 << 9),
	PPG_STATE_STOP = (1 << 10),
	PPG_STATE_STOPPING = (1 << 11),
	PPG_STATE_STOPPED = (1 << 12),
};

struct ipu_psys_ppg {
	struct ipu_psys_pg *kpg;
	struct ipu_psys_fh *fh;
	struct list_head list;
	struct list_head sched_list;
	u64 token;
	void *manifest;
	struct mutex mutex;     /* Protects kcmd and ppg state field */
	struct list_head kcmds_new_list;
	struct list_head kcmds_processing_list;
	struct list_head kcmds_finished_list;
	enum ipu_psys_ppg_state state;
	u32 pri_base;
	int pri_dynamic;
};

struct ipu_psys_buffer_set {
	struct list_head list;
	struct ipu_fw_psys_buffer_set *buf_set;
	size_t size;
	size_t buf_set_size;
	dma_addr_t dma_addr;
	void *kaddr;
	struct ipu_psys_kcmd *kcmd;
};

int ipu_psys_kcmd_start(struct ipu_psys *psys, struct ipu_psys_kcmd *kcmd);
void ipu_psys_kcmd_complete(struct ipu_psys_ppg *kppg,
			    struct ipu_psys_kcmd *kcmd,
			    int error);
int ipu_psys_fh_init(struct ipu_psys_fh *fh);
int ipu_psys_fh_deinit(struct ipu_psys_fh *fh);

#endif /* IPU_PLATFORM_PSYS_H */
