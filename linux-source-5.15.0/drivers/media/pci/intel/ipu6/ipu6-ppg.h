/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020 Intel Corporation
 */

#ifndef IPU6_PPG_H
#define IPU6_PPG_H

#include "ipu-psys.h"
/* starting from '2' in case of someone passes true or false */
enum SCHED_LIST {
	SCHED_START_LIST = 2,
	SCHED_STOP_LIST
};

enum ipu_psys_power_gating_state {
	PSYS_POWER_NORMAL = 0,
	PSYS_POWER_GATING,
	PSYS_POWER_GATED
};

int ipu_psys_ppg_get_bufset(struct ipu_psys_kcmd *kcmd,
			    struct ipu_psys_ppg *kppg);
struct ipu_psys_kcmd *ipu_psys_ppg_get_stop_kcmd(struct ipu_psys_ppg *kppg);
void ipu_psys_scheduler_remove_kppg(struct ipu_psys_ppg *kppg,
				    enum SCHED_LIST type);
void ipu_psys_scheduler_add_kppg(struct ipu_psys_ppg *kppg,
				 enum SCHED_LIST type);
int ipu_psys_ppg_start(struct ipu_psys_ppg *kppg);
int ipu_psys_ppg_resume(struct ipu_psys_ppg *kppg);
int ipu_psys_ppg_stop(struct ipu_psys_ppg *kppg);
int ipu_psys_ppg_suspend(struct ipu_psys_ppg *kppg);
void ipu_psys_ppg_complete(struct ipu_psys *psys, struct ipu_psys_ppg *kppg);
bool ipu_psys_ppg_enqueue_bufsets(struct ipu_psys_ppg *kppg);
void ipu_psys_enter_power_gating(struct ipu_psys *psys);
void ipu_psys_exit_power_gating(struct ipu_psys *psys);

#endif /* IPU6_PPG_H */
