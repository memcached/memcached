/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2013 - 2020 Intel Corporation */

#ifndef IPU_BUTTRESS_H
#define IPU_BUTTRESS_H

#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include "ipu.h"

#define IPU_BUTTRESS_NUM_OF_SENS_CKS	3
#define IPU_BUTTRESS_NUM_OF_PLL_CKS	3
#define IPU_BUTTRESS_TSC_CLK		19200000

#define BUTTRESS_POWER_TIMEOUT			200000

#define BUTTRESS_PS_FREQ_STEP		25U
#define BUTTRESS_MIN_FORCE_PS_FREQ	(BUTTRESS_PS_FREQ_STEP * 8)
#define BUTTRESS_MAX_FORCE_PS_FREQ	(BUTTRESS_PS_FREQ_STEP * 32)

#define BUTTRESS_IS_FREQ_STEP		25U
#define BUTTRESS_MIN_FORCE_IS_FREQ	(BUTTRESS_IS_FREQ_STEP * 8)
#define BUTTRESS_MAX_FORCE_IS_FREQ	(BUTTRESS_IS_FREQ_STEP * 16)

struct ipu_buttress_ctrl {
	u32 freq_ctl, pwr_sts_shift, pwr_sts_mask, pwr_sts_on, pwr_sts_off;
	union {
		unsigned int divisor;
		unsigned int ratio;
	};
	union {
		unsigned int divisor_shift;
		unsigned int ratio_shift;
	};
	unsigned int qos_floor;
	bool started;
};

struct ipu_buttress_fused_freqs {
	unsigned int min_freq;
	unsigned int max_freq;
	unsigned int efficient_freq;
};

struct ipu_buttress_ipc {
	struct completion send_complete;
	struct completion recv_complete;
	u32 nack;
	u32 nack_mask;
	u32 recv_data;
	u32 csr_out;
	u32 csr_in;
	u32 db0_in;
	u32 db0_out;
	u32 data0_out;
	u32 data0_in;
};

struct ipu_buttress {
	struct mutex power_mutex, auth_mutex, cons_mutex, ipc_mutex;
	struct ipu_buttress_ipc cse;
	struct ipu_buttress_ipc ish;
	struct list_head constraints;
	struct ipu_buttress_fused_freqs psys_fused_freqs;
	unsigned int psys_min_freq;
	u32 wdt_cached_value;
	u8 psys_force_ratio;
	bool force_suspend;
	u32 ref_clk;
};

struct ipu_buttress_sensor_clk_freq {
	unsigned int rate;
	unsigned int val;
};

struct firmware;

enum ipu_buttress_ipc_domain {
	IPU_BUTTRESS_IPC_CSE,
	IPU_BUTTRESS_IPC_ISH,
};

struct ipu_buttress_constraint {
	struct list_head list;
	unsigned int min_freq;
};

struct ipu_ipc_buttress_bulk_msg {
	u32 cmd;
	u32 expected_resp;
	bool require_resp;
	u8 cmd_size;
};

int ipu_buttress_ipc_reset(struct ipu_device *isp,
			   struct ipu_buttress_ipc *ipc);
int ipu_buttress_map_fw_image(struct ipu_bus_device *sys,
			      const struct firmware *fw, struct sg_table *sgt);
int ipu_buttress_unmap_fw_image(struct ipu_bus_device *sys,
				struct sg_table *sgt);
int ipu_buttress_power(struct device *dev,
		       struct ipu_buttress_ctrl *ctrl, bool on);
void
ipu_buttress_add_psys_constraint(struct ipu_device *isp,
				 struct ipu_buttress_constraint *constraint);
void
ipu_buttress_remove_psys_constraint(struct ipu_device *isp,
				    struct ipu_buttress_constraint *constraint);
void ipu_buttress_set_secure_mode(struct ipu_device *isp);
bool ipu_buttress_get_secure_mode(struct ipu_device *isp);
int ipu_buttress_authenticate(struct ipu_device *isp);
int ipu_buttress_reset_authentication(struct ipu_device *isp);
bool ipu_buttress_auth_done(struct ipu_device *isp);
int ipu_buttress_start_tsc_sync(struct ipu_device *isp);
int ipu_buttress_tsc_read(struct ipu_device *isp, u64 *val);
u64 ipu_buttress_tsc_ticks_to_ns(u64 ticks, const struct ipu_device *isp);

irqreturn_t ipu_buttress_isr(int irq, void *isp_ptr);
irqreturn_t ipu_buttress_isr_threaded(int irq, void *isp_ptr);
int ipu_buttress_debugfs_init(struct ipu_device *isp);
int ipu_buttress_init(struct ipu_device *isp);
void ipu_buttress_exit(struct ipu_device *isp);
void ipu_buttress_csi_port_config(struct ipu_device *isp,
				  u32 legacy, u32 combo);
int ipu_buttress_restore(struct ipu_device *isp);

int ipu_buttress_psys_freq_get(void *data, u64 *val);
#endif /* IPU_BUTTRESS_H */
