/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2013 - 2020 Intel Corporation */

#ifndef IPU_FW_COM_H
#define IPU_FW_COM_H

struct ipu_fw_com_context;
struct ipu_bus_device;

struct ipu_fw_syscom_queue_config {
	unsigned int queue_size;	/* tokens per queue */
	unsigned int token_size;	/* bytes per token */
};

#define SYSCOM_BUTTRESS_FW_PARAMS_ISYS_OFFSET	0
#define SYSCOM_BUTTRESS_FW_PARAMS_PSYS_OFFSET	7

struct ipu_fw_com_cfg {
	unsigned int num_input_queues;
	unsigned int num_output_queues;
	struct ipu_fw_syscom_queue_config *input;
	struct ipu_fw_syscom_queue_config *output;

	unsigned int dmem_addr;

	/* firmware-specific configuration data */
	void *specific_addr;
	unsigned int specific_size;
	int (*cell_ready)(struct ipu_bus_device *adev);
	void (*cell_start)(struct ipu_bus_device *adev);

	unsigned int buttress_boot_offset;
};

void *ipu_fw_com_prepare(struct ipu_fw_com_cfg *cfg,
			 struct ipu_bus_device *adev, void __iomem *base);

int ipu_fw_com_open(struct ipu_fw_com_context *ctx);
int ipu_fw_com_ready(struct ipu_fw_com_context *ctx);
int ipu_fw_com_close(struct ipu_fw_com_context *ctx);
int ipu_fw_com_release(struct ipu_fw_com_context *ctx, unsigned int force);

void *ipu_recv_get_token(struct ipu_fw_com_context *ctx, int q_nbr);
void ipu_recv_put_token(struct ipu_fw_com_context *ctx, int q_nbr);
void *ipu_send_get_token(struct ipu_fw_com_context *ctx, int q_nbr);
void ipu_send_put_token(struct ipu_fw_com_context *ctx, int q_nbr);

#endif
