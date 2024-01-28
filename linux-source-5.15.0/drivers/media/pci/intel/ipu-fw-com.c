// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2013 - 2020 Intel Corporation

#include <asm/cacheflush.h>

#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>

#include "ipu.h"
#include "ipu-fw-com.h"
#include "ipu-bus.h"

/*
 * FWCOM layer is a shared resource between FW and driver. It consist
 * of token queues to both send and receive directions. Queue is simply
 * an array of structures with read and write indexes to the queue.
 * There are 1...n queues to both directions. Queues locates in
 * system ram and are mapped to ISP MMU so that both CPU and ISP can
 * see the same buffer. Indexes are located in ISP DMEM so that FW code
 * can poll those with very low latency and cost. CPU access to indexes is
 * more costly but that happens only at message sending time and
 * interrupt trigged message handling. CPU doesn't need to poll indexes.
 * wr_reg / rd_reg are offsets to those dmem location. They are not
 * the indexes itself.
 */

/* Shared structure between driver and FW - do not modify */
struct ipu_fw_sys_queue {
	u64 host_address;
	u32 vied_address;
	u32 size;
	u32 token_size;
	u32 wr_reg;	/* reg no in subsystem's regmem */
	u32 rd_reg;
	u32 _align;
};

struct ipu_fw_sys_queue_res {
	u64 host_address;
	u32 vied_address;
	u32 reg;
};

enum syscom_state {
	/* Program load or explicit host setting should init to this */
	SYSCOM_STATE_UNINIT = 0x57A7E000,
	/* SP Syscom sets this when it is ready for use */
	SYSCOM_STATE_READY = 0x57A7E001,
	/* SP Syscom sets this when no more syscom accesses will happen */
	SYSCOM_STATE_INACTIVE = 0x57A7E002
};

enum syscom_cmd {
	/* Program load or explicit host setting should init to this */
	SYSCOM_COMMAND_UNINIT = 0x57A7F000,
	/* Host Syscom requests syscom to become inactive */
	SYSCOM_COMMAND_INACTIVE = 0x57A7F001
};

/* firmware config: data that sent from the host to SP via DDR */
/* Cell copies data into a context */

struct ipu_fw_syscom_config {
	u32 firmware_address;

	u32 num_input_queues;
	u32 num_output_queues;

	/* ISP pointers to an array of ipu_fw_sys_queue structures */
	u32 input_queue;
	u32 output_queue;

	/* ISYS / PSYS private data */
	u32 specific_addr;
	u32 specific_size;
};

/* End of shared structures / data */

struct ipu_fw_com_context {
	struct ipu_bus_device *adev;
	void __iomem *dmem_addr;
	int (*cell_ready)(struct ipu_bus_device *adev);
	void (*cell_start)(struct ipu_bus_device *adev);

	void *dma_buffer;
	dma_addr_t dma_addr;
	unsigned int dma_size;
	unsigned long attrs;

	unsigned int num_input_queues;
	unsigned int num_output_queues;

	struct ipu_fw_sys_queue *input_queue;	/* array of host to SP queues */
	struct ipu_fw_sys_queue *output_queue;	/* array of SP to host */

	void *config_host_addr;
	void *specific_host_addr;
	u64 ibuf_host_addr;
	u64 obuf_host_addr;

	u32 config_vied_addr;
	u32 input_queue_vied_addr;
	u32 output_queue_vied_addr;
	u32 specific_vied_addr;
	u32 ibuf_vied_addr;
	u32 obuf_vied_addr;

	unsigned int buttress_boot_offset;
	void __iomem *base_addr;
};

#define FW_COM_WR_REG 0
#define FW_COM_RD_REG 4

#define REGMEM_OFFSET 0
#define TUNIT_MAGIC_PATTERN 0x5a5a5a5a

enum regmem_id {
	/* pass pkg_dir address to SPC in non-secure mode */
	PKG_DIR_ADDR_REG = 0,
	/* Tunit CFG blob for secure - provided by host.*/
	TUNIT_CFG_DWR_REG = 1,
	/* syscom commands - modified by the host */
	SYSCOM_COMMAND_REG = 2,
	/* Store interrupt status - updated by SP */
	SYSCOM_IRQ_REG = 3,
	/* first syscom queue pointer register */
	SYSCOM_QPR_BASE_REG = 4
};

enum message_direction {
	DIR_RECV = 0,
	DIR_SEND
};

#define BUTRESS_FW_BOOT_PARAMS_0 0x4000
#define BUTTRESS_FW_BOOT_PARAM_REG(base, offset, id) ((base) \
	+ BUTRESS_FW_BOOT_PARAMS_0 + ((offset) + (id)) * 4)

enum buttress_syscom_id {
	/* pass syscom configuration to SPC */
	SYSCOM_CONFIG_ID		= 0,
	/* syscom state - modified by SP */
	SYSCOM_STATE_ID			= 1,
	/* syscom vtl0 addr mask */
	SYSCOM_VTL0_ADDR_MASK_ID	= 2,
	SYSCOM_ID_MAX
};

static unsigned int num_messages(unsigned int wr, unsigned int rd,
				 unsigned int size)
{
	if (wr < rd)
		wr += size;
	return wr - rd;
}

static unsigned int num_free(unsigned int wr, unsigned int rd,
			     unsigned int size)
{
	return size - num_messages(wr, rd, size);
}

static unsigned int curr_index(void __iomem *q_dmem,
			       enum message_direction dir)
{
	return readl(q_dmem +
			 (dir == DIR_RECV ? FW_COM_RD_REG : FW_COM_WR_REG));
}

static unsigned int inc_index(void __iomem *q_dmem, struct ipu_fw_sys_queue *q,
			      enum message_direction dir)
{
	unsigned int index;

	index = curr_index(q_dmem, dir) + 1;
	return index >= q->size ? 0 : index;
}

static unsigned int ipu_sys_queue_buf_size(unsigned int size,
					   unsigned int token_size)
{
	return (size + 1) * token_size;
}

static void ipu_sys_queue_init(struct ipu_fw_sys_queue *q, unsigned int size,
			       unsigned int token_size,
			       struct ipu_fw_sys_queue_res *res)
{
	unsigned int buf_size;

	q->size = size + 1;
	q->token_size = token_size;
	buf_size = ipu_sys_queue_buf_size(size, token_size);

	/* acquire the shared buffer space */
	q->host_address = res->host_address;
	res->host_address += buf_size;
	q->vied_address = res->vied_address;
	res->vied_address += buf_size;

	/* acquire the shared read and writer pointers */
	q->wr_reg = res->reg;
	res->reg++;
	q->rd_reg = res->reg;
	res->reg++;
}

void *ipu_fw_com_prepare(struct ipu_fw_com_cfg *cfg,
			 struct ipu_bus_device *adev, void __iomem *base)
{
	struct ipu_fw_com_context *ctx;
	struct ipu_fw_syscom_config *fw_cfg;
	unsigned int i;
	unsigned int sizeall, offset;
	unsigned int sizeinput = 0, sizeoutput = 0;
	unsigned long attrs = 0;
	struct ipu_fw_sys_queue_res res;

	/* error handling */
	if (!cfg || !cfg->cell_start || !cfg->cell_ready)
		return NULL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;
	ctx->dmem_addr = base + cfg->dmem_addr + REGMEM_OFFSET;
	ctx->adev = adev;
	ctx->cell_start = cfg->cell_start;
	ctx->cell_ready = cfg->cell_ready;
	ctx->buttress_boot_offset = cfg->buttress_boot_offset;
	ctx->base_addr  = base;

	ctx->num_input_queues = cfg->num_input_queues;
	ctx->num_output_queues = cfg->num_output_queues;

	/*
	 * Allocate DMA mapped memory. Allocate one big chunk.
	 */
	sizeall =
	    /* Base cfg for FW */
	    roundup(sizeof(struct ipu_fw_syscom_config), 8) +
	    /* Descriptions of the queues */
	    cfg->num_input_queues * sizeof(struct ipu_fw_sys_queue) +
	    cfg->num_output_queues * sizeof(struct ipu_fw_sys_queue) +
	    /* FW specific information structure */
	    roundup(cfg->specific_size, 8);

	for (i = 0; i < cfg->num_input_queues; i++)
		sizeinput += ipu_sys_queue_buf_size(cfg->input[i].queue_size,
						cfg->input[i].token_size);

	for (i = 0; i < cfg->num_output_queues; i++)
		sizeoutput += ipu_sys_queue_buf_size(cfg->output[i].queue_size,
						 cfg->output[i].token_size);

	sizeall += sizeinput + sizeoutput;

	ctx->dma_buffer = dma_alloc_attrs(&ctx->adev->dev, sizeall,
					  &ctx->dma_addr, GFP_KERNEL,
					  attrs);
	ctx->attrs = attrs;
	if (!ctx->dma_buffer) {
		dev_err(&ctx->adev->dev, "failed to allocate dma memory\n");
		kfree(ctx);
		return NULL;
	}

	ctx->dma_size = sizeall;

	/* This is the address where FW starts to parse allocations */
	ctx->config_host_addr = ctx->dma_buffer;
	ctx->config_vied_addr = ctx->dma_addr;
	fw_cfg = (struct ipu_fw_syscom_config *)ctx->config_host_addr;
	offset = roundup(sizeof(struct ipu_fw_syscom_config), 8);

	ctx->input_queue = ctx->dma_buffer + offset;
	ctx->input_queue_vied_addr = ctx->dma_addr + offset;
	offset += cfg->num_input_queues * sizeof(struct ipu_fw_sys_queue);

	ctx->output_queue = ctx->dma_buffer + offset;
	ctx->output_queue_vied_addr = ctx->dma_addr + offset;
	offset += cfg->num_output_queues * sizeof(struct ipu_fw_sys_queue);

	ctx->specific_host_addr = ctx->dma_buffer + offset;
	ctx->specific_vied_addr = ctx->dma_addr + offset;
	offset += roundup(cfg->specific_size, 8);

	ctx->ibuf_host_addr = (uintptr_t)(ctx->dma_buffer + offset);
	ctx->ibuf_vied_addr = ctx->dma_addr + offset;
	offset += sizeinput;

	ctx->obuf_host_addr = (uintptr_t)(ctx->dma_buffer + offset);
	ctx->obuf_vied_addr = ctx->dma_addr + offset;
	offset += sizeoutput;

	/* initialize input queues */
	res.reg = SYSCOM_QPR_BASE_REG;
	res.host_address = ctx->ibuf_host_addr;
	res.vied_address = ctx->ibuf_vied_addr;
	for (i = 0; i < cfg->num_input_queues; i++) {
		ipu_sys_queue_init(ctx->input_queue + i,
				   cfg->input[i].queue_size,
				   cfg->input[i].token_size, &res);
	}

	/* initialize output queues */
	res.host_address = ctx->obuf_host_addr;
	res.vied_address = ctx->obuf_vied_addr;
	for (i = 0; i < cfg->num_output_queues; i++) {
		ipu_sys_queue_init(ctx->output_queue + i,
				   cfg->output[i].queue_size,
				   cfg->output[i].token_size, &res);
	}

	/* copy firmware specific data */
	if (cfg->specific_addr && cfg->specific_size) {
		memcpy((void *)ctx->specific_host_addr,
		       cfg->specific_addr, cfg->specific_size);
	}

	fw_cfg->num_input_queues = cfg->num_input_queues;
	fw_cfg->num_output_queues = cfg->num_output_queues;
	fw_cfg->input_queue = ctx->input_queue_vied_addr;
	fw_cfg->output_queue = ctx->output_queue_vied_addr;
	fw_cfg->specific_addr = ctx->specific_vied_addr;
	fw_cfg->specific_size = cfg->specific_size;
	return ctx;
}
EXPORT_SYMBOL_GPL(ipu_fw_com_prepare);

int ipu_fw_com_open(struct ipu_fw_com_context *ctx)
{
	/*
	 * Disable tunit configuration by FW.
	 * This feature is used to configure tunit in secure mode.
	 */
	writel(TUNIT_MAGIC_PATTERN, ctx->dmem_addr + TUNIT_CFG_DWR_REG * 4);
	/* Check if SP is in valid state */
	if (!ctx->cell_ready(ctx->adev))
		return -EIO;

	/* store syscom uninitialized command */
	writel(SYSCOM_COMMAND_UNINIT,
	       ctx->dmem_addr + SYSCOM_COMMAND_REG * 4);

	/* store syscom uninitialized state */
	writel(SYSCOM_STATE_UNINIT,
	       BUTTRESS_FW_BOOT_PARAM_REG(ctx->base_addr,
					  ctx->buttress_boot_offset,
					  SYSCOM_STATE_ID));

	/* store firmware configuration address */
	writel(ctx->config_vied_addr,
	       BUTTRESS_FW_BOOT_PARAM_REG(ctx->base_addr,
					  ctx->buttress_boot_offset,
					  SYSCOM_CONFIG_ID));
	ctx->cell_start(ctx->adev);

	return 0;
}
EXPORT_SYMBOL_GPL(ipu_fw_com_open);

int ipu_fw_com_close(struct ipu_fw_com_context *ctx)
{
	int state;

	state = readl(BUTTRESS_FW_BOOT_PARAM_REG(ctx->base_addr,
						 ctx->buttress_boot_offset,
						 SYSCOM_STATE_ID));
	if (state != SYSCOM_STATE_READY)
		return -EBUSY;

	/* set close request flag */
	writel(SYSCOM_COMMAND_INACTIVE, ctx->dmem_addr +
		   SYSCOM_COMMAND_REG * 4);

	return 0;
}
EXPORT_SYMBOL_GPL(ipu_fw_com_close);

int ipu_fw_com_release(struct ipu_fw_com_context *ctx, unsigned int force)
{
	/* check if release is forced, an verify cell state if it is not */
	if (!force && !ctx->cell_ready(ctx->adev))
		return -EBUSY;

	dma_free_attrs(&ctx->adev->dev, ctx->dma_size,
		       ctx->dma_buffer, ctx->dma_addr,
		       ctx->attrs);
	kfree(ctx);
	return 0;
}
EXPORT_SYMBOL_GPL(ipu_fw_com_release);

int ipu_fw_com_ready(struct ipu_fw_com_context *ctx)
{
	int state;

	state = readl(BUTTRESS_FW_BOOT_PARAM_REG(ctx->base_addr,
						 ctx->buttress_boot_offset,
						 SYSCOM_STATE_ID));
	if (state != SYSCOM_STATE_READY)
		return -EBUSY;	/* SPC is not ready to handle messages yet */

	return 0;
}
EXPORT_SYMBOL_GPL(ipu_fw_com_ready);

static bool is_index_valid(struct ipu_fw_sys_queue *q, unsigned int index)
{
	if (index >= q->size)
		return false;
	return true;
}

void *ipu_send_get_token(struct ipu_fw_com_context *ctx, int q_nbr)
{
	struct ipu_fw_sys_queue *q = &ctx->input_queue[q_nbr];
	void __iomem *q_dmem = ctx->dmem_addr + q->wr_reg * 4;
	unsigned int wr, rd;
	unsigned int packets;
	unsigned int index;

	wr = readl(q_dmem + FW_COM_WR_REG);
	rd = readl(q_dmem + FW_COM_RD_REG);

	/* Catch indexes in dmem */
	if (!is_index_valid(q, wr) || !is_index_valid(q, rd))
		return NULL;

	packets = num_free(wr + 1, rd, q->size);
	if (!packets)
		return NULL;

	index = curr_index(q_dmem, DIR_SEND);

	return (void *)(unsigned long)q->host_address + (index * q->token_size);
}
EXPORT_SYMBOL_GPL(ipu_send_get_token);

void ipu_send_put_token(struct ipu_fw_com_context *ctx, int q_nbr)
{
	struct ipu_fw_sys_queue *q = &ctx->input_queue[q_nbr];
	void __iomem *q_dmem = ctx->dmem_addr + q->wr_reg * 4;
	int index = curr_index(q_dmem, DIR_SEND);

	/* Increment index */
	index = inc_index(q_dmem, q, DIR_SEND);

	writel(index, q_dmem + FW_COM_WR_REG);
}
EXPORT_SYMBOL_GPL(ipu_send_put_token);

void *ipu_recv_get_token(struct ipu_fw_com_context *ctx, int q_nbr)
{
	struct ipu_fw_sys_queue *q = &ctx->output_queue[q_nbr];
	void __iomem *q_dmem = ctx->dmem_addr + q->wr_reg * 4;
	unsigned int wr, rd;
	unsigned int packets;
	void *addr;

	wr = readl(q_dmem + FW_COM_WR_REG);
	rd = readl(q_dmem + FW_COM_RD_REG);

	/* Catch indexes in dmem? */
	if (!is_index_valid(q, wr) || !is_index_valid(q, rd))
		return NULL;

	packets = num_messages(wr, rd, q->size);
	if (!packets)
		return NULL;

	addr = (void *)(unsigned long)q->host_address + (rd * q->token_size);

	return addr;
}
EXPORT_SYMBOL_GPL(ipu_recv_get_token);

void ipu_recv_put_token(struct ipu_fw_com_context *ctx, int q_nbr)
{
	struct ipu_fw_sys_queue *q = &ctx->output_queue[q_nbr];
	void __iomem *q_dmem = ctx->dmem_addr + q->wr_reg * 4;
	unsigned int rd = inc_index(q_dmem, q, DIR_RECV);

	/* Release index */
	writel(rd, q_dmem + FW_COM_RD_REG);
}
EXPORT_SYMBOL_GPL(ipu_recv_put_token);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Intel ipu fw comm library");
