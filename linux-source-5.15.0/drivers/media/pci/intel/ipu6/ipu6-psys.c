// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2020 Intel Corporation

#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/pm_runtime.h>
#include <linux/kthread.h>
#include <linux/init_task.h>
#include <linux/version.h>
#include <uapi/linux/sched/types.h>
#include <linux/module.h>
#include <linux/fs.h>

#include "ipu.h"
#include "ipu-psys.h"
#include "ipu6-ppg.h"
#include "ipu-platform-regs.h"
#include "ipu-trace.h"

static bool early_pg_transfer;
module_param(early_pg_transfer, bool, 0664);
MODULE_PARM_DESC(early_pg_transfer,
		 "Copy PGs back to user after resource allocation");

bool enable_power_gating = true;
module_param(enable_power_gating, bool, 0664);
MODULE_PARM_DESC(enable_power_gating, "enable power gating");

struct ipu_trace_block psys_trace_blocks[] = {
	{
		.offset = IPU_TRACE_REG_PS_TRACE_UNIT_BASE,
		.type = IPU_TRACE_BLOCK_TUN,
	},
	{
		.offset = IPU_TRACE_REG_PS_SPC_EVQ_BASE,
		.type = IPU_TRACE_BLOCK_TM,
	},
	{
		.offset = IPU_TRACE_REG_PS_SPP0_EVQ_BASE,
		.type = IPU_TRACE_BLOCK_TM,
	},
	{
		.offset = IPU_TRACE_REG_PS_SPC_GPC_BASE,
		.type = IPU_TRACE_BLOCK_GPC,
	},
	{
		.offset = IPU_TRACE_REG_PS_SPP0_GPC_BASE,
		.type = IPU_TRACE_BLOCK_GPC,
	},
	{
		.offset = IPU_TRACE_REG_PS_MMU_GPC_BASE,
		.type = IPU_TRACE_BLOCK_GPC,
	},
	{
		.offset = IPU_TRACE_REG_PS_GPREG_TRACE_TIMER_RST_N,
		.type = IPU_TRACE_TIMER_RST,
	},
	{
		.type = IPU_TRACE_BLOCK_END,
	}
};

static void ipu6_set_sp_info_bits(void *base)
{
	int i;

	writel(IPU_INFO_REQUEST_DESTINATION_IOSF,
	       base + IPU_REG_PSYS_INFO_SEG_0_CONFIG_ICACHE_MASTER);

	for (i = 0; i < 4; i++)
		writel(IPU_INFO_REQUEST_DESTINATION_IOSF,
		       base + IPU_REG_PSYS_INFO_SEG_CMEM_MASTER(i));
	for (i = 0; i < 4; i++)
		writel(IPU_INFO_REQUEST_DESTINATION_IOSF,
		       base + IPU_REG_PSYS_INFO_SEG_XMEM_MASTER(i));
}

#define PSYS_SUBDOMAINS_STATUS_WAIT_COUNT        1000
void ipu_psys_subdomains_power(struct ipu_psys *psys, bool on)
{
	unsigned int i;
	u32 val;

	/* power domain req */
	dev_dbg(&psys->adev->dev, "power %s psys sub-domains",
		on ? "UP" : "DOWN");
	if (on)
		writel(IPU_PSYS_SUBDOMAINS_POWER_MASK,
		       psys->adev->isp->base + IPU_PSYS_SUBDOMAINS_POWER_REQ);
	else
		writel(0x0,
		       psys->adev->isp->base + IPU_PSYS_SUBDOMAINS_POWER_REQ);

	i = 0;
	do {
		usleep_range(10, 20);
		val = readl(psys->adev->isp->base +
			    IPU_PSYS_SUBDOMAINS_POWER_STATUS);
		if (!(val & BIT(31))) {
			dev_dbg(&psys->adev->dev,
				"PS sub-domains req done with status 0x%x",
				val);
			break;
		}
		i++;
	} while (i < PSYS_SUBDOMAINS_STATUS_WAIT_COUNT);

	if (i == PSYS_SUBDOMAINS_STATUS_WAIT_COUNT)
		dev_warn(&psys->adev->dev, "Psys sub-domains %s req timeout!",
			 on ? "UP" : "DOWN");
}

void ipu_psys_setup_hw(struct ipu_psys *psys)
{
	void __iomem *base = psys->pdata->base;
	void __iomem *spc_regs_base =
	    base + psys->pdata->ipdata->hw_variant.spc_offset;
	void *psys_iommu0_ctrl;
	u32 irqs;
	const u8 r3 = IPU_DEVICE_AB_GROUP1_TARGET_ID_R3_SPC_STATUS_REG;
	const u8 r4 = IPU_DEVICE_AB_GROUP1_TARGET_ID_R4_SPC_MASTER_BASE_ADDR;
	const u8 r5 = IPU_DEVICE_AB_GROUP1_TARGET_ID_R5_SPC_PC_STALL;

	if (!psys->adev->isp->secure_mode) {
		/* configure access blocker for non-secure mode */
		writel(NCI_AB_ACCESS_MODE_RW,
		       base + IPU_REG_DMA_TOP_AB_GROUP1_BASE_ADDR +
		       IPU_REG_DMA_TOP_AB_RING_ACCESS_OFFSET(r3));
		writel(NCI_AB_ACCESS_MODE_RW,
		       base + IPU_REG_DMA_TOP_AB_GROUP1_BASE_ADDR +
		       IPU_REG_DMA_TOP_AB_RING_ACCESS_OFFSET(r4));
		writel(NCI_AB_ACCESS_MODE_RW,
		       base + IPU_REG_DMA_TOP_AB_GROUP1_BASE_ADDR +
		       IPU_REG_DMA_TOP_AB_RING_ACCESS_OFFSET(r5));
	}
	psys_iommu0_ctrl = base +
		psys->pdata->ipdata->hw_variant.mmu_hw[0].offset +
		IPU_MMU_INFO_OFFSET;
	writel(IPU_INFO_REQUEST_DESTINATION_IOSF, psys_iommu0_ctrl);

	ipu6_set_sp_info_bits(spc_regs_base + IPU_PSYS_REG_SPC_STATUS_CTRL);
	ipu6_set_sp_info_bits(spc_regs_base + IPU_PSYS_REG_SPP0_STATUS_CTRL);

	/* Enable FW interrupt #0 */
	writel(0, base + IPU_REG_PSYS_GPDEV_FWIRQ(0));
	irqs = IPU_PSYS_GPDEV_IRQ_FWIRQ(IPU_PSYS_GPDEV_FWIRQ0);
	writel(irqs, base + IPU_REG_PSYS_GPDEV_IRQ_EDGE);
	writel(irqs, base + IPU_REG_PSYS_GPDEV_IRQ_LEVEL_NOT_PULSE);
	writel(0xffffffff, base + IPU_REG_PSYS_GPDEV_IRQ_CLEAR);
	writel(irqs, base + IPU_REG_PSYS_GPDEV_IRQ_MASK);
	writel(irqs, base + IPU_REG_PSYS_GPDEV_IRQ_ENABLE);
}

static struct ipu_psys_ppg *ipu_psys_identify_kppg(struct ipu_psys_kcmd *kcmd)
{
	struct ipu_psys_scheduler *sched = &kcmd->fh->sched;
	struct ipu_psys_ppg *kppg, *tmp;

	mutex_lock(&kcmd->fh->mutex);
	if (list_empty(&sched->ppgs))
		goto not_found;

	list_for_each_entry_safe(kppg, tmp, &sched->ppgs, list) {
		if (ipu_fw_psys_pg_get_token(kcmd)
		    != kppg->token)
			continue;
		mutex_unlock(&kcmd->fh->mutex);
		return kppg;
	}

not_found:
	mutex_unlock(&kcmd->fh->mutex);
	return NULL;
}

/*
 * Called to free up all resources associated with a kcmd.
 * After this the kcmd doesn't anymore exist in the driver.
 */
static void ipu_psys_kcmd_free(struct ipu_psys_kcmd *kcmd)
{
	struct ipu_psys_ppg *kppg;
	struct ipu_psys_scheduler *sched;

	if (!kcmd)
		return;

	kppg = ipu_psys_identify_kppg(kcmd);
	sched = &kcmd->fh->sched;

	if (kcmd->kbuf_set) {
		mutex_lock(&sched->bs_mutex);
		kcmd->kbuf_set->buf_set_size = 0;
		mutex_unlock(&sched->bs_mutex);
		kcmd->kbuf_set = NULL;
	}

	if (kppg) {
		mutex_lock(&kppg->mutex);
		if (!list_empty(&kcmd->list))
			list_del(&kcmd->list);
		mutex_unlock(&kppg->mutex);
	}

	kfree(kcmd->pg_manifest);
	kfree(kcmd->kbufs);
	kfree(kcmd->buffers);
	kfree(kcmd);
}

static struct ipu_psys_kcmd *ipu_psys_copy_cmd(struct ipu_psys_command *cmd,
					       struct ipu_psys_fh *fh)
{
	struct ipu_psys *psys = fh->psys;
	struct ipu_psys_kcmd *kcmd;
	struct ipu_psys_kbuffer *kpgbuf;
	unsigned int i;
	int ret, prevfd, fd;

	fd = prevfd = -1;

	if (cmd->bufcount > IPU_MAX_PSYS_CMD_BUFFERS)
		return NULL;

	if (!cmd->pg_manifest_size)
		return NULL;

	kcmd = kzalloc(sizeof(*kcmd), GFP_KERNEL);
	if (!kcmd)
		return NULL;

	kcmd->state = KCMD_STATE_PPG_NEW;
	kcmd->fh = fh;
	INIT_LIST_HEAD(&kcmd->list);

	mutex_lock(&fh->mutex);
	fd = cmd->pg;
	kpgbuf = ipu_psys_lookup_kbuffer(fh, fd);
	if (!kpgbuf || !kpgbuf->sgt) {
		dev_err(&psys->adev->dev, "%s kbuf %p with fd %d not found.\n",
			__func__, kpgbuf, fd);
		mutex_unlock(&fh->mutex);
		goto error;
	}

	/* check and remap if possibe */
	ret = ipu_psys_mapbuf_locked(fd, fh, kpgbuf);
	if (ret) {
		dev_err(&psys->adev->dev, "%s remap failed\n", __func__);
		mutex_unlock(&fh->mutex);
		goto error;
	}

	kpgbuf = ipu_psys_lookup_kbuffer(fh, fd);
	if (!kpgbuf || !kpgbuf->sgt) {
		WARN(1, "kbuf not found or unmapped.\n");
		mutex_unlock(&fh->mutex);
		goto error;
	}
	mutex_unlock(&fh->mutex);

	kcmd->pg_user = kpgbuf->kaddr;
	kcmd->kpg = __get_pg_buf(psys, kpgbuf->len);
	if (!kcmd->kpg)
		goto error;

	memcpy(kcmd->kpg->pg, kcmd->pg_user, kcmd->kpg->pg_size);

	kcmd->pg_manifest = kzalloc(cmd->pg_manifest_size, GFP_KERNEL);
	if (!kcmd->pg_manifest)
		goto error;

	ret = copy_from_user(kcmd->pg_manifest, cmd->pg_manifest,
			     cmd->pg_manifest_size);
	if (ret)
		goto error;

	kcmd->pg_manifest_size = cmd->pg_manifest_size;

	kcmd->user_token = cmd->user_token;
	kcmd->issue_id = cmd->issue_id;
	kcmd->priority = cmd->priority;
	if (kcmd->priority >= IPU_PSYS_CMD_PRIORITY_NUM)
		goto error;

	/*
	 * Kenel enable bitmap be used only.
	 */
	memcpy(kcmd->kernel_enable_bitmap, cmd->kernel_enable_bitmap,
	       sizeof(cmd->kernel_enable_bitmap));

	kcmd->nbuffers = ipu_fw_psys_pg_get_terminal_count(kcmd);
	kcmd->buffers = kcalloc(kcmd->nbuffers, sizeof(*kcmd->buffers),
				GFP_KERNEL);
	if (!kcmd->buffers)
		goto error;

	kcmd->kbufs = kcalloc(kcmd->nbuffers, sizeof(kcmd->kbufs[0]),
			      GFP_KERNEL);
	if (!kcmd->kbufs)
		goto error;

	/* should be stop cmd for ppg */
	if (!cmd->buffers) {
		kcmd->state = KCMD_STATE_PPG_STOP;
		return kcmd;
	}

	if (!cmd->bufcount || kcmd->nbuffers > cmd->bufcount)
		goto error;

	ret = copy_from_user(kcmd->buffers, cmd->buffers,
			     kcmd->nbuffers * sizeof(*kcmd->buffers));
	if (ret)
		goto error;

	for (i = 0; i < kcmd->nbuffers; i++) {
		struct ipu_fw_psys_terminal *terminal;

		terminal = ipu_fw_psys_pg_get_terminal(kcmd, i);
		if (!terminal)
			continue;

		if (!(kcmd->buffers[i].flags & IPU_BUFFER_FLAG_DMA_HANDLE)) {
			kcmd->state = KCMD_STATE_PPG_START;
			continue;
		}
		if (kcmd->state == KCMD_STATE_PPG_START) {
			dev_err(&psys->adev->dev,
				"err: all buffer.flags&DMA_HANDLE must 0\n");
			goto error;
		}

		mutex_lock(&fh->mutex);
		fd = kcmd->buffers[i].base.fd;
		kpgbuf = ipu_psys_lookup_kbuffer(fh, fd);
		if (!kpgbuf || !kpgbuf->sgt) {
			dev_err(&psys->adev->dev,
				"%s kcmd->buffers[%d] %p fd %d not found.\n",
				__func__, i, kpgbuf, fd);
			mutex_unlock(&fh->mutex);
			goto error;
		}

		ret = ipu_psys_mapbuf_locked(fd, fh, kpgbuf);
		if (ret) {
			dev_err(&psys->adev->dev, "%s remap failed\n",
				__func__);
			mutex_unlock(&fh->mutex);
			goto error;
		}

		kpgbuf = ipu_psys_lookup_kbuffer(fh, fd);
		if (!kpgbuf || !kpgbuf->sgt) {
			WARN(1, "kbuf not found or unmapped.\n");
			mutex_unlock(&fh->mutex);
			goto error;
		}
		mutex_unlock(&fh->mutex);
		kcmd->kbufs[i] = kpgbuf;
		if (!kcmd->kbufs[i] || !kcmd->kbufs[i]->sgt ||
		    kcmd->kbufs[i]->len < kcmd->buffers[i].bytes_used)
			goto error;
		if ((kcmd->kbufs[i]->flags &
		     IPU_BUFFER_FLAG_NO_FLUSH) ||
		    (kcmd->buffers[i].flags &
		     IPU_BUFFER_FLAG_NO_FLUSH) ||
		    prevfd == kcmd->buffers[i].base.fd)
			continue;

		prevfd = kcmd->buffers[i].base.fd;
		dma_sync_sg_for_device(&psys->adev->dev,
				       kcmd->kbufs[i]->sgt->sgl,
				       kcmd->kbufs[i]->sgt->orig_nents,
				       DMA_BIDIRECTIONAL);
	}

	if (kcmd->state != KCMD_STATE_PPG_START)
		kcmd->state = KCMD_STATE_PPG_ENQUEUE;

	return kcmd;
error:
	ipu_psys_kcmd_free(kcmd);

	dev_dbg(&psys->adev->dev, "failed to copy cmd\n");

	return NULL;
}

static struct ipu_psys_buffer_set *
ipu_psys_lookup_kbuffer_set(struct ipu_psys *psys, u32 addr)
{
	struct ipu_psys_fh *fh;
	struct ipu_psys_buffer_set *kbuf_set;
	struct ipu_psys_scheduler *sched;

	list_for_each_entry(fh, &psys->fhs, list) {
		sched = &fh->sched;
		mutex_lock(&sched->bs_mutex);
		list_for_each_entry(kbuf_set, &sched->buf_sets, list) {
			if (kbuf_set->buf_set &&
			    kbuf_set->buf_set->ipu_virtual_address == addr) {
				mutex_unlock(&sched->bs_mutex);
				return kbuf_set;
			}
		}
		mutex_unlock(&sched->bs_mutex);
	}

	return NULL;
}

static struct ipu_psys_ppg *ipu_psys_lookup_ppg(struct ipu_psys *psys,
						dma_addr_t pg_addr)
{
	struct ipu_psys_scheduler *sched;
	struct ipu_psys_ppg *kppg, *tmp;
	struct ipu_psys_fh *fh;

	list_for_each_entry(fh, &psys->fhs, list) {
		sched = &fh->sched;
		mutex_lock(&fh->mutex);
		if (list_empty(&sched->ppgs)) {
			mutex_unlock(&fh->mutex);
			continue;
		}

		list_for_each_entry_safe(kppg, tmp, &sched->ppgs, list) {
			if (pg_addr != kppg->kpg->pg_dma_addr)
				continue;
			mutex_unlock(&fh->mutex);
			return kppg;
		}
		mutex_unlock(&fh->mutex);
	}

	return NULL;
}

/*
 * Move kcmd into completed state (due to running finished or failure).
 * Fill up the event struct and notify waiters.
 */
void ipu_psys_kcmd_complete(struct ipu_psys_ppg *kppg,
			    struct ipu_psys_kcmd *kcmd, int error)
{
	struct ipu_psys_fh *fh = kcmd->fh;
	struct ipu_psys *psys = fh->psys;

	kcmd->ev.type = IPU_PSYS_EVENT_TYPE_CMD_COMPLETE;
	kcmd->ev.user_token = kcmd->user_token;
	kcmd->ev.issue_id = kcmd->issue_id;
	kcmd->ev.error = error;
	list_move_tail(&kcmd->list, &kppg->kcmds_finished_list);

	if (kcmd->constraint.min_freq)
		ipu_buttress_remove_psys_constraint(psys->adev->isp,
						    &kcmd->constraint);

	if (!early_pg_transfer && kcmd->pg_user && kcmd->kpg->pg) {
		struct ipu_psys_kbuffer *kbuf;

		kbuf = ipu_psys_lookup_kbuffer_by_kaddr(kcmd->fh,
							kcmd->pg_user);
		if (kbuf && kbuf->valid)
			memcpy(kcmd->pg_user,
			       kcmd->kpg->pg, kcmd->kpg->pg_size);
		else
			dev_dbg(&psys->adev->dev, "Skipping unmapped buffer\n");
	}

	kcmd->state = KCMD_STATE_PPG_COMPLETE;
	wake_up_interruptible(&fh->wait);
}

/*
 * Submit kcmd into psys queue. If running fails, complete the kcmd
 * with an error.
 *
 * Found a runnable PG. Move queue to the list tail for round-robin
 * scheduling and run the PG. Start the watchdog timer if the PG was
 * started successfully. Enable PSYS power if requested.
 */
int ipu_psys_kcmd_start(struct ipu_psys *psys, struct ipu_psys_kcmd *kcmd)
{
	int ret;

	if (psys->adev->isp->flr_done)
		return -EIO;

	if (early_pg_transfer && kcmd->pg_user && kcmd->kpg->pg)
		memcpy(kcmd->pg_user, kcmd->kpg->pg, kcmd->kpg->pg_size);

	ret = ipu_fw_psys_pg_start(kcmd);
	if (ret) {
		dev_err(&psys->adev->dev, "failed to start kcmd!\n");
		return ret;
	}

	ipu_fw_psys_pg_dump(psys, kcmd, "run");

	ret = ipu_fw_psys_pg_disown(kcmd);
	if (ret) {
		dev_err(&psys->adev->dev, "failed to start kcmd!\n");
		return ret;
	}

	return 0;
}

static int ipu_psys_kcmd_send_to_ppg_start(struct ipu_psys_kcmd *kcmd)
{
	struct ipu_psys_fh *fh = kcmd->fh;
	struct ipu_psys_scheduler *sched = &fh->sched;
	struct ipu_psys *psys = fh->psys;
	struct ipu_psys_ppg *kppg;
	struct ipu_psys_resource_pool *rpr;
	int queue_id;
	int ret;

	rpr = &psys->resource_pool_running;

	kppg = kzalloc(sizeof(*kppg), GFP_KERNEL);
	if (!kppg)
		return -ENOMEM;

	kppg->fh = fh;
	kppg->kpg = kcmd->kpg;
	kppg->state = PPG_STATE_START;
	kppg->pri_base = kcmd->priority;
	kppg->pri_dynamic = 0;
	INIT_LIST_HEAD(&kppg->list);

	mutex_init(&kppg->mutex);
	INIT_LIST_HEAD(&kppg->kcmds_new_list);
	INIT_LIST_HEAD(&kppg->kcmds_processing_list);
	INIT_LIST_HEAD(&kppg->kcmds_finished_list);
	INIT_LIST_HEAD(&kppg->sched_list);

	kppg->manifest = kzalloc(kcmd->pg_manifest_size, GFP_KERNEL);
	if (!kppg->manifest) {
		kfree(kppg);
		return -ENOMEM;
	}
	memcpy(kppg->manifest, kcmd->pg_manifest,
	       kcmd->pg_manifest_size);

	queue_id = ipu_psys_allocate_cmd_queue_resource(rpr);
	if (queue_id == -ENOSPC) {
		dev_err(&psys->adev->dev, "no available queue\n");
		kfree(kppg->manifest);
		kfree(kppg);
		mutex_unlock(&psys->mutex);
		return -ENOMEM;
	}

	/*
	 * set token as start cmd will immediately be followed by a
	 * enqueue cmd so that kppg could be retrieved.
	 */
	kppg->token = (u64)kcmd->kpg;
	ipu_fw_psys_pg_set_token(kcmd, kppg->token);
	ipu_fw_psys_ppg_set_base_queue_id(kcmd, queue_id);
	ret = ipu_fw_psys_pg_set_ipu_vaddress(kcmd,
					      kcmd->kpg->pg_dma_addr);
	if (ret) {
		ipu_psys_free_cmd_queue_resource(rpr, queue_id);
		kfree(kppg->manifest);
		kfree(kppg);
		return -EIO;
	}
	memcpy(kcmd->pg_user, kcmd->kpg->pg, kcmd->kpg->pg_size);

	mutex_lock(&fh->mutex);
	list_add_tail(&kppg->list, &sched->ppgs);
	mutex_unlock(&fh->mutex);

	mutex_lock(&kppg->mutex);
	list_add(&kcmd->list, &kppg->kcmds_new_list);
	mutex_unlock(&kppg->mutex);

	dev_dbg(&psys->adev->dev,
		"START ppg(%d, 0x%p) kcmd 0x%p, queue %d\n",
		ipu_fw_psys_pg_get_id(kcmd), kppg, kcmd, queue_id);

	/* Kick l-scheduler thread */
	atomic_set(&psys->wakeup_count, 1);
	wake_up_interruptible(&psys->sched_cmd_wq);

	return 0;
}

static int ipu_psys_kcmd_send_to_ppg(struct ipu_psys_kcmd *kcmd)
{
	struct ipu_psys_fh *fh = kcmd->fh;
	struct ipu_psys *psys = fh->psys;
	struct ipu_psys_ppg *kppg;
	struct ipu_psys_resource_pool *rpr;
	unsigned long flags;
	u8 id;
	bool resche = true;

	rpr = &psys->resource_pool_running;
	if (kcmd->state == KCMD_STATE_PPG_START)
		return ipu_psys_kcmd_send_to_ppg_start(kcmd);

	kppg = ipu_psys_identify_kppg(kcmd);
	spin_lock_irqsave(&psys->pgs_lock, flags);
	kcmd->kpg->pg_size = 0;
	spin_unlock_irqrestore(&psys->pgs_lock, flags);
	if (!kppg) {
		dev_err(&psys->adev->dev, "token not match\n");
		return -EINVAL;
	}

	kcmd->kpg = kppg->kpg;

	dev_dbg(&psys->adev->dev, "%s ppg(%d, 0x%p) kcmd %p\n",
		(kcmd->state == KCMD_STATE_PPG_STOP) ?
		"STOP" : "ENQUEUE",
		ipu_fw_psys_pg_get_id(kcmd), kppg, kcmd);

	if (kcmd->state == KCMD_STATE_PPG_STOP) {
		mutex_lock(&kppg->mutex);
		if (kppg->state == PPG_STATE_STOPPED) {
			dev_dbg(&psys->adev->dev,
				"kppg 0x%p  stopped!\n", kppg);
			id = ipu_fw_psys_ppg_get_base_queue_id(kcmd);
			ipu_psys_free_cmd_queue_resource(rpr, id);
			ipu_psys_kcmd_complete(kppg, kcmd, 0);
			pm_runtime_put(&psys->adev->dev);
			resche = false;
		} else {
			list_add(&kcmd->list, &kppg->kcmds_new_list);
		}
		mutex_unlock(&kppg->mutex);
	} else {
		int ret;

		ret = ipu_psys_ppg_get_bufset(kcmd, kppg);
		if (ret)
			return ret;

		mutex_lock(&kppg->mutex);
		list_add_tail(&kcmd->list, &kppg->kcmds_new_list);
		mutex_unlock(&kppg->mutex);
	}

	if (resche) {
		/* Kick l-scheduler thread */
		atomic_set(&psys->wakeup_count, 1);
		wake_up_interruptible(&psys->sched_cmd_wq);
	}
	return 0;
}

int ipu_psys_kcmd_new(struct ipu_psys_command *cmd, struct ipu_psys_fh *fh)
{
	struct ipu_psys *psys = fh->psys;
	struct ipu_psys_kcmd *kcmd;
	size_t pg_size;
	int ret;

	if (psys->adev->isp->flr_done)
		return -EIO;

	kcmd = ipu_psys_copy_cmd(cmd, fh);
	if (!kcmd)
		return -EINVAL;

	pg_size = ipu_fw_psys_pg_get_size(kcmd);
	if (pg_size > kcmd->kpg->pg_size) {
		dev_dbg(&psys->adev->dev, "pg size mismatch %lu %lu\n",
			pg_size, kcmd->kpg->pg_size);
		ret = -EINVAL;
		goto error;
	}

	if (ipu_fw_psys_pg_get_protocol(kcmd) !=
			IPU_FW_PSYS_PROCESS_GROUP_PROTOCOL_PPG) {
		dev_err(&psys->adev->dev, "No support legacy pg now\n");
		ret = -EINVAL;
		goto error;
	}

	if (cmd->min_psys_freq) {
		kcmd->constraint.min_freq = cmd->min_psys_freq;
		ipu_buttress_add_psys_constraint(psys->adev->isp,
						 &kcmd->constraint);
	}

	ret = ipu_psys_kcmd_send_to_ppg(kcmd);
	if (ret)
		goto error;

	dev_dbg(&psys->adev->dev,
		"IOC_QCMD: user_token:%llx issue_id:0x%llx pri:%d\n",
		cmd->user_token, cmd->issue_id, cmd->priority);

	return 0;

error:
	ipu_psys_kcmd_free(kcmd);

	return ret;
}

static bool ipu_psys_kcmd_is_valid(struct ipu_psys *psys,
				   struct ipu_psys_kcmd *kcmd)
{
	struct ipu_psys_fh *fh;
	struct ipu_psys_kcmd *kcmd0;
	struct ipu_psys_ppg *kppg, *tmp;
	struct ipu_psys_scheduler *sched;

	list_for_each_entry(fh, &psys->fhs, list) {
		sched = &fh->sched;
		mutex_lock(&fh->mutex);
		if (list_empty(&sched->ppgs)) {
			mutex_unlock(&fh->mutex);
			continue;
		}
		list_for_each_entry_safe(kppg, tmp, &sched->ppgs, list) {
			mutex_lock(&kppg->mutex);
			list_for_each_entry(kcmd0,
					    &kppg->kcmds_processing_list,
					    list) {
				if (kcmd0 == kcmd) {
					mutex_unlock(&kppg->mutex);
					mutex_unlock(&fh->mutex);
					return true;
				}
			}
			mutex_unlock(&kppg->mutex);
		}
		mutex_unlock(&fh->mutex);
	}

	return false;
}

void ipu_psys_handle_events(struct ipu_psys *psys)
{
	struct ipu_psys_kcmd *kcmd;
	struct ipu_fw_psys_event event;
	struct ipu_psys_ppg *kppg;
	bool error;
	u32 hdl;
	u16 cmd, status;
	int res;

	do {
		memset(&event, 0, sizeof(event));
		if (!ipu_fw_psys_rcv_event(psys, &event))
			break;

		if (!event.context_handle)
			break;

		dev_dbg(&psys->adev->dev, "ppg event: 0x%x, %d, status %d\n",
			event.context_handle, event.command, event.status);

		error = false;
		/*
		 * event.command == CMD_RUN shows this is fw processing frame
		 * done as pPG mode, and event.context_handle should be pointer
		 * of buffer set; so we make use of this pointer to lookup
		 * kbuffer_set and kcmd
		 */
		hdl = event.context_handle;
		cmd = event.command;
		status = event.status;

		kppg = NULL;
		kcmd = NULL;
		if (cmd == IPU_FW_PSYS_PROCESS_GROUP_CMD_RUN) {
			struct ipu_psys_buffer_set *kbuf_set;
			/*
			 * Need change ppg state when the 1st running is done
			 * (after PPG started/resumed)
			 */
			kbuf_set = ipu_psys_lookup_kbuffer_set(psys, hdl);
			if (kbuf_set)
				kcmd = kbuf_set->kcmd;
			if (!kbuf_set || !kcmd)
				error = true;
			else
				kppg = ipu_psys_identify_kppg(kcmd);
		} else if (cmd == IPU_FW_PSYS_PROCESS_GROUP_CMD_STOP ||
			   cmd == IPU_FW_PSYS_PROCESS_GROUP_CMD_SUSPEND ||
			   cmd == IPU_FW_PSYS_PROCESS_GROUP_CMD_RESUME) {
			/*
			 * STOP/SUSPEND/RESUME cmd event would run this branch;
			 * only stop cmd queued by user has stop_kcmd and need
			 * to notify user to dequeue.
			 */
			kppg = ipu_psys_lookup_ppg(psys, hdl);
			if (kppg) {
				mutex_lock(&kppg->mutex);
				if (kppg->state == PPG_STATE_STOPPING) {
					kcmd = ipu_psys_ppg_get_stop_kcmd(kppg);
					if (!kcmd)
						error = true;
				}
				mutex_unlock(&kppg->mutex);
			}
		} else {
			dev_err(&psys->adev->dev, "invalid event\n");
			continue;
		}

		if (error || !kppg) {
			dev_err(&psys->adev->dev, "event error, command %d\n",
				cmd);
			break;
		}

		dev_dbg(&psys->adev->dev, "event to kppg 0x%p, kcmd 0x%p\n",
			kppg, kcmd);

		ipu_psys_ppg_complete(psys, kppg);

		if (kcmd && ipu_psys_kcmd_is_valid(psys, kcmd)) {
			res = (status == IPU_PSYS_EVENT_CMD_COMPLETE ||
			       status == IPU_PSYS_EVENT_FRAGMENT_COMPLETE) ?
				0 : -EIO;
			mutex_lock(&kppg->mutex);
			ipu_psys_kcmd_complete(kppg, kcmd, res);
			mutex_unlock(&kppg->mutex);
		}
	} while (1);
}

int ipu_psys_fh_init(struct ipu_psys_fh *fh)
{
	struct ipu_psys *psys = fh->psys;
	struct ipu_psys_buffer_set *kbuf_set, *kbuf_set_tmp;
	struct ipu_psys_scheduler *sched = &fh->sched;
	int i;

	mutex_init(&sched->bs_mutex);
	INIT_LIST_HEAD(&sched->buf_sets);
	INIT_LIST_HEAD(&sched->ppgs);
	pm_runtime_dont_use_autosuspend(&psys->adev->dev);
	/* allocate and map memory for buf_sets */
	for (i = 0; i < IPU_PSYS_BUF_SET_POOL_SIZE; i++) {
		kbuf_set = kzalloc(sizeof(*kbuf_set), GFP_KERNEL);
		if (!kbuf_set)
			goto out_free_buf_sets;
		kbuf_set->kaddr = dma_alloc_attrs(&psys->adev->dev,
						  IPU_PSYS_BUF_SET_MAX_SIZE,
						  &kbuf_set->dma_addr,
						  GFP_KERNEL,
						  0);
		if (!kbuf_set->kaddr) {
			kfree(kbuf_set);
			goto out_free_buf_sets;
		}
		kbuf_set->size = IPU_PSYS_BUF_SET_MAX_SIZE;
		list_add(&kbuf_set->list, &sched->buf_sets);
	}

	return 0;

out_free_buf_sets:
	list_for_each_entry_safe(kbuf_set, kbuf_set_tmp,
				 &sched->buf_sets, list) {
		dma_free_attrs(&psys->adev->dev,
			       kbuf_set->size, kbuf_set->kaddr,
			       kbuf_set->dma_addr, 0);
		list_del(&kbuf_set->list);
		kfree(kbuf_set);
	}
	mutex_destroy(&sched->bs_mutex);

	return -ENOMEM;
}

int ipu_psys_fh_deinit(struct ipu_psys_fh *fh)
{
	struct ipu_psys *psys = fh->psys;
	struct ipu_psys_ppg *kppg, *kppg0;
	struct ipu_psys_kcmd *kcmd, *kcmd0;
	struct ipu_psys_buffer_set *kbuf_set, *kbuf_set0;
	struct ipu_psys_scheduler *sched = &fh->sched;
	struct ipu_psys_resource_pool *rpr;
	struct ipu_psys_resource_alloc *alloc;
	u8 id;

	mutex_lock(&fh->mutex);
	if (!list_empty(&sched->ppgs)) {
		list_for_each_entry_safe(kppg, kppg0, &sched->ppgs, list) {
			unsigned long flags;

			mutex_lock(&kppg->mutex);
			if (!(kppg->state &
			      (PPG_STATE_STOPPED |
			       PPG_STATE_STOPPING))) {
				struct ipu_psys_kcmd tmp = {
					.kpg = kppg->kpg,
				};

				rpr = &psys->resource_pool_running;
				alloc = &kppg->kpg->resource_alloc;
				id = ipu_fw_psys_ppg_get_base_queue_id(&tmp);
				ipu_psys_ppg_stop(kppg);
				ipu_psys_free_resources(alloc, rpr);
				ipu_psys_free_cmd_queue_resource(rpr, id);
				dev_dbg(&psys->adev->dev,
				    "s_change:%s %p %d -> %d\n", __func__,
				    kppg, kppg->state, PPG_STATE_STOPPED);
				kppg->state = PPG_STATE_STOPPED;
				if (psys->power_gating != PSYS_POWER_GATED)
					pm_runtime_put(&psys->adev->dev);
			}
			list_del(&kppg->list);
			mutex_unlock(&kppg->mutex);

			list_for_each_entry_safe(kcmd, kcmd0,
						 &kppg->kcmds_new_list, list) {
				kcmd->pg_user = NULL;
				mutex_unlock(&fh->mutex);
				ipu_psys_kcmd_free(kcmd);
				mutex_lock(&fh->mutex);
			}

			list_for_each_entry_safe(kcmd, kcmd0,
						 &kppg->kcmds_processing_list,
						 list) {
				kcmd->pg_user = NULL;
				mutex_unlock(&fh->mutex);
				ipu_psys_kcmd_free(kcmd);
				mutex_lock(&fh->mutex);
			}

			list_for_each_entry_safe(kcmd, kcmd0,
						 &kppg->kcmds_finished_list,
						 list) {
				kcmd->pg_user = NULL;
				mutex_unlock(&fh->mutex);
				ipu_psys_kcmd_free(kcmd);
				mutex_lock(&fh->mutex);
			}

			spin_lock_irqsave(&psys->pgs_lock, flags);
			kppg->kpg->pg_size = 0;
			spin_unlock_irqrestore(&psys->pgs_lock, flags);

			mutex_destroy(&kppg->mutex);
			kfree(kppg->manifest);
			kfree(kppg);
		}
	}
	mutex_unlock(&fh->mutex);

	mutex_lock(&sched->bs_mutex);
	list_for_each_entry_safe(kbuf_set, kbuf_set0, &sched->buf_sets, list) {
		dma_free_attrs(&psys->adev->dev,
			       kbuf_set->size, kbuf_set->kaddr,
			       kbuf_set->dma_addr, 0);
		list_del(&kbuf_set->list);
		kfree(kbuf_set);
	}
	mutex_unlock(&sched->bs_mutex);
	mutex_destroy(&sched->bs_mutex);

	return 0;
}

struct ipu_psys_kcmd *ipu_get_completed_kcmd(struct ipu_psys_fh *fh)
{
	struct ipu_psys_scheduler *sched = &fh->sched;
	struct ipu_psys_kcmd *kcmd;
	struct ipu_psys_ppg *kppg;

	mutex_lock(&fh->mutex);
	if (list_empty(&sched->ppgs)) {
		mutex_unlock(&fh->mutex);
		return NULL;
	}

	list_for_each_entry(kppg, &sched->ppgs, list) {
		mutex_lock(&kppg->mutex);
		if (list_empty(&kppg->kcmds_finished_list)) {
			mutex_unlock(&kppg->mutex);
			continue;
		}

		kcmd = list_first_entry(&kppg->kcmds_finished_list,
					struct ipu_psys_kcmd, list);
		mutex_unlock(&fh->mutex);
		mutex_unlock(&kppg->mutex);
		dev_dbg(&fh->psys->adev->dev,
			"get completed kcmd 0x%p\n", kcmd);
		return kcmd;
	}
	mutex_unlock(&fh->mutex);

	return NULL;
}

long ipu_ioctl_dqevent(struct ipu_psys_event *event,
		       struct ipu_psys_fh *fh, unsigned int f_flags)
{
	struct ipu_psys *psys = fh->psys;
	struct ipu_psys_kcmd *kcmd = NULL;
	int rval;

	dev_dbg(&psys->adev->dev, "IOC_DQEVENT\n");

	if (!(f_flags & O_NONBLOCK)) {
		rval = wait_event_interruptible(fh->wait,
						(kcmd =
						 ipu_get_completed_kcmd(fh)));
		if (rval == -ERESTARTSYS)
			return rval;
	}

	if (!kcmd) {
		kcmd = ipu_get_completed_kcmd(fh);
		if (!kcmd)
			return -ENODATA;
	}

	*event = kcmd->ev;
	ipu_psys_kcmd_free(kcmd);

	return 0;
}
