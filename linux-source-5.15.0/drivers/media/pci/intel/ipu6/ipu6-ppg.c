// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2020 Intel Corporation

#include <linux/module.h>
#include <linux/pm_runtime.h>

#include <asm/cacheflush.h>

#include "ipu6-ppg.h"

static bool enable_suspend_resume;
module_param(enable_suspend_resume, bool, 0664);
MODULE_PARM_DESC(enable_suspend_resume, "enable fw ppg suspend/resume api");

static struct ipu_psys_kcmd *
ipu_psys_ppg_get_kcmd(struct ipu_psys_ppg *kppg, enum ipu_psys_cmd_state state)
{
	struct ipu_psys_kcmd *kcmd;

	if (list_empty(&kppg->kcmds_new_list))
		return NULL;

	list_for_each_entry(kcmd, &kppg->kcmds_new_list, list) {
		if (kcmd->state == state)
			return kcmd;
	}

	return NULL;
}

struct ipu_psys_kcmd *ipu_psys_ppg_get_stop_kcmd(struct ipu_psys_ppg *kppg)
{
	struct ipu_psys_kcmd *kcmd;

	WARN(!mutex_is_locked(&kppg->mutex), "ppg locking error");

	if (list_empty(&kppg->kcmds_processing_list))
		return NULL;

	list_for_each_entry(kcmd, &kppg->kcmds_processing_list, list) {
		if (kcmd->state == KCMD_STATE_PPG_STOP)
			return kcmd;
	}

	return NULL;
}

static struct ipu_psys_buffer_set *
__get_buf_set(struct ipu_psys_fh *fh, size_t buf_set_size)
{
	struct ipu_psys_buffer_set *kbuf_set;
	struct ipu_psys_scheduler *sched = &fh->sched;

	mutex_lock(&sched->bs_mutex);
	list_for_each_entry(kbuf_set, &sched->buf_sets, list) {
		if (!kbuf_set->buf_set_size &&
		    kbuf_set->size >= buf_set_size) {
			kbuf_set->buf_set_size = buf_set_size;
			mutex_unlock(&sched->bs_mutex);
			return kbuf_set;
		}
	}

	mutex_unlock(&sched->bs_mutex);
	/* no suitable buffer available, allocate new one */
	kbuf_set = kzalloc(sizeof(*kbuf_set), GFP_KERNEL);
	if (!kbuf_set)
		return NULL;

	kbuf_set->kaddr = dma_alloc_attrs(&fh->psys->adev->dev,
					  buf_set_size, &kbuf_set->dma_addr,
					  GFP_KERNEL, 0);
	if (!kbuf_set->kaddr) {
		kfree(kbuf_set);
		return NULL;
	}

	kbuf_set->buf_set_size = buf_set_size;
	kbuf_set->size = buf_set_size;
	mutex_lock(&sched->bs_mutex);
	list_add(&kbuf_set->list, &sched->buf_sets);
	mutex_unlock(&sched->bs_mutex);

	return kbuf_set;
}

static struct ipu_psys_buffer_set *
ipu_psys_create_buffer_set(struct ipu_psys_kcmd *kcmd,
			   struct ipu_psys_ppg *kppg)
{
	struct ipu_psys_fh *fh = kcmd->fh;
	struct ipu_psys *psys = fh->psys;
	struct ipu_psys_buffer_set *kbuf_set;
	size_t buf_set_size;
	u32 *keb;

	buf_set_size = ipu_fw_psys_ppg_get_buffer_set_size(kcmd);

	kbuf_set = __get_buf_set(fh, buf_set_size);
	if (!kbuf_set) {
		dev_err(&psys->adev->dev, "failed to create buffer set\n");
		return NULL;
	}

	kbuf_set->buf_set = ipu_fw_psys_ppg_create_buffer_set(kcmd,
							      kbuf_set->kaddr,
							      0);

	ipu_fw_psys_ppg_buffer_set_vaddress(kbuf_set->buf_set,
					    kbuf_set->dma_addr);
	keb = kcmd->kernel_enable_bitmap;
	ipu_fw_psys_ppg_buffer_set_set_kernel_enable_bitmap(kbuf_set->buf_set,
							    keb);

	return kbuf_set;
}

int ipu_psys_ppg_get_bufset(struct ipu_psys_kcmd *kcmd,
			    struct ipu_psys_ppg *kppg)
{
	struct ipu_psys *psys = kppg->fh->psys;
	struct ipu_psys_buffer_set *kbuf_set;
	unsigned int i;
	int ret;

	kbuf_set = ipu_psys_create_buffer_set(kcmd, kppg);
	if (!kbuf_set) {
		ret = -EINVAL;
		goto error;
	}
	kcmd->kbuf_set = kbuf_set;
	kbuf_set->kcmd = kcmd;

	for (i = 0; i < kcmd->nbuffers; i++) {
		struct ipu_fw_psys_terminal *terminal;
		u32 buffer;

		terminal = ipu_fw_psys_pg_get_terminal(kcmd, i);
		if (!terminal)
			continue;

		buffer = (u32)kcmd->kbufs[i]->dma_addr +
				    kcmd->buffers[i].data_offset;

		ret = ipu_fw_psys_ppg_set_buffer_set(kcmd, terminal, i, buffer);
		if (ret) {
			dev_err(&psys->adev->dev, "Unable to set bufset\n");
			goto error;
		}
	}

	return 0;

error:
	dev_err(&psys->adev->dev, "failed to get buffer set\n");
	return ret;
}

void ipu_psys_ppg_complete(struct ipu_psys *psys, struct ipu_psys_ppg *kppg)
{
	u8 queue_id;
	int old_ppg_state;

	if (!psys || !kppg)
		return;

	mutex_lock(&kppg->mutex);
	old_ppg_state = kppg->state;
	if (kppg->state == PPG_STATE_STOPPING) {
		struct ipu_psys_kcmd tmp_kcmd = {
			.kpg = kppg->kpg,
		};

		kppg->state = PPG_STATE_STOPPED;
		ipu_psys_free_resources(&kppg->kpg->resource_alloc,
					&psys->resource_pool_running);
		queue_id = ipu_fw_psys_ppg_get_base_queue_id(&tmp_kcmd);
		ipu_psys_free_cmd_queue_resource(&psys->resource_pool_running,
						 queue_id);
		pm_runtime_put(&psys->adev->dev);
	} else {
		if (kppg->state == PPG_STATE_SUSPENDING) {
			kppg->state = PPG_STATE_SUSPENDED;
			ipu_psys_free_resources(&kppg->kpg->resource_alloc,
						&psys->resource_pool_running);
		} else if (kppg->state == PPG_STATE_STARTED ||
			   kppg->state == PPG_STATE_RESUMED) {
			kppg->state = PPG_STATE_RUNNING;
		}

		/* Kick l-scheduler thread for FW callback,
		 * also for checking if need to enter power gating
		 */
		atomic_set(&psys->wakeup_count, 1);
		wake_up_interruptible(&psys->sched_cmd_wq);
	}
	if (old_ppg_state != kppg->state)
		dev_dbg(&psys->adev->dev, "s_change:%s: %p %d -> %d\n",
			__func__, kppg, old_ppg_state, kppg->state);

	mutex_unlock(&kppg->mutex);
}

int ipu_psys_ppg_start(struct ipu_psys_ppg *kppg)
{
	struct ipu_psys *psys = kppg->fh->psys;
	struct ipu_psys_kcmd *kcmd = ipu_psys_ppg_get_kcmd(kppg,
						KCMD_STATE_PPG_START);
	unsigned int i;
	int ret;

	if (!kcmd) {
		dev_err(&psys->adev->dev, "failed to find start kcmd!\n");
		return -EINVAL;
	}

	dev_dbg(&psys->adev->dev, "start ppg id %d, addr 0x%p\n",
		ipu_fw_psys_pg_get_id(kcmd), kppg);

	kppg->state = PPG_STATE_STARTING;
	for (i = 0; i < kcmd->nbuffers; i++) {
		struct ipu_fw_psys_terminal *terminal;

		terminal = ipu_fw_psys_pg_get_terminal(kcmd, i);
		if (!terminal)
			continue;

		ret = ipu_fw_psys_terminal_set(terminal, i, kcmd, 0,
					       kcmd->buffers[i].len);
		if (ret) {
			dev_err(&psys->adev->dev, "Unable to set terminal\n");
			return ret;
		}
	}

	ret = ipu_fw_psys_pg_submit(kcmd);
	if (ret) {
		dev_err(&psys->adev->dev, "failed to submit kcmd!\n");
		return ret;
	}

	ret = ipu_psys_allocate_resources(&psys->adev->dev,
					  kcmd->kpg->pg,
					  kcmd->pg_manifest,
					  &kcmd->kpg->resource_alloc,
					  &psys->resource_pool_running);
	if (ret) {
		dev_err(&psys->adev->dev, "alloc resources failed!\n");
		return ret;
	}

	ret = pm_runtime_get_sync(&psys->adev->dev);
	if (ret < 0) {
		dev_err(&psys->adev->dev, "failed to power on psys\n");
		goto error;
	}

	ret = ipu_psys_kcmd_start(psys, kcmd);
	if (ret) {
		ipu_psys_kcmd_complete(kppg, kcmd, -EIO);
		goto error;
	}

	dev_dbg(&psys->adev->dev, "s_change:%s: %p %d -> %d\n",
		__func__, kppg, kppg->state, PPG_STATE_STARTED);
	kppg->state = PPG_STATE_STARTED;
	ipu_psys_kcmd_complete(kppg, kcmd, 0);

	return 0;

error:
	pm_runtime_put_noidle(&psys->adev->dev);
	ipu_psys_reset_process_cell(&psys->adev->dev,
				    kcmd->kpg->pg,
				    kcmd->pg_manifest,
				    kcmd->kpg->pg->process_count);
	ipu_psys_free_resources(&kppg->kpg->resource_alloc,
				&psys->resource_pool_running);

	dev_err(&psys->adev->dev, "failed to start ppg\n");
	return ret;
}

int ipu_psys_ppg_resume(struct ipu_psys_ppg *kppg)
{
	struct ipu_psys *psys = kppg->fh->psys;
	struct ipu_psys_kcmd tmp_kcmd = {
		.kpg = kppg->kpg,
		.fh = kppg->fh,
	};
	int ret;

	dev_dbg(&psys->adev->dev, "resume ppg id %d, addr 0x%p\n",
		ipu_fw_psys_pg_get_id(&tmp_kcmd), kppg);

	kppg->state = PPG_STATE_RESUMING;
	if (enable_suspend_resume) {
		ret = ipu_psys_allocate_resources(&psys->adev->dev,
						  kppg->kpg->pg,
						  kppg->manifest,
						  &kppg->kpg->resource_alloc,
						  &psys->resource_pool_running);
		if (ret) {
			dev_err(&psys->adev->dev, "failed to allocate res\n");
			return -EIO;
		}

		ret = ipu_fw_psys_ppg_resume(&tmp_kcmd);
		if (ret) {
			dev_err(&psys->adev->dev, "failed to resume ppg\n");
			goto error;
		}
	} else {
		kppg->kpg->pg->state = IPU_FW_PSYS_PROCESS_GROUP_READY;
		ret = ipu_fw_psys_pg_submit(&tmp_kcmd);
		if (ret) {
			dev_err(&psys->adev->dev, "failed to submit kcmd!\n");
			return ret;
		}

		ret = ipu_psys_allocate_resources(&psys->adev->dev,
						  kppg->kpg->pg,
						  kppg->manifest,
						  &kppg->kpg->resource_alloc,
						  &psys->resource_pool_running);
		if (ret) {
			dev_err(&psys->adev->dev, "failed to allocate res\n");
			return ret;
		}

		ret = ipu_psys_kcmd_start(psys, &tmp_kcmd);
		if (ret) {
			dev_err(&psys->adev->dev, "failed to start kcmd!\n");
			goto error;
		}
	}
	dev_dbg(&psys->adev->dev, "s_change:%s: %p %d -> %d\n",
		__func__, kppg, kppg->state, PPG_STATE_RESUMED);
	kppg->state = PPG_STATE_RESUMED;

	return 0;

error:
	ipu_psys_reset_process_cell(&psys->adev->dev,
				    kppg->kpg->pg,
				    kppg->manifest,
				    kppg->kpg->pg->process_count);
	ipu_psys_free_resources(&kppg->kpg->resource_alloc,
				&psys->resource_pool_running);

	return ret;
}

int ipu_psys_ppg_stop(struct ipu_psys_ppg *kppg)
{
	struct ipu_psys_kcmd *kcmd = ipu_psys_ppg_get_kcmd(kppg,
							   KCMD_STATE_PPG_STOP);
	struct ipu_psys *psys = kppg->fh->psys;
	struct ipu_psys_kcmd kcmd_temp;
	int ppg_id, ret = 0;

	if (kcmd) {
		list_move_tail(&kcmd->list, &kppg->kcmds_processing_list);
	} else {
		dev_dbg(&psys->adev->dev, "Exceptional stop happened!\n");
		kcmd_temp.kpg = kppg->kpg;
		kcmd_temp.fh = kppg->fh;
		kcmd = &kcmd_temp;
		/* delete kppg in stop list to avoid this ppg resuming */
		ipu_psys_scheduler_remove_kppg(kppg, SCHED_STOP_LIST);
	}

	ppg_id = ipu_fw_psys_pg_get_id(kcmd);
	dev_dbg(&psys->adev->dev, "stop ppg(%d, addr 0x%p)\n", ppg_id, kppg);

	if (kppg->state & PPG_STATE_SUSPENDED) {
		if (enable_suspend_resume) {
			dev_dbg(&psys->adev->dev, "need resume before stop!\n");
			kcmd_temp.kpg = kppg->kpg;
			kcmd_temp.fh = kppg->fh;
			ret = ipu_fw_psys_ppg_resume(&kcmd_temp);
			if (ret)
				dev_err(&psys->adev->dev,
					"ppg(%d) failed to resume\n", ppg_id);
		} else if (kcmd != &kcmd_temp) {
			ipu_psys_free_cmd_queue_resource(
				&psys->resource_pool_running,
				ipu_fw_psys_ppg_get_base_queue_id(kcmd));
			ipu_psys_kcmd_complete(kppg, kcmd, 0);
			dev_dbg(&psys->adev->dev,
				"s_change:%s %p %d -> %d\n", __func__,
				kppg, kppg->state, PPG_STATE_STOPPED);
			pm_runtime_put(&psys->adev->dev);
			kppg->state = PPG_STATE_STOPPED;
			return 0;
		} else {
			return 0;
		}
	}
	dev_dbg(&psys->adev->dev, "s_change:%s %p %d -> %d\n",
		__func__, kppg, kppg->state, PPG_STATE_STOPPING);
	kppg->state = PPG_STATE_STOPPING;
	ret = ipu_fw_psys_pg_abort(kcmd);
	if (ret)
		dev_err(&psys->adev->dev, "ppg(%d) failed to abort\n", ppg_id);

	return ret;
}

int ipu_psys_ppg_suspend(struct ipu_psys_ppg *kppg)
{
	struct ipu_psys *psys = kppg->fh->psys;
	struct ipu_psys_kcmd tmp_kcmd = {
		.kpg = kppg->kpg,
		.fh = kppg->fh,
	};
	int ppg_id = ipu_fw_psys_pg_get_id(&tmp_kcmd);
	int ret = 0;

	dev_dbg(&psys->adev->dev, "suspend ppg(%d, addr 0x%p)\n", ppg_id, kppg);

	dev_dbg(&psys->adev->dev, "s_change:%s %p %d -> %d\n",
		__func__, kppg, kppg->state, PPG_STATE_SUSPENDING);
	kppg->state = PPG_STATE_SUSPENDING;
	if (enable_suspend_resume)
		ret = ipu_fw_psys_ppg_suspend(&tmp_kcmd);
	else
		ret = ipu_fw_psys_pg_abort(&tmp_kcmd);
	if (ret)
		dev_err(&psys->adev->dev, "failed to %s ppg(%d)\n",
			enable_suspend_resume ? "suspend" : "stop", ret);

	return ret;
}

static bool ipu_psys_ppg_is_bufset_existing(struct ipu_psys_ppg *kppg)
{
	return !list_empty(&kppg->kcmds_new_list);
}

/*
 * ipu_psys_ppg_enqueue_bufsets - enqueue buffer sets to firmware
 * Sometimes, if the ppg is at suspended state, this function will return true
 * to reschedule and let the resume command scheduled before the buffer sets
 * enqueuing.
 */
bool ipu_psys_ppg_enqueue_bufsets(struct ipu_psys_ppg *kppg)
{
	struct ipu_psys_kcmd *kcmd, *kcmd0;
	struct ipu_psys *psys = kppg->fh->psys;
	bool need_resume = false;

	mutex_lock(&kppg->mutex);

	if (kppg->state & (PPG_STATE_STARTED | PPG_STATE_RESUMED |
			   PPG_STATE_RUNNING)) {
		if (ipu_psys_ppg_is_bufset_existing(kppg)) {
			list_for_each_entry_safe(kcmd, kcmd0,
						 &kppg->kcmds_new_list, list) {
				int ret;

				if (kcmd->state != KCMD_STATE_PPG_ENQUEUE) {
					need_resume = true;
					break;
				}

				ret = ipu_fw_psys_ppg_enqueue_bufs(kcmd);
				if (ret) {
					dev_err(&psys->adev->dev,
						"kppg 0x%p fail to qbufset %d",
						kppg, ret);
					break;
				}
				list_move_tail(&kcmd->list,
					       &kppg->kcmds_processing_list);
				dev_dbg(&psys->adev->dev,
					"kppg %d %p queue kcmd 0x%p fh 0x%p\n",
					ipu_fw_psys_pg_get_id(kcmd),
					kppg, kcmd, kcmd->fh);
			}
		}
	}

	mutex_unlock(&kppg->mutex);
	return need_resume;
}

void ipu_psys_enter_power_gating(struct ipu_psys *psys)
{
	struct ipu_psys_scheduler *sched;
	struct ipu_psys_ppg *kppg, *tmp;
	struct ipu_psys_fh *fh;
	int ret = 0;

	list_for_each_entry(fh, &psys->fhs, list) {
		mutex_lock(&fh->mutex);
		sched = &fh->sched;
		if (list_empty(&sched->ppgs)) {
			mutex_unlock(&fh->mutex);
			continue;
		}

		list_for_each_entry_safe(kppg, tmp, &sched->ppgs, list) {
			mutex_lock(&kppg->mutex);
			/*
			 * Only for SUSPENDED kppgs, STOPPED kppgs has already
			 * power down and new kppgs might come now.
			 */
			if (kppg->state != PPG_STATE_SUSPENDED) {
				mutex_unlock(&kppg->mutex);
				continue;
			}

			ret = pm_runtime_put_autosuspend(&psys->adev->dev);
			if (ret < 0) {
				dev_err(&psys->adev->dev,
					"failed to power gating off\n");
				pm_runtime_get_sync(&psys->adev->dev);

			}
			mutex_unlock(&kppg->mutex);
		}
		mutex_unlock(&fh->mutex);
	}
}

void ipu_psys_exit_power_gating(struct ipu_psys *psys)
{
	struct ipu_psys_scheduler *sched;
	struct ipu_psys_ppg *kppg, *tmp;
	struct ipu_psys_fh *fh;
	int ret = 0;

	list_for_each_entry(fh, &psys->fhs, list) {
		mutex_lock(&fh->mutex);
		sched = &fh->sched;
		if (list_empty(&sched->ppgs)) {
			mutex_unlock(&fh->mutex);
			continue;
		}

		list_for_each_entry_safe(kppg, tmp, &sched->ppgs, list) {
			mutex_lock(&kppg->mutex);
			/* Only for SUSPENDED kppgs */
			if (kppg->state != PPG_STATE_SUSPENDED) {
				mutex_unlock(&kppg->mutex);
				continue;
			}

			ret = pm_runtime_get_sync(&psys->adev->dev);
			if (ret < 0) {
				dev_err(&psys->adev->dev,
					"failed to power gating\n");
				pm_runtime_put_noidle(&psys->adev->dev);
			}
			mutex_unlock(&kppg->mutex);
		}
		mutex_unlock(&fh->mutex);
	}
}
