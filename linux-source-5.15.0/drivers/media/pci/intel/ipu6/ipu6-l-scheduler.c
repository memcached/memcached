// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2020 Intel Corporation

#include "ipu-psys.h"
#include "ipu6-ppg.h"

extern bool enable_power_gating;

struct sched_list {
	struct list_head list;
	/* to protect the list */
	struct mutex lock;
};

static struct sched_list start_list = {
	.list	= LIST_HEAD_INIT(start_list.list),
	.lock	= __MUTEX_INITIALIZER(start_list.lock),
};

static struct sched_list stop_list = {
	.list	= LIST_HEAD_INIT(stop_list.list),
	.lock	= __MUTEX_INITIALIZER(stop_list.lock),
};

static struct sched_list *get_sc_list(enum SCHED_LIST type)
{
	/* for debug purposes */
	WARN_ON(type != SCHED_START_LIST && type != SCHED_STOP_LIST);

	if (type == SCHED_START_LIST)
		return &start_list;
	return &stop_list;
}

static bool is_kppg_in_list(struct ipu_psys_ppg *kppg, struct list_head *head)
{
	struct ipu_psys_ppg *tmp;

	list_for_each_entry(tmp, head, sched_list) {
		if (kppg == tmp)
			return true;
	}

	return false;
}

void ipu_psys_scheduler_remove_kppg(struct ipu_psys_ppg *kppg,
				    enum SCHED_LIST type)
{
	struct sched_list *sc_list = get_sc_list(type);
	struct ipu_psys_ppg *tmp0, *tmp1;
	struct ipu_psys *psys = kppg->fh->psys;

	mutex_lock(&sc_list->lock);
	list_for_each_entry_safe(tmp0, tmp1, &sc_list->list, sched_list) {
		if (tmp0 == kppg) {
			dev_dbg(&psys->adev->dev,
				 "remove from %s list, kppg(%d 0x%p) state %d\n",
				 type == SCHED_START_LIST ? "start" : "stop",
				 kppg->kpg->pg->ID, kppg, kppg->state);
			list_del_init(&kppg->sched_list);
		}
	}
	mutex_unlock(&sc_list->lock);
}

void ipu_psys_scheduler_add_kppg(struct ipu_psys_ppg *kppg,
				 enum SCHED_LIST type)
{
	int cur_pri = kppg->pri_base + kppg->pri_dynamic;
	struct sched_list *sc_list = get_sc_list(type);
	struct ipu_psys *psys = kppg->fh->psys;
	struct ipu_psys_ppg *tmp0, *tmp1;

	dev_dbg(&psys->adev->dev,
		"add to %s list, kppg(%d 0x%p) state %d prio(%d %d) fh 0x%p\n",
		type == SCHED_START_LIST ? "start" : "stop",
		kppg->kpg->pg->ID, kppg, kppg->state,
		kppg->pri_base, kppg->pri_dynamic, kppg->fh);

	mutex_lock(&sc_list->lock);
	if (list_empty(&sc_list->list)) {
		list_add(&kppg->sched_list, &sc_list->list);
		goto out;
	}

	if (is_kppg_in_list(kppg, &sc_list->list)) {
		dev_dbg(&psys->adev->dev, "kppg already in list\n");
		goto out;
	}

	list_for_each_entry_safe(tmp0, tmp1, &sc_list->list, sched_list) {
		int tmp_pri = tmp0->pri_base + tmp0->pri_dynamic;

		dev_dbg(&psys->adev->dev,
			"found kppg(%d 0x%p), state %d pri(%d %d) fh 0x%p\n",
			tmp0->kpg->pg->ID, tmp0, tmp0->state,
			tmp0->pri_base, tmp0->pri_dynamic, tmp0->fh);

		if (type == SCHED_START_LIST && tmp_pri > cur_pri) {
			list_add(&kppg->sched_list, tmp0->sched_list.prev);
			goto out;
		} else if (type == SCHED_STOP_LIST && tmp_pri < cur_pri) {
			list_add(&kppg->sched_list, tmp0->sched_list.prev);
			goto out;
		}
	}

	list_add_tail(&kppg->sched_list, &sc_list->list);
out:
	mutex_unlock(&sc_list->lock);
}

static int ipu_psys_detect_resource_contention(struct ipu_psys_ppg *kppg)
{
	struct ipu_psys_resource_pool *try_res_pool;
	struct ipu_psys *psys = kppg->fh->psys;
	int ret = 0;
	int state;

	try_res_pool = kzalloc(sizeof(*try_res_pool), GFP_KERNEL);
	if (IS_ERR_OR_NULL(try_res_pool))
		return -ENOMEM;

	mutex_lock(&kppg->mutex);
	state = kppg->state;
	mutex_unlock(&kppg->mutex);
	if (state == PPG_STATE_STARTED || state == PPG_STATE_RUNNING ||
	    state == PPG_STATE_RESUMED)
		goto exit;

	ret = ipu_psys_resource_pool_init(try_res_pool);
	if (ret < 0) {
		dev_err(&psys->adev->dev, "unable to alloc pg resources\n");
		WARN_ON(1);
		goto exit;
	}

	ipu_psys_resource_copy(&psys->resource_pool_running, try_res_pool);
	ret = ipu_psys_try_allocate_resources(&psys->adev->dev,
					      kppg->kpg->pg,
					      kppg->manifest,
					      try_res_pool);

	ipu_psys_resource_pool_cleanup(try_res_pool);
exit:
	kfree(try_res_pool);

	return ret;
}

static void ipu_psys_scheduler_ppg_sort(struct ipu_psys *psys, bool *stopping)
{
	struct ipu_psys_ppg *kppg, *tmp;
	struct ipu_psys_scheduler *sched;
	struct ipu_psys_fh *fh;

	list_for_each_entry(fh, &psys->fhs, list) {
		mutex_lock(&fh->mutex);
		sched = &fh->sched;

		if (list_empty(&sched->ppgs)) {
			mutex_unlock(&fh->mutex);
			continue;
		}

		list_for_each_entry_safe(kppg, tmp, &sched->ppgs, list) {
			mutex_lock(&kppg->mutex);
			if (kppg->state == PPG_STATE_START ||
			    kppg->state == PPG_STATE_RESUME) {
				ipu_psys_scheduler_add_kppg(kppg,
							    SCHED_START_LIST);
			} else if (kppg->state == PPG_STATE_RUNNING) {
				ipu_psys_scheduler_add_kppg(kppg,
							    SCHED_STOP_LIST);
			} else if (kppg->state == PPG_STATE_SUSPENDING ||
				   kppg->state == PPG_STATE_STOPPING) {
				/* there are some suspending/stopping ppgs */
				*stopping = true;
			} else if (kppg->state == PPG_STATE_RESUMING ||
				   kppg->state == PPG_STATE_STARTING) {
				   /* how about kppg are resuming/starting? */
			}
			mutex_unlock(&kppg->mutex);
		}
		mutex_unlock(&fh->mutex);
	}
}

static void ipu_psys_scheduler_update_start_ppg_priority(void)
{
	struct sched_list *sc_list = get_sc_list(SCHED_START_LIST);
	struct ipu_psys_ppg *kppg, *tmp;

	mutex_lock(&sc_list->lock);
	if (!list_empty(&sc_list->list))
		list_for_each_entry_safe(kppg, tmp, &sc_list->list, sched_list)
			kppg->pri_dynamic--;
	mutex_unlock(&sc_list->lock);
}

static bool ipu_psys_scheduler_switch_ppg(struct ipu_psys *psys)
{
	struct sched_list *sc_list = get_sc_list(SCHED_STOP_LIST);
	struct ipu_psys_ppg *kppg;
	bool resched = false;

	mutex_lock(&sc_list->lock);
	if (list_empty(&sc_list->list)) {
		/* some ppgs are RESUMING/STARTING */
		dev_dbg(&psys->adev->dev, "no candidated stop ppg\n");
		mutex_unlock(&sc_list->lock);
		return false;
	}
	kppg = list_first_entry(&sc_list->list, struct ipu_psys_ppg,
				sched_list);
	mutex_unlock(&sc_list->lock);

	mutex_lock(&kppg->mutex);
	if (!(kppg->state & PPG_STATE_STOP)) {
		dev_dbg(&psys->adev->dev, "s_change:%s: %p %d -> %d\n",
			__func__, kppg, kppg->state, PPG_STATE_SUSPEND);
		kppg->state = PPG_STATE_SUSPEND;
		resched = true;
	}
	mutex_unlock(&kppg->mutex);

	return resched;
}

/*
 * search all kppgs and sort them into start_list and stop_list, alway start
 * first kppg(high priority) in start_list;
 * if there is resource contention, it would switch kppgs in stop_list
 * to suspend state one by one
 */
static bool ipu_psys_scheduler_ppg_start(struct ipu_psys *psys)
{
	struct sched_list *sc_list = get_sc_list(SCHED_START_LIST);
	struct ipu_psys_ppg *kppg, *kppg0;
	bool stopping_existed = false;
	int ret;

	ipu_psys_scheduler_ppg_sort(psys, &stopping_existed);

	mutex_lock(&sc_list->lock);
	if (list_empty(&sc_list->list)) {
		dev_dbg(&psys->adev->dev, "no ppg to start\n");
		mutex_unlock(&sc_list->lock);
		return false;
	}

	list_for_each_entry_safe(kppg, kppg0,
				 &sc_list->list, sched_list) {
		mutex_unlock(&sc_list->lock);

		ret = ipu_psys_detect_resource_contention(kppg);
		if (ret < 0) {
			dev_dbg(&psys->adev->dev,
				"ppg %d resource detect failed(%d)\n",
				kppg->kpg->pg->ID, ret);
			/*
			 * switch out other ppg in 2 cases:
			 * 1. resource contention
			 * 2. no suspending/stopping ppg
			 */
			if (ret == -ENOSPC) {
				if (!stopping_existed &&
				    ipu_psys_scheduler_switch_ppg(psys)) {
					return true;
				}
				dev_dbg(&psys->adev->dev,
					"ppg is suspending/stopping\n");
			} else {
				dev_err(&psys->adev->dev,
					"detect resource error %d\n", ret);
			}
		} else {
			kppg->pri_dynamic = 0;

			mutex_lock(&kppg->mutex);
			if (kppg->state == PPG_STATE_START)
				ipu_psys_ppg_start(kppg);
			else
				ipu_psys_ppg_resume(kppg);
			mutex_unlock(&kppg->mutex);

			ipu_psys_scheduler_remove_kppg(kppg,
						       SCHED_START_LIST);
			ipu_psys_scheduler_update_start_ppg_priority();
		}
		mutex_lock(&sc_list->lock);
	}
	mutex_unlock(&sc_list->lock);

	return false;
}

static bool ipu_psys_scheduler_ppg_enqueue_bufset(struct ipu_psys *psys)
{
	struct ipu_psys_scheduler *sched;
	struct ipu_psys_ppg *kppg;
	struct ipu_psys_fh *fh;
	bool resched = false;

	list_for_each_entry(fh, &psys->fhs, list) {
		mutex_lock(&fh->mutex);
		sched = &fh->sched;
		if (list_empty(&sched->ppgs)) {
			mutex_unlock(&fh->mutex);
			continue;
		}

		list_for_each_entry(kppg, &sched->ppgs, list) {
			if (ipu_psys_ppg_enqueue_bufsets(kppg))
				resched = true;
		}
		mutex_unlock(&fh->mutex);
	}

	return resched;
}

/*
 * This function will check all kppgs within fhs, and if kppg state
 * is STOP or SUSPEND, l-scheduler will call ppg function to stop
 * or suspend it and update stop list
 */

static bool ipu_psys_scheduler_ppg_halt(struct ipu_psys *psys)
{
	struct ipu_psys_scheduler *sched;
	struct ipu_psys_ppg *kppg, *tmp;
	struct ipu_psys_fh *fh;
	bool stopping_exit = false;

	list_for_each_entry(fh, &psys->fhs, list) {
		mutex_lock(&fh->mutex);
		sched = &fh->sched;
		if (list_empty(&sched->ppgs)) {
			mutex_unlock(&fh->mutex);
			continue;
		}

		list_for_each_entry_safe(kppg, tmp, &sched->ppgs, list) {
			mutex_lock(&kppg->mutex);
			if (kppg->state & PPG_STATE_STOP) {
				ipu_psys_ppg_stop(kppg);
				ipu_psys_scheduler_remove_kppg(kppg,
							       SCHED_STOP_LIST);
			} else if (kppg->state == PPG_STATE_SUSPEND) {
				ipu_psys_ppg_suspend(kppg);
				ipu_psys_scheduler_remove_kppg(kppg,
							       SCHED_STOP_LIST);
			} else if (kppg->state == PPG_STATE_SUSPENDING ||
				   kppg->state == PPG_STATE_STOPPING) {
				stopping_exit = true;
			}
			mutex_unlock(&kppg->mutex);
		}
		mutex_unlock(&fh->mutex);
	}
	return stopping_exit;
}

static void ipu_psys_update_ppg_state_by_kcmd(struct ipu_psys *psys,
					      struct ipu_psys_ppg *kppg,
					      struct ipu_psys_kcmd *kcmd)
{
	int old_ppg_state = kppg->state;

	/*
	 * Respond kcmd when ppg is in stable state:
	 * STARTED/RESUMED/RUNNING/SUSPENDED/STOPPED
	 */
	if (kppg->state == PPG_STATE_STARTED ||
	    kppg->state == PPG_STATE_RESUMED ||
	    kppg->state == PPG_STATE_RUNNING) {
		if (kcmd->state == KCMD_STATE_PPG_START)
			ipu_psys_kcmd_complete(kppg, kcmd, 0);
		else if (kcmd->state == KCMD_STATE_PPG_STOP)
			kppg->state = PPG_STATE_STOP;
	} else if (kppg->state == PPG_STATE_SUSPENDED) {
		if (kcmd->state == KCMD_STATE_PPG_START)
			ipu_psys_kcmd_complete(kppg, kcmd, 0);
		else if (kcmd->state == KCMD_STATE_PPG_STOP)
			/*
			 * Record the previous state
			 * because here need resume at first
			 */
			kppg->state |= PPG_STATE_STOP;
		else if (kcmd->state == KCMD_STATE_PPG_ENQUEUE)
			kppg->state = PPG_STATE_RESUME;
	} else if (kppg->state == PPG_STATE_STOPPED) {
		if (kcmd->state == KCMD_STATE_PPG_START)
			kppg->state = PPG_STATE_START;
		else if (kcmd->state == KCMD_STATE_PPG_STOP)
			ipu_psys_kcmd_complete(kppg, kcmd, 0);
		else if (kcmd->state == KCMD_STATE_PPG_ENQUEUE) {
			dev_err(&psys->adev->dev, "ppg %p stopped!\n", kppg);
			ipu_psys_kcmd_complete(kppg, kcmd, -EIO);
		}
	}

	if (old_ppg_state != kppg->state)
		dev_dbg(&psys->adev->dev, "s_change:%s: %p %d -> %d\n",
			__func__, kppg, old_ppg_state, kppg->state);
}

static void ipu_psys_scheduler_kcmd_set(struct ipu_psys *psys)
{
	struct ipu_psys_kcmd *kcmd;
	struct ipu_psys_scheduler *sched;
	struct ipu_psys_ppg *kppg, *tmp;
	struct ipu_psys_fh *fh;

	list_for_each_entry(fh, &psys->fhs, list) {
		mutex_lock(&fh->mutex);
		sched = &fh->sched;
		if (list_empty(&sched->ppgs)) {
			mutex_unlock(&fh->mutex);
			continue;
		}

		list_for_each_entry_safe(kppg, tmp, &sched->ppgs, list) {
			mutex_lock(&kppg->mutex);
			if (list_empty(&kppg->kcmds_new_list)) {
				mutex_unlock(&kppg->mutex);
				continue;
			};

			kcmd = list_first_entry(&kppg->kcmds_new_list,
						struct ipu_psys_kcmd, list);
			ipu_psys_update_ppg_state_by_kcmd(psys, kppg, kcmd);
			mutex_unlock(&kppg->mutex);
		}
		mutex_unlock(&fh->mutex);
	}
}

static bool is_ready_to_enter_power_gating(struct ipu_psys *psys)
{
	struct ipu_psys_scheduler *sched;
	struct ipu_psys_ppg *kppg, *tmp;
	struct ipu_psys_fh *fh;

	list_for_each_entry(fh, &psys->fhs, list) {
		mutex_lock(&fh->mutex);
		sched = &fh->sched;
		if (list_empty(&sched->ppgs)) {
			mutex_unlock(&fh->mutex);
			continue;
		}

		list_for_each_entry_safe(kppg, tmp, &sched->ppgs, list) {
			mutex_lock(&kppg->mutex);
			if (!list_empty(&kppg->kcmds_new_list) ||
			    !list_empty(&kppg->kcmds_processing_list)) {
				mutex_unlock(&kppg->mutex);
				mutex_unlock(&fh->mutex);
				return false;
			}
			if (!(kppg->state == PPG_STATE_RUNNING ||
			      kppg->state == PPG_STATE_STOPPED ||
			      kppg->state == PPG_STATE_SUSPENDED)) {
				mutex_unlock(&kppg->mutex);
				mutex_unlock(&fh->mutex);
				return false;
			}
			mutex_unlock(&kppg->mutex);
		}
		mutex_unlock(&fh->mutex);
	}

	return true;
}

static bool has_pending_kcmd(struct ipu_psys *psys)
{
	struct ipu_psys_scheduler *sched;
	struct ipu_psys_ppg *kppg, *tmp;
	struct ipu_psys_fh *fh;

	list_for_each_entry(fh, &psys->fhs, list) {
		mutex_lock(&fh->mutex);
		sched = &fh->sched;
		if (list_empty(&sched->ppgs)) {
			mutex_unlock(&fh->mutex);
			continue;
		}

		list_for_each_entry_safe(kppg, tmp, &sched->ppgs, list) {
			mutex_lock(&kppg->mutex);
			if (!list_empty(&kppg->kcmds_new_list) ||
			    !list_empty(&kppg->kcmds_processing_list)) {
				mutex_unlock(&kppg->mutex);
				mutex_unlock(&fh->mutex);
				return true;
			}
			mutex_unlock(&kppg->mutex);
		}
		mutex_unlock(&fh->mutex);
	}

	return false;
}

static bool ipu_psys_scheduler_exit_power_gating(struct ipu_psys *psys)
{
	/* Assume power gating process can be aborted directly during START */
	if (psys->power_gating == PSYS_POWER_GATED) {
		dev_dbg(&psys->adev->dev, "powergating: exit ---\n");
		ipu_psys_exit_power_gating(psys);
	}
	psys->power_gating = PSYS_POWER_NORMAL;
	return false;
}

static bool ipu_psys_scheduler_enter_power_gating(struct ipu_psys *psys)
{
	struct ipu_psys_scheduler *sched;
	struct ipu_psys_ppg *kppg, *tmp;
	struct ipu_psys_fh *fh;

	if (!enable_power_gating)
		return false;

	if (psys->power_gating == PSYS_POWER_NORMAL &&
	    is_ready_to_enter_power_gating(psys)) {
		/* Enter power gating */
		dev_dbg(&psys->adev->dev, "powergating: enter +++\n");
		psys->power_gating = PSYS_POWER_GATING;
	}

	if (psys->power_gating != PSYS_POWER_GATING)
		return false;

	/* Suspend ppgs one by one */
	list_for_each_entry(fh, &psys->fhs, list) {
		mutex_lock(&fh->mutex);
		sched = &fh->sched;
		if (list_empty(&sched->ppgs)) {
			mutex_unlock(&fh->mutex);
			continue;
		}

		list_for_each_entry_safe(kppg, tmp, &sched->ppgs, list) {
			mutex_lock(&kppg->mutex);
			if (kppg->state == PPG_STATE_RUNNING) {
				kppg->state = PPG_STATE_SUSPEND;
				mutex_unlock(&kppg->mutex);
				mutex_unlock(&fh->mutex);
				return true;
			}

			if (kppg->state != PPG_STATE_SUSPENDED &&
			    kppg->state != PPG_STATE_STOPPED) {
				/* Can't enter power gating */
				mutex_unlock(&kppg->mutex);
				mutex_unlock(&fh->mutex);
				/* Need re-run l-scheduler to suspend ppg? */
				return (kppg->state & PPG_STATE_STOP ||
					kppg->state == PPG_STATE_SUSPEND);
			}
			mutex_unlock(&kppg->mutex);
		}
		mutex_unlock(&fh->mutex);
	}

	psys->power_gating = PSYS_POWER_GATED;
	ipu_psys_enter_power_gating(psys);

	return false;
}

void ipu_psys_run_next(struct ipu_psys *psys)
{
	/* Wake up scheduler due to unfinished work */
	bool need_trigger = false;
	/* Wait FW callback if there are stopping/suspending/running ppg */
	bool wait_fw_finish = false;
	/*
	 * Code below will crash if fhs is empty. Normally this
	 * shouldn't happen.
	 */
	if (list_empty(&psys->fhs)) {
		WARN_ON(1);
		return;
	}

	/* Abort power gating process */
	if (psys->power_gating != PSYS_POWER_NORMAL &&
	    has_pending_kcmd(psys))
		need_trigger = ipu_psys_scheduler_exit_power_gating(psys);

	/* Handle kcmd and related ppg switch */
	if (psys->power_gating == PSYS_POWER_NORMAL) {
		ipu_psys_scheduler_kcmd_set(psys);
		wait_fw_finish = ipu_psys_scheduler_ppg_halt(psys);
		need_trigger |= ipu_psys_scheduler_ppg_start(psys);
		need_trigger |= ipu_psys_scheduler_ppg_enqueue_bufset(psys);
	}
	if (!(need_trigger || wait_fw_finish)) {
		/* Nothing to do, enter power gating */
		need_trigger = ipu_psys_scheduler_enter_power_gating(psys);
		if (psys->power_gating == PSYS_POWER_GATING)
			wait_fw_finish = ipu_psys_scheduler_ppg_halt(psys);
	}

	if (need_trigger && !wait_fw_finish) {
		dev_dbg(&psys->adev->dev, "scheduler: wake up\n");
		atomic_set(&psys->wakeup_count, 1);
		wake_up_interruptible(&psys->sched_cmd_wq);
	}
}
