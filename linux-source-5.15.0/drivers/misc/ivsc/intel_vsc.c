// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 Intel Corporation */

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/vsc.h>

#include "intel_vsc.h"

#define ACE_PRIVACY_ON 2

struct intel_vsc {
	spinlock_t lock;
	struct mutex mutex;

	void *csi;
	struct vsc_csi_ops *csi_ops;
	uint16_t csi_registerred;

	void *ace;
	struct vsc_ace_ops *ace_ops;
	uint16_t ace_registerred;
};

static struct intel_vsc vsc;

static int check_component_ready(void)
{
	int ret = -1;
	unsigned long flags;

	spin_lock_irqsave(&vsc.lock, flags);

	if (vsc.ace_registerred && vsc.csi_registerred)
		ret = 0;

	spin_unlock_irqrestore(&vsc.lock, flags);

	return ret;
}

static void update_camera_status(struct vsc_camera_status *status,
				 struct camera_status *s)
{
	if (status && s) {
		status->owner = s->camera_owner;
		status->exposure_level = s->exposure_level;
		status->status = VSC_PRIVACY_OFF;

		if (s->privacy_stat == ACE_PRIVACY_ON)
			status->status = VSC_PRIVACY_ON;
	}
}

int vsc_register_ace(void *ace, struct vsc_ace_ops *ops)
{
	unsigned long flags;

	if (ace && ops) {
		if (ops->ipu_own_camera && ops->ace_own_camera) {
			spin_lock_irqsave(&vsc.lock, flags);

			vsc.ace = ace;
			vsc.ace_ops = ops;
			vsc.ace_registerred = true;

			spin_unlock_irqrestore(&vsc.lock, flags);

			return 0;
		}
	}

	pr_err("register ace failed\n");
	return -1;
}
EXPORT_SYMBOL_GPL(vsc_register_ace);

void vsc_unregister_ace(void)
{
	unsigned long flags;

	spin_lock_irqsave(&vsc.lock, flags);

	vsc.ace_registerred = false;

	spin_unlock_irqrestore(&vsc.lock, flags);
}
EXPORT_SYMBOL_GPL(vsc_unregister_ace);

int vsc_register_csi(void *csi, struct vsc_csi_ops *ops)
{
	unsigned long flags;

	if (csi && ops) {
		if (ops->set_privacy_callback &&
		    ops->set_owner && ops->set_mipi_conf) {
			spin_lock_irqsave(&vsc.lock, flags);

			vsc.csi = csi;
			vsc.csi_ops = ops;
			vsc.csi_registerred = true;

			spin_unlock_irqrestore(&vsc.lock, flags);

			return 0;
		}
	}

	pr_err("register csi failed\n");
	return -1;
}
EXPORT_SYMBOL_GPL(vsc_register_csi);

void vsc_unregister_csi(void)
{
	unsigned long flags;

	spin_lock_irqsave(&vsc.lock, flags);

	vsc.csi_registerred = false;

	spin_unlock_irqrestore(&vsc.lock, flags);
}
EXPORT_SYMBOL_GPL(vsc_unregister_csi);

int vsc_acquire_camera_sensor(struct vsc_mipi_config *config,
			      vsc_privacy_callback_t callback,
			      void *handle,
			      struct vsc_camera_status *status)
{
	int ret;
	struct camera_status s;
	struct mipi_conf conf = { 0 };

	struct vsc_csi_ops *csi_ops;
	struct vsc_ace_ops *ace_ops;

	if (!config)
		return -EINVAL;

	ret = check_component_ready();
	if (ret < 0) {
		pr_info("intel vsc not ready\n");
		return -EAGAIN;
	}

	mutex_lock(&vsc.mutex);
	/* no need check component again here */

	csi_ops = vsc.csi_ops;
	ace_ops = vsc.ace_ops;

	csi_ops->set_privacy_callback(vsc.csi, callback, handle);

	ret = ace_ops->ipu_own_camera(vsc.ace, &s);
	if (ret) {
		pr_err("ipu own camera failed\n");
		goto err;
	}
	update_camera_status(status, &s);

	ret = csi_ops->set_owner(vsc.csi, CSI_IPU);
	if (ret) {
		pr_err("ipu own csi failed\n");
		goto err;
	}

	conf.lane_num = config->lane_num;
	conf.freq = config->freq;
	ret = csi_ops->set_mipi_conf(vsc.csi, &conf);
	if (ret) {
		pr_err("config mipi failed\n");
		goto err;
	}

err:
	mutex_unlock(&vsc.mutex);
	msleep(100);
	return ret;
}
EXPORT_SYMBOL_GPL(vsc_acquire_camera_sensor);

int vsc_release_camera_sensor(struct vsc_camera_status *status)
{
	int ret;
	struct camera_status s;

	struct vsc_csi_ops *csi_ops;
	struct vsc_ace_ops *ace_ops;

	ret = check_component_ready();
	if (ret < 0) {
		pr_info("intel vsc not ready\n");
		return -EAGAIN;
	}

	mutex_lock(&vsc.mutex);
	/* no need check component again here */

	csi_ops = vsc.csi_ops;
	ace_ops = vsc.ace_ops;

	csi_ops->set_privacy_callback(vsc.csi, NULL, NULL);

	ret = csi_ops->set_owner(vsc.csi, CSI_FW);
	if (ret) {
		pr_err("vsc own csi failed\n");
		goto err;
	}

	ret = ace_ops->ace_own_camera(vsc.ace, &s);
	if (ret) {
		pr_err("vsc own camera failed\n");
		goto err;
	}
	update_camera_status(status, &s);

err:
	mutex_unlock(&vsc.mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(vsc_release_camera_sensor);

static int __init intel_vsc_init(void)
{
	memset(&vsc, 0, sizeof(struct intel_vsc));

	spin_lock_init(&vsc.lock);
	mutex_init(&vsc.mutex);

	vsc.csi_registerred = false;
	vsc.ace_registerred = false;

	return 0;
}

static void __exit intel_vsc_exit(void)
{
}

module_init(intel_vsc_init);
module_exit(intel_vsc_exit);

MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
MODULE_SOFTDEP("post: mei_csi mei_ace");
MODULE_DESCRIPTION("Device driver for Intel VSC");
