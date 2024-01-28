// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 Intel Corporation */

#include <linux/completion.h>
#include <linux/kernel.h>
#include <linux/mei_cl_bus.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uuid.h>
#include <linux/vsc.h>

#include "intel_vsc.h"

#define CSI_TIMEOUT			(5 * HZ)
#define MEI_CSI_DRIVER_NAME		"vsc_csi"

/**
 * Identify the command id that can be downloaded
 * to firmware, as well as the privacy notify id
 * used when processing privacy actions.
 *
 * This enumeration is local to the mei csi.
 */
enum csi_cmd_id {
	/* used to set csi ownership */
	CSI_SET_OWNER,

	/* used to get csi ownership */
	CSI_GET_OWNER,

	/* used to configurate mipi */
	CSI_SET_MIPI_CONF,

	/* used to get current mipi configuration */
	CSI_GET_MIPI_CONF,

	/* used to set csi power state */
	CSI_SET_POWER_STATE,

	/* used to get csi power state */
	CSI_GET_POWER_STATE,

	/* privacy notification id used when privacy state changes */
	CSI_PRIVACY_NOTIF,
};

enum privacy_state {
	PRIVACY_OFF = 0,
	PRIVACY_ON,
};

/**
 * CSI command structure.
 */
struct csi_cmd {
	uint32_t cmd_id;
	union _cmd_param {
		uint32_t param;
		struct mipi_conf conf;
	} param;
} __packed;

/**
 * CSI command response structure.
 */
struct csi_notif {
	uint32_t cmd_id;
	int status;
	union _resp_cont {
		uint32_t cont;
		struct mipi_conf conf;
	} cont;
} __packed;

struct mei_csi {
	struct mei_cl_device *cldev;

	struct mutex cmd_mutex;
	struct csi_notif *notif;
	struct completion response;

	spinlock_t privacy_lock;
	void *handle;
	vsc_privacy_callback_t callback;
};

static int mei_csi_send(struct mei_csi *csi, uint8_t *buf, size_t len)
{
	struct csi_cmd *cmd = (struct csi_cmd *)buf;
	int ret;

	reinit_completion(&csi->response);

	ret = mei_cldev_send(csi->cldev, buf, len);
	if (ret < 0) {
		dev_err(&csi->cldev->dev,
			"send command fail %d\n", ret);
		return ret;
	}

	ret = wait_for_completion_killable_timeout(&csi->response, CSI_TIMEOUT);
	if (ret < 0) {
		dev_err(&csi->cldev->dev,
			"command %d response error\n", cmd->cmd_id);
		return ret;
	} else if (ret == 0) {
		dev_err(&csi->cldev->dev,
			"command %d response timeout\n", cmd->cmd_id);
		ret = -ETIMEDOUT;
		return ret;
	}

	ret = csi->notif->status;
	if (ret == -1) {
		dev_info(&csi->cldev->dev,
			 "privacy on, command id = %d\n", cmd->cmd_id);
		ret = 0;
	} else if (ret) {
		dev_err(&csi->cldev->dev,
			"command %d response fail %d\n", cmd->cmd_id, ret);
		return ret;
	}

	if (csi->notif->cmd_id != cmd->cmd_id) {
		dev_err(&csi->cldev->dev,
			"command response id mismatch, sent %d but got %d\n",
			cmd->cmd_id, csi->notif->cmd_id);
		ret = -1;
	}

	return ret;
}

static int csi_set_owner(void *csi, enum csi_owner owner)
{
	struct csi_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	int ret;
	struct mei_csi *p_csi = (struct mei_csi *)csi;

	cmd.cmd_id = CSI_SET_OWNER;
	cmd.param.param = owner;
	cmd_len += sizeof(cmd.param.param);

	mutex_lock(&p_csi->cmd_mutex);
	ret = mei_csi_send(p_csi, (uint8_t *)&cmd, cmd_len);
	mutex_unlock(&p_csi->cmd_mutex);

	return ret;
}

static int csi_get_owner(void *csi, enum csi_owner *owner)
{
	struct csi_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	int ret;
	struct mei_csi *p_csi = (struct mei_csi *)csi;

	cmd.cmd_id = CSI_GET_OWNER;

	mutex_lock(&p_csi->cmd_mutex);
	ret = mei_csi_send(p_csi, (uint8_t *)&cmd, cmd_len);
	if (!ret)
		*owner = p_csi->notif->cont.cont;
	mutex_unlock(&p_csi->cmd_mutex);

	return ret;
}

static int csi_set_mipi_conf(void *csi, struct mipi_conf *conf)
{
	struct csi_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	int ret;
	struct mei_csi *p_csi = (struct mei_csi *)csi;

	cmd.cmd_id = CSI_SET_MIPI_CONF;
	cmd.param.conf.freq = conf->freq;
	cmd.param.conf.lane_num = conf->lane_num;
	cmd_len += sizeof(cmd.param.conf);

	mutex_lock(&p_csi->cmd_mutex);
	ret = mei_csi_send(p_csi, (uint8_t *)&cmd, cmd_len);
	mutex_unlock(&p_csi->cmd_mutex);

	return ret;
}

static int csi_get_mipi_conf(void *csi, struct mipi_conf *conf)
{
	struct csi_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	struct mipi_conf *res;
	int ret;
	struct mei_csi *p_csi = (struct mei_csi *)csi;

	cmd.cmd_id = CSI_GET_MIPI_CONF;

	mutex_lock(&p_csi->cmd_mutex);
	ret = mei_csi_send(p_csi, (uint8_t *)&cmd, cmd_len);
	if (!ret) {
		res = &p_csi->notif->cont.conf;
		conf->freq = res->freq;
		conf->lane_num = res->lane_num;
	}
	mutex_unlock(&p_csi->cmd_mutex);

	return ret;
}

static int csi_set_power_state(void *csi, enum csi_power_state state)
{
	struct csi_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	int ret;
	struct mei_csi *p_csi = (struct mei_csi *)csi;

	cmd.cmd_id = CSI_SET_POWER_STATE;
	cmd.param.param = state;
	cmd_len += sizeof(cmd.param.param);

	mutex_lock(&p_csi->cmd_mutex);
	ret = mei_csi_send(p_csi, (uint8_t *)&cmd, cmd_len);
	mutex_unlock(&p_csi->cmd_mutex);

	return ret;
}

static int csi_get_power_state(void *csi, enum csi_power_state *state)
{
	struct csi_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	int ret;
	struct mei_csi *p_csi = (struct mei_csi *)csi;

	cmd.cmd_id = CSI_GET_POWER_STATE;

	mutex_lock(&p_csi->cmd_mutex);
	ret = mei_csi_send(p_csi, (uint8_t *)&cmd, cmd_len);
	if (!ret)
		*state = p_csi->notif->cont.cont;
	mutex_unlock(&p_csi->cmd_mutex);

	return ret;
}

static void csi_set_privacy_callback(void *csi,
				     vsc_privacy_callback_t callback,
				     void *handle)
{
	unsigned long flags;
	struct mei_csi *p_csi = (struct mei_csi *)csi;

	spin_lock_irqsave(&p_csi->privacy_lock, flags);
	p_csi->callback = callback;
	p_csi->handle = handle;
	spin_unlock_irqrestore(&p_csi->privacy_lock, flags);
}

static struct vsc_csi_ops csi_ops = {
	.set_owner = csi_set_owner,
	.get_owner = csi_get_owner,
	.set_mipi_conf = csi_set_mipi_conf,
	.get_mipi_conf = csi_get_mipi_conf,
	.set_power_state = csi_set_power_state,
	.get_power_state = csi_get_power_state,
	.set_privacy_callback = csi_set_privacy_callback,
};

static void privacy_notify(struct mei_csi *csi, uint8_t state)
{
	unsigned long flags;
	void *handle;
	vsc_privacy_callback_t callback;

	spin_lock_irqsave(&csi->privacy_lock, flags);
	callback = csi->callback;
	handle = csi->handle;
	spin_unlock_irqrestore(&csi->privacy_lock, flags);

	if (callback)
		callback(handle, state);
}

/**
 * callback for command response receive
 */
static void mei_csi_rx(struct mei_cl_device *cldev)
{
	int ret;
	struct csi_notif notif = {0};
	struct mei_csi *csi = mei_cldev_get_drvdata(cldev);

	ret = mei_cldev_recv(cldev, (uint8_t *)&notif,
			     sizeof(struct csi_notif));
	if (ret < 0) {
		dev_err(&cldev->dev, "failure in recv %d\n", ret);
		return;
	}

	switch (notif.cmd_id) {
	case CSI_PRIVACY_NOTIF:
		switch (notif.cont.cont) {
		case PRIVACY_ON:
			privacy_notify(csi, 0);

			dev_info(&cldev->dev, "privacy on\n");
			break;

		case PRIVACY_OFF:
			privacy_notify(csi, 1);

			dev_info(&cldev->dev, "privacy off\n");
			break;

		default:
			dev_err(&cldev->dev,
				"recv privacy wrong state\n");
			break;
		}
		break;

	case CSI_SET_OWNER:
	case CSI_GET_OWNER:
	case CSI_SET_MIPI_CONF:
	case CSI_GET_MIPI_CONF:
	case CSI_SET_POWER_STATE:
	case CSI_GET_POWER_STATE:
		memcpy(csi->notif, &notif, ret);

		if (!completion_done(&csi->response))
			complete(&csi->response);
		break;

	default:
		dev_err(&cldev->dev,
			"recv not supported notification(%d)\n",
			notif.cmd_id);
		break;
	}
}

static int mei_csi_probe(struct mei_cl_device *cldev,
			 const struct mei_cl_device_id *id)
{
	struct mei_csi *csi;
	int ret;
	uint8_t *p;
	size_t csi_size = sizeof(struct mei_csi);

	p = kzalloc(csi_size + sizeof(struct csi_notif), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	csi = (struct mei_csi *)p;
	csi->notif = (struct csi_notif *)(p + csi_size);

	csi->cldev = cldev;

	mutex_init(&csi->cmd_mutex);
	init_completion(&csi->response);

	spin_lock_init(&csi->privacy_lock);

	mei_cldev_set_drvdata(cldev, csi);

	ret = mei_cldev_enable(cldev);
	if (ret < 0) {
		dev_err(&cldev->dev,
			"couldn't enable csi client ret=%d\n", ret);
		goto err_out;
	}

	ret = mei_cldev_register_rx_cb(cldev, mei_csi_rx);
	if (ret) {
		dev_err(&cldev->dev,
			"couldn't register rx event ret=%d\n", ret);
		goto err_disable;
	}

	vsc_register_csi(csi, &csi_ops);

	return 0;

err_disable:
	mei_cldev_disable(cldev);

err_out:
	kfree(csi);

	return ret;
}

static void mei_csi_remove(struct mei_cl_device *cldev)
{
	struct mei_csi *csi = mei_cldev_get_drvdata(cldev);

	vsc_unregister_csi();

	if (!completion_done(&csi->response))
		complete(&csi->response);

	mei_cldev_disable(cldev);

	/* wait until no buffer access */
	mutex_lock(&csi->cmd_mutex);
	mutex_unlock(&csi->cmd_mutex);

	kfree(csi);
}

#define MEI_UUID_CSI UUID_LE(0x92335FCF, 0x3203, 0x4472, \
			     0xAF, 0x93, 0x7b, 0x44, 0x53, 0xAC, 0x29, 0xDA)

static const struct mei_cl_device_id mei_csi_tbl[] = {
	{ MEI_CSI_DRIVER_NAME, MEI_UUID_CSI, MEI_CL_VERSION_ANY },

	/* required last entry */
	{ }
};
MODULE_DEVICE_TABLE(mei, mei_csi_tbl);

static struct mei_cl_driver mei_csi_driver = {
	.id_table = mei_csi_tbl,
	.name = MEI_CSI_DRIVER_NAME,

	.probe = mei_csi_probe,
	.remove = mei_csi_remove,
};

static int __init mei_csi_init(void)
{
	int ret;

	ret = mei_cldev_driver_register(&mei_csi_driver);
	if (ret) {
		pr_err("mei csi driver registration failed: %d\n", ret);
		return ret;
	}

	return 0;
}

static void __exit mei_csi_exit(void)
{
	mei_cldev_driver_unregister(&mei_csi_driver);
}

module_init(mei_csi_init);
module_exit(mei_csi_exit);

MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Device driver for Intel VSC CSI client");
