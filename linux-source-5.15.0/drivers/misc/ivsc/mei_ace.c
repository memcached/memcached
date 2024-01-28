// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 Intel Corporation */

#include <linux/completion.h>
#include <linux/kernel.h>
#include <linux/mei_cl_bus.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uuid.h>
#include <linux/vsc.h>

#include "intel_vsc.h"

#define ACE_TIMEOUT			(5 * HZ)
#define MEI_ACE_DRIVER_NAME		"vsc_ace"

#define UUID_GET_FW_ID UUID_LE(0x6167DCFB, 0x72F1, 0x4584, \
			       0xBF, 0xE3, 0x84, 0x17, 0x71, 0xAA, 0x79, 0x0B)

enum notif_rsp {
	NOTIF = 0,
	REPLY = 1,
};

enum notify_type {
	FW_READY = 8,
	EXCEPTION = 10,
	WATCHDOG_TIMEOUT = 15,
	MANAGEMENT_NOTIF = 16,
	NOTIFICATION = 27,
};

enum message_source {
	FW_MSG = 0,
	DRV_MSG = 1,
};

enum notify_event_type {
	STATE_NOTIF = 0x1,
	CTRL_NOTIF = 0x2,
	DPHY_NOTIF = 0x3,
};

enum ace_cmd_type {
	ACE_CMD_GET = 3,
	ACE_CMD_SET = 4,
};

enum ace_cmd_id {
	IPU_OWN_CAMERA = 0x13,
	ACE_OWN_CAMERA = 0x14,
	GET_CAMERA_STATUS = 0x15,
	GET_FW_ID = 0x1A,
};

struct ace_cmd_hdr {
	uint32_t module_id : 16;
	uint32_t instance_id : 8;
	uint32_t type : 5;
	uint32_t rsp : 1;
	uint32_t msg_tgt : 1;
	uint32_t _hw_rsvd_0 : 1;

	uint32_t param_size : 20;
	uint32_t cmd_id : 8;
	uint32_t final_block : 1;
	uint32_t init_block : 1;
	uint32_t _hw_rsvd_2 : 2;
} __packed;

union ace_cmd_param {
	uuid_le uuid;
	uint32_t param;
};

struct ace_cmd {
	struct ace_cmd_hdr hdr;
	union ace_cmd_param param;
} __packed;

union ace_notif_hdr {
	struct _response {
		uint32_t status : 24;
		uint32_t type : 5;
		uint32_t rsp : 1;
		uint32_t msg_tgt : 1;
		uint32_t _hw_rsvd_0 : 1;

		uint32_t param_size : 20;
		uint32_t cmd_id : 8;
		uint32_t final_block : 1;
		uint32_t init_block : 1;

		uint32_t _hw_rsvd_2 : 2;
	} __packed response;

	struct _notify {
		uint32_t rsvd2 : 16;
		uint32_t notif_type : 8;
		uint32_t type : 5;
		uint32_t rsp : 1;
		uint32_t msg_tgt : 1;
		uint32_t _hw_rsvd_0 : 1;

		uint32_t rsvd1 : 30;
		uint32_t _hw_rsvd_2 : 2;
	} __packed notify;

	struct _management {
		uint32_t event_id : 16;
		uint32_t notif_type : 8;
		uint32_t type : 5;
		uint32_t rsp : 1;
		uint32_t msg_tgt : 1;
		uint32_t _hw_rsvd_0 : 1;

		uint32_t event_data_size : 16;
		uint32_t request_target : 1;
		uint32_t request_type : 5;
		uint32_t request_id : 8;
		uint32_t _hw_rsvd_2 : 2;
	} __packed management;
};

union ace_notif_cont {
	uint16_t module_id;
	uint8_t state_notif;
	struct camera_status stat;
};

struct ace_notif {
	union ace_notif_hdr hdr;
	union ace_notif_cont cont;
} __packed;

struct mei_ace {
	struct mei_cl_device *cldev;

	struct mutex cmd_mutex;
	struct ace_notif *cmd_resp;
	struct completion response;

	struct completion reply;
	struct ace_notif *reply_notif;

	uint16_t module_id;
	uint16_t init_wait_q_woken;
	wait_queue_head_t init_wait_q;
};

static inline void init_cmd_hdr(struct ace_cmd_hdr *hdr)
{
	memset(hdr, 0, sizeof(struct ace_cmd_hdr));

	hdr->type = ACE_CMD_SET;
	hdr->msg_tgt = DRV_MSG;
	hdr->init_block = 1;
	hdr->final_block = 1;
}

static uint16_t get_fw_id(struct mei_ace *ace)
{
	int ret;

	ret = wait_event_interruptible(ace->init_wait_q,
				       ace->init_wait_q_woken);
	if (ret < 0)
		dev_warn(&ace->cldev->dev,
			 "incorrect fw id sent to fw\n");

	return ace->module_id;
}

static int construct_command(struct mei_ace *ace, struct ace_cmd *cmd,
			     enum ace_cmd_id cmd_id)
{
	struct ace_cmd_hdr *hdr = &cmd->hdr;
	union ace_cmd_param *param = &cmd->param;

	init_cmd_hdr(hdr);

	hdr->cmd_id = cmd_id;
	switch (cmd_id) {
	case GET_FW_ID:
		param->uuid = UUID_GET_FW_ID;
		hdr->param_size = sizeof(param->uuid);
		break;
	case ACE_OWN_CAMERA:
		param->param = 0;
		hdr->module_id = get_fw_id(ace);
		hdr->param_size = sizeof(param->param);
		break;
	case IPU_OWN_CAMERA:
	case GET_CAMERA_STATUS:
		hdr->module_id = get_fw_id(ace);
		break;
	default:
		dev_err(&ace->cldev->dev,
			"sending not supported command");
		break;
	}

	return hdr->param_size + sizeof(cmd->hdr);
}

static int send_command_sync(struct mei_ace *ace,
			     struct ace_cmd *cmd, size_t len)
{
	int ret;
	struct ace_cmd_hdr *cmd_hdr = &cmd->hdr;
	union ace_notif_hdr *resp_hdr = &ace->cmd_resp->hdr;
	union ace_notif_hdr *reply_hdr = &ace->reply_notif->hdr;

	reinit_completion(&ace->response);
	reinit_completion(&ace->reply);

	ret = mei_cldev_send(ace->cldev, (uint8_t *)cmd, len);
	if (ret < 0) {
		dev_err(&ace->cldev->dev,
			"send command fail %d\n", ret);
		return ret;
	}

	ret = wait_for_completion_killable_timeout(&ace->reply, ACE_TIMEOUT);
	if (ret < 0) {
		dev_err(&ace->cldev->dev,
			"command %d notify reply error\n", cmd_hdr->cmd_id);
		return ret;
	} else if (ret == 0) {
		dev_err(&ace->cldev->dev,
			"command %d notify reply timeout\n", cmd_hdr->cmd_id);
		ret = -ETIMEDOUT;
		return ret;
	}

	if (reply_hdr->response.cmd_id != cmd_hdr->cmd_id) {
		dev_err(&ace->cldev->dev,
			"reply notify mismatch, sent %d but got %d\n",
			cmd_hdr->cmd_id, reply_hdr->response.cmd_id);
		return -1;
	}

	ret = reply_hdr->response.status;
	if (ret) {
		dev_err(&ace->cldev->dev,
			"command %d reply wrong status = %d\n",
			cmd_hdr->cmd_id, ret);
		return -1;
	}

	ret = wait_for_completion_killable_timeout(&ace->response, ACE_TIMEOUT);
	if (ret < 0) {
		dev_err(&ace->cldev->dev,
			"command %d response error\n", cmd_hdr->cmd_id);
		return ret;
	} else if (ret == 0) {
		dev_err(&ace->cldev->dev,
			"command %d response timeout\n", cmd_hdr->cmd_id);
		ret = -ETIMEDOUT;
		return ret;
	}

	if (resp_hdr->management.request_id != cmd_hdr->cmd_id) {
		dev_err(&ace->cldev->dev,
			"command response mismatch, sent %d but got %d\n",
			cmd_hdr->cmd_id, resp_hdr->management.request_id);
		return -1;
	}

	return 0;
}

static int trigger_get_fw_id(struct mei_ace *ace)
{
	int ret;
	struct ace_cmd cmd;
	size_t cmd_len;

	cmd_len = construct_command(ace, &cmd, GET_FW_ID);

	ret = mei_cldev_send(ace->cldev, (uint8_t *)&cmd, cmd_len);
	if (ret < 0)
		dev_err(&ace->cldev->dev,
			"send get fw id command fail %d\n", ret);

	return ret;
}

static int set_camera_ownership(struct mei_ace *ace,
				enum ace_cmd_id cmd_id,
				struct camera_status *status)
{
	struct ace_cmd cmd;
	size_t cmd_len;
	union ace_notif_cont *cont;
	int ret;

	cmd_len = construct_command(ace, &cmd, cmd_id);

	mutex_lock(&ace->cmd_mutex);

	ret = send_command_sync(ace, &cmd, cmd_len);
	if (!ret) {
		cont = &ace->cmd_resp->cont;
		memcpy(status, &cont->stat, sizeof(*status));
	}

	mutex_unlock(&ace->cmd_mutex);

	return ret;
}

int ipu_own_camera(void *ace, struct camera_status *status)
{
	struct mei_ace *p_ace = (struct mei_ace *)ace;

	return set_camera_ownership(p_ace, IPU_OWN_CAMERA, status);
}

int ace_own_camera(void *ace, struct camera_status *status)
{
	struct mei_ace *p_ace = (struct mei_ace *)ace;

	return set_camera_ownership(p_ace, ACE_OWN_CAMERA, status);
}

int get_camera_status(void *ace, struct camera_status *status)
{
	int ret;
	struct ace_cmd cmd;
	size_t cmd_len;
	union ace_notif_cont *cont;
	struct mei_ace *p_ace = (struct mei_ace *)ace;

	cmd_len = construct_command(p_ace, &cmd, GET_CAMERA_STATUS);

	mutex_lock(&p_ace->cmd_mutex);

	ret = send_command_sync(p_ace, &cmd, cmd_len);
	if (!ret) {
		cont = &p_ace->cmd_resp->cont;
		memcpy(status, &cont->stat, sizeof(*status));
	}

	mutex_unlock(&p_ace->cmd_mutex);

	return ret;
}

static struct vsc_ace_ops ace_ops = {
	.ace_own_camera = ace_own_camera,
	.ipu_own_camera = ipu_own_camera,
	.get_camera_status = get_camera_status,
};

static void handle_notify(struct mei_ace *ace, struct ace_notif *resp, int len)
{
	union ace_notif_hdr *hdr = &resp->hdr;
	struct mei_cl_device *cldev = ace->cldev;

	if (hdr->notify.msg_tgt != FW_MSG ||
	    hdr->notify.type != NOTIFICATION) {
		dev_err(&cldev->dev, "recv incorrect notification\n");
		return;
	}

	switch (hdr->notify.notif_type) {
	/* firmware ready notification sent to driver
	 * after HECI client connected with firmware.
	 */
	case FW_READY:
		dev_info(&cldev->dev, "firmware ready\n");

		trigger_get_fw_id(ace);
		break;

	case MANAGEMENT_NOTIF:
		if (hdr->management.event_id == CTRL_NOTIF) {
			switch (hdr->management.request_id) {
			case GET_FW_ID:
				dev_warn(&cldev->dev,
					 "shouldn't reach here\n");
				break;

			case ACE_OWN_CAMERA:
			case IPU_OWN_CAMERA:
			case GET_CAMERA_STATUS:
				memcpy(ace->cmd_resp, resp, len);

				if (!completion_done(&ace->response))
					complete(&ace->response);
				break;

			default:
				dev_err(&cldev->dev,
					"incorrect command id notif\n");
				break;
			}
		}
		break;

	case EXCEPTION:
		dev_err(&cldev->dev, "firmware exception\n");
		break;

	case WATCHDOG_TIMEOUT:
		dev_err(&cldev->dev, "firmware watchdog timeout\n");
		break;

	default:
		dev_err(&cldev->dev,
			"recv unknown notification(%d)\n",
			hdr->notify.notif_type);
		break;
	}
}

 /* callback for command response receive */
static void mei_ace_rx(struct mei_cl_device *cldev)
{
	struct mei_ace *ace = mei_cldev_get_drvdata(cldev);
	int ret;
	struct ace_notif resp;
	union ace_notif_hdr *hdr = &resp.hdr;

	ret = mei_cldev_recv(cldev, (uint8_t *)&resp, sizeof(resp));
	if (ret < 0) {
		dev_err(&cldev->dev, "failure in recv %d\n", ret);
		return;
	} else if (ret < sizeof(union ace_notif_hdr)) {
		dev_err(&cldev->dev, "recv small data %d\n", ret);
		return;
	}

	switch (hdr->notify.rsp) {
	case REPLY:
		if (hdr->response.cmd_id == GET_FW_ID) {
			ace->module_id = resp.cont.module_id;

			ace->init_wait_q_woken = true;
			wake_up_all(&ace->init_wait_q);

			dev_info(&cldev->dev, "recv firmware id\n");
		} else {
			memcpy(ace->reply_notif, &resp, ret);

			if (!completion_done(&ace->reply))
				complete(&ace->reply);
		}
		break;

	case NOTIF:
		handle_notify(ace, &resp, ret);
		break;

	default:
		dev_err(&cldev->dev,
			"recv unknown response(%d)\n", hdr->notify.rsp);
		break;
	}
}

static int mei_ace_probe(struct mei_cl_device *cldev,
			 const struct mei_cl_device_id *id)
{
	struct mei_ace *ace;
	int ret;
	uint8_t *addr;
	size_t ace_size = sizeof(struct mei_ace);
	size_t reply_size = sizeof(struct ace_notif);
	size_t response_size = sizeof(struct ace_notif);

	ace = kzalloc(ace_size + response_size + reply_size, GFP_KERNEL);
	if (!ace)
		return -ENOMEM;

	addr = (uint8_t *)ace;
	ace->cmd_resp = (struct ace_notif *)(addr + ace_size);

	addr = (uint8_t *)ace->cmd_resp;
	ace->reply_notif = (struct ace_notif *)(addr + response_size);

	ace->cldev = cldev;

	ace->init_wait_q_woken = false;
	init_waitqueue_head(&ace->init_wait_q);

	mutex_init(&ace->cmd_mutex);
	init_completion(&ace->response);
	init_completion(&ace->reply);

	mei_cldev_set_drvdata(cldev, ace);

	ret = mei_cldev_enable(cldev);
	if (ret < 0) {
		dev_err(&cldev->dev,
			"couldn't enable ace client ret=%d\n", ret);
		goto err_out;
	}

	ret = mei_cldev_register_rx_cb(cldev, mei_ace_rx);
	if (ret) {
		dev_err(&cldev->dev,
			"couldn't register rx cb ret=%d\n", ret);
		goto err_disable;
	}

	trigger_get_fw_id(ace);

	vsc_register_ace(ace, &ace_ops);
	return 0;

err_disable:
	mei_cldev_disable(cldev);

err_out:
	kfree(ace);

	return ret;
}

static void mei_ace_remove(struct mei_cl_device *cldev)
{
	struct mei_ace *ace = mei_cldev_get_drvdata(cldev);

	vsc_unregister_ace();

	if (!completion_done(&ace->response))
		complete(&ace->response);

	if (!completion_done(&ace->reply))
		complete(&ace->reply);

	if (wq_has_sleeper(&ace->init_wait_q))
		wake_up_all(&ace->init_wait_q);

	mei_cldev_disable(cldev);

	/* wait until no buffer access */
	mutex_lock(&ace->cmd_mutex);
	mutex_unlock(&ace->cmd_mutex);

	kfree(ace);
}

#define MEI_UUID_ACE UUID_LE(0x5DB76CF6, 0x0A68, 0x4ED6, \
			     0x9B, 0x78, 0x03, 0x61, 0x63, 0x5E, 0x24, 0x47)

static const struct mei_cl_device_id mei_ace_tbl[] = {
	{ MEI_ACE_DRIVER_NAME, MEI_UUID_ACE, MEI_CL_VERSION_ANY },

	/* required last entry */
	{ }
};
MODULE_DEVICE_TABLE(mei, mei_ace_tbl);

static struct mei_cl_driver mei_ace_driver = {
	.id_table = mei_ace_tbl,
	.name = MEI_ACE_DRIVER_NAME,

	.probe = mei_ace_probe,
	.remove = mei_ace_remove,
};

static int __init mei_ace_init(void)
{
	int ret;

	ret = mei_cldev_driver_register(&mei_ace_driver);
	if (ret) {
		pr_err("mei ace driver registration failed: %d\n", ret);
		return ret;
	}

	return 0;
}

static void __exit mei_ace_exit(void)
{
	mei_cldev_driver_unregister(&mei_ace_driver);
}

module_init(mei_ace_init);
module_exit(mei_ace_exit);

MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Device driver for Intel VSC ACE client");
