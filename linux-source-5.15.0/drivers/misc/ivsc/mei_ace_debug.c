// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 Intel Corporation */

#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/mei_cl_bus.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/uuid.h>

#define MAX_RECV_SIZE			8192
#define MAX_LOG_SIZE			0x40000000
#define LOG_CONFIG_PARAM_COUNT		7
#define COMMAND_TIMEOUT 		(5 * HZ)
#define ACE_LOG_FILE			"/var/log/vsc_ace.log"
#define MEI_ACE_DEBUG_DRIVER_NAME	"vsc_ace_debug"

enum notif_rsp {
	NOTIF = 0,
	REPLY = 1,
};

enum message_source {
	FW_MSG = 0,
	DRV_MSG = 1,
};

enum notify_type {
	LOG_BUFFER_STATUS = 6,
	FW_READY = 8,
	MANAGEMENT_NOTIF = 16,
	NOTIFICATION = 27,
};

enum notify_event_type {
	STATE_NOTIF = 1,
	CTRL_NOTIF = 2,
};

enum ace_cmd_id {
	GET_FW_VER = 0,
	LOG_CONFIG = 6,
	SET_SYS_TIME = 20,
	GET_FW_ID = 26,
};

enum ace_cmd_type {
	ACE_CMD_GET = 3,
	ACE_CMD_SET = 4,
};

struct firmware_version {
	uint32_t type;
	uint32_t len;

	uint16_t major;
	uint16_t minor;
	uint16_t hotfix;
	uint16_t build;
} __packed;

union tracing_config {
	struct _uart_config {
		uint32_t instance;
		uint32_t baudrate;
	} __packed uart;

	struct _i2c_config {
		uint32_t instance;
		uint32_t speed;
		uint32_t address;
		uint32_t reg;
	} __packed i2c;
};

struct log_config {
	uint32_t aging_period;
	uint32_t fifo_period;
	uint32_t enable;
	uint32_t priority_mask[16];
	uint32_t tracing_method;
	uint32_t tracing_format;
	union tracing_config config;
} __packed;

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
	uint64_t time;
	struct log_config config;
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

	struct _log_notify {
		uint32_t rsvd0 : 12;
		uint32_t source_core : 4;
		uint32_t notif_type : 8;
		uint32_t type : 5;
		uint32_t rsp : 1;
		uint32_t msg_tgt : 1;
		uint32_t _hw_rsvd_0 : 1;

		uint32_t rsvd1 : 30;
		uint32_t _hw_rsvd_2 : 2;
	} __packed log_notify;

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
	struct firmware_version version;
};

struct ace_notif {
	union ace_notif_hdr hdr;
	union ace_notif_cont cont;
} __packed;

struct mei_ace_debug {
	struct mei_cl_device *cldev;

	struct mutex cmd_mutex;
	struct ace_notif cmd_resp;
	struct completion response;

	struct completion reply;
	struct ace_notif reply_notif;

	loff_t pos;
	struct file *ace_file;

	uint8_t *recv_buf;

	struct dentry *dfs_dir;
};

static inline void init_cmd_hdr(struct ace_cmd_hdr *hdr)
{
	memset(hdr, 0, sizeof(struct ace_cmd_hdr));

	hdr->type = ACE_CMD_SET;
	hdr->msg_tgt = DRV_MSG;
	hdr->init_block = 1;
	hdr->final_block = 1;
}

static int construct_command(struct mei_ace_debug *ad,
			     struct ace_cmd *cmd,
			     enum ace_cmd_id cmd_id,
			     void *user_data)
{
	struct ace_cmd_hdr *hdr = &cmd->hdr;
	union ace_cmd_param *param = &cmd->param;

	init_cmd_hdr(hdr);

	hdr->cmd_id = cmd_id;
	switch (cmd_id) {
	case GET_FW_VER:
		hdr->type = ACE_CMD_GET;
		break;
	case SET_SYS_TIME:
		param->time = ktime_get_ns();
		hdr->param_size = sizeof(param->time);
		break;
	case GET_FW_ID:
		memcpy(&param->uuid, user_data, sizeof(param->uuid));
		hdr->param_size = sizeof(param->uuid);
		break;
	case LOG_CONFIG:
		memcpy(&param->config, user_data, sizeof(param->config));
		hdr->param_size = sizeof(param->config);
		break;
	default:
		dev_err(&ad->cldev->dev,
			"sending not supported command");
		break;
	}

	return hdr->param_size + sizeof(cmd->hdr);
}

static int send_command_sync(struct mei_ace_debug *ad,
			     struct ace_cmd *cmd, size_t len)
{
	int ret;
	struct ace_cmd_hdr *cmd_hdr = &cmd->hdr;
	union ace_notif_hdr *reply_hdr = &ad->reply_notif.hdr;

	reinit_completion(&ad->reply);

	ret = mei_cldev_send(ad->cldev, (uint8_t *)cmd, len);
	if (ret < 0) {
		dev_err(&ad->cldev->dev,
			"send command fail %d\n", ret);
		return ret;
	}

	ret = wait_for_completion_killable_timeout(&ad->reply, COMMAND_TIMEOUT);
	if (ret < 0) {
		dev_err(&ad->cldev->dev,
			"command %d notify reply error\n", cmd_hdr->cmd_id);
		return ret;
	} else if (ret == 0) {
		dev_err(&ad->cldev->dev,
			"command %d notify reply timeout\n", cmd_hdr->cmd_id);
		ret = -ETIMEDOUT;
		return ret;
	}

	if (reply_hdr->response.cmd_id != cmd_hdr->cmd_id) {
		dev_err(&ad->cldev->dev,
			"reply notify mismatch, sent %d but got %d\n",
			cmd_hdr->cmd_id, reply_hdr->response.cmd_id);
		return -1;
	}

	ret = reply_hdr->response.status;
	if (ret) {
		dev_err(&ad->cldev->dev,
			"command %d reply wrong status = %d\n",
			cmd_hdr->cmd_id, ret);
		return -1;
	}

	return 0;
}

static int set_system_time(struct mei_ace_debug *ad)
{
	struct ace_cmd cmd;
	size_t cmd_len;
	int ret;

	cmd_len = construct_command(ad, &cmd, SET_SYS_TIME, NULL);

	mutex_lock(&ad->cmd_mutex);
	ret = send_command_sync(ad, &cmd, cmd_len);
	mutex_unlock(&ad->cmd_mutex);

	return ret;
}

static ssize_t ad_time_write(struct file *file,
			     const char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct mei_ace_debug *ad = file->private_data;
	int ret;

	ret = set_system_time(ad);
	if (ret)
		return ret;

	return count;
}

static int config_log(struct mei_ace_debug *ad, struct log_config *config)
{
	struct ace_cmd cmd;
	size_t cmd_len;
	int ret;

	cmd_len = construct_command(ad, &cmd, LOG_CONFIG, config);

	mutex_lock(&ad->cmd_mutex);
	ret = send_command_sync(ad, &cmd, cmd_len);
	mutex_unlock(&ad->cmd_mutex);

	return ret;
}

static ssize_t ad_log_config_write(struct file *file,
				   const char __user *ubuf,
				   size_t count, loff_t *ppos)
{
	struct mei_ace_debug *ad = file->private_data;
	int ret;
	uint8_t *buf;
	struct log_config config = {0};

	buf = memdup_user_nul(ubuf, min(count, (size_t)(PAGE_SIZE - 1)));
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	ret = sscanf(buf, "%u %u %u %u %u %u %u",
		     &config.aging_period,
		     &config.fifo_period,
		     &config.enable,
		     &config.priority_mask[0],
		     &config.priority_mask[1],
		     &config.tracing_format,
		     &config.tracing_method);
	if (ret != LOG_CONFIG_PARAM_COUNT) {
		dev_err(&ad->cldev->dev,
			"please input all the required parameters\n");
		return -EINVAL;
	}

	ret = config_log(ad, &config);
	if (ret)
		return ret;

	return count;
}

static int get_firmware_version(struct mei_ace_debug *ad,
				struct firmware_version *version)
{
	struct ace_cmd cmd;
	size_t cmd_len;
	union ace_notif_cont *cont;
	int ret;

	cmd_len = construct_command(ad, &cmd, GET_FW_VER, NULL);

	mutex_lock(&ad->cmd_mutex);
	ret = send_command_sync(ad, &cmd, cmd_len);
	if (!ret) {
		cont = &ad->reply_notif.cont;
		memcpy(version, &cont->version, sizeof(*version));
	}
	mutex_unlock(&ad->cmd_mutex);

	return ret;
}

static ssize_t ad_firmware_version_read(struct file *file,
					char __user *buf,
					size_t count, loff_t *ppos)
{
	struct mei_ace_debug *ad = file->private_data;
	int ret, pos;
	struct firmware_version version;
	unsigned long addr = get_zeroed_page(GFP_KERNEL);

	if (!addr)
		return -ENOMEM;

	ret = get_firmware_version(ad, &version);
	if (ret)
		goto out;

	pos = snprintf((char *)addr, PAGE_SIZE,
		       "firmware version: %u.%u.%u.%u\n",
		       version.major, version.minor,
		       version.hotfix, version.build);

	ret = simple_read_from_buffer(buf, count, ppos, (char *)addr, pos);

out:
	free_page(addr);
	return ret;
}

#define AD_DFS_ADD_FILE(name)						\
	debugfs_create_file(#name, 0644, ad->dfs_dir, ad,		\
			    &ad_dfs_##name##_fops)

#define AD_DFS_FILE_OPS(name)						\
static const struct file_operations ad_dfs_##name##_fops = {		\
	.read = ad_##name##_read,					\
	.write = ad_##name##_write,					\
	.open = simple_open,						\
}

#define AD_DFS_FILE_READ_OPS(name)					\
static const struct file_operations ad_dfs_##name##_fops = {		\
	.read = ad_##name##_read,					\
	.open = simple_open,						\
}

#define AD_DFS_FILE_WRITE_OPS(name)					\
static const struct file_operations ad_dfs_##name##_fops = {		\
	.write = ad_##name##_write,					\
	.open = simple_open,						\
}

AD_DFS_FILE_WRITE_OPS(time);
AD_DFS_FILE_WRITE_OPS(log_config);

AD_DFS_FILE_READ_OPS(firmware_version);

static void handle_notify(struct mei_ace_debug *ad,
			  struct ace_notif *notif, int len)
{
	int ret;
	struct file *file;
	loff_t *pos;
	union ace_notif_hdr *hdr = &notif->hdr;
	struct mei_cl_device *cldev = ad->cldev;

	if (hdr->notify.msg_tgt != FW_MSG ||
	    hdr->notify.type != NOTIFICATION) {
		dev_err(&cldev->dev, "recv wrong notification\n");
		return;
	}

	switch (hdr->notify.notif_type) {
	case FW_READY:
		/* firmware ready notification sent to driver
		 * after HECI client connected with firmware.
		 */
		dev_info(&cldev->dev, "firmware ready\n");
		break;

	case LOG_BUFFER_STATUS:
		if (ad->pos < MAX_LOG_SIZE) {
			pos = &ad->pos;
			file = ad->ace_file;

			ret = kernel_write(file,
					   (uint8_t *)notif + sizeof(*hdr),
					   len - sizeof(*hdr),
					   pos);
			if (ret < 0)
				dev_err(&cldev->dev,
					"error in writing log %d\n", ret);
			else
				*pos += ret;
		} else
			dev_warn(&cldev->dev,
				 "already exceed max log size\n");
		break;

	case MANAGEMENT_NOTIF:
		if (hdr->management.event_id == CTRL_NOTIF) {
			switch (hdr->management.request_id) {
			case GET_FW_VER:
			case LOG_CONFIG:
			case SET_SYS_TIME:
			case GET_FW_ID:
				memcpy(&ad->cmd_resp, notif, len);

				if (!completion_done(&ad->response))
					complete(&ad->response);
				break;

			default:
				dev_err(&cldev->dev,
					"wrong command id(%d) notif\n",
					hdr->management.request_id);
				break;
			}
		}
		break;

	default:
		dev_info(&cldev->dev,
			 "unexpected notify(%d)\n", hdr->notify.notif_type);
		break;
	}
}

/* callback for command response receive */
static void mei_ace_debug_rx(struct mei_cl_device *cldev)
{
	struct mei_ace_debug *ad = mei_cldev_get_drvdata(cldev);
	int ret;
	struct ace_notif *notif;
	union ace_notif_hdr *hdr;

	ret = mei_cldev_recv(cldev, ad->recv_buf, MAX_RECV_SIZE);
	if (ret < 0) {
		dev_err(&cldev->dev, "failure in recv %d\n", ret);
		return;
	} else if (ret < sizeof(union ace_notif_hdr)) {
		dev_err(&cldev->dev, "recv small data %d\n", ret);
		return;
	}
	notif = (struct ace_notif *)ad->recv_buf;
	hdr = &notif->hdr;

	switch (hdr->notify.rsp) {
	case REPLY:
		memcpy(&ad->reply_notif, notif, sizeof(struct ace_notif));

		if (!completion_done(&ad->reply))
			complete(&ad->reply);
		break;

	case NOTIF:
		handle_notify(ad, notif, ret);
		break;

	default:
		dev_err(&cldev->dev,
			"unexpected response(%d)\n", hdr->notify.rsp);
		break;
	}
}

static int mei_ace_debug_probe(struct mei_cl_device *cldev,
			       const struct mei_cl_device_id *id)
{
	struct mei_ace_debug *ad;
	int ret;
	uint32_t order = get_order(MAX_RECV_SIZE);

	ad = kzalloc(sizeof(struct mei_ace_debug), GFP_KERNEL);
	if (!ad)
		return -ENOMEM;

	ad->recv_buf = (uint8_t *)__get_free_pages(GFP_KERNEL, order);
	if (!ad->recv_buf) {
		kfree(ad);
		return -ENOMEM;
	}

	ad->cldev = cldev;

	mutex_init(&ad->cmd_mutex);
	init_completion(&ad->response);
	init_completion(&ad->reply);

	mei_cldev_set_drvdata(cldev, ad);

	ret = mei_cldev_enable(cldev);
	if (ret < 0) {
		dev_err(&cldev->dev,
			"couldn't enable ace debug client ret=%d\n", ret);
		goto err_out;
	}

	ret = mei_cldev_register_rx_cb(cldev, mei_ace_debug_rx);
	if (ret) {
		dev_err(&cldev->dev,
			"couldn't register ace debug rx cb ret=%d\n", ret);
		goto err_disable;
	}

	ad->ace_file = filp_open(ACE_LOG_FILE,
				 O_CREAT | O_RDWR | O_LARGEFILE | O_TRUNC,
				 0600);
	if (IS_ERR(ad->ace_file)) {
		dev_err(&cldev->dev,
			"filp_open(%s) failed\n", ACE_LOG_FILE);
		ret = PTR_ERR(ad->ace_file);
		goto err_disable;
	}
	ad->pos = 0;

	ad->dfs_dir = debugfs_create_dir("vsc_ace", NULL);
	if (ad->dfs_dir) {
		AD_DFS_ADD_FILE(log_config);
		AD_DFS_ADD_FILE(time);
		AD_DFS_ADD_FILE(firmware_version);
	}

	return 0;

err_disable:
	mei_cldev_disable(cldev);

err_out:
	free_pages((unsigned long)ad->recv_buf, order);

	kfree(ad);

	return ret;
}

static void mei_ace_debug_remove(struct mei_cl_device *cldev)
{
	uint32_t order = get_order(MAX_RECV_SIZE);
	struct mei_ace_debug *ad = mei_cldev_get_drvdata(cldev);

	if (!completion_done(&ad->response))
		complete(&ad->response);

	if (!completion_done(&ad->reply))
		complete(&ad->reply);

	mei_cldev_disable(cldev);

	debugfs_remove_recursive(ad->dfs_dir);

	filp_close(ad->ace_file, NULL);

	/* wait until no buffer access */
	mutex_lock(&ad->cmd_mutex);
	mutex_unlock(&ad->cmd_mutex);

	free_pages((unsigned long)ad->recv_buf, order);

	kfree(ad);
}

#define MEI_UUID_ACE_DEBUG UUID_LE(0xFB285857, 0xFC24, 0x4BF3, 0xBD, \
				   0x80, 0x2A, 0xBC, 0x44, 0xE3, 0xC2, 0x0B)

static const struct mei_cl_device_id mei_ace_debug_tbl[] = {
	{ MEI_ACE_DEBUG_DRIVER_NAME, MEI_UUID_ACE_DEBUG, MEI_CL_VERSION_ANY },

	/* required last entry */
	{ }
};
MODULE_DEVICE_TABLE(mei, mei_ace_debug_tbl);

static struct mei_cl_driver mei_ace_debug_driver = {
	.id_table = mei_ace_debug_tbl,
	.name = MEI_ACE_DEBUG_DRIVER_NAME,

	.probe = mei_ace_debug_probe,
	.remove = mei_ace_debug_remove,
};

static int __init mei_ace_debug_init(void)
{
	int ret;

	ret = mei_cldev_driver_register(&mei_ace_debug_driver);
	if (ret) {
		pr_err("mei ace debug driver registration failed: %d\n", ret);
		return ret;
	}

	return 0;
}

static void __exit mei_ace_debug_exit(void)
{
	mei_cldev_driver_unregister(&mei_ace_debug_driver);
}

module_init(mei_ace_debug_init);
module_exit(mei_ace_debug_exit);

MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Device driver for Intel VSC ACE debug client");
