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

#define MEI_PSE_DRIVER_NAME	"vsc_pse"

#define PSE_TIMEOUT		(5 * HZ)

#define CONT_OFFSET		offsetof(struct pse_notif, cont)
#define NOTIF_HEADER_LEN	8

#define MAX_RECV_SIZE		8192
#define MAX_LOG_SIZE		0x40000000
#define EM_LOG_FILE		"/var/log/vsc_em.log"
#define SEM_LOG_FILE		"/var/log/vsc_sem.log"

#define PM_SUBSYS_MAX		2
#define PM_STATE_NAME_LEN	16
#define DEV_NUM			64
#define DEV_NAME_LEN		32

#define FORMAT			"|%16.32s |%12u "
#define FORMAT_TAIL		"|\n"
#define CONSTRUCTED_FORMAT	(FORMAT FORMAT FORMAT FORMAT FORMAT_TAIL)
#define TITLE			"|   Device Name   | Block Count "
#define TITLE_TAIL		"|"
#define CONSTRUCTED_TITLE	(TITLE TITLE TITLE TITLE TITLE_TAIL)

enum pse_cmd_id {
	LOG_ONOFF = 0,
	SET_WATERMARK = 1,
	DUMP_TRACE = 2,
	SET_TIMEOUT = 3,
	SET_LOG_LEVEL = 4,
	SET_TIME = 5,
	GET_TIME = 6,
	DUMP_POWER_DATA = 7,
	TRACE_DATA_NOTIF = 8,
	GET_FW_VER = 10,
};

enum pm_state {
	ACTIVE = 0,
	CORE_HALT,
	CORE_CLK_GATE,
	DEEP_SLEEP,
	STATE_MAX,
};

struct fw_version {
	uint32_t major;
	uint32_t minor;
	uint32_t hotfix;
	uint32_t build;
} __packed;

struct dev_info {
	char name[DEV_NAME_LEN];
	uint32_t block_cnt;
} __packed;

struct dev_list {
	struct dev_info dev[DEV_NUM];
	uint32_t dev_cnt;
} __packed;

struct pm_status {
	char name[PM_STATE_NAME_LEN];
	uint64_t start;
	uint64_t end;
	uint64_t duration;
	uint64_t count;
} __packed;

struct pm_subsys {
	uint64_t total;
	struct pm_status status[STATE_MAX];
	struct dev_list dev;
	uint16_t crc;
} __packed;

struct pm_data {
	struct pm_subsys subsys[PM_SUBSYS_MAX];
} __packed;

struct pse_cmd {
	uint32_t cmd_id;
	union _cmd_param {
		uint32_t param;
		uint64_t time;
	} param;
} __packed;

struct pse_notif {
	uint32_t cmd_id;
	int8_t status;
	uint8_t source;
	int16_t size;
	union _resp_cont {
		uint64_t time;
		struct fw_version ver;
	} cont;
} __packed;

struct mei_pse {
	struct mei_cl_device *cldev;

	struct mutex cmd_mutex;
	struct pse_notif notif;
	struct completion response;

	uint8_t *recv_buf;

	uint8_t *pm_data;
	uint32_t pm_data_pos;

	loff_t em_pos;
	struct file *em_file;

	loff_t sem_pos;
	struct file *sem_file;

	struct dentry *dfs_dir;
};

static int mei_pse_send(struct mei_pse *pse, struct pse_cmd *cmd, size_t len)
{
	int ret;

	reinit_completion(&pse->response);

	ret = mei_cldev_send(pse->cldev, (uint8_t *)cmd, len);
	if (ret < 0) {
		dev_err(&pse->cldev->dev,
			"send command fail %d\n", ret);
		return ret;
	}

	ret = wait_for_completion_killable_timeout(&pse->response, PSE_TIMEOUT);
	if (ret < 0) {
		dev_err(&pse->cldev->dev,
			"command %d response error\n", cmd->cmd_id);
		return ret;
	} else if (ret == 0) {
		dev_err(&pse->cldev->dev,
			"command %d response timeout\n", cmd->cmd_id);
		ret = -ETIMEDOUT;
		return ret;
	}

	ret = pse->notif.status;
	if (ret) {
		dev_err(&pse->cldev->dev,
			"command %d response fail %d\n", cmd->cmd_id, ret);
		return ret;
	}

	if (pse->notif.cmd_id != cmd->cmd_id) {
		dev_err(&pse->cldev->dev,
			"command response id mismatch, sent %d but got %d\n",
			cmd->cmd_id, pse->notif.cmd_id);
		ret = -1;
	}

	return ret;
}

static int pse_log_onoff(struct mei_pse *pse, uint8_t onoff)
{
	struct pse_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	int ret;

	cmd.cmd_id = LOG_ONOFF;
	cmd.param.param = onoff;
	cmd_len += sizeof(cmd.param.param);

	mutex_lock(&pse->cmd_mutex);
	ret = mei_pse_send(pse, &cmd, cmd_len);
	mutex_unlock(&pse->cmd_mutex);

	return ret;
}

static ssize_t pse_log_onoff_write(struct file *file,
				   const char __user *buf,
				   size_t count, loff_t *ppos)
{
	struct mei_pse *pse = file->private_data;
	int ret;
	uint8_t state;

	ret = kstrtou8_from_user(buf, count, 0, &state);
	if (ret)
		return ret;

	pse_log_onoff(pse, state);

	return count;
}

static int pse_set_watermark(struct mei_pse *pse, int val)
{
	struct pse_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	int ret;

	if (val < -1 || val > 100) {
		dev_err(&pse->cldev->dev, "error water mark value\n");
		return -1;
	}

	cmd.cmd_id = SET_WATERMARK;
	cmd.param.param = val;
	cmd_len += sizeof(cmd.param.param);

	mutex_lock(&pse->cmd_mutex);
	ret = mei_pse_send(pse, &cmd, cmd_len);
	mutex_unlock(&pse->cmd_mutex);

	return ret;
}

static ssize_t pse_watermark_write(struct file *file,
				   const char __user *buf,
				   size_t count, loff_t *ppos)
{
	struct mei_pse *pse = file->private_data;
	int ret, val;

	ret = kstrtoint_from_user(buf, count, 0, &val);
	if (ret)
		return ret;

	pse_set_watermark(pse, val);

	return count;
}

static int pse_dump_trace(struct mei_pse *pse)
{
	struct pse_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	int ret;

	cmd.cmd_id = DUMP_TRACE;

	mutex_lock(&pse->cmd_mutex);
	ret = mei_pse_send(pse, &cmd, cmd_len);
	mutex_unlock(&pse->cmd_mutex);

	return ret;
}

static ssize_t pse_dump_trace_write(struct file *file,
				    const char __user *buf,
				    size_t count, loff_t *ppos)
{
	struct mei_pse *pse = file->private_data;
	int ret;
	uint8_t val;

	ret = kstrtou8_from_user(buf, count, 0, &val);
	if (ret)
		return ret;

	if (!val)
		return -EINVAL;

	pse_dump_trace(pse);

	return count;
}

static int pse_set_timeout(struct mei_pse *pse, int val)
{
	struct pse_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	int ret;

	if (val < -1 || val > 999) {
		dev_err(&pse->cldev->dev, "error timeout value\n");
		return -1;
	}

	cmd.cmd_id = SET_TIMEOUT;
	cmd.param.param = val;
	cmd_len += sizeof(cmd.param.param);

	mutex_lock(&pse->cmd_mutex);
	ret = mei_pse_send(pse, &cmd, cmd_len);
	mutex_unlock(&pse->cmd_mutex);

	return ret;
}

static ssize_t pse_timeout_write(struct file *file,
				 const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct mei_pse *pse = file->private_data;
	int ret, val;

	ret = kstrtoint_from_user(buf, count, 0, &val);
	if (ret)
		return ret;

	pse_set_timeout(pse, val);

	return count;
}

static int pse_set_log_level(struct mei_pse *pse, int val)
{
	struct pse_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	int ret;

	if (val < 0 || val > 4) {
		dev_err(&pse->cldev->dev, "unsupported log level\n");
		return -1;
	}

	cmd.cmd_id = SET_LOG_LEVEL;
	cmd.param.param = val;
	cmd_len += sizeof(cmd.param.param);

	mutex_lock(&pse->cmd_mutex);
	ret = mei_pse_send(pse, &cmd, cmd_len);
	mutex_unlock(&pse->cmd_mutex);

	return ret;
}

static ssize_t pse_log_level_write(struct file *file,
				   const char __user *buf,
				   size_t count, loff_t *ppos)
{
	struct mei_pse *pse = file->private_data;
	int ret, val;

	ret = kstrtoint_from_user(buf, count, 0, &val);
	if (ret)
		return ret;

	pse_set_log_level(pse, val);

	return count;
}

static int pse_set_time(struct mei_pse *pse)
{
	struct pse_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	int ret;

	cmd.cmd_id = SET_TIME;
	cmd.param.time = ktime_get_ns();
	cmd_len += sizeof(cmd.param.time);

	mutex_lock(&pse->cmd_mutex);
	ret = mei_pse_send(pse, &cmd, cmd_len);
	mutex_unlock(&pse->cmd_mutex);

	return ret;
}

static ssize_t pse_time_write(struct file *file,
			      const char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct mei_pse *pse = file->private_data;
	int ret;

	ret = pse_set_time(pse);
	if (ret)
		return ret;

	return count;
}

static int pse_get_time(struct mei_pse *pse, uint64_t *val)
{
	struct pse_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	int ret;

	cmd.cmd_id = GET_TIME;

	mutex_lock(&pse->cmd_mutex);
	ret = mei_pse_send(pse, &cmd, cmd_len);
	mutex_unlock(&pse->cmd_mutex);
	if (!ret) {
		*val = pse->notif.cont.time;

		dev_info(&pse->cldev->dev,
			 "time = (%llu) nanoseconds\n", *val);
	}

	return ret;
}

static ssize_t pse_time_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct mei_pse *pse = file->private_data;
	int ret, pos;
	uint64_t val;
	unsigned long addr = get_zeroed_page(GFP_KERNEL);

	if (!addr)
		return -ENOMEM;

	ret = pse_get_time(pse, &val);
	if (ret)
		goto out;

	pos = snprintf((char *)addr, PAGE_SIZE,
		       "pse time = (%llu) nanoseconds\n", val);

	ret = simple_read_from_buffer(buf, count, ppos, (char *)addr, pos);

out:
	free_page(addr);
	return ret;
}

static int pse_dump_power_data(struct mei_pse *pse)
{
	struct pse_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	int ret;

	cmd.cmd_id = DUMP_POWER_DATA;

	mutex_lock(&pse->cmd_mutex);
	ret = mei_pse_send(pse, &cmd, cmd_len);
	mutex_unlock(&pse->cmd_mutex);

	return ret;
}

static int dump_power_state_data(struct mei_pse *pse,
				 char *addr, int pos, int len)
{
	const char * const names[] = {"EM7D", "SEM"};
	const char *title =
		"| power states | duration(ms) | count | percentage(%) |";
	struct pm_subsys *subsys;
	uint64_t total_duration, duration, num, frac;
	int i, j;

	for (i = 0; i < PM_SUBSYS_MAX; i++) {
		subsys = &((struct pm_data *)pse->pm_data)->subsys[i];

		pos += snprintf((char *)addr + pos,
				len - pos,
				"power state of %s:\n",
				names[i]);

		pos += snprintf((char *)addr + pos,
				len - pos,
				"%s\n",
				title);

		total_duration = 0;
		for (j = 0; j < STATE_MAX; j++)
			total_duration += subsys->status[j].duration;

		for (j = 0; j < STATE_MAX; j++) {
			duration = subsys->status[j].duration * 100;
			num = duration / total_duration;
			frac = (duration % total_duration *
				10000000 / total_duration + 5) / 10;

			pos += snprintf((char *)addr + pos,
					len - pos,
					"|%13.16s |%13llu |%6llu |%7u.%06u |\n",
					subsys->status[j].name,
					subsys->status[j].duration,
					subsys->status[j].count,
					(uint32_t)num,
					(uint32_t)frac);
		}

		pos += snprintf((char *)addr + pos, len - pos, "\n");
	}

	return pos;
}

static int dump_dev_power_data(struct mei_pse *pse,
			       char *addr, int pos, int len)
{
	const char * const names[] = {"EM7D", "SEM"};
	struct pm_subsys *subsys;
	int i, j;
	const char *title = CONSTRUCTED_TITLE;
	const char *format = CONSTRUCTED_FORMAT;

	for (i = 0; i < PM_SUBSYS_MAX; i++) {
		subsys = &((struct pm_data *)pse->pm_data)->subsys[i];

		pos += snprintf((char *)addr + pos,
				len - pos,
				"device list of %s:\n",
				names[i]);

		pos += snprintf((char *)addr + pos,
				len - pos,
				"%s\n",
				title);

		for (j = 0; j < subsys->dev.dev_cnt; j += 4) {
			switch (subsys->dev.dev_cnt - j) {
			case 1:
				pos += snprintf((char *)addr + pos,
						len - pos,
						format,
						subsys->dev.dev[j].name,
						subsys->dev.dev[j].block_cnt,
						"", 0,
						"", 0,
						"", 0);
				break;

			case 2:
				pos += snprintf((char *)addr + pos,
						len - pos,
						format,
						subsys->dev.dev[j].name,
						subsys->dev.dev[j].block_cnt,
						subsys->dev.dev[j+1].name,
						subsys->dev.dev[j+1].block_cnt,
						"", 0,
						"", 0);
				break;

			case 3:
				pos += snprintf((char *)addr + pos,
						len - pos,
						format,
						subsys->dev.dev[j].name,
						subsys->dev.dev[j].block_cnt,
						subsys->dev.dev[j+1].name,
						subsys->dev.dev[j+1].block_cnt,
						subsys->dev.dev[j+2].name,
						subsys->dev.dev[j+2].block_cnt,
						"", 0);
				break;

			default:
				pos += snprintf((char *)addr + pos,
						len - pos,
						format,
						subsys->dev.dev[j].name,
						subsys->dev.dev[j].block_cnt,
						subsys->dev.dev[j+1].name,
						subsys->dev.dev[j+1].block_cnt,
						subsys->dev.dev[j+2].name,
						subsys->dev.dev[j+2].block_cnt,
						subsys->dev.dev[j+3].name,
						subsys->dev.dev[j+3].block_cnt);
				break;
			}
		}

		if (i < PM_SUBSYS_MAX - 1)
			pos += snprintf((char *)addr + pos, len - pos, "\n");
	}

	return pos;
}

static ssize_t pse_power_data_read(struct file *file, char __user *buf,
				   size_t count, loff_t *ppos)
{
	struct mei_pse *pse = file->private_data;
	unsigned long addr = get_zeroed_page(GFP_KERNEL);
	int ret, pos = 0;

	if (!addr)
		return -ENOMEM;

	ret = pse_dump_power_data(pse);
	if (ret)
		goto out;

	pos = dump_power_state_data(pse, (char *)addr, pos, PAGE_SIZE);
	pos = dump_dev_power_data(pse, (char *)addr, pos, PAGE_SIZE);

	ret = simple_read_from_buffer(buf, count, ppos, (char *)addr, pos);

out:
	free_page(addr);
	return ret;
}

static int pse_get_fw_ver(struct mei_pse *pse, struct fw_version *ver)
{
	struct pse_cmd cmd;
	size_t cmd_len = sizeof(cmd.cmd_id);
	int ret;

	cmd.cmd_id = GET_FW_VER;

	mutex_lock(&pse->cmd_mutex);
	ret = mei_pse_send(pse, &cmd, cmd_len);
	if (!ret) {
		memcpy(ver, &pse->notif.cont.ver, sizeof(*ver));

		dev_info(&pse->cldev->dev,
			 "fw version: %u.%u.%u.%u\n",
			 ver->major, ver->minor, ver->hotfix, ver->build);
	}
	mutex_unlock(&pse->cmd_mutex);

	return ret;
}

static ssize_t pse_fw_ver_read(struct file *file, char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct mei_pse *pse = file->private_data;
	int ret, pos;
	struct fw_version ver;
	unsigned long addr = get_zeroed_page(GFP_KERNEL);

	if (!addr)
		return -ENOMEM;

	ret = pse_get_fw_ver(pse, &ver);
	if (ret)
		goto out;

	pos = snprintf((char *)addr, PAGE_SIZE,
		       "fw version: %u.%u.%u.%u\n",
		       ver.major, ver.minor, ver.hotfix, ver.build);

	ret = simple_read_from_buffer(buf, count, ppos, (char *)addr, pos);

out:
	free_page(addr);
	return ret;
}

#define PSE_DFS_ADD_FILE(name)						\
	debugfs_create_file(#name, 0644, pse->dfs_dir, pse,		\
			    &pse_dfs_##name##_fops)

#define PSE_DFS_FILE_OPS(name)						\
static const struct file_operations pse_dfs_##name##_fops = {		\
	.read = pse_##name##_read,					\
	.write = pse_##name##_write,					\
	.open = simple_open,						\
}

#define PSE_DFS_FILE_READ_OPS(name)					\
static const struct file_operations pse_dfs_##name##_fops = {		\
	.read = pse_##name##_read,					\
	.open = simple_open,						\
}

#define PSE_DFS_FILE_WRITE_OPS(name)					\
static const struct file_operations pse_dfs_##name##_fops = {		\
	.write = pse_##name##_write,					\
	.open = simple_open,						\
}

PSE_DFS_FILE_WRITE_OPS(log_onoff);
PSE_DFS_FILE_WRITE_OPS(watermark);
PSE_DFS_FILE_WRITE_OPS(dump_trace);
PSE_DFS_FILE_WRITE_OPS(timeout);
PSE_DFS_FILE_WRITE_OPS(log_level);

PSE_DFS_FILE_OPS(time);

PSE_DFS_FILE_READ_OPS(fw_ver);
PSE_DFS_FILE_READ_OPS(power_data);

/* callback for command response receive */
static void mei_pse_rx(struct mei_cl_device *cldev)
{
	int ret;
	struct pse_notif *notif;
	struct mei_pse *pse = mei_cldev_get_drvdata(cldev);
	struct file *file;
	loff_t *pos;

	ret = mei_cldev_recv(cldev, pse->recv_buf, MAX_RECV_SIZE);
	if (ret < 0) {
		dev_err(&cldev->dev, "failure in recv %d\n", ret);
		return;
	}
	notif = (struct pse_notif *)pse->recv_buf;

	switch (notif->cmd_id) {
	case TRACE_DATA_NOTIF:
		if (notif->source) {
			file = pse->sem_file;
			pos = &pse->sem_pos;
		} else {
			file = pse->em_file;
			pos = &pse->em_pos;
		}

		if (*pos < MAX_LOG_SIZE) {
			ret = kernel_write(file,
					   pse->recv_buf + CONT_OFFSET,
					   ret - CONT_OFFSET,
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

	case LOG_ONOFF:
	case SET_WATERMARK:
	case DUMP_TRACE:
	case SET_TIMEOUT:
	case SET_LOG_LEVEL:
	case SET_TIME:
	case GET_TIME:
	case GET_FW_VER:
		memcpy(&pse->notif, notif, ret);

		if (!completion_done(&pse->response))
			complete(&pse->response);
		break;

	case DUMP_POWER_DATA:
		if (notif->status == 0) {
			memcpy(pse->pm_data + pse->pm_data_pos,
			       pse->recv_buf + NOTIF_HEADER_LEN,
			       ret - NOTIF_HEADER_LEN);
			pse->pm_data_pos += ret - NOTIF_HEADER_LEN;

			if (pse->pm_data_pos >= sizeof(struct pm_data)) {
				pse->pm_data_pos = 0;
				memcpy(&pse->notif, notif, NOTIF_HEADER_LEN);

				if (!completion_done(&pse->response))
					complete(&pse->response);
			}
		} else {
			dev_err(&cldev->dev, "error in recving power data\n");

			pse->pm_data_pos = 0;
			memcpy(&pse->notif, notif, NOTIF_HEADER_LEN);

			if (!completion_done(&pse->response))
				complete(&pse->response);
		}
		break;

	default:
		dev_err(&cldev->dev,
			"recv not supported notification\n");
		break;
	}
}

static int mei_pse_probe(struct mei_cl_device *cldev,
			 const struct mei_cl_device_id *id)
{
	struct mei_pse *pse;
	int ret;
	uint32_t order = get_order(MAX_RECV_SIZE);

	pse = kzalloc(sizeof(struct mei_pse), GFP_KERNEL);
	if (!pse)
		return -ENOMEM;

	pse->recv_buf = (uint8_t *)__get_free_pages(GFP_KERNEL, order);
	if (!pse->recv_buf) {
		kfree(pse);
		return -ENOMEM;
	}

	pse->pm_data = (uint8_t *)__get_free_pages(GFP_KERNEL, order);
	if (!pse->pm_data) {
		free_pages((unsigned long)pse->recv_buf, order);
		kfree(pse);
		return -ENOMEM;
	}
	pse->pm_data_pos = 0;

	pse->cldev = cldev;
	mutex_init(&pse->cmd_mutex);
	init_completion(&pse->response);

	mei_cldev_set_drvdata(cldev, pse);

	ret = mei_cldev_enable(cldev);
	if (ret < 0) {
		dev_err(&cldev->dev,
			"couldn't enable pse client ret=%d\n", ret);
		goto err_out;
	}

	ret = mei_cldev_register_rx_cb(cldev, mei_pse_rx);
	if (ret) {
		dev_err(&cldev->dev,
			"couldn't register rx event ret=%d\n", ret);
		goto err_disable;
	}

	pse->em_file = filp_open(EM_LOG_FILE,
				 O_CREAT | O_RDWR | O_LARGEFILE | O_TRUNC,
				 0600);
	if (IS_ERR(pse->em_file)) {
		dev_err(&cldev->dev,
			"filp_open(%s) failed\n", EM_LOG_FILE);
		ret = PTR_ERR(pse->em_file);
		goto err_disable;
	}
	pse->em_pos = 0;

	pse->sem_file = filp_open(SEM_LOG_FILE,
				  O_CREAT | O_RDWR | O_LARGEFILE | O_TRUNC,
				  0600);
	if (IS_ERR(pse->sem_file)) {
		dev_err(&cldev->dev,
			"filp_open(%s) failed\n", SEM_LOG_FILE);
		ret = PTR_ERR(pse->sem_file);
		goto err_close;
	}
	pse->sem_pos = 0;

	pse->dfs_dir = debugfs_create_dir("vsc_pse", NULL);
	if (pse->dfs_dir) {
		PSE_DFS_ADD_FILE(log_onoff);
		PSE_DFS_ADD_FILE(watermark);
		PSE_DFS_ADD_FILE(dump_trace);
		PSE_DFS_ADD_FILE(timeout);
		PSE_DFS_ADD_FILE(log_level);
		PSE_DFS_ADD_FILE(time);
		PSE_DFS_ADD_FILE(fw_ver);
		PSE_DFS_ADD_FILE(power_data);
	}

	return 0;

err_close:
	filp_close(pse->em_file, NULL);

err_disable:
	mei_cldev_disable(cldev);

err_out:
	free_pages((unsigned long)pse->pm_data, order);

	free_pages((unsigned long)pse->recv_buf, order);

	kfree(pse);

	return ret;
}

static void mei_pse_remove(struct mei_cl_device *cldev)
{
	struct mei_pse *pse = mei_cldev_get_drvdata(cldev);
	uint32_t order = get_order(MAX_RECV_SIZE);

	if (!completion_done(&pse->response))
		complete(&pse->response);

	mei_cldev_disable(cldev);

	debugfs_remove_recursive(pse->dfs_dir);

	filp_close(pse->em_file, NULL);
	filp_close(pse->sem_file, NULL);

	/* wait until no buffer acccess */
	mutex_lock(&pse->cmd_mutex);
	mutex_unlock(&pse->cmd_mutex);

	free_pages((unsigned long)pse->pm_data, order);

	free_pages((unsigned long)pse->recv_buf, order);

	kfree(pse);
}

#define MEI_UUID_PSE UUID_LE(0xD035E00C, 0x6DAE, 0x4B6D, \
			     0xB4, 0x7A, 0xF8, 0x8E, 0x30, 0x2A, 0x40, 0x4E)

static const struct mei_cl_device_id mei_pse_tbl[] = {
	{ MEI_PSE_DRIVER_NAME, MEI_UUID_PSE, MEI_CL_VERSION_ANY },

	/* required last entry */
	{ }
};
MODULE_DEVICE_TABLE(mei, mei_pse_tbl);

static struct mei_cl_driver mei_pse_driver = {
	.id_table = mei_pse_tbl,
	.name = MEI_PSE_DRIVER_NAME,

	.probe = mei_pse_probe,
	.remove = mei_pse_remove,
};

static int __init mei_pse_init(void)
{
	int ret;

	ret = mei_cldev_driver_register(&mei_pse_driver);
	if (ret) {
		pr_err("mei pse driver registration failed: %d\n", ret);
		return ret;
	}

	return 0;
}

static void __exit mei_pse_exit(void)
{
	mei_cldev_driver_unregister(&mei_pse_driver);
}

module_init(mei_pse_init);
module_exit(mei_pse_exit);

MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Device driver for Intel VSC PSE client");
