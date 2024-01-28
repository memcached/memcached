// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2014 - 2021 Intel Corporation

#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/sizes.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "ipu.h"
#include "ipu-platform-regs.h"
#include "ipu-trace.h"

struct trace_register_range {
	u32 start;
	u32 end;
};

#define MEMORY_RING_BUFFER_SIZE		(SZ_1M * 32)
#define TRACE_MESSAGE_SIZE		16
/*
 * It looks that the trace unit sometimes writes outside the given buffer.
 * To avoid memory corruption one extra page is reserved at the end
 * of the buffer. Read also the extra area since it may contain valid data.
 */
#define MEMORY_RING_BUFFER_GUARD	PAGE_SIZE
#define MEMORY_RING_BUFFER_OVERREAD	MEMORY_RING_BUFFER_GUARD
#define MAX_TRACE_REGISTERS		200
#define TRACE_CONF_DUMP_BUFFER_SIZE	(MAX_TRACE_REGISTERS * 2 * 32)
#define TRACE_CONF_DATA_MAX_LEN		(1024 * 4)
#define WPT_TRACE_CONF_DATA_MAX_LEN	(1024 * 64)

struct config_value {
	u32 reg;
	u32 value;
};

struct ipu_trace_buffer {
	dma_addr_t dma_handle;
	void *memory_buffer;
};

struct ipu_subsystem_wptrace_config {
	bool open;
	char *conf_dump_buffer;
	int size_conf_dump;
	unsigned int fill_level;
	struct config_value config[MAX_TRACE_REGISTERS];
};

struct ipu_subsystem_trace_config {
	u32 offset;
	void __iomem *base;
	struct ipu_trace_buffer memory;	/* ring buffer */
	struct device *dev;
	struct ipu_trace_block *blocks;
	unsigned int fill_level;	/* Nbr of regs in config table below */
	bool running;
	/* Cached register values  */
	struct config_value config[MAX_TRACE_REGISTERS];
	/* watchpoint trace info */
	struct ipu_subsystem_wptrace_config wpt;
};

struct ipu_trace {
	struct mutex lock; /* Protect ipu trace operations */
	bool open;
	char *conf_dump_buffer;
	int size_conf_dump;

	struct ipu_subsystem_trace_config isys;
	struct ipu_subsystem_trace_config psys;
};

static void __ipu_trace_restore(struct device *dev)
{
	struct ipu_bus_device *adev = to_ipu_bus_device(dev);
	struct ipu_device *isp = adev->isp;
	struct ipu_trace *trace = isp->trace;
	struct config_value *config;
	struct ipu_subsystem_trace_config *sys = adev->trace_cfg;
	struct ipu_trace_block *blocks;
	u32 mapped_trace_buffer;
	void __iomem *addr = NULL;
	int i;

	if (trace->open) {
		dev_info(dev, "Trace control file open. Skipping update\n");
		return;
	}

	if (!sys)
		return;

	/* leave if no trace configuration for this subsystem */
	if (sys->fill_level == 0)
		return;

	/* Find trace unit base address */
	blocks = sys->blocks;
	while (blocks->type != IPU_TRACE_BLOCK_END) {
		if (blocks->type == IPU_TRACE_BLOCK_TUN) {
			addr = sys->base + blocks->offset;
			break;
		}
		blocks++;
	}
	if (!addr)
		return;

	if (!sys->memory.memory_buffer) {
		sys->memory.memory_buffer =
		    dma_alloc_coherent(dev, MEMORY_RING_BUFFER_SIZE +
				       MEMORY_RING_BUFFER_GUARD,
				       &sys->memory.dma_handle,
				       GFP_KERNEL);
	}

	if (!sys->memory.memory_buffer) {
		dev_err(dev, "No memory for tracing. Trace unit disabled\n");
		return;
	}

	config = sys->config;
	mapped_trace_buffer = sys->memory.dma_handle;

	/* ring buffer base */
	writel(mapped_trace_buffer, addr + TRACE_REG_TUN_DRAM_BASE_ADDR);

	/* ring buffer end */
	writel(mapped_trace_buffer + MEMORY_RING_BUFFER_SIZE -
		   TRACE_MESSAGE_SIZE, addr + TRACE_REG_TUN_DRAM_END_ADDR);

	/* Infobits for ddr trace */
	writel(IPU_INFO_REQUEST_DESTINATION_PRIMARY,
	       addr + TRACE_REG_TUN_DDR_INFO_VAL);

	/* Find trace timer reset address */
	addr = NULL;
	blocks = sys->blocks;
	while (blocks->type != IPU_TRACE_BLOCK_END) {
		if (blocks->type == IPU_TRACE_TIMER_RST) {
			addr = sys->base + blocks->offset;
			break;
		}
		blocks++;
	}
	if (!addr) {
		dev_err(dev, "No trace reset addr\n");
		return;
	}

	/* Remove reset from trace timers */
	writel(TRACE_REG_GPREG_TRACE_TIMER_RST_OFF, addr);

	/* Register config received from userspace */
	for (i = 0; i < sys->fill_level; i++) {
		dev_dbg(dev,
			"Trace restore: reg 0x%08x, value 0x%08x\n",
			config[i].reg, config[i].value);
		writel(config[i].value, isp->base + config[i].reg);
	}

	/* Register wpt config received from userspace, and only psys has wpt */
	config = sys->wpt.config;
	for (i = 0; i < sys->wpt.fill_level; i++) {
		dev_dbg(dev, "Trace restore: reg 0x%08x, value 0x%08x\n",
			config[i].reg, config[i].value);
		writel(config[i].value, isp->base + config[i].reg);
	}
	sys->running = true;
}

void ipu_trace_restore(struct device *dev)
{
	struct ipu_trace *trace = to_ipu_bus_device(dev)->isp->trace;

	if (!trace)
		return;

	mutex_lock(&trace->lock);
	__ipu_trace_restore(dev);
	mutex_unlock(&trace->lock);
}
EXPORT_SYMBOL_GPL(ipu_trace_restore);

static void __ipu_trace_stop(struct device *dev)
{
	struct ipu_subsystem_trace_config *sys =
	    to_ipu_bus_device(dev)->trace_cfg;
	struct ipu_trace_block *blocks;

	if (!sys)
		return;

	if (!sys->running)
		return;
	sys->running = false;

	/* Turn off all the gpc blocks */
	blocks = sys->blocks;
	while (blocks->type != IPU_TRACE_BLOCK_END) {
		if (blocks->type == IPU_TRACE_BLOCK_GPC) {
			writel(0, sys->base + blocks->offset +
				   TRACE_REG_GPC_OVERALL_ENABLE);
		}
		blocks++;
	}

	/* Turn off all the trace monitors */
	blocks = sys->blocks;
	while (blocks->type != IPU_TRACE_BLOCK_END) {
		if (blocks->type == IPU_TRACE_BLOCK_TM) {
			writel(0, sys->base + blocks->offset +
				   TRACE_REG_TM_TRACE_ENABLE_NPK);

			writel(0, sys->base + blocks->offset +
				   TRACE_REG_TM_TRACE_ENABLE_DDR);
		}
		blocks++;
	}

	/* Turn off trace units */
	blocks = sys->blocks;
	while (blocks->type != IPU_TRACE_BLOCK_END) {
		if (blocks->type == IPU_TRACE_BLOCK_TUN) {
			writel(0, sys->base + blocks->offset +
				   TRACE_REG_TUN_DDR_ENABLE);
			writel(0, sys->base + blocks->offset +
				   TRACE_REG_TUN_NPK_ENABLE);
		}
		blocks++;
	}
}

void ipu_trace_stop(struct device *dev)
{
	struct ipu_trace *trace = to_ipu_bus_device(dev)->isp->trace;

	if (!trace)
		return;

	mutex_lock(&trace->lock);
	__ipu_trace_stop(dev);
	mutex_unlock(&trace->lock);
}
EXPORT_SYMBOL_GPL(ipu_trace_stop);

static int update_register_cache(struct ipu_device *isp, u32 reg, u32 value)
{
	struct ipu_trace *dctrl = isp->trace;
	struct ipu_subsystem_trace_config *sys;
	int rval = -EINVAL;

	if (dctrl->isys.offset == dctrl->psys.offset) {
		/* For the IPU with uniform address space */
		if (reg >= IPU_ISYS_OFFSET &&
		    reg < IPU_ISYS_OFFSET + TRACE_REG_MAX_ISYS_OFFSET)
			sys = &dctrl->isys;
		else if (reg >= IPU_PSYS_OFFSET &&
			 reg < IPU_PSYS_OFFSET + TRACE_REG_MAX_PSYS_OFFSET)
			sys = &dctrl->psys;
		else
			goto error;
	} else {
		if (dctrl->isys.offset &&
		    reg >= dctrl->isys.offset &&
		    reg < dctrl->isys.offset + TRACE_REG_MAX_ISYS_OFFSET)
			sys = &dctrl->isys;
		else if (dctrl->psys.offset &&
			 reg >= dctrl->psys.offset &&
			 reg < dctrl->psys.offset + TRACE_REG_MAX_PSYS_OFFSET)
			sys = &dctrl->psys;
		else
			goto error;
	}

	if (sys->fill_level < MAX_TRACE_REGISTERS) {
		dev_dbg(sys->dev,
			"Trace reg addr 0x%08x value 0x%08x\n", reg, value);
		sys->config[sys->fill_level].reg = reg;
		sys->config[sys->fill_level].value = value;
		sys->fill_level++;
	} else {
		rval = -ENOMEM;
		goto error;
	}
	return 0;
error:
	dev_info(&isp->pdev->dev,
		 "Trace register address 0x%08x ignored as invalid register\n",
		 reg);
	return rval;
}

static void traceconf_dump(struct ipu_device *isp)
{
	struct ipu_subsystem_trace_config *sys[2] = {
		&isp->trace->isys,
		&isp->trace->psys
	};
	int i, j, rem_size;
	char *out;

	isp->trace->size_conf_dump = 0;
	out = isp->trace->conf_dump_buffer;
	rem_size = TRACE_CONF_DUMP_BUFFER_SIZE;

	for (j = 0; j < ARRAY_SIZE(sys); j++) {
		for (i = 0; i < sys[j]->fill_level && rem_size > 0; i++) {
			int bytes_print;
			int n = snprintf(out, rem_size, "0x%08x = 0x%08x\n",
					 sys[j]->config[i].reg,
					 sys[j]->config[i].value);

			bytes_print = min(n, rem_size - 1);
			rem_size -= bytes_print;
			out += bytes_print;
		}
	}
	isp->trace->size_conf_dump = out - isp->trace->conf_dump_buffer;
}

static void clear_trace_buffer(struct ipu_subsystem_trace_config *sys)
{
	if (!sys->memory.memory_buffer)
		return;

	memset(sys->memory.memory_buffer, 0, MEMORY_RING_BUFFER_SIZE +
	       MEMORY_RING_BUFFER_OVERREAD);

	dma_sync_single_for_device(sys->dev,
				   sys->memory.dma_handle,
				   MEMORY_RING_BUFFER_SIZE +
				   MEMORY_RING_BUFFER_GUARD, DMA_FROM_DEVICE);
}

static int traceconf_open(struct inode *inode, struct file *file)
{
	int ret;
	struct ipu_device *isp;

	if (!inode->i_private)
		return -EACCES;

	isp = inode->i_private;

	ret = mutex_trylock(&isp->trace->lock);
	if (!ret)
		return -EBUSY;

	if (isp->trace->open) {
		mutex_unlock(&isp->trace->lock);
		return -EBUSY;
	}

	file->private_data = isp;
	isp->trace->open = 1;
	if (file->f_mode & FMODE_WRITE) {
		/* TBD: Allocate temp buffer for processing.
		 * Push validated buffer to active config
		 */

		/* Forget old config if opened for write */
		isp->trace->isys.fill_level = 0;
		isp->trace->psys.fill_level = 0;
		isp->trace->psys.wpt.fill_level = 0;
	}

	if (file->f_mode & FMODE_READ) {
		isp->trace->conf_dump_buffer =
		    vzalloc(TRACE_CONF_DUMP_BUFFER_SIZE);
		if (!isp->trace->conf_dump_buffer) {
			isp->trace->open = 0;
			mutex_unlock(&isp->trace->lock);
			return -ENOMEM;
		}
		traceconf_dump(isp);
	}
	mutex_unlock(&isp->trace->lock);
	return 0;
}

static ssize_t traceconf_read(struct file *file, char __user *buf,
			      size_t len, loff_t *ppos)
{
	struct ipu_device *isp = file->private_data;

	return simple_read_from_buffer(buf, len, ppos,
				       isp->trace->conf_dump_buffer,
				       isp->trace->size_conf_dump);
}

static ssize_t traceconf_write(struct file *file, const char __user *buf,
			       size_t len, loff_t *ppos)
{
	int i;
	struct ipu_device *isp = file->private_data;
	ssize_t bytes = 0;
	char *ipu_trace_buffer = NULL;
	size_t buffer_size = 0;
	u32 ipu_trace_number = 0;
	struct config_value *cfg_buffer = NULL;

	if ((*ppos < 0) || (len > TRACE_CONF_DATA_MAX_LEN) ||
	    (len < sizeof(ipu_trace_number))) {
		dev_info(&isp->pdev->dev,
			"length is error, len:%ld, loff:%lld\n",
			len, *ppos);
		return -EINVAL;
	}

	ipu_trace_buffer = vzalloc(len);
	if (!ipu_trace_buffer)
		return -ENOMEM;

	bytes = copy_from_user(ipu_trace_buffer, buf, len);
	if (bytes != 0) {
		vfree(ipu_trace_buffer);
		return -EFAULT;
	}

	memcpy(&ipu_trace_number, ipu_trace_buffer, sizeof(u32));
	buffer_size = ipu_trace_number * sizeof(struct config_value);
	if ((buffer_size + sizeof(ipu_trace_number)) != len) {
		dev_info(&isp->pdev->dev,
			"File size is not right, len:%ld, buffer_size:%zu\n",
			len, buffer_size);
		vfree(ipu_trace_buffer);
		return -EFAULT;
	}

	mutex_lock(&isp->trace->lock);
	cfg_buffer = (struct config_value *)(ipu_trace_buffer + sizeof(u32));
	for (i = 0; i < ipu_trace_number; i++) {
		update_register_cache(isp, cfg_buffer[i].reg,
			cfg_buffer[i].value);
	}
	mutex_unlock(&isp->trace->lock);
	vfree(ipu_trace_buffer);

	return len;
}

static int traceconf_release(struct inode *inode, struct file *file)
{
	struct ipu_device *isp = file->private_data;
	struct device *psys_dev = isp->psys ? &isp->psys->dev : NULL;
	struct device *isys_dev = isp->isys ? &isp->isys->dev : NULL;
	int pm_rval = -EINVAL;

	/*
	 * Turn devices on outside trace->lock mutex. PM transition may
	 * cause call to function which tries to take the same lock.
	 * Also do this before trace->open is set back to 0 to avoid
	 * double restore (one here and one in pm transition). We can't
	 * rely purely on the restore done by pm call backs since trace
	 * configuration can occur in any phase compared to other activity.
	 */

	if (file->f_mode & FMODE_WRITE) {
		if (isys_dev)
			pm_rval = pm_runtime_get_sync(isys_dev);

		if (pm_rval >= 0) {
			/* ISYS ok or missing */
			if (psys_dev)
				pm_rval = pm_runtime_get_sync(psys_dev);

			if (pm_rval < 0) {
				pm_runtime_put_noidle(psys_dev);
				if (isys_dev)
					pm_runtime_put(isys_dev);
			}
		} else {
			pm_runtime_put_noidle(&isp->isys->dev);
		}
	}

	mutex_lock(&isp->trace->lock);
	isp->trace->open = 0;
	vfree(isp->trace->conf_dump_buffer);
	isp->trace->conf_dump_buffer = NULL;

	if (pm_rval >= 0) {
		/* Update new cfg to HW */
		if (isys_dev) {
			__ipu_trace_stop(isys_dev);
			clear_trace_buffer(isp->isys->trace_cfg);
			__ipu_trace_restore(isys_dev);
		}

		if (psys_dev) {
			__ipu_trace_stop(psys_dev);
			clear_trace_buffer(isp->psys->trace_cfg);
			__ipu_trace_restore(psys_dev);
		}
	}

	mutex_unlock(&isp->trace->lock);

	if (pm_rval >= 0) {
		/* Again - this must be done with trace->lock not taken */
		if (psys_dev)
			pm_runtime_put(psys_dev);
		if (isys_dev)
			pm_runtime_put(isys_dev);
	}
	return 0;
}

static const struct file_operations ipu_traceconf_fops = {
	.owner = THIS_MODULE,
	.open = traceconf_open,
	.release = traceconf_release,
	.read = traceconf_read,
	.write = traceconf_write,
	.llseek = no_llseek,
};

static void wptraceconf_dump(struct ipu_device *isp)
{
	struct ipu_subsystem_wptrace_config *sys = &isp->trace->psys.wpt;
	int i, rem_size;
	char *out;

	sys->size_conf_dump = 0;
	out = sys->conf_dump_buffer;
	rem_size = TRACE_CONF_DUMP_BUFFER_SIZE;

	for (i = 0; i < sys->fill_level && rem_size > 0; i++) {
		int bytes_print;
		int n = snprintf(out, rem_size, "0x%08x = 0x%08x\n",
				 sys->config[i].reg,
				 sys->config[i].value);

		bytes_print = min(n, rem_size - 1);
		rem_size -= bytes_print;
		out += bytes_print;
	}
	sys->size_conf_dump = out - sys->conf_dump_buffer;
}

static int wptraceconf_open(struct inode *inode, struct file *file)
{
	int ret;
	struct ipu_device *isp;

	if (!inode->i_private)
		return -EACCES;

	isp = inode->i_private;
	ret = mutex_trylock(&isp->trace->lock);
	if (!ret)
		return -EBUSY;

	if (isp->trace->psys.wpt.open) {
		mutex_unlock(&isp->trace->lock);
		return -EBUSY;
	}

	file->private_data = isp;
	if (file->f_mode & FMODE_WRITE) {
		/* TBD: Allocate temp buffer for processing.
		 * Push validated buffer to active config
		 */
		/* Forget old config if opened for write */
		isp->trace->psys.wpt.fill_level = 0;
	}

	if (file->f_mode & FMODE_READ) {
		isp->trace->psys.wpt.conf_dump_buffer =
		    vzalloc(TRACE_CONF_DUMP_BUFFER_SIZE);
		if (!isp->trace->psys.wpt.conf_dump_buffer) {
			mutex_unlock(&isp->trace->lock);
			return -ENOMEM;
		}
		wptraceconf_dump(isp);
	}
	mutex_unlock(&isp->trace->lock);
	return 0;
}

static ssize_t wptraceconf_read(struct file *file, char __user *buf,
			      size_t len, loff_t *ppos)
{
	struct ipu_device *isp = file->private_data;

	return simple_read_from_buffer(buf, len, ppos,
				       isp->trace->psys.wpt.conf_dump_buffer,
				       isp->trace->psys.wpt.size_conf_dump);
}

static ssize_t wptraceconf_write(struct file *file, const char __user *buf,
			       size_t len, loff_t *ppos)
{
	int i;
	struct ipu_device *isp = file->private_data;
	ssize_t bytes = 0;
	char *wpt_info_buffer = NULL;
	size_t buffer_size = 0;
	u32 wp_node_number = 0;
	struct config_value *wpt_buffer = NULL;
	struct ipu_subsystem_wptrace_config *wpt = &isp->trace->psys.wpt;

	if ((*ppos < 0) || (len > WPT_TRACE_CONF_DATA_MAX_LEN) ||
	    (len < sizeof(wp_node_number))) {
		dev_info(&isp->pdev->dev,
			"length is error, len:%ld, loff:%lld\n",
			len, *ppos);
		return -EINVAL;
	}

	wpt_info_buffer = vzalloc(len);
	if (!wpt_info_buffer)
		return -ENOMEM;

	bytes = copy_from_user(wpt_info_buffer, buf, len);
	if (bytes != 0) {
		vfree(wpt_info_buffer);
		return -EFAULT;
	}

	memcpy(&wp_node_number, wpt_info_buffer, sizeof(u32));
	buffer_size = wp_node_number * sizeof(struct config_value);
	if ((buffer_size + sizeof(wp_node_number)) != len) {
		dev_info(&isp->pdev->dev,
			"File size is not right, len:%ld, buffer_size:%zu\n",
			len, buffer_size);
		vfree(wpt_info_buffer);
		return -EFAULT;
	}

	mutex_lock(&isp->trace->lock);
	wpt_buffer = (struct config_value *)(wpt_info_buffer + sizeof(u32));
	for (i = 0; i < wp_node_number; i++) {
		if (wpt->fill_level < MAX_TRACE_REGISTERS) {
			wpt->config[wpt->fill_level].reg = wpt_buffer[i].reg;
			wpt->config[wpt->fill_level].value =
				wpt_buffer[i].value;
			wpt->fill_level++;
		} else {
			dev_info(&isp->pdev->dev,
				 "Address 0x%08x ignored as invalid register\n",
				 wpt_buffer[i].reg);
			break;
		}
	}
	mutex_unlock(&isp->trace->lock);
	vfree(wpt_info_buffer);

	return len;
}

static int wptraceconf_release(struct inode *inode, struct file *file)
{
	struct ipu_device *isp = file->private_data;

	mutex_lock(&isp->trace->lock);
	isp->trace->open = 0;
	vfree(isp->trace->psys.wpt.conf_dump_buffer);
	isp->trace->psys.wpt.conf_dump_buffer = NULL;
	mutex_unlock(&isp->trace->lock);

	return 0;
}

static const struct file_operations ipu_wptraceconf_fops = {
	.owner = THIS_MODULE,
	.open = wptraceconf_open,
	.release = wptraceconf_release,
	.read = wptraceconf_read,
	.write = wptraceconf_write,
	.llseek = no_llseek,
};

static int gettrace_open(struct inode *inode, struct file *file)
{
	struct ipu_subsystem_trace_config *sys = inode->i_private;

	if (!sys)
		return -EACCES;

	if (!sys->memory.memory_buffer)
		return -EACCES;

	dma_sync_single_for_cpu(sys->dev,
				sys->memory.dma_handle,
				MEMORY_RING_BUFFER_SIZE +
				MEMORY_RING_BUFFER_GUARD, DMA_FROM_DEVICE);

	file->private_data = sys;
	return 0;
};

static ssize_t gettrace_read(struct file *file, char __user *buf,
			     size_t len, loff_t *ppos)
{
	struct ipu_subsystem_trace_config *sys = file->private_data;

	return simple_read_from_buffer(buf, len, ppos,
				       sys->memory.memory_buffer,
				       MEMORY_RING_BUFFER_SIZE +
				       MEMORY_RING_BUFFER_OVERREAD);
}

static ssize_t gettrace_write(struct file *file, const char __user *buf,
			      size_t len, loff_t *ppos)
{
	struct ipu_subsystem_trace_config *sys = file->private_data;
	static const char str[] = "clear";
	char buffer[sizeof(str)] = { 0 };
	ssize_t ret;

	ret = simple_write_to_buffer(buffer, sizeof(buffer), ppos, buf, len);
	if (ret < 0)
		return ret;

	if (ret < sizeof(str) - 1)
		return -EINVAL;

	if (!strncmp(str, buffer, sizeof(str) - 1)) {
		clear_trace_buffer(sys);
		return len;
	}

	return -EINVAL;
}

static int gettrace_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations ipu_gettrace_fops = {
	.owner = THIS_MODULE,
	.open = gettrace_open,
	.release = gettrace_release,
	.read = gettrace_read,
	.write = gettrace_write,
	.llseek = no_llseek,
};

int ipu_trace_init(struct ipu_device *isp, void __iomem *base,
		   struct device *dev, struct ipu_trace_block *blocks)
{
	struct ipu_bus_device *adev = to_ipu_bus_device(dev);
	struct ipu_trace *trace = isp->trace;
	struct ipu_subsystem_trace_config *sys;
	int ret = 0;

	if (!isp->trace)
		return 0;

	mutex_lock(&isp->trace->lock);

	if (dev == &isp->isys->dev) {
		sys = &trace->isys;
	} else if (dev == &isp->psys->dev) {
		sys = &trace->psys;
	} else {
		ret = -EINVAL;
		goto leave;
	}

	adev->trace_cfg = sys;
	sys->dev = dev;
	sys->offset = base - isp->base;	/* sub system offset */
	sys->base = base;
	sys->blocks = blocks;

leave:
	mutex_unlock(&isp->trace->lock);

	return ret;
}
EXPORT_SYMBOL_GPL(ipu_trace_init);

void ipu_trace_uninit(struct device *dev)
{
	struct ipu_bus_device *adev = to_ipu_bus_device(dev);
	struct ipu_device *isp = adev->isp;
	struct ipu_trace *trace = isp->trace;
	struct ipu_subsystem_trace_config *sys = adev->trace_cfg;

	if (!trace || !sys)
		return;

	mutex_lock(&trace->lock);

	if (sys->memory.memory_buffer)
		dma_free_coherent(sys->dev,
				  MEMORY_RING_BUFFER_SIZE +
				  MEMORY_RING_BUFFER_GUARD,
				  sys->memory.memory_buffer,
				  sys->memory.dma_handle);

	sys->dev = NULL;
	sys->memory.memory_buffer = NULL;

	mutex_unlock(&trace->lock);
}
EXPORT_SYMBOL_GPL(ipu_trace_uninit);

int ipu_trace_debugfs_add(struct ipu_device *isp, struct dentry *dir)
{
	struct dentry *files[4];
	int i = 0;

	files[i] = debugfs_create_file("traceconf", 0644,
				       dir, isp, &ipu_traceconf_fops);
	if (!files[i])
		return -ENOMEM;
	i++;

	files[i] = debugfs_create_file("wptraceconf", 0644,
				       dir, isp, &ipu_wptraceconf_fops);
	if (!files[i])
		goto error;
	i++;

	files[i] = debugfs_create_file("getisystrace", 0444,
				       dir,
				       &isp->trace->isys, &ipu_gettrace_fops);

	if (!files[i])
		goto error;
	i++;

	files[i] = debugfs_create_file("getpsystrace", 0444,
				       dir,
				       &isp->trace->psys, &ipu_gettrace_fops);
	if (!files[i])
		goto error;

	return 0;

error:
	for (; i > 0; i--)
		debugfs_remove(files[i - 1]);
	return -ENOMEM;
}

int ipu_trace_add(struct ipu_device *isp)
{
	isp->trace = devm_kzalloc(&isp->pdev->dev,
				  sizeof(struct ipu_trace), GFP_KERNEL);
	if (!isp->trace)
		return -ENOMEM;

	mutex_init(&isp->trace->lock);

	return 0;
}

void ipu_trace_release(struct ipu_device *isp)
{
	if (!isp->trace)
		return;
	mutex_destroy(&isp->trace->lock);
}

MODULE_AUTHOR("Samu Onkalo <samu.onkalo@intel.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Intel ipu trace support");
