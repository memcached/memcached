// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2020 Intel Corporation

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#include <linux/pm_runtime.h>

#include "ipu-isys.h"
#include "ipu-platform-regs.h"

#define IPU_ISYS_GPC_NUM		16

#ifndef CONFIG_PM
#define pm_runtime_get_sync(d)		0
#define pm_runtime_put(d)		0
#endif

struct ipu_isys_gpc {
	bool enable;
	unsigned int route;
	unsigned int source;
	unsigned int sense;
	unsigned int gpcindex;
	void *prit;
};

struct ipu_isys_gpcs {
	bool gpc_enable;
	struct ipu_isys_gpc gpc[IPU_ISYS_GPC_NUM];
	void *prit;
};

static int ipu6_isys_gpc_global_enable_get(void *data, u64 *val)
{
	struct ipu_isys_gpcs *isys_gpcs = data;
	struct ipu_isys *isys = isys_gpcs->prit;

	mutex_lock(&isys->mutex);

	*val = isys_gpcs->gpc_enable;

	mutex_unlock(&isys->mutex);
	return 0;
}

static int ipu6_isys_gpc_global_enable_set(void *data, u64 val)
{
	struct ipu_isys_gpcs *isys_gpcs = data;
	struct ipu_isys *isys = isys_gpcs->prit;
	void __iomem *base;
	int i, ret;

	if (val != 0 && val != 1)
		return -EINVAL;

	if (!isys || !isys->pdata || !isys->pdata->base)
		return -EINVAL;

	mutex_lock(&isys->mutex);

	base = isys->pdata->base + IPU_ISYS_GPC_BASE;

	ret = pm_runtime_get_sync(&isys->adev->dev);
	if (ret < 0) {
		pm_runtime_put(&isys->adev->dev);
		mutex_unlock(&isys->mutex);
		return ret;
	}

	if (!val) {
		writel(0x0, base + IPU_ISYS_GPREG_TRACE_TIMER_RST);
		writel(0x0, base + IPU_ISF_CDC_MMU_GPC_OVERALL_ENABLE);
		writel(0xffff, base + IPU_ISF_CDC_MMU_GPC_SOFT_RESET);
		isys_gpcs->gpc_enable = false;
		for (i = 0; i < IPU_ISYS_GPC_NUM; i++) {
			isys_gpcs->gpc[i].enable = 0;
			isys_gpcs->gpc[i].sense = 0;
			isys_gpcs->gpc[i].route = 0;
			isys_gpcs->gpc[i].source = 0;
		}
		pm_runtime_mark_last_busy(&isys->adev->dev);
		pm_runtime_put_autosuspend(&isys->adev->dev);
	} else {
		/*
		 * Set gpc reg and start all gpc here.
		 * RST free running local timer.
		 */
		writel(0x0, base + IPU_ISYS_GPREG_TRACE_TIMER_RST);
		writel(0x1, base + IPU_ISYS_GPREG_TRACE_TIMER_RST);

		for (i = 0; i < IPU_ISYS_GPC_NUM; i++) {
			/* Enable */
			writel(isys_gpcs->gpc[i].enable,
			       base + IPU_ISF_CDC_MMU_GPC_ENABLE0 + 4 * i);
			/* Setting (route/source/sense) */
			writel((isys_gpcs->gpc[i].sense
					<< IPU_GPC_SENSE_OFFSET)
				+ (isys_gpcs->gpc[i].route
					<< IPU_GPC_ROUTE_OFFSET)
				+ (isys_gpcs->gpc[i].source
					<< IPU_GPC_SOURCE_OFFSET),
				base + IPU_ISF_CDC_MMU_GPC_CNT_SEL0 + 4 * i);
		}

		/* Soft reset and Overall Enable. */
		writel(0x0, base + IPU_ISF_CDC_MMU_GPC_OVERALL_ENABLE);
		writel(0xffff, base + IPU_ISF_CDC_MMU_GPC_SOFT_RESET);
		writel(0x1, base + IPU_ISF_CDC_MMU_GPC_OVERALL_ENABLE);

		isys_gpcs->gpc_enable = true;
	}

	mutex_unlock(&isys->mutex);
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(isys_gpc_globe_enable_fops,
			ipu6_isys_gpc_global_enable_get,
			ipu6_isys_gpc_global_enable_set, "%llu\n");

static int ipu6_isys_gpc_count_get(void *data, u64 *val)
{
	struct ipu_isys_gpc *isys_gpc = data;
	struct ipu_isys *isys = isys_gpc->prit;
	void __iomem *base;

	if (!isys || !isys->pdata || !isys->pdata->base)
		return -EINVAL;

	spin_lock(&isys->power_lock);
	if (isys->power) {
		base = isys->pdata->base + IPU_ISYS_GPC_BASE;
		*val = readl(base + IPU_ISF_CDC_MMU_GPC_VALUE0
				 + 4 * isys_gpc->gpcindex);
	} else {
		*val = 0;
	}
	spin_unlock(&isys->power_lock);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(isys_gpc_count_fops, ipu6_isys_gpc_count_get,
			NULL, "%llu\n");

int ipu_isys_gpc_init_debugfs(struct ipu_isys *isys)
{
	struct dentry *gpcdir;
	struct dentry *dir;
	struct dentry *file;
	int i;
	char gpcname[10];
	struct ipu_isys_gpcs *isys_gpcs;

	isys_gpcs = devm_kzalloc(&isys->adev->dev, sizeof(*isys_gpcs),
				 GFP_KERNEL);
	if (!isys_gpcs)
		return -ENOMEM;

	gpcdir = debugfs_create_dir("gpcs", isys->debugfsdir);
	if (IS_ERR(gpcdir))
		return -ENOMEM;

	isys_gpcs->prit = isys;
	file = debugfs_create_file("enable", 0600, gpcdir, isys_gpcs,
				   &isys_gpc_globe_enable_fops);
	if (IS_ERR(file))
		goto err;

	for (i = 0; i < IPU_ISYS_GPC_NUM; i++) {
		sprintf(gpcname, "gpc%d", i);
		dir = debugfs_create_dir(gpcname, gpcdir);
		if (IS_ERR(dir))
			goto err;

		debugfs_create_bool("enable", 0600, dir,
				    &isys_gpcs->gpc[i].enable);

		debugfs_create_u32("source", 0600, dir,
				   &isys_gpcs->gpc[i].source);

		debugfs_create_u32("route", 0600, dir,
				   &isys_gpcs->gpc[i].route);

		debugfs_create_u32("sense", 0600, dir,
				   &isys_gpcs->gpc[i].sense);

		isys_gpcs->gpc[i].gpcindex = i;
		isys_gpcs->gpc[i].prit = isys;
		file = debugfs_create_file("count", 0400, dir,
					   &isys_gpcs->gpc[i],
					   &isys_gpc_count_fops);
		if (IS_ERR(file))
			goto err;
	}

	return 0;

err:
	debugfs_remove_recursive(gpcdir);
	return -ENOMEM;
}
#endif
