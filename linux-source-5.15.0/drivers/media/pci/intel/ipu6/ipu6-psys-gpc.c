// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2020 Intel Corporation

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#include <linux/pm_runtime.h>

#include "ipu-psys.h"
#include "ipu-platform-regs.h"

/*
 * GPC (Gerneral Performance Counters)
 */
#define IPU_PSYS_GPC_NUM 16

#ifndef CONFIG_PM
#define pm_runtime_get_sync(d)			0
#define pm_runtime_put(d)			0
#endif

struct ipu_psys_gpc {
	bool enable;
	unsigned int route;
	unsigned int source;
	unsigned int sense;
	unsigned int gpcindex;
	void *prit;
};

struct ipu_psys_gpcs {
	bool gpc_enable;
	struct ipu_psys_gpc gpc[IPU_PSYS_GPC_NUM];
	void *prit;
};

static int ipu6_psys_gpc_global_enable_get(void *data, u64 *val)
{
	struct ipu_psys_gpcs *psys_gpcs = data;
	struct ipu_psys *psys = psys_gpcs->prit;

	mutex_lock(&psys->mutex);

	*val = psys_gpcs->gpc_enable;

	mutex_unlock(&psys->mutex);
	return 0;
}

static int ipu6_psys_gpc_global_enable_set(void *data, u64 val)
{
	struct ipu_psys_gpcs *psys_gpcs = data;
	struct ipu_psys *psys = psys_gpcs->prit;
	void __iomem *base;
	int idx, res;

	if (val != 0 && val != 1)
		return -EINVAL;

	if (!psys || !psys->pdata || !psys->pdata->base)
		return -EINVAL;

	mutex_lock(&psys->mutex);

	base = psys->pdata->base + IPU_GPC_BASE;

	res = pm_runtime_get_sync(&psys->adev->dev);
	if (res < 0) {
		pm_runtime_put(&psys->adev->dev);
		mutex_unlock(&psys->mutex);
		return res;
	}

	if (val == 0) {
		writel(0x0, base + IPU_GPREG_TRACE_TIMER_RST);
		writel(0x0, base + IPU_CDC_MMU_GPC_OVERALL_ENABLE);
		writel(0xffff, base + IPU_CDC_MMU_GPC_SOFT_RESET);
		psys_gpcs->gpc_enable = false;
		for (idx = 0; idx < IPU_PSYS_GPC_NUM; idx++) {
			psys_gpcs->gpc[idx].enable = 0;
			psys_gpcs->gpc[idx].sense = 0;
			psys_gpcs->gpc[idx].route = 0;
			psys_gpcs->gpc[idx].source = 0;
		}
		pm_runtime_mark_last_busy(&psys->adev->dev);
		pm_runtime_put_autosuspend(&psys->adev->dev);
	} else {
		/* Set gpc reg and start all gpc here.
		 * RST free running local timer.
		 */
		writel(0x0, base + IPU_GPREG_TRACE_TIMER_RST);
		writel(0x1, base + IPU_GPREG_TRACE_TIMER_RST);

		for (idx = 0; idx < IPU_PSYS_GPC_NUM; idx++) {
			/* Enable */
			writel(psys_gpcs->gpc[idx].enable,
			       base + IPU_CDC_MMU_GPC_ENABLE0 + 4 * idx);
			/* Setting (route/source/sense) */
			writel((psys_gpcs->gpc[idx].sense
					<< IPU_GPC_SENSE_OFFSET)
				+ (psys_gpcs->gpc[idx].route
					<< IPU_GPC_ROUTE_OFFSET)
				+ (psys_gpcs->gpc[idx].source
					<< IPU_GPC_SOURCE_OFFSET),
				base + IPU_CDC_MMU_GPC_CNT_SEL0 + 4 * idx);
		}

		/* Soft reset and Overall Enable. */
		writel(0x0, base + IPU_CDC_MMU_GPC_OVERALL_ENABLE);
		writel(0xffff, base + IPU_CDC_MMU_GPC_SOFT_RESET);
		writel(0x1, base + IPU_CDC_MMU_GPC_OVERALL_ENABLE);

		psys_gpcs->gpc_enable = true;
	}

	mutex_unlock(&psys->mutex);
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(psys_gpc_globe_enable_fops,
			ipu6_psys_gpc_global_enable_get,
			ipu6_psys_gpc_global_enable_set, "%llu\n");

static int ipu6_psys_gpc_count_get(void *data, u64 *val)
{
	struct ipu_psys_gpc *psys_gpc = data;
	struct ipu_psys *psys = psys_gpc->prit;
	void __iomem *base;
	int res;

	if (!psys || !psys->pdata || !psys->pdata->base)
		return -EINVAL;

	mutex_lock(&psys->mutex);

	base = psys->pdata->base + IPU_GPC_BASE;

	res = pm_runtime_get_sync(&psys->adev->dev);
	if (res < 0) {
		pm_runtime_put(&psys->adev->dev);
		mutex_unlock(&psys->mutex);
		return res;
	}

	*val = readl(base + IPU_CDC_MMU_GPC_VALUE0 + 4 * psys_gpc->gpcindex);

	mutex_unlock(&psys->mutex);
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(psys_gpc_count_fops,
			ipu6_psys_gpc_count_get,
			NULL, "%llu\n");

int ipu_psys_gpc_init_debugfs(struct ipu_psys *psys)
{
	struct dentry *gpcdir;
	struct dentry *dir;
	struct dentry *file;
	int idx;
	char gpcname[10];
	struct ipu_psys_gpcs *psys_gpcs;

	psys_gpcs = devm_kzalloc(&psys->dev, sizeof(*psys_gpcs), GFP_KERNEL);
	if (!psys_gpcs)
		return -ENOMEM;

	gpcdir = debugfs_create_dir("gpc", psys->debugfsdir);
	if (IS_ERR(gpcdir))
		return -ENOMEM;

	psys_gpcs->prit = psys;
	file = debugfs_create_file("enable", 0600, gpcdir, psys_gpcs,
				   &psys_gpc_globe_enable_fops);
	if (IS_ERR(file))
		goto err;

	for (idx = 0; idx < IPU_PSYS_GPC_NUM; idx++) {
		sprintf(gpcname, "gpc%d", idx);
		dir = debugfs_create_dir(gpcname, gpcdir);
		if (IS_ERR(dir))
			goto err;

		debugfs_create_bool("enable", 0600, dir,
				    &psys_gpcs->gpc[idx].enable);

		debugfs_create_u32("source", 0600, dir,
				   &psys_gpcs->gpc[idx].source);

		debugfs_create_u32("route", 0600, dir,
				   &psys_gpcs->gpc[idx].route);

		debugfs_create_u32("sense", 0600, dir,
				   &psys_gpcs->gpc[idx].sense);

		psys_gpcs->gpc[idx].gpcindex = idx;
		psys_gpcs->gpc[idx].prit = psys;
		file = debugfs_create_file("count", 0400, dir,
					   &psys_gpcs->gpc[idx],
					   &psys_gpc_count_fops);
		if (IS_ERR(file))
			goto err;
	}

	return 0;

err:
	debugfs_remove_recursive(gpcdir);
	return -ENOMEM;
}
#endif
