// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2013 - 2020 Intel Corporation

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/sizes.h>

#include "ipu.h"
#include "ipu-platform.h"
#include "ipu-dma.h"

#ifdef CONFIG_PM
static struct bus_type ipu_bus;

static int bus_pm_runtime_suspend(struct device *dev)
{
	struct ipu_bus_device *adev = to_ipu_bus_device(dev);
	int rval;

	rval = pm_generic_runtime_suspend(dev);
	if (rval)
		return rval;

	rval = ipu_buttress_power(dev, adev->ctrl, false);
	dev_dbg(dev, "%s: buttress power down %d\n", __func__, rval);
	if (!rval)
		return 0;

	dev_err(dev, "power down failed!\n");

	/* Powering down failed, attempt to resume device now */
	rval = pm_generic_runtime_resume(dev);
	if (!rval)
		return -EBUSY;

	return -EIO;
}

static int bus_pm_runtime_resume(struct device *dev)
{
	struct ipu_bus_device *adev = to_ipu_bus_device(dev);
	int rval;

	rval = ipu_buttress_power(dev, adev->ctrl, true);
	dev_dbg(dev, "%s: buttress power up %d\n", __func__, rval);
	if (rval)
		return rval;

	rval = pm_generic_runtime_resume(dev);
	dev_dbg(dev, "%s: resume %d\n", __func__, rval);
	if (rval)
		goto out_err;

	return 0;

out_err:
	ipu_buttress_power(dev, adev->ctrl, false);

	return -EBUSY;
}

static const struct dev_pm_ops ipu_bus_pm_ops = {
	.runtime_suspend = bus_pm_runtime_suspend,
	.runtime_resume = bus_pm_runtime_resume,
};

#define IPU_BUS_PM_OPS	(&ipu_bus_pm_ops)
#else
#define IPU_BUS_PM_OPS	NULL
#endif

static int ipu_bus_match(struct device *dev, struct device_driver *drv)
{
	struct ipu_bus_driver *adrv = to_ipu_bus_driver(drv);

	dev_dbg(dev, "bus match: \"%s\" --- \"%s\"\n", dev_name(dev),
		adrv->wanted);

	return !strncmp(dev_name(dev), adrv->wanted, strlen(adrv->wanted));
}

static int ipu_bus_probe(struct device *dev)
{
	struct ipu_bus_device *adev = to_ipu_bus_device(dev);
	struct ipu_bus_driver *adrv = to_ipu_bus_driver(dev->driver);
	int rval;

	dev_dbg(dev, "bus probe dev %s\n", dev_name(dev));

	adev->adrv = adrv;
	if (!adrv->probe) {
		rval = -ENODEV;
		goto out_err;
	}
	rval = pm_runtime_get_sync(&adev->dev);
	if (rval < 0) {
		dev_err(&adev->dev, "Failed to get runtime PM\n");
		goto out_err;
	}

	rval = adrv->probe(adev);
	pm_runtime_put(&adev->dev);

	if (rval)
		goto out_err;

	return 0;

out_err:
	ipu_bus_set_drvdata(adev, NULL);
	adev->adrv = NULL;

	return rval;
}

static void ipu_bus_remove(struct device *dev)
{
	struct ipu_bus_device *adev = to_ipu_bus_device(dev);
	struct ipu_bus_driver *adrv = to_ipu_bus_driver(dev->driver);

	if (adrv->remove)
		adrv->remove(adev);
}

static struct bus_type ipu_bus = {
	.name = IPU_BUS_NAME,
	.match = ipu_bus_match,
	.probe = ipu_bus_probe,
	.remove = ipu_bus_remove,
	.pm = IPU_BUS_PM_OPS,
};

static struct mutex ipu_bus_mutex;

static void ipu_bus_release(struct device *dev)
{
}

struct ipu_bus_device *ipu_bus_add_device(struct pci_dev *pdev,
					  struct device *parent, void *pdata,
					  struct ipu_buttress_ctrl *ctrl,
					  char *name, unsigned int nr)
{
	struct ipu_bus_device *adev;
	struct ipu_device *isp = pci_get_drvdata(pdev);
	int rval;

	adev = devm_kzalloc(&pdev->dev, sizeof(*adev), GFP_KERNEL);
	if (!adev)
		return ERR_PTR(-ENOMEM);

	adev->dev.parent = parent;
	adev->dev.bus = &ipu_bus;
	adev->dev.release = ipu_bus_release;
	adev->dev.dma_ops = &ipu_dma_ops;
	adev->dma_mask = DMA_BIT_MASK(isp->secure_mode ?
				      IPU_MMU_ADDRESS_BITS :
				      IPU_MMU_ADDRESS_BITS_NON_SECURE);
	adev->dev.dma_mask = &adev->dma_mask;
	adev->dev.dma_parms = pdev->dev.dma_parms;
	adev->dev.coherent_dma_mask = adev->dma_mask;
	adev->ctrl = ctrl;
	adev->pdata = pdata;
	adev->isp = isp;
	mutex_init(&adev->resume_lock);
	dev_set_name(&adev->dev, "%s%d", name, nr);

	rval = device_register(&adev->dev);
	if (rval) {
		put_device(&adev->dev);
		return ERR_PTR(rval);
	}

	mutex_lock(&ipu_bus_mutex);
	list_add(&adev->list, &isp->devices);
	mutex_unlock(&ipu_bus_mutex);

	pm_runtime_allow(&adev->dev);
	pm_runtime_enable(&adev->dev);

	return adev;
}

void ipu_bus_del_devices(struct pci_dev *pdev)
{
	struct ipu_device *isp = pci_get_drvdata(pdev);
	struct ipu_bus_device *adev, *save;

	mutex_lock(&ipu_bus_mutex);

	list_for_each_entry_safe(adev, save, &isp->devices, list) {
		pm_runtime_disable(&adev->dev);
		list_del(&adev->list);
		device_unregister(&adev->dev);
	}

	mutex_unlock(&ipu_bus_mutex);
}

int ipu_bus_register_driver(struct ipu_bus_driver *adrv)
{
	adrv->drv.bus = &ipu_bus;
	return driver_register(&adrv->drv);
}
EXPORT_SYMBOL(ipu_bus_register_driver);

int ipu_bus_unregister_driver(struct ipu_bus_driver *adrv)
{
	driver_unregister(&adrv->drv);
	return 0;
}
EXPORT_SYMBOL(ipu_bus_unregister_driver);

int ipu_bus_register(void)
{
	mutex_init(&ipu_bus_mutex);
	return bus_register(&ipu_bus);
}

void ipu_bus_unregister(void)
{
	mutex_destroy(&ipu_bus_mutex);
	return bus_unregister(&ipu_bus);
}

static int flr_rpm_recovery(struct device *dev, void *p)
{
	dev_dbg(dev, "FLR recovery call\n");
	/*
	 * We are not necessarily going through device from child to
	 * parent. runtime PM refuses to change state for parent if the child
	 * is still active. At FLR (full reset for whole IPU) that doesn't
	 * matter. Everything has been power gated by HW during the FLR cycle
	 * and we are just cleaning up SW state. Thus, ignore child during
	 * set_suspended.
	 */
	pm_suspend_ignore_children(dev, true);
	pm_runtime_set_suspended(dev);
	pm_suspend_ignore_children(dev, false);

	return 0;
}

int ipu_bus_flr_recovery(void)
{
	bus_for_each_dev(&ipu_bus, NULL, NULL, flr_rpm_recovery);
	return 0;
}
