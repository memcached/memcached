/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2013 - 2020 Intel Corporation */

#ifndef IPU_BUS_H
#define IPU_BUS_H

#include <linux/device.h>
#include <linux/irqreturn.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/pci.h>

#define IPU_BUS_NAME	IPU_NAME "-bus"

struct ipu_buttress_ctrl;
struct ipu_subsystem_trace_config;

struct ipu_bus_device {
	struct device dev;
	struct list_head list;
	void *pdata;
	struct ipu_bus_driver *adrv;
	struct ipu_mmu *mmu;
	struct ipu_device *isp;
	struct ipu_subsystem_trace_config *trace_cfg;
	struct ipu_buttress_ctrl *ctrl;
	u64 dma_mask;
	/* Protect runtime_resume calls on the dev */
	struct mutex resume_lock;
};

#define to_ipu_bus_device(_dev) container_of(_dev, struct ipu_bus_device, dev)

struct ipu_bus_driver {
	struct device_driver drv;
	const char *wanted;
	int (*probe)(struct ipu_bus_device *adev);
	void (*remove)(struct ipu_bus_device *adev);
	irqreturn_t (*isr)(struct ipu_bus_device *adev);
	irqreturn_t (*isr_threaded)(struct ipu_bus_device *adev);
	bool wake_isr_thread;
};

#define to_ipu_bus_driver(_drv) container_of(_drv, struct ipu_bus_driver, drv)

struct ipu_bus_device *ipu_bus_add_device(struct pci_dev *pdev,
					  struct device *parent, void *pdata,
					  struct ipu_buttress_ctrl *ctrl,
					  char *name, unsigned int nr);
void ipu_bus_del_devices(struct pci_dev *pdev);

int ipu_bus_register_driver(struct ipu_bus_driver *adrv);
int ipu_bus_unregister_driver(struct ipu_bus_driver *adrv);

int ipu_bus_register(void);
void ipu_bus_unregister(void);

#define module_ipu_bus_driver(drv)			\
	module_driver(drv, ipu_bus_register_driver, \
		ipu_bus_unregister_driver)

#define ipu_bus_set_drvdata(adev, data) dev_set_drvdata(&(adev)->dev, data)
#define ipu_bus_get_drvdata(adev) dev_get_drvdata(&(adev)->dev)

int ipu_bus_flr_recovery(void);

#endif
