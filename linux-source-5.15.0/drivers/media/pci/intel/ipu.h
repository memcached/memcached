/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2013 - 2020 Intel Corporation */

#ifndef IPU_H
#define IPU_H

#include <linux/ioport.h>
#include <linux/list.h>
#include <uapi/linux/media.h>
#include <linux/version.h>

#include "ipu-pdata.h"
#include "ipu-bus.h"
#include "ipu-buttress.h"
#include "ipu-trace.h"

#define IPU6_PCI_ID	0x9a19
#define IPU6SE_PCI_ID	0x4e19
#define IPU6EP_ADL_P_PCI_ID	0x465d
#define IPU6EP_ADL_N_PCI_ID	0x462e
#define IPU6EP_RPL_P_PCI_ID	0xa75d
#define IPU6EP_MTL_PCI_ID	0x7d19

enum ipu_version {
	IPU_VER_INVALID = 0,
	IPU_VER_6,
	IPU_VER_6SE,
	IPU_VER_6EP,
};

/*
 * IPU version definitions to reflect the IPU driver changes.
 * Both ISYS and PSYS share the same version.
 */
#define IPU_MAJOR_VERSION 1
#define IPU_MINOR_VERSION 0
#define IPU_DRIVER_VERSION (IPU_MAJOR_VERSION << 16 | IPU_MINOR_VERSION)

/* processing system frequency: 25Mhz x ratio, Legal values [8,32] */
#define PS_FREQ_CTL_DEFAULT_RATIO	0x12

/* input system frequency: 1600Mhz / divisor. Legal values [2,8] */
#define IS_FREQ_SOURCE			1600000000
#define IS_FREQ_CTL_DIVISOR		0x4

/*
 * ISYS DMA can overshoot. For higher resolutions over allocation is one line
 * but it must be at minimum 1024 bytes. Value could be different in
 * different versions / generations thus provide it via platform data.
 */
#define IPU_ISYS_OVERALLOC_MIN		1024

/*
 * Physical pages in GDA is 128, page size is 2K for IPU6, 1K for others.
 */
#define IPU_DEVICE_GDA_NR_PAGES		128

/*
 * Virtualization factor to calculate the available virtual pages.
 */
#define IPU_DEVICE_GDA_VIRT_FACTOR	32

struct pci_dev;
struct list_head;
struct firmware;

#define NR_OF_MMU_RESOURCES			2

struct ipu_device {
	struct pci_dev *pdev;
	struct list_head devices;
	struct ipu_bus_device *isys;
	struct ipu_bus_device *psys;
	struct ipu_buttress buttress;

	const struct firmware *cpd_fw;
	const char *cpd_fw_name;
	u64 *pkg_dir;
	dma_addr_t pkg_dir_dma_addr;
	unsigned int pkg_dir_size;
	struct sg_table fw_sgt;

	void __iomem *base;
#ifdef CONFIG_DEBUG_FS
	struct dentry *ipu_dir;
#endif
	struct ipu_trace *trace;
	bool flr_done;
	bool ipc_reinit;
	bool secure_mode;

	int (*cpd_fw_reload)(struct ipu_device *isp);
};

#define IPU_DMA_MASK	39
#define IPU_LIB_CALL_TIMEOUT_MS		2000
#define IPU_PSYS_CMD_TIMEOUT_MS	2000
#define IPU_PSYS_OPEN_TIMEOUT_US	   50
#define IPU_PSYS_OPEN_RETRY (10000 / IPU_PSYS_OPEN_TIMEOUT_US)

int ipu_fw_authenticate(void *data, u64 val);
void ipu_configure_spc(struct ipu_device *isp,
		       const struct ipu_hw_variants *hw_variant,
		       int pkg_dir_idx, void __iomem *base, u64 *pkg_dir,
		       dma_addr_t pkg_dir_dma_addr);
int request_cpd_fw(const struct firmware **firmware_p, const char *name,
		   struct device *device);
extern enum ipu_version ipu_ver;
void ipu_internal_pdata_init(void);

#endif /* IPU_H */
