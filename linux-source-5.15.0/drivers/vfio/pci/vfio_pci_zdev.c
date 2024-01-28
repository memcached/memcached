// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO ZPCI devices support
 *
 * Copyright (C) IBM Corp. 2020.  All rights reserved.
 *	Author(s): Pierre Morel <pmorel@linux.ibm.com>
 *                 Matthew Rosato <mjrosato@linux.ibm.com>
 */
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include <linux/vfio_zdev.h>
#include <linux/kvm_host.h>
#include <asm/pci_clp.h>
#include <asm/pci_io.h>

#include <linux/vfio_pci_core.h>

/*
 * Add the Base PCI Function information to the device info region.
 */
static int zpci_base_cap(struct zpci_dev *zdev, struct vfio_info_cap *caps)
{
	struct vfio_device_info_cap_zpci_base cap = {
		.header.id = VFIO_DEVICE_INFO_CAP_ZPCI_BASE,
		.header.version = 2,
		.start_dma = zdev->start_dma,
		.end_dma = zdev->end_dma,
		.pchid = zdev->pchid,
		.vfn = zdev->vfn,
		.fmb_length = zdev->fmb_length,
		.pft = zdev->pft,
		.gid = zdev->pfgid,
		.fh = zdev->fh
	};

	return vfio_info_add_capability(caps, &cap.header, sizeof(cap));
}

/*
 * Add the Base PCI Function Group information to the device info region.
 */
static int zpci_group_cap(struct zpci_dev *zdev, struct vfio_info_cap *caps)
{
	struct vfio_device_info_cap_zpci_group cap = {
		.header.id = VFIO_DEVICE_INFO_CAP_ZPCI_GROUP,
		.header.version = 2,
		.dasm = zdev->dma_mask,
		.msi_addr = zdev->msi_addr,
		.flags = VFIO_DEVICE_INFO_ZPCI_FLAG_REFRESH,
		.mui = zdev->fmb_update,
		.noi = zdev->max_msi,
		.maxstbl = ZPCI_MAX_WRITE_SIZE,
		.version = zdev->version,
		.reserved = 0,
		.imaxstbl = zdev->maxstbl
	};

	return vfio_info_add_capability(caps, &cap.header, sizeof(cap));
}

/*
 * Add the device utility string to the device info region.
 */
static int zpci_util_cap(struct zpci_dev *zdev, struct vfio_info_cap *caps)
{
	struct vfio_device_info_cap_zpci_util *cap;
	int cap_size = sizeof(*cap) + CLP_UTIL_STR_LEN;
	int ret;

	cap = kmalloc(cap_size, GFP_KERNEL);
	if (!cap)
		return -ENOMEM;

	cap->header.id = VFIO_DEVICE_INFO_CAP_ZPCI_UTIL;
	cap->header.version = 1;
	cap->size = CLP_UTIL_STR_LEN;
	memcpy(cap->util_str, zdev->util_str, cap->size);

	ret = vfio_info_add_capability(caps, &cap->header, cap_size);

	kfree(cap);

	return ret;
}

/*
 * Add the function path string to the device info region.
 */
static int zpci_pfip_cap(struct zpci_dev *zdev, struct vfio_info_cap *caps)
{
	struct vfio_device_info_cap_zpci_pfip *cap;
	int cap_size = sizeof(*cap) + CLP_PFIP_NR_SEGMENTS;
	int ret;

	cap = kmalloc(cap_size, GFP_KERNEL);
	if (!cap)
		return -ENOMEM;

	cap->header.id = VFIO_DEVICE_INFO_CAP_ZPCI_PFIP;
	cap->header.version = 1;
	cap->size = CLP_PFIP_NR_SEGMENTS;
	memcpy(cap->pfip, zdev->pfip, cap->size);

	ret = vfio_info_add_capability(caps, &cap->header, cap_size);

	kfree(cap);

	return ret;
}

/*
 * Add all supported capabilities to the VFIO_DEVICE_GET_INFO capability chain.
 */
int vfio_pci_info_zdev_add_caps(struct vfio_pci_core_device *vdev,
				struct vfio_info_cap *caps)
{
	struct zpci_dev *zdev = to_zpci(vdev->pdev);
	int ret;

	if (!zdev)
		return -ENODEV;

	ret = zpci_base_cap(zdev, caps);
	if (ret)
		return ret;

	ret = zpci_group_cap(zdev, caps);
	if (ret)
		return ret;

	if (zdev->util_str_avail) {
		ret = zpci_util_cap(zdev, caps);
		if (ret)
			return ret;
	}

	ret = zpci_pfip_cap(zdev, caps);

	return ret;
}

static int vfio_pci_zdev_group_notifier(struct notifier_block *nb,
					unsigned long action, void *data)
{
	struct zpci_dev *zdev = container_of(nb, struct zpci_dev,
					     kvm_group_nb);

	if (action == VFIO_GROUP_NOTIFY_SET_KVM && zpci_kvm_hook.kvm_register) {
		if (data) {
			if (zpci_kvm_hook.kvm_register(zdev, data))
				return NOTIFY_BAD;
		}
	}

	return NOTIFY_OK;
}

int vfio_pci_zdev_open_device(struct vfio_pci_core_device *vdev)
{
	struct zpci_dev *zdev = to_zpci(vdev->pdev);
	unsigned long events = VFIO_GROUP_NOTIFY_SET_KVM;
	int ret;

	if (!zdev)
		return -ENODEV;

	/*
	 * Jammy-specific: backporting upstream commit 421cfe6596f6cb would
	 * require a large number of pre-req series to also be applied,
	 * affecting vfio across all platforms.
	 * Instead implement a vfio KVM group notifier here which only
	 * affects vfio-pci-zdev.  Rather than relying on the kvm pointer
	 * being provided in the vdev, get it from the notifier.  Sice we know
	 * the kvm will already be set, we can then immediately unregister the
	 * notifier.
	 */
	zdev->kvm_group_nb.notifier_call = vfio_pci_zdev_group_notifier;
	ret = vfio_register_notifier(&vdev->pdev->dev, VFIO_GROUP_NOTIFY,
				     &events, &zdev->kvm_group_nb);
	if (ret != 0) {
		pr_warn("vfio_register_notifier for group failed: %d\n", ret);
		return ret;
	}

	vfio_unregister_notifier(&vdev->pdev->dev, VFIO_GROUP_NOTIFY,
				 &zdev->kvm_group_nb);

	return 0;
}

void vfio_pci_zdev_close_device(struct vfio_pci_core_device *vdev)
{
	struct zpci_dev *zdev = to_zpci(vdev->pdev);

	if (!zdev || !zdev->kzdev)
		return;

	if (zpci_kvm_hook.kvm_unregister)
		zpci_kvm_hook.kvm_unregister(zdev);
}
