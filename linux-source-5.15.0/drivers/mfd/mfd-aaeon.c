// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * UP Board main platform driver and FPGA configuration support
 *
 * Copyright (c) 2021, AAEON Ltd.
 *
 * Author: Kunyang_Fan <knuyang_fan@aaeon.com.tw>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/acpi.h>
#include <linux/gpio.h>
#include <linux/kernel.h>
#include <linux/mfd/core.h>
#include <linux/module.h>
#include <linux/platform_data/x86/asus-wmi.h>
#include <linux/platform_device.h>
#include <linux/leds.h>
#include <linux/wmi.h>

#define AAEON_WMI_MGMT_GUID      "97845ED0-4E6D-11DE-8A39-0800200C9A66"

#define WMI_REPORT_CAPABILITY_METHOD	0x00000000
#define MAX_BFPI_VERSION		255
#define GET_REVISION_ID			0x00

struct aaeon_wmi_priv {
	const struct mfd_cell *cells;
	size_t ncells;
};

static const struct mfd_cell aaeon_mfd_cells[] = {
	{ .name = "gpio-aaeon" },
	{ .name = "hwmon-aaeon"},
	{ .name = "leds-aaeon"},
	{ .name = "wdt-aaeon"},
};

static const struct aaeon_wmi_priv aaeon_wmi_priv_data = {
	.cells = aaeon_mfd_cells,
	.ncells = ARRAY_SIZE(aaeon_mfd_cells),
};

static int aaeon_wmi_check_device(void)
{
	int err;
	int retval;

	err = asus_wmi_evaluate_method(WMI_REPORT_CAPABILITY_METHOD, GET_REVISION_ID, 0,
				       &retval);
	if (err)
		return -ENODEV;
	if (retval < 3 || retval > MAX_BFPI_VERSION)
		return -ENODEV;

	return 0;
}

static int aaeon_wmi_probe(struct wmi_device *wdev, const void *context)
{
	struct aaeon_wmi_priv *priv;

	if (!wmi_has_guid(AAEON_WMI_MGMT_GUID)) {
		dev_info(&wdev->dev, "AAEON Management GUID not found\n");
		return -ENODEV;
	}

	if (aaeon_wmi_check_device())
		return -ENODEV;

	priv = (struct aaeon_wmi_priv *)context;
	dev_set_drvdata(&wdev->dev, priv);

	return devm_mfd_add_devices(&wdev->dev, 0, priv->cells,
				    priv->ncells, NULL, 0, NULL);
}

static const struct wmi_device_id aaeon_wmi_id_table[] = {
	{ AAEON_WMI_MGMT_GUID, (void *)&aaeon_wmi_priv_data },
	{}
};

static struct wmi_driver aaeon_wmi_driver = {
	.driver = {
		.name = "mfd-aaeon",
	},
	.id_table = aaeon_wmi_id_table,
	.probe = aaeon_wmi_probe,
};

module_wmi_driver(aaeon_wmi_driver);

MODULE_DEVICE_TABLE(wmi, aaeon_wmi_id_table);
MODULE_AUTHOR("Kunyang Fan <kunyang_fan@aaeon.com.tw>");
MODULE_DESCRIPTION("AAEON Board WMI driver");
MODULE_LICENSE("GPL v2");
