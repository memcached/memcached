// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * AAEON LED driver
 *
 * Copyright (c) 2021, AAEON Ltd.
 *
 * Author: Kunyang Fan <kunyang_fan@aaeon.com.tw>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/acpi.h>
#include <linux/bitops.h>
#include <linux/leds.h>
#include <linux/module.h>
#include <linux/platform_data/x86/asus-wmi.h>
#include <linux/platform_device.h>

#define DRVNAME "led_aaeon"
#define ASUS_NB_WMI_EVENT_GUID   "0B3CBB35-E3C2-45ED-91C2-4C5A6D195D1C"
#define AAEON_WMI_MGMT_GUID      "97845ED0-4E6D-11DE-8A39-0800200C9A66"

#define GET_LED_NUMBER_ID        0x00060000
#define GET_LED_METHOD_ID        0x00060001
#define SET_LED_METHOD_ID        0x00060002
#define GET_LED_NUMBER_METHOD_ID 0x10


struct aaeon_led_data {
	int id;
	struct led_classdev cdev;
};

static int aaeon_led_get_number(void)
{
	int err, retval;

	err = asus_wmi_evaluate_method(GET_LED_NUMBER_ID,
				       GET_LED_NUMBER_METHOD_ID,
				       0, &retval);
	if (err)
		return err;

	return retval;
}

static enum led_brightness aaeon_led_brightness_get(struct led_classdev
						      *cdev)
{
	int err, brightness;
	struct aaeon_led_data *led =
			container_of(cdev, struct aaeon_led_data, cdev);
	u32 arg0;

	arg0 = (u32)(led->id & 0xF);
	err = asus_wmi_evaluate_method(GET_LED_METHOD_ID, arg0, 0, &brightness);
	if (err)
		return err;

	return brightness;
};

static void aaeon_led_brightness_set(struct led_classdev *cdev,
				       enum led_brightness brightness)
{
	int err, retval;
	struct aaeon_led_data *led =
			container_of(cdev, struct aaeon_led_data, cdev);
	u32 arg0;

	arg0 = (u32)(led->id & 0xF);
	if (brightness != LED_OFF)
		arg0 |= BIT(16);

	err = asus_wmi_evaluate_method(SET_LED_METHOD_ID, arg0, 0, &retval);
};

static int __init aaeon_add_led_device(struct platform_device *pdev,
					   int id)
{
	struct aaeon_led_data *led;

	led = devm_kzalloc(&pdev->dev, sizeof(struct aaeon_led_data), GFP_KERNEL);
	if (!led)
		return -ENOMEM;

	led->id = id;
	led->cdev.brightness_get = aaeon_led_brightness_get;
	led->cdev.brightness_set = aaeon_led_brightness_set;
	led->cdev.name = devm_kasprintf(&pdev->dev, GFP_KERNEL, "led:%d:", id);

	if (!led->cdev.name)
		return -ENOMEM;

	return devm_led_classdev_register(&pdev->dev, &led->cdev);
}

static int aaeon_led_probe(struct platform_device *pdev)
{
	int err = -ENODEV, i;
	int led_number = 0;

	pr_debug("aaeon led device probe!\n");
	/* Prevent other drivers adding this platfom device */
	if (!wmi_has_guid(AAEON_WMI_MGMT_GUID)) {
		pr_debug("AAEON Management GUID not found\n");
		return -ENODEV;
	}

	/* Query the number of led devices board support */
	led_number = aaeon_led_get_number();

	/*
	 * If the number is 0 or can't get the number of leds,
	 * no need to register any led device node.
	 */
	if (led_number <= 0)
		return -ENODEV;

	for (i = 0; i < led_number; i++) {
		err = aaeon_add_led_device(pdev, i);
		if (err)
			break;
	}

	return err;
}

static struct platform_driver aaeon_led_driver = {
	.driver = {
		.name = "leds-aaeon",
	},
};

module_platform_driver_probe(aaeon_led_driver, aaeon_led_probe);

MODULE_ALIAS("platform:leds-aaeon");
MODULE_DESCRIPTION("AAEON LED Driver");
MODULE_AUTHOR("Kunyang Fan <kunyang_fan@asus.com>");
MODULE_LICENSE("GPL v2");
