// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * AAEON GPIO driver
 * Copyright (c) 2021, AAEON Ltd.
 *
 * Author: Edward Lin <edward1_lin@aaeon.com.tw>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/acpi.h>
#include <linux/bitops.h>
#include <linux/gpio/driver.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_data/x86/asus-wmi.h>
#include <linux/platform_device.h>

#define DRVNAME "gpio_aaeon"
#define ASUS_NB_WMI_EVENT_GUID   "0B3CBB35-E3C2-45ED-91C2-4C5A6D195D1C"
#define AAEON_WMI_MGMT_GUID      "97845ED0-4E6D-11DE-8A39-0800200C9A66"

#define GET_GPIO_NUMBER_ID       0x00010000
#define GET_LEVEL_METHOD_ID      0x00010001
#define SET_LEVEL_METHOD_ID      0x00010002
#define GET_DIRECTION_METHOD_ID  0x00010003
#define SET_DIRECTION_METHOD_ID  0x00010004
#define GET_SIO_NUMBER_METHOD_ID 0xF0010

struct aaeon_gpio_bank {
	struct gpio_chip chip;
	unsigned int regbase;
	struct aaeon_gpio_data *data;
};

struct aaeon_gpio_data {
	int nr_bank;
	struct aaeon_gpio_bank *bank;
};

static int aaeon_gpio_get_number(void);
static int aaeon_gpio_get_direction(struct gpio_chip *chip,
				 unsigned int offset);
static int aaeon_gpio_output_set_direction(struct gpio_chip *chip,
				 unsigned int offset, int value);
static int aaeon_gpio_input_set_direction(struct gpio_chip *chip,
				 unsigned int offset);
static int aaeon_gpio_get(struct gpio_chip *chip,
				 unsigned int offset);
static void aaeon_gpio_set(struct gpio_chip *chip, unsigned int offset,
				 int value);

#define AAEON_GPIO_BANK(_base, _ngpio, _regbase)			\
{									\
	.chip = {							\
		.label            = DRVNAME,				\
		.owner            = THIS_MODULE,			\
		.get_direction    = aaeon_gpio_get_direction,		\
		.direction_input  = aaeon_gpio_input_set_direction,     \
		.direction_output = aaeon_gpio_output_set_direction,    \
		.get              = aaeon_gpio_get,			\
		.set              = aaeon_gpio_set,			\
		.base             = _base,				\
		.ngpio            = _ngpio,				\
		.can_sleep        = true,				\
	},								\
	.regbase = _regbase,						\
}

static struct aaeon_gpio_bank aaeon_gpio_bank[] = {
	AAEON_GPIO_BANK(0, 0, 0xF0),
};

static int aaeon_gpio_get_direction(struct gpio_chip *chip, unsigned int offset)
{
	int err, retval;
	u32 dev_id = 0x0;

	dev_id |= offset;
	err = asus_wmi_evaluate_method(GET_DIRECTION_METHOD_ID, dev_id,
				       0, &retval);
	if (err)
		return err;

	return retval;
}

static int aaeon_gpio_input_set_direction(struct gpio_chip *chip,
					  unsigned int offset)
{
	int err, retval;
	u32 dev_id;

	dev_id = BIT(16) | offset;
	err = asus_wmi_evaluate_method(SET_DIRECTION_METHOD_ID, dev_id,
				       0, &retval);
	if (err)
		return err;

	return retval;
}

static int aaeon_gpio_output_set_direction(struct gpio_chip *chip,
					   unsigned int offset, int value)
{
	int err, retval;
	u32 dev_id = 0x0;

	dev_id |= offset;
	err = asus_wmi_evaluate_method(SET_DIRECTION_METHOD_ID, dev_id,
				       0, &retval);
	if (err)
		return err;

	return retval;
}

static int aaeon_gpio_get(struct gpio_chip *chip, unsigned int offset)
{
	int err, retval;
	u32 dev_id = 0x0;

	dev_id |= offset;
	err = asus_wmi_evaluate_method(GET_LEVEL_METHOD_ID, dev_id, 0, &retval);
	if (err)
		return err;

	return retval;
}

static void aaeon_gpio_set(struct gpio_chip *chip, unsigned int offset,
			   int value)
{
	int retval;
	u32 dev_id = offset;

	if (value)
		dev_id = BIT(16) | dev_id;

	asus_wmi_evaluate_method(SET_LEVEL_METHOD_ID, dev_id, 0, &retval);
}

static int aaeon_gpio_get_number(void)
{
	int err, retval;

	err = asus_wmi_evaluate_method(GET_GPIO_NUMBER_ID,
				       GET_SIO_NUMBER_METHOD_ID,
				       0, &retval);
	if (err)
		return err;

	return retval;
}

static int __init aaeon_gpio_probe(struct platform_device *pdev)
{
	int err, i;
	int dio_number = 0;
	struct aaeon_gpio_data *data;
	struct aaeon_gpio_bank *bank;

	/* Prevent other drivers adding this platfom device */
	if (!wmi_has_guid(AAEON_WMI_MGMT_GUID)) {
		pr_debug("AAEON Management GUID not found\n");
		return -ENODEV;
	}

	dio_number = aaeon_gpio_get_number();
	if (dio_number < 0)
		return -ENODEV;

	data = devm_kzalloc(&pdev->dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->nr_bank = ARRAY_SIZE(aaeon_gpio_bank);
	data->bank = aaeon_gpio_bank;
	platform_set_drvdata(pdev, data);
	bank = &data->bank[0];
	bank->chip.parent = &pdev->dev;
	bank->chip.ngpio = dio_number;
	bank->data = data;
	err = devm_gpiochip_add_data(&pdev->dev, &bank->chip, bank);
	if (err)
		pr_debug("Failed to register gpiochip %d: %d\n", i, err);

	return err;
}

static struct platform_driver aaeon_gpio_driver = {
	.driver = {
		.name = "gpio-aaeon",
	},
};

module_platform_driver_probe(aaeon_gpio_driver, aaeon_gpio_probe);

MODULE_ALIAS("platform:gpio-aaeon");
MODULE_DESCRIPTION("AAEON GPIO Driver");
MODULE_AUTHOR("Edward Lin <edward1_lin@aaeon.com.tw>");
MODULE_LICENSE("GPL v2");
