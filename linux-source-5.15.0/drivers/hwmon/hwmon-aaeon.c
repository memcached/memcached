// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * AAEON HWMON driver
 * Copyright (c) 2021, AAEON Ltd.
 *
 * Author: Edward Lin	<edward1_lin@aaeon.com.tw>
 * Author: Kunyang Fan	<kunyang_fan@aaeon.com.tw>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/acpi.h>
#include <linux/err.h>
#include <linux/jiffies.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_data/x86/asus-wmi.h>
#include <linux/platform_device.h>

#define DRVNAME "hwmon-aaeon"

#define AAEON_WMI_MGMT_GUID		"97845ED0-4E6D-11DE-8A39-0800200C9A66"

#define AAEON_VERSION_METHOD_ID		0x00000000
#define HWM_INFORMATION_METHOD_ID	0x00030000
#define HWM_METHOD_ID				0x00030001

#define BITMAP_TEMP_ARG			0x12
#define BITMAP_FAN_ARG			0x13
#define BITMAP_VOLTAGE_ARG		0x14

#define SENSOR_TEMP_NUMBER		0
#define SENSOR_FAN_NUMBER		1
#define SENSOR_VOLTAGE_NUMBER	2
#define SENSOR_MAX_NUMBER		2

static ssize_t aaeon_show_sensor(struct device *dev,
			       struct device_attribute *devattr, char *buf);
static ssize_t aaeon_show_sensor_name(struct device *dev,
				    struct device_attribute *devattr,
				    char *buf);
static ssize_t aaeon_show_version(struct device *dev,
				  struct device_attribute *devattr, char *buf);
static ssize_t name_show(struct device *dev, struct device_attribute *devattr,
			 char *buf);
static int aaeon_get_version(void);
static int aaeon_hwmon_probe(struct platform_device *pdev);
static int aaeon_hwmon_remove(struct platform_device *pdev);

static const char * const temp_sensors_name_table[] = {
			"CPU_Temp",
			"SYS1_Temp",
			"SYS2_Temp",
};

static const char * const temp_sensors_name_table_V3[] = {
			"SYS_Temp",
			"CPU_Temp",
};

static const char * const fan_sensors_name_table[] = {
			"CPU_FAN",
			"SYS1_FAN",
			"SYS2_FAN",
			"Chasis1_FAN",
			"Chasis2_FAN",
};

static const char * const fan_sensors_name_table_V3[] = {
			"Chasis_FAN",
			"CPU_FAN",
};

static const char * const voltage_sensors_name_table[] = {
			"VCORE_Voltage",
			"VMEM_Voltage",
			"+12_Voltage",
			"+5_Voltage",
			"+3.3_Voltage",
			"+1.8_Voltage",
			"5VSB_Voltage",
			"3VSB_Voltage",
			"VBAT_Voltage",
};

static const char * const voltage_sensors_name_table_V3[] = {
			"VCORE_Voltage",
			"+5_Voltage",
			"AVCC_Voltage",
			"+3.3_Voltage",
			"+12_Voltage",
			"VCOREREFIN_Voltage",
			"VIN4_Voltage",
			"3VSB_Voltage",
			"VBAT_Voltage",
};

struct aaeon_hwmon_data {
	struct device *hwmon_dev;
	int bfpi_version;
	u32 temp_bitmap;
	u32 fan_bitmap;
	u32 voltage_bitmap;
	unsigned int sensors_number[SENSOR_MAX_NUMBER + 1];
	const char * const *temp_names;
	const char * const *fan_names;
	const char * const *voltage_names;
};

/* Temperature attributes */
static struct sensor_device_attribute_2 temp_sys_nodes_atts[] = {
	SENSOR_ATTR_2(temp1_input, 0444, aaeon_show_sensor, NULL,
				SENSOR_TEMP_NUMBER, 0),
	SENSOR_ATTR_2(temp1_label, 0444, aaeon_show_sensor_name, NULL,
				SENSOR_TEMP_NUMBER, 0),
	SENSOR_ATTR_2(temp2_input, 0444, aaeon_show_sensor, NULL,
				SENSOR_TEMP_NUMBER, 1),
	SENSOR_ATTR_2(temp2_label, 0444, aaeon_show_sensor_name, NULL,
				SENSOR_TEMP_NUMBER, 1),
	SENSOR_ATTR_2(temp3_input, 0444, aaeon_show_sensor, NULL,
				SENSOR_TEMP_NUMBER, 2),
	SENSOR_ATTR_2(temp3_label, 0444, aaeon_show_sensor_name, NULL,
				SENSOR_TEMP_NUMBER, 2),
};

/* Cooler Fan attributes */
static struct sensor_device_attribute_2 fan_sys_nodes_atts[] = {
	SENSOR_ATTR_2(fan1_input, 0444, aaeon_show_sensor, NULL,
				SENSOR_FAN_NUMBER, 0),
	SENSOR_ATTR_2(fan1_label, 0444, aaeon_show_sensor_name, NULL,
				SENSOR_FAN_NUMBER, 0),
	SENSOR_ATTR_2(fan2_input, 0444, aaeon_show_sensor, NULL,
				SENSOR_FAN_NUMBER, 1),
	SENSOR_ATTR_2(fan2_label, 0444, aaeon_show_sensor_name, NULL,
				SENSOR_FAN_NUMBER, 1),
	SENSOR_ATTR_2(fan3_input, 0444, aaeon_show_sensor, NULL,
				SENSOR_FAN_NUMBER, 2),
	SENSOR_ATTR_2(fan3_label, 0444, aaeon_show_sensor_name, NULL,
				SENSOR_FAN_NUMBER, 2),
	SENSOR_ATTR_2(fan4_input, 0444, aaeon_show_sensor, NULL,
				SENSOR_FAN_NUMBER, 3),
	SENSOR_ATTR_2(fan4_label, 0444, aaeon_show_sensor_name, NULL,
				SENSOR_FAN_NUMBER, 3),
	SENSOR_ATTR_2(fan5_input, 0444, aaeon_show_sensor, NULL,
				SENSOR_FAN_NUMBER, 4),
	SENSOR_ATTR_2(fan5_label, 0444, aaeon_show_sensor_name, NULL,
				SENSOR_FAN_NUMBER, 4),
};

/* Voltage attributes */
static struct sensor_device_attribute_2 voltage_sys_nodes_atts[] = {
	SENSOR_ATTR_2(in1_input, 0444, aaeon_show_sensor, NULL,
			SENSOR_VOLTAGE_NUMBER, 0),
	SENSOR_ATTR_2(in1_label, 0444, aaeon_show_sensor_name, NULL,
			SENSOR_VOLTAGE_NUMBER, 0),
	SENSOR_ATTR_2(in2_input, 0444, aaeon_show_sensor, NULL,
			SENSOR_VOLTAGE_NUMBER, 1),
	SENSOR_ATTR_2(in2_label, 0444, aaeon_show_sensor_name, NULL,
			SENSOR_VOLTAGE_NUMBER, 1),
	SENSOR_ATTR_2(in3_input, 0444, aaeon_show_sensor, NULL,
			SENSOR_VOLTAGE_NUMBER, 2),
	SENSOR_ATTR_2(in3_label, 0444, aaeon_show_sensor_name, NULL,
			SENSOR_VOLTAGE_NUMBER, 2),
	SENSOR_ATTR_2(in4_input, 0444, aaeon_show_sensor, NULL,
			SENSOR_VOLTAGE_NUMBER, 3),
	SENSOR_ATTR_2(in4_label, 0444, aaeon_show_sensor_name, NULL,
			SENSOR_VOLTAGE_NUMBER, 3),
	SENSOR_ATTR_2(in5_input, 0444, aaeon_show_sensor, NULL,
			SENSOR_VOLTAGE_NUMBER, 4),
	SENSOR_ATTR_2(in5_label, 0444, aaeon_show_sensor_name, NULL,
			SENSOR_VOLTAGE_NUMBER, 4),
	SENSOR_ATTR_2(in6_input, 0444, aaeon_show_sensor, NULL,
			SENSOR_VOLTAGE_NUMBER, 5),
	SENSOR_ATTR_2(in6_label, 0444, aaeon_show_sensor_name, NULL,
			SENSOR_VOLTAGE_NUMBER, 5),
	SENSOR_ATTR_2(in7_input, 0444, aaeon_show_sensor, NULL,
			SENSOR_VOLTAGE_NUMBER, 6),
	SENSOR_ATTR_2(in7_label, 0444, aaeon_show_sensor_name, NULL,
			SENSOR_VOLTAGE_NUMBER, 6),
	SENSOR_ATTR_2(in8_input, 0444, aaeon_show_sensor, NULL,
			SENSOR_VOLTAGE_NUMBER, 7),
	SENSOR_ATTR_2(in8_label, 0444, aaeon_show_sensor_name, NULL,
			SENSOR_VOLTAGE_NUMBER, 7),
	SENSOR_ATTR_2(in9_input, 0444, aaeon_show_sensor, NULL,
			SENSOR_VOLTAGE_NUMBER, 8),
	SENSOR_ATTR_2(in9_label, 0444, aaeon_show_sensor_name, NULL,
			SENSOR_VOLTAGE_NUMBER, 8),

};

static struct sensor_device_attribute_2 info_sys_nodes_atts[] = {
	/* WMI version Information */
	SENSOR_ATTR_2(AAEON_VERSION, 0444, aaeon_show_version, NULL, 0, 0),
};

DEVICE_ATTR_RO(name);
static ssize_t name_show(struct device *dev, struct device_attribute *devattr,
			 char *buf)
{
	return sprintf(buf, "%s\n", DRVNAME);
}

static ssize_t aaeon_show_version(struct device *dev,
				  struct device_attribute *devattr, char *buf)
{
	struct aaeon_hwmon_data *data =
			(struct aaeon_hwmon_data *)dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", data->bfpi_version);
}

static ssize_t aaeon_show_sensor_name(struct device *dev,
				    struct device_attribute *devattr, char *buf)
{
	u8 nr = to_sensor_dev_attr_2(devattr)->nr;
	u8 index = to_sensor_dev_attr_2(devattr)->index;
	struct aaeon_hwmon_data *data =
			(struct aaeon_hwmon_data *)dev_get_drvdata(dev);

	if (nr > SENSOR_MAX_NUMBER || index >= data->sensors_number[nr]) {
		pr_debug("Can not check the device");
		return -1;
	}

	switch (nr) {
	case SENSOR_TEMP_NUMBER:
		return sprintf(buf, "%s\n", data->temp_names[index]);
	case SENSOR_FAN_NUMBER:
		return sprintf(buf, "%s\n", data->fan_names[index]);
	case SENSOR_VOLTAGE_NUMBER:
		return sprintf(buf, "%s\n", data->voltage_names[index]);
	default:
		break;
	}

	return 0;
}

static ssize_t aaeon_show_sensor(struct device *dev,
			       struct device_attribute *devattr, char *buf)
{
	u8 nr = to_sensor_dev_attr_2(devattr)->nr;
	u8 index = to_sensor_dev_attr_2(devattr)->index;
	u32 dev_id;
	int retval, err;
	struct aaeon_hwmon_data *data =
			(struct aaeon_hwmon_data *)dev_get_drvdata(dev);

	if (nr > SENSOR_MAX_NUMBER || index >= data->sensors_number[nr]) {
		pr_debug("Can not check the device");
		return -1;
	}

	/* For the V3 version, index need offset */
	if (data->bfpi_version == 0x03 && nr != SENSOR_VOLTAGE_NUMBER)
		index++;

	dev_id = (index << 12) | (nr << 8);
	err = asus_wmi_evaluate_method(HWM_METHOD_ID, dev_id, 0, &retval);
	if (err)
		return err;

	/* For the V3 version, need to convert the raw value*/
	if (nr == SENSOR_VOLTAGE_NUMBER && data->bfpi_version == 0x03) {
		switch (index) {
		case 0: /* VCORE */
			retval = retval * 16;
			break;
		case 1: /* +5V */
			retval = (retval * 2008) / 50;
			break;
		case 2: /* AVCC */
			retval = retval * 16;
			break;
		case 3: /* +3.3V */
			retval = retval * 16;
			break;
		case 4: /* +12V */
			retval = retval * 96;
			break;
		case 5: /* VCOREREFIN */
			retval = (retval * 552) / 41;
			break;
		case 6: /* VIN4 */
			retval = retval * 8;
			break;
		case 7: /* 3VSB */
			retval = retval * 16;
			break;
		case 8: /* VBAT */
			retval = retval * 16;
			break;
		default:
			break;
		}
	} else if (nr == SENSOR_TEMP_NUMBER && data->bfpi_version == 0x03)
		retval = retval * 1000;

	return sprintf(buf, "%d\n", retval);
}

static int aaeon_hwmon_create_sub_sysfs_fs(struct platform_device *pdev,
					struct sensor_device_attribute_2 *attr,
					int sensor_number,
					u32 sensor_mask,
					int bfpi_version)
{
	int i, err = 0;

	for (i = 0; i < sensor_number; i++) {
		if (bfpi_version == 0x03 || sensor_mask & BIT(i)) {
			err = device_create_file(&pdev->dev, &attr[2 * i].dev_attr);
			if (err)
				break;
			err = device_create_file(&pdev->dev, &attr[2 * i + 1].dev_attr);
			if (err)
				break;
		}
	}

	return err;
}

static int
aaeon_hwmon_create_sysfs_files(struct platform_device *pdev, struct aaeon_hwmon_data *data)
{
	int err;

	/* register sysfs interface files */
	err = device_create_file(&pdev->dev, &dev_attr_name);
	if (err)
		return err;

	/* registe sysfs to dump sensors BFPI version */
	err = device_create_file(&pdev->dev, &info_sys_nodes_atts[0].dev_attr);
	if (err)
		return err;

	/* create temperature name and value node */
	err = aaeon_hwmon_create_sub_sysfs_fs(pdev, temp_sys_nodes_atts,
				data->sensors_number[SENSOR_TEMP_NUMBER],
				data->temp_bitmap, data->bfpi_version);
	if (err)
		return err;

	/* create fan name and value node */
	err = aaeon_hwmon_create_sub_sysfs_fs(pdev, fan_sys_nodes_atts,
				data->sensors_number[SENSOR_FAN_NUMBER],
				data->fan_bitmap, data->bfpi_version);
	if (err)
		return err;

	/* create voltage name and value node */
	err = aaeon_hwmon_create_sub_sysfs_fs(pdev, voltage_sys_nodes_atts,
				data->sensors_number[SENSOR_VOLTAGE_NUMBER],
				data->voltage_bitmap, data->bfpi_version);
	if (err)
		return err;

	return 0;
}

static void aaeon_hwmon_remove_sub_sysfs_fs(struct platform_device *pdev,
					struct sensor_device_attribute_2 *attr,
					int sensor_number,
					u32 sensor_mask,
					int bfpi_version)
{
	int i;

	for (i = 0; i < sensor_number; i++) {
		if (bfpi_version == 0x03 || sensor_mask & BIT(i)) {
			device_remove_file(&pdev->dev, &attr[2 * i].dev_attr);
			device_remove_file(&pdev->dev, &attr[2 * i + 1].dev_attr);
		}
	}
}

static void
aaeon_hwmon_remove_sysfs_files(struct platform_device *pdev,
			       struct aaeon_hwmon_data *data)
{
	/* degister sysfs interface files */
	device_remove_file(&pdev->dev, &dev_attr_name);

	/* degiste sysfs to dump sensors BFPI version */
	device_remove_file(&pdev->dev, &info_sys_nodes_atts[0].dev_attr);

	/* remove temperature name and value node */
	aaeon_hwmon_remove_sub_sysfs_fs(pdev, temp_sys_nodes_atts,
				data->sensors_number[SENSOR_TEMP_NUMBER],
				data->temp_bitmap,
				data->bfpi_version);

	/* remove fan name and value node */
	aaeon_hwmon_remove_sub_sysfs_fs(pdev, fan_sys_nodes_atts,
				data->sensors_number[SENSOR_FAN_NUMBER],
				data->fan_bitmap,
				data->bfpi_version);

	/* remove voltage name and value node */
	aaeon_hwmon_remove_sub_sysfs_fs(pdev, voltage_sys_nodes_atts,
				data->sensors_number[SENSOR_VOLTAGE_NUMBER],
				data->voltage_bitmap,
				data->bfpi_version);
}

static int aaeon_hwmon_remove(struct platform_device *pdev)
{
	struct aaeon_hwmon_data *data = platform_get_drvdata(pdev);

	if (data->hwmon_dev)
		hwmon_device_unregister(data->hwmon_dev);

	aaeon_hwmon_remove_sysfs_files(pdev, data);

	return 0;
}

static int aaeon_get_version(void)
{
	int err, retval;
	u32 dev_id = 0x00;

	err = asus_wmi_evaluate_method(AAEON_VERSION_METHOD_ID, dev_id, 0,
				       &retval);
	if (err)
		return err;

	return retval;
}

static int aaeon_hwmon_init_drv_data(struct aaeon_hwmon_data *data)
{
	int err;

	data->bfpi_version = aaeon_get_version();
	if (data->bfpi_version < 0) {
		pr_debug("Error BFPI verion\n");
		return -1;
	}

	if (data->bfpi_version == 0x03) {
		/* set the number of bits in temp bitmap */
		data->sensors_number[SENSOR_TEMP_NUMBER] =
				ARRAY_SIZE(temp_sensors_name_table_V3);
		data->temp_names = temp_sensors_name_table_V3;

		/* set the number of bits in fan bitmap */
		data->sensors_number[SENSOR_FAN_NUMBER] =
				ARRAY_SIZE(fan_sensors_name_table_V3);
		data->fan_names = fan_sensors_name_table_V3;

		/* set the number of bits in voltage bitmap */
		data->sensors_number[SENSOR_VOLTAGE_NUMBER] =
				ARRAY_SIZE(voltage_sensors_name_table_V3);
		data->voltage_names = voltage_sensors_name_table_V3;
	} else {
		/* set the number of bits in temp bitmap */
		data->sensors_number[SENSOR_TEMP_NUMBER] =
				ARRAY_SIZE(temp_sensors_name_table);
		data->temp_names = temp_sensors_name_table;

		/* set the number of bits in fan bitmap */
		data->sensors_number[SENSOR_FAN_NUMBER] =
				ARRAY_SIZE(fan_sensors_name_table);
		data->fan_names = fan_sensors_name_table;

		/* set the number of bits in voltage bitmap */
		data->sensors_number[SENSOR_VOLTAGE_NUMBER] =
				ARRAY_SIZE(voltage_sensors_name_table);
		data->voltage_names = voltage_sensors_name_table;
	}

	/* get temp supported bitmap */
	err = asus_wmi_evaluate_method(HWM_INFORMATION_METHOD_ID,
				BITMAP_TEMP_ARG, 0, &data->temp_bitmap);
	if (err)
		return err;

	/* get fan supported bitmap */
	err = asus_wmi_evaluate_method(HWM_INFORMATION_METHOD_ID,
				BITMAP_FAN_ARG, 0, &data->fan_bitmap);
	if (err)
		return err;

	/* get voltage supported bitmap */
	err = asus_wmi_evaluate_method(HWM_INFORMATION_METHOD_ID,
				BITMAP_VOLTAGE_ARG, 0, &data->voltage_bitmap);
	if (err)
		return err;

	return 0;
}

static int aaeon_hwmon_probe(struct platform_device *pdev)
{
	int err;
	struct aaeon_hwmon_data *data;

	pr_debug("aaeon hwomon device probe (support V3)!\n");
	if (!wmi_has_guid(AAEON_WMI_MGMT_GUID)) {
		pr_info("AAEON Management GUID not found\n");
		return -ENODEV;
	}

	data = devm_kzalloc(&pdev->dev, sizeof(struct aaeon_hwmon_data),
			    GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	err = aaeon_hwmon_init_drv_data(data);
	if (err) {
		pr_info("Error to get sensor support bitmap\n");
		goto exit;
	}

	if (data->bfpi_version != 0x03 && data->temp_bitmap == 0 &&
		data->fan_bitmap == 0 && data->voltage_bitmap == 0) {
		pr_debug("No sensors found\n");
		err = -ENODEV;
		goto exit;
	}

	platform_set_drvdata(pdev, data);
	err = aaeon_hwmon_create_sysfs_files(pdev, data);
	if (err)
		goto exit;

	data->hwmon_dev = devm_hwmon_device_register_with_info(&pdev->dev,
							  "AAEON_HWM",
							  data,
							  NULL,
							  NULL);
	if (IS_ERR(data->hwmon_dev)) {
		err = PTR_ERR(data->hwmon_dev);
		data->hwmon_dev = NULL;
		goto exit_unregister_sysfs;
	}

	return 0;

exit_unregister_sysfs:
	aaeon_hwmon_remove(pdev);
exit:
	return err;
}

static struct platform_driver aaeon_hwmon_driver = {
	.driver = {
		.name = DRVNAME,
		.owner = THIS_MODULE,
	},
	.probe = aaeon_hwmon_probe,
	.remove = aaeon_hwmon_remove,
};

module_platform_driver_probe(aaeon_hwmon_driver, aaeon_hwmon_probe);

MODULE_ALIAS("platform:hwmon-aaeon");
MODULE_DESCRIPTION("AAEON Hardware Monitoring Driver");
MODULE_AUTHOR("Edward Lin <edward1_lin@aaeon.com.tw>");
MODULE_AUTHOR("Kunyang Fan <kunyang_fan@aaeon.com.tw>");
MODULE_LICENSE("GPL v2");
