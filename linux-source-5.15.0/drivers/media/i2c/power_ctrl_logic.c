// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020-2021 Intel Corporation.

#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/gpio/consumer.h>

#define PCL_DRV_NAME "power_ctrl_logic"

struct power_ctrl_logic {
	/* gpio resource*/
	struct gpio_desc *reset_gpio;
	struct gpio_desc *powerdn_gpio;
	struct gpio_desc *clocken_gpio;
	struct gpio_desc *indled_gpio;
	/* status */
	struct mutex status_lock;
	bool power_on;
	bool gpio_ready;
};

struct power_ctrl_gpio {
	const char *name;
	struct gpio_desc **pin;
};

/* mcu gpio resources*/
static const struct acpi_gpio_params camreset_gpio  = { 0, 0, false };
static const struct acpi_gpio_params campwdn_gpio   = { 1, 0, false };
static const struct acpi_gpio_params midmclken_gpio = { 2, 0, false };
static const struct acpi_gpio_params led_gpio       = { 3, 0, false };
static const struct acpi_gpio_mapping dsc1_acpi_gpios[] = {
	{ "camreset-gpios", &camreset_gpio, 1 },
	{ "campwdn-gpios", &campwdn_gpio, 1 },
	{ "midmclken-gpios", &midmclken_gpio, 1 },
	{ "indled-gpios", &led_gpio, 1 },
	{ }
};

static struct power_ctrl_logic pcl = {
	.reset_gpio = NULL,
	.powerdn_gpio = NULL,
	.clocken_gpio = NULL,
	.indled_gpio = NULL,
	.power_on = false,
	.gpio_ready = false,
};

static struct power_ctrl_gpio pcl_gpios[] = {
	{ "camreset", &pcl.reset_gpio },
	{ "campwdn", &pcl.powerdn_gpio },
	{ "midmclken", &pcl.clocken_gpio},
	{ "indled", &pcl.indled_gpio},
};

static int power_ctrl_logic_add(struct acpi_device *adev)
{
	int i, ret;

	dev_dbg(&adev->dev, "@%s, enter\n", __func__);
	set_primary_fwnode(&adev->dev, &adev->fwnode);

	ret = acpi_dev_add_driver_gpios(adev, dsc1_acpi_gpios);
	if (ret) {
		dev_err(&adev->dev, "@%s: --111---fail to add gpio. ret %d\n", __func__, ret);
		return -EBUSY;
	}

	for (i = 0; i < ARRAY_SIZE(pcl_gpios); i++) {
		*pcl_gpios[i].pin = gpiod_get(&adev->dev, pcl_gpios[i].name, GPIOD_OUT_LOW);
		if (IS_ERR(*pcl_gpios[i].pin)) {
			dev_dbg(&adev->dev, "failed to get gpio %s\n", pcl_gpios[i].name);
			return -EPROBE_DEFER;
		}
	}

	mutex_lock(&pcl.status_lock);
	pcl.gpio_ready = true;
	mutex_unlock(&pcl.status_lock);

	dev_dbg(&adev->dev, "@%s, exit\n", __func__);
	return ret;
}

static int power_ctrl_logic_remove(struct acpi_device *adev)
{
	dev_dbg(&adev->dev, "@%s, enter\n", __func__);
	mutex_lock(&pcl.status_lock);
	pcl.gpio_ready = false;
	gpiod_set_value_cansleep(pcl.reset_gpio, 0);
	gpiod_put(pcl.reset_gpio);
	gpiod_set_value_cansleep(pcl.powerdn_gpio, 0);
	gpiod_put(pcl.powerdn_gpio);
	gpiod_set_value_cansleep(pcl.clocken_gpio, 0);
	gpiod_put(pcl.clocken_gpio);
	gpiod_set_value_cansleep(pcl.indled_gpio, 0);
	gpiod_put(pcl.indled_gpio);
	mutex_unlock(&pcl.status_lock);
	dev_dbg(&adev->dev, "@%s, exit\n", __func__);
	return 0;
}

static struct acpi_device_id acpi_ids[] = {
	{ "INT3472", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, acpi_ids);

static struct acpi_driver _driver = {
	.name = PCL_DRV_NAME,
	.class = PCL_DRV_NAME,
	.ids = acpi_ids,
	.ops = {
		.add = power_ctrl_logic_add,
		.remove = power_ctrl_logic_remove,
	},
};
module_acpi_driver(_driver);

int power_ctrl_logic_set_power(int on)
{
	mutex_lock(&pcl.status_lock);
	if (!pcl.gpio_ready) {
		pr_debug("@%s,failed to set power, gpio_ready=%d, on=%d\n",
			 __func__, pcl.gpio_ready, on);
		mutex_unlock(&pcl.status_lock);
		return -EPROBE_DEFER;
	}
	if (pcl.power_on != on) {
		gpiod_set_value_cansleep(pcl.reset_gpio, on);
		gpiod_set_value_cansleep(pcl.powerdn_gpio, on);
		gpiod_set_value_cansleep(pcl.clocken_gpio, on);
		gpiod_set_value_cansleep(pcl.indled_gpio, on);
		pcl.power_on = on;
	}
	mutex_unlock(&pcl.status_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(power_ctrl_logic_set_power);

MODULE_AUTHOR("Bingbu Cao <bingbu.cao@intel.com>");
MODULE_AUTHOR("Qiu, Tianshu <tian.shu.qiu@intel.com>");
MODULE_AUTHOR("Xu, Chongyang <chongyang.xu@intel.com>");
MODULE_DESCRIPTION("Power Control Logic Driver");
MODULE_LICENSE("GPL v2");
