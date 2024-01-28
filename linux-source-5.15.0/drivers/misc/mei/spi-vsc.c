// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021, Intel Corporation. All rights reserved.
 * Intel Management Engine Interface (Intel MEI) Linux driver
 */
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/mei.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/spi/spi.h>

#include "hw-vsc.h"

#define CVFD_ACPI_ID_TGL "INTC1059"
#define CVFD_ACPI_ID_ADL "INTC1095"
#define LINK_NUMBER (1)
#define METHOD_NAME_SID "SID"

/* gpio resources */
static const struct acpi_gpio_params wakeuphost_gpio = { 0, 0, false };
static const struct acpi_gpio_params wakeuphostint_gpio = { 1, 0, false };
static const struct acpi_gpio_params resetfw_gpio = { 2, 0, false };
static const struct acpi_gpio_params wakeupfw = { 3, 0, false };
static const struct acpi_gpio_mapping mei_vsc_acpi_gpios[] = {
	{ "wakeuphost-gpios", &wakeuphost_gpio, 1 },
	{ "wakeuphostint-gpios", &wakeuphostint_gpio, 1 },
	{ "resetfw-gpios", &resetfw_gpio, 1 },
	{ "wakeupfw-gpios", &wakeupfw, 1 },
	{}
};

static struct acpi_device *find_cvfd_child_adev(struct acpi_device *parent)
{
	struct acpi_device *adev;

	if (!parent)
		return NULL;

	list_for_each_entry (adev, &parent->children, node) {
		if (!strcmp(CVFD_ACPI_ID_TGL, acpi_device_hid(adev)) ||
		    !strcmp(CVFD_ACPI_ID_ADL, acpi_device_hid(adev)))
			return adev;
	}

	return NULL;
}

static int get_sensor_name(struct mei_device *dev)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	struct spi_device *spi = hw->spi;
	struct acpi_device *adev;
	union acpi_object obj = { .type = ACPI_TYPE_INTEGER };
	union acpi_object *ret_obj;
	struct acpi_object_list arg_list = {
		.count = 1,
		.pointer = &obj,
	};
	struct acpi_buffer buffer = { ACPI_ALLOCATE_BUFFER, NULL };
	acpi_status status;
	char *c;

	adev = find_cvfd_child_adev(ACPI_COMPANION(&spi->dev));
	if (!adev) {
		dev_err(&spi->dev, "ACPI not found CVFD device\n");
		return -ENODEV;
	}

	obj.integer.value = LINK_NUMBER;
	status = acpi_evaluate_object(adev->handle, METHOD_NAME_SID, &arg_list,
				      &buffer);
	if (ACPI_FAILURE(status)) {
		dev_err(&spi->dev, "can't evaluate SID method: %d\n", status);
		return -ENODEV;
	}

	ret_obj = buffer.pointer;
	dev_dbg(&spi->dev, "SID status %d %lld %d - %d %s %d\n", status,
		buffer.length, ret_obj->type, ret_obj->string.length,
		ret_obj->string.pointer,
		acpi_has_method(adev->handle, METHOD_NAME_SID));

	if (ret_obj->string.length > sizeof(hw->cam_sensor_name)) {
		ACPI_FREE(buffer.pointer);
		return -EINVAL;
	}
	memcpy(hw->cam_sensor_name, ret_obj->string.pointer,
	       ret_obj->string.length);

	/* camera sensor name are all in lower case */
	for (c = hw->cam_sensor_name; *c != '\0'; c++)
		*c = tolower(*c);

	ACPI_FREE(buffer.pointer);
	return 0;
}

static int mei_vsc_probe(struct spi_device *spi)
{
	struct mei_vsc_hw *hw;
	struct mei_device *dev;
	int ret;

	dev = mei_vsc_dev_init(&spi->dev);
	if (!dev)
		return -ENOMEM;

	hw = to_vsc_hw(dev);
	mutex_init(&hw->mutex);
	init_waitqueue_head(&hw->xfer_wait);
	hw->spi = spi;
	spi_set_drvdata(spi, dev);

	ret = get_sensor_name(dev);
	if (ret)
		return ret;

	ret = devm_acpi_dev_add_driver_gpios(&spi->dev, mei_vsc_acpi_gpios);
	if (ret) {
		dev_err(&spi->dev, "%s: fail to add gpio\n", __func__);
		return -EBUSY;
	}

	hw->wakeuphost = devm_gpiod_get(&spi->dev, "wakeuphost", GPIOD_IN);
	if (IS_ERR(hw->wakeuphost)) {
		dev_err(&spi->dev, "gpio get irq failed\n");
		return -EINVAL;
	}
	hw->resetfw = devm_gpiod_get(&spi->dev, "resetfw", GPIOD_OUT_HIGH);
	if (IS_ERR(hw->resetfw)) {
		dev_err(&spi->dev, "gpio get resetfw failed\n");
		return -EINVAL;
	}
	hw->wakeupfw = devm_gpiod_get(&spi->dev, "wakeupfw", GPIOD_OUT_HIGH);
	if (IS_ERR(hw->wakeupfw)) {
		dev_err(&spi->dev, "gpio get wakeupfw failed\n");
		return -EINVAL;
	}

	ret = acpi_dev_gpio_irq_get_by(ACPI_COMPANION(&spi->dev),
				       "wakeuphostint-gpios", 0);
	if (ret < 0)
		return ret;

	hw->wakeuphostint = ret;
	irq_set_status_flags(hw->wakeuphostint, IRQ_DISABLE_UNLAZY);
	ret = request_threaded_irq(hw->wakeuphostint, mei_vsc_irq_quick_handler,
				   mei_vsc_irq_thread_handler,
				   IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
				   KBUILD_MODNAME, dev);
	if (mei_start(dev)) {
		dev_err(&spi->dev, "init hw failure.\n");
		ret = -ENODEV;
		goto release_irq;
	}

	ret = mei_register(dev, &spi->dev);
	if (ret)
		goto stop;

	pm_runtime_enable(dev->dev);
	dev_dbg(&spi->dev, "initialization successful.\n");
	return 0;

stop:
	mei_stop(dev);
release_irq:
	mei_cancel_work(dev);
	mei_disable_interrupts(dev);
	free_irq(hw->wakeuphostint, dev);
	return ret;
}

static int __maybe_unused mei_vsc_suspend(struct device *device)
{
	struct spi_device *spi = to_spi_device(device);
	struct mei_device *dev = spi_get_drvdata(spi);
	struct mei_vsc_hw *hw = to_vsc_hw(dev);

	if (!dev)
		return -ENODEV;

	dev_dbg(dev->dev, "%s\n", __func__);

	hw->disconnect = true;
	mei_stop(dev);
	mei_disable_interrupts(dev);
	free_irq(hw->wakeuphostint, dev);
	return 0;
}

static int __maybe_unused mei_vsc_resume(struct device *device)
{
	struct spi_device *spi = to_spi_device(device);
	struct mei_device *dev = spi_get_drvdata(spi);
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	int ret;

	dev_dbg(dev->dev, "%s\n", __func__);
	irq_set_status_flags(hw->wakeuphostint, IRQ_DISABLE_UNLAZY);
	ret = request_threaded_irq(hw->wakeuphostint, mei_vsc_irq_quick_handler,
				   mei_vsc_irq_thread_handler,
				   IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
				   KBUILD_MODNAME, dev);
	if (ret) {
		dev_err(device, "request_threaded_irq failed: irq = %d.\n",
			hw->wakeuphostint);
		return ret;
	}

	hw->disconnect = false;
	ret = mei_restart(dev);
	if (ret)
		return ret;

	/* Start timer if stopped in suspend */
	schedule_delayed_work(&dev->timer_work, HZ);
	return 0;
}

static int mei_vsc_remove(struct spi_device *spi)
{
	struct mei_device *dev = spi_get_drvdata(spi);
	struct mei_vsc_hw *hw = to_vsc_hw(dev);

	dev_info(&spi->dev, "%s %d", __func__, hw->wakeuphostint);

	pm_runtime_disable(dev->dev);
	hw->disconnect = true;
	mei_stop(dev);
	mei_disable_interrupts(dev);
	free_irq(hw->wakeuphostint, dev);
	mei_deregister(dev);
	mutex_destroy(&hw->mutex);
	return 0;
}

/**
 * mei_vsc_shutdown - Device Removal Routine
 *
 * @spi: SPI device structure
 *
 * mei_vsc_shutdown is called from the reboot notifier
 * it's a simplified version of remove so we go down
 * faster.
 */
static void mei_vsc_shutdown(struct spi_device *spi)
{
	struct mei_device *dev = spi_get_drvdata(spi);
	struct mei_vsc_hw *hw = to_vsc_hw(dev);

	dev_dbg(dev->dev, "shutdown\n");
	hw->disconnect = true;
	mei_stop(dev);

	mei_disable_interrupts(dev);
	free_irq(hw->wakeuphostint, dev);
}

static const struct dev_pm_ops mei_vsc_pm_ops = {

	SET_SYSTEM_SLEEP_PM_OPS(mei_vsc_suspend, mei_vsc_resume)
};

static const struct acpi_device_id mei_vsc_acpi_ids[] = {
	{ "INTC1058", 1 },
	{ "INTC1094", 1 },
	{},
};
MODULE_DEVICE_TABLE(acpi, mei_vsc_acpi_ids);

static struct spi_driver mei_vsc_driver = {
	.driver = {
		.name	= KBUILD_MODNAME,
		.acpi_match_table = ACPI_PTR(mei_vsc_acpi_ids),
		.pm		= &mei_vsc_pm_ops,
	},
	.probe		= mei_vsc_probe,
	.remove		= mei_vsc_remove,
	.shutdown = mei_vsc_shutdown,
	.driver.probe_type = PROBE_PREFER_ASYNCHRONOUS,
};
module_spi_driver(mei_vsc_driver);

MODULE_AUTHOR("Ye Xiang <xiang.ye@intel.com>");
MODULE_DESCRIPTION("Intel MEI VSC driver");
MODULE_LICENSE("GPL v2");
