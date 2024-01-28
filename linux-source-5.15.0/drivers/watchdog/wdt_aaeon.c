// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * AAEON WDT driver
 *
 * Author: Edward Lin <edward1_lin@aaeon.com.tw>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/acpi.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/platform_data/x86/asus-wmi.h>
#include <linux/platform_device.h>
#include <linux/reboot.h>
#include <linux/uaccess.h>
#include <linux/watchdog.h>

#define AAEON_WMI_MGMT_GUID      "97845ED0-4E6D-11DE-8A39-0800200C9A66"
#define WMI_WDT_GETMAX_METHOD_ID	0x00020000
#define WMI_WDT_GETVALUE_METHOD_ID	0x00020001
#define WMI_WDT_SETANDSTOP_METHOD_ID	0x00020002

#define WMI_WDT_SUPPORTED_DEVICE_ID                                            \
	0x12 /* Dev_Id for WDT_WMI supported or not */
#define WMI_WDT_GETMAX_DEVICE_ID  0x10  /* Dev_Id for WDT_WMI get Max timeout */
#define WMI_WDT_STOP_DEVICE_ID    0x00  /* Dev_Id for WDT_WMI stop watchdog*/

/* Default values */
#define WATCHDOG_TIMEOUT  60000  /* 1 minute default timeout */
#define WATCHDOG_MAX_TIMEOUT  (60000 * 255) /* WD_TIME is a byte long */
#define WATCHDOG_PULSE_WIDTH  5000 /* default pulse width for watchdog signal */

static const int max_timeout = WATCHDOG_MAX_TIMEOUT;
static int timeout = WATCHDOG_TIMEOUT;    /* default timeout in seconds */
module_param(timeout, int, 0);
MODULE_PARM_DESC(timeout, "Initial watchdog timeout in mini-seconds");

static bool nowayout = WATCHDOG_NOWAYOUT;
module_param(nowayout, bool, 0444);
MODULE_PARM_DESC(nowayout, " Disable watchdog shutdown on close");

/* Wdog internal data information */
struct watchdog_data {
	unsigned long       opened;       /* driver open state */
	struct mutex        lock;         /* concurrency control */
	char                expect_close; /* controlled close */
	struct watchdog_info ident;       /* wdog information*/
	unsigned short      timeout;      /* current wdog timeout */
	u8                  timer_val;    /* content for the WD_TIME register */
	char                minutes_mode;
	u8                  pulse_val;    /* pulse width flag */
	char                pulse_mode;   /* enable pulse output mode? */
	char                caused_reboot;/* last reboot was by the watchdog */
};

static long aaeon_watchdog_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg);
static int aaeon_watchdog_notify_sys(struct notifier_block *this,
			       unsigned long code, void *unused);

static struct watchdog_data watchdog = {
	.lock = __MUTEX_INITIALIZER(watchdog.lock),
};

/* /dev/watchdog api available options */
static const struct file_operations watchdog_fops = {
	.owner              = THIS_MODULE,
	.unlocked_ioctl     = aaeon_watchdog_ioctl,
};

static struct miscdevice watchdog_miscdev = {
	.minor      = WATCHDOG_MINOR,
	.name       = "watchdog",
	.fops       = &watchdog_fops,
};

static struct notifier_block watchdog_notifier = {
	.notifier_call = aaeon_watchdog_notify_sys,
};

/* Internal Configuration functions */
static int aaeon_watchdog_set_timeout(int timeout)
{
	int err = 0;
	u32 retval, dev_id = timeout;

	if (timeout <= 0 || timeout >  max_timeout) {
		pr_debug("watchdog timeout out of range\n");
		return -EINVAL;
	}

	mutex_lock(&watchdog.lock);
	err = asus_wmi_evaluate_method(WMI_WDT_SETANDSTOP_METHOD_ID,
				       dev_id, 0, &retval);
	mutex_unlock(&watchdog.lock);

	return err;
}

static int aaeon_watchdog_get_timeout(void)
{
	int err = 0;
	u32 retval;

	if (timeout <= 0 || timeout >  max_timeout) {
		pr_debug("watchdog timeout out of range\n");
		return -EINVAL;
	}
	mutex_lock(&watchdog.lock);
	err = asus_wmi_evaluate_method(WMI_WDT_GETVALUE_METHOD_ID,
				       0, 0, &retval);
	mutex_unlock(&watchdog.lock);

	return err ? err : retval;
}

static int aaeon_watchdog_stop(void)
{
	int err = 0;

	mutex_lock(&watchdog.lock);
	err = asus_wmi_evaluate_method(WMI_WDT_SETANDSTOP_METHOD_ID,
				       0, 0, NULL);
	mutex_unlock(&watchdog.lock);

	return err;
}

static int aaeon_watchdog_get_maxsupport(void)
{
	int err;
	u32 retval;

	mutex_lock(&watchdog.lock);
	err = asus_wmi_evaluate_method(WMI_WDT_GETMAX_METHOD_ID,
				       WMI_WDT_GETMAX_DEVICE_ID,
				       0, &retval);
	mutex_unlock(&watchdog.lock);

	return err ? err : retval;

}

static long aaeon_watchdog_ioctl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	int new_timeout;

	union {
		struct watchdog_info __user *ident;
		int __user *i;
	} uarg;

	uarg.i = (int __user *) arg;
	switch (cmd) {
	case WDIOC_SETTIMEOUT:
		if (get_user(new_timeout, uarg.i))
			return -EFAULT;
		if (aaeon_watchdog_set_timeout(new_timeout))
			return -EINVAL;
		return 0;
	case WDIOC_GETTIMEOUT:
		return aaeon_watchdog_get_timeout();
	case WDIOS_DISABLECARD:
		return aaeon_watchdog_stop();
	case WDIOC_GETSUPPORT:
		return aaeon_watchdog_get_maxsupport();
	default:
		return -ENOTTY;
	}
}

static int aaeon_watchdog_notify_sys(struct notifier_block *this,
			       unsigned long code, void *unused)
{
	if (code == SYS_DOWN || code == SYS_HALT)
		aaeon_watchdog_stop();
	return NOTIFY_DONE;
}

static int aaeon_wdt_probe(struct platform_device *pdev)
{
	int err = 0;
	int retval = 0;

	pr_debug("aaeon watchdog device probe!\n");
	if (!wmi_has_guid(AAEON_WMI_MGMT_GUID)) {
		pr_debug("AAEON Management GUID not found\n");
		return -ENODEV;
	}
	err = asus_wmi_evaluate_method(WMI_WDT_GETMAX_METHOD_ID,
				       WMI_WDT_SUPPORTED_DEVICE_ID, 0, &retval);
	if (err)
		goto exit;

	/*
	 * This driver imitates the old type SIO watchdog driver to
	 * provide the basic control for watchdog functions and only
	 * access by customized userspace tool
	 */
	err = misc_register(&watchdog_miscdev);
	if (err) {
		pr_debug(" cannot register miscdev on minor=%d\n",
			 watchdog_miscdev.minor);
		goto exit;
	}

	err = register_reboot_notifier(&watchdog_notifier);
	if (err)
		goto exit_miscdev;

	if (nowayout)
		__module_get(THIS_MODULE);

	return 0;

exit_miscdev:
	misc_deregister(&watchdog_miscdev);
exit:
	return err;
}

static struct platform_driver aaeon_wdt_driver = {
	.driver = {
		.name = "wdt-aaeon",
	},
};

module_platform_driver_probe(aaeon_wdt_driver, aaeon_wdt_probe);

MODULE_ALIAS("platform:wdt-aaeon");
MODULE_DESCRIPTION("AAEON WDT Driver");
MODULE_AUTHOR("Edward Lin <edward1_lin@aaeon.com.tw>");
MODULE_LICENSE("GPL v2");
