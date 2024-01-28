/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_USB_LJCA_H
#define __LINUX_USB_LJCA_H

#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/types.h>

#define MAX_GPIO_NUM 64

struct ljca_gpio_info {
	int num;
	DECLARE_BITMAP(valid_pin_map, MAX_GPIO_NUM);
};

struct ljca_i2c_info {
	u8 id;
	u8 capacity;
	u8 intr_pin;
};

struct ljca_spi_info {
	u8 id;
	u8 capacity;
};

struct ljca_platform_data {
	int type;
	union {
		struct ljca_gpio_info gpio_info;
		struct ljca_i2c_info i2c_info;
		struct ljca_spi_info spi_info;
	};
};

typedef void (*ljca_event_cb_t)(struct platform_device *pdev, u8 cmd,
				const void *evt_data, int len);

int ljca_register_event_cb(struct platform_device *pdev,
			   ljca_event_cb_t event_cb);
void ljca_unregister_event_cb(struct platform_device *pdev);
int ljca_transfer(struct platform_device *pdev, u8 cmd, const void *obuf,
		  int obuf_len, void *ibuf, int *ibuf_len);
int ljca_transfer_noack(struct platform_device *pdev, u8 cmd, const void *obuf,
			int obuf_len);

#endif
