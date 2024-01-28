// SPDX-License-Identifier: GPL-2.0-only
/*
 * Intel La Jolla Cove Adapter USB driver
 *
 * Copyright (c) 2021, Intel Corporation.
 */

#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/mfd/core.h>
#include <linux/mfd/ljca.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/usb.h>

enum ljca_acpi_match_adr {
	LJCA_ACPI_MATCH_GPIO,
	LJCA_ACPI_MATCH_I2C1,
	LJCA_ACPI_MATCH_I2C2,
	LJCA_ACPI_MATCH_SPI1,
};

static char *gpio_hids[] = {
	"INTC1074",
	"INTC1096",
};
static struct mfd_cell_acpi_match ljca_acpi_match_gpio;

static char *i2c_hids[] = {
	"INTC1075",
	"INTC1097",
};
static struct mfd_cell_acpi_match ljca_acpi_match_i2cs[2];

static char *spi_hids[] = {
	"INTC1091",
	"INTC1098",
};
static struct mfd_cell_acpi_match ljca_acpi_match_spis[1];

struct ljca_msg {
	u8 type;
	u8 cmd;
	u8 flags;
	u8 len;
	u8 data[];
} __packed;

struct fw_version {
	u8 major;
	u8 minor;
	u16 patch;
	u16 build;
} __packed;

/* stub types */
enum stub_type {
	MNG_STUB = 1,
	DIAG_STUB,
	GPIO_STUB,
	I2C_STUB,
	SPI_STUB,
};

/* command Flags */
#define ACK_FLAG BIT(0)
#define RESP_FLAG BIT(1)
#define CMPL_FLAG BIT(2)

/* MNG stub commands */
enum ljca_mng_cmd {
	MNG_GET_VERSION = 1,
	MNG_RESET_NOTIFY,
	MNG_RESET,
	MNG_ENUM_GPIO,
	MNG_ENUM_I2C,
	MNG_POWER_STATE_CHANGE,
	MNG_SET_DFU_MODE,
	MNG_ENUM_SPI,
};

/* DIAG commands */
enum diag_cmd {
	DIAG_GET_STATE = 1,
	DIAG_GET_STATISTIC,
	DIAG_SET_TRACE_LEVEL,
	DIAG_SET_ECHO_MODE,
	DIAG_GET_FW_LOG,
	DIAG_GET_FW_COREDUMP,
	DIAG_TRIGGER_WDT,
	DIAG_TRIGGER_FAULT,
	DIAG_FEED_WDT,
	DIAG_GET_SECURE_STATE,
};

struct ljca_i2c_ctr_info {
	u8 id;
	u8 capacity;
	u8 intr_pin;
} __packed;

struct ljca_i2c_descriptor {
	u8 num;
	struct ljca_i2c_ctr_info info[];
} __packed;

struct ljca_spi_ctr_info {
	u8 id;
	u8 capacity;
} __packed;

struct ljca_spi_descriptor {
	u8 num;
	struct ljca_spi_ctr_info info[];
} __packed;

struct ljca_bank_descriptor {
	u8 bank_id;
	u8 pin_num;

	/* 1 bit for each gpio, 1 means valid */
	u32 valid_pins;
} __packed;

struct ljca_gpio_descriptor {
	u8 pins_per_bank;
	u8 bank_num;
	struct ljca_bank_descriptor bank_desc[];
} __packed;

#define MAX_PACKET_SIZE 64
#define MAX_PAYLOAD_SIZE (MAX_PACKET_SIZE - sizeof(struct ljca_msg))
#define USB_WRITE_TIMEOUT 200
#define USB_WRITE_ACK_TIMEOUT 500
#define USB_ENUM_STUB_TIMEOUT 20

struct ljca_event_cb_entry {
	struct platform_device *pdev;
	ljca_event_cb_t notify;
};

struct ljca_stub_packet {
	u8 *ibuf;
	u32 ibuf_len;
};

struct ljca_stub {
	struct list_head list;
	u8 type;
	struct usb_interface *intf;
	spinlock_t event_cb_lock;

	struct ljca_stub_packet ipacket;

	/* for identify ack */
	bool acked;
	int cur_cmd;

	struct ljca_event_cb_entry event_entry;
};

static inline void *ljca_priv(const struct ljca_stub *stub)
{
	return (char *)stub + sizeof(struct ljca_stub);
}

enum ljca_state {
	LJCA_STOPPED,
	LJCA_INITED,
	LJCA_RESET_HANDSHAKE,
	LJCA_RESET_SYNCED,
	LJCA_ENUM_GPIO_COMPLETE,
	LJCA_ENUM_I2C_COMPLETE,
	LJCA_ENUM_SPI_COMPLETE,
	LJCA_SUSPEND,
	LJCA_STARTED,
	LJCA_FAILED,
};

struct ljca_dev {
	struct usb_device *udev;
	struct usb_interface *intf;
	u8 in_ep; /* the address of the bulk in endpoint */
	u8 out_ep; /* the address of the bulk out endpoint */

	/* the urb/buffer for read */
	struct urb *in_urb;
	unsigned char *ibuf;
	size_t ibuf_len;

	int state;

	struct list_head stubs_list;

	/* to wait for an ongoing write ack */
	wait_queue_head_t ack_wq;

	struct mfd_cell *cells;
	int cell_count;
	struct mutex mutex;
};

static int try_match_acpi_hid(struct acpi_device *child,
			      struct mfd_cell_acpi_match *match, char **hids,
			      int hids_num)
{
	struct acpi_device_id ids[2] = {};
	int i;

	for (i = 0; i < hids_num; i++) {
		strlcpy(ids[0].id, hids[i], sizeof(ids[0].id));
		if (!acpi_match_device_ids(child, ids)) {
			match->pnpid = hids[i];
			break;
		}
	}

	return 0;
}

static int precheck_acpi_hid(struct usb_interface *intf)
{
	struct acpi_device *parent, *child;

	parent = ACPI_COMPANION(&intf->dev);
	if (!parent)
		return -ENODEV;

	list_for_each_entry (child, &parent->children, node) {
		try_match_acpi_hid(child, &ljca_acpi_match_gpio, gpio_hids,
				   ARRAY_SIZE(gpio_hids));
		try_match_acpi_hid(child, &ljca_acpi_match_i2cs[0], i2c_hids,
				   ARRAY_SIZE(i2c_hids));
		try_match_acpi_hid(child, &ljca_acpi_match_i2cs[1], i2c_hids,
				   ARRAY_SIZE(i2c_hids));
		try_match_acpi_hid(child, &ljca_acpi_match_spis[0], spi_hids,
				   ARRAY_SIZE(spi_hids));
	}

	return 0;
}

static bool ljca_validate(void *data, u32 data_len)
{
	struct ljca_msg *header = (struct ljca_msg *)data;

	return (header->len + sizeof(*header) == data_len);
}

void ljca_dump(struct ljca_dev *ljca, void *buf, int len)
{
	int i;
	u8 tmp[256] = { 0 };
	int n = 0;

	if (!len)
		return;

	for (i = 0; i < len; i++)
		n += scnprintf(tmp + n, sizeof(tmp) - n - 1, "%02x ",
			       ((u8 *)buf)[i]);

	dev_dbg(&ljca->intf->dev, "%s\n", tmp);
}

static struct ljca_stub *ljca_stub_alloc(struct ljca_dev *ljca, int priv_size)
{
	struct ljca_stub *stub;

	stub = kzalloc(sizeof(*stub) + priv_size, GFP_KERNEL);
	if (!stub)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&stub->event_cb_lock);
	INIT_LIST_HEAD(&stub->list);
	list_add_tail(&stub->list, &ljca->stubs_list);
	dev_dbg(&ljca->intf->dev, "enuming a stub success\n");
	return stub;
}

static struct ljca_stub *ljca_stub_find(struct ljca_dev *ljca, u8 type)
{
	struct ljca_stub *stub;

	list_for_each_entry (stub, &ljca->stubs_list, list) {
		if (stub->type == type)
			return stub;
	}

	dev_err(&ljca->intf->dev, "usb stub not find, type: %d", type);
	return ERR_PTR(-ENODEV);
}

static void ljca_stub_notify(struct ljca_stub *stub, u8 cmd,
			     const void *evt_data, int len)
{
	unsigned long flags;
	spin_lock_irqsave(&stub->event_cb_lock, flags);
	if (stub->event_entry.notify && stub->event_entry.pdev)
		stub->event_entry.notify(stub->event_entry.pdev, cmd, evt_data,
					 len);
	spin_unlock_irqrestore(&stub->event_cb_lock, flags);
}

static int ljca_parse(struct ljca_dev *ljca, struct ljca_msg *header)
{
	struct ljca_stub *stub;

	stub = ljca_stub_find(ljca, header->type);
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	if (!(header->flags & ACK_FLAG)) {
		ljca_stub_notify(stub, header->cmd, header->data, header->len);
		return 0;
	}

	if (stub->cur_cmd != header->cmd) {
		dev_err(&ljca->intf->dev, "header->cmd:%x != stub->cur_cmd:%x",
			header->cmd, stub->cur_cmd);
		return -EINVAL;
	}

	stub->ipacket.ibuf_len = header->len;
	if (stub->ipacket.ibuf)
		memcpy(stub->ipacket.ibuf, header->data, header->len);

	stub->acked = true;
	wake_up(&ljca->ack_wq);

	return 0;
}

static int ljca_stub_write(struct ljca_stub *stub, u8 cmd, const void *obuf,
			   int obuf_len, void *ibuf, int *ibuf_len,
			   bool wait_ack, int timeout)
{
	struct ljca_msg *header;
	struct ljca_dev *ljca = usb_get_intfdata(stub->intf);
	int ret;
	u8 flags = CMPL_FLAG;
	int actual;

	if (ljca->state == LJCA_STOPPED)
		return -ENODEV;

	if (obuf_len > MAX_PAYLOAD_SIZE)
		return -EINVAL;

	if (wait_ack)
		flags |= ACK_FLAG;

	stub->ipacket.ibuf_len = 0;
	header = kmalloc(sizeof(*header) + obuf_len, GFP_KERNEL);
	if (!header)
		return -ENOMEM;

	header->type = stub->type;
	header->cmd = cmd;
	header->flags = flags;
	header->len = obuf_len;

	memcpy(header->data, obuf, obuf_len);
	dev_dbg(&ljca->intf->dev, "send: type:%d cmd:%d flags:%d len:%d\n",
		header->type, header->cmd, header->flags, header->len);
	ljca_dump(ljca, header->data, header->len);

	mutex_lock(&ljca->mutex);
	stub->cur_cmd = cmd;
	stub->ipacket.ibuf = ibuf;
	stub->acked = false;
	usb_autopm_get_interface(ljca->intf);
	ret = usb_bulk_msg(ljca->udev,
			   usb_sndbulkpipe(ljca->udev, ljca->out_ep), header,
			   sizeof(struct ljca_msg) + obuf_len, &actual,
			   USB_WRITE_TIMEOUT);
	kfree(header);
	if (ret || actual != sizeof(struct ljca_msg) + obuf_len) {
		dev_err(&ljca->intf->dev,
			"bridge write failed ret:%d total_len:%d\n ", ret,
			actual);
		goto error;
	}

	if (wait_ack) {
		ret = wait_event_timeout(ljca->ack_wq, stub->acked,
					 msecs_to_jiffies(timeout));
		if (!ret || !stub->acked) {
			dev_err(&ljca->intf->dev,
				"acked sem wait timed out ret:%d timeout:%d ack:%d\n",
				ret, timeout, stub->acked);
			ret = -ETIMEDOUT;
			goto error;
		}
	}

	if (ibuf_len)
		*ibuf_len = stub->ipacket.ibuf_len;

	stub->ipacket.ibuf = NULL;
	stub->ipacket.ibuf_len = 0;
	ret = 0;
error:
	usb_autopm_put_interface(ljca->intf);
	mutex_unlock(&ljca->mutex);
	return ret;
}

static int ljca_transfer_internal(struct platform_device *pdev, u8 cmd,
				  const void *obuf, int obuf_len, void *ibuf,
				  int *ibuf_len, bool wait_ack)
{
	struct ljca_platform_data *ljca_pdata;
	struct ljca_dev *ljca;
	struct ljca_stub *stub;

	if (!pdev)
		return -EINVAL;

	ljca = dev_get_drvdata(pdev->dev.parent);
	ljca_pdata = dev_get_platdata(&pdev->dev);
	stub = ljca_stub_find(ljca, ljca_pdata->type);
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	return ljca_stub_write(stub, cmd, obuf, obuf_len, ibuf, ibuf_len,
			       wait_ack, USB_WRITE_ACK_TIMEOUT);
}

int ljca_transfer(struct platform_device *pdev, u8 cmd, const void *obuf,
		  int obuf_len, void *ibuf, int *ibuf_len)
{
	return ljca_transfer_internal(pdev, cmd, obuf, obuf_len, ibuf, ibuf_len,
				      true);
}
EXPORT_SYMBOL_GPL(ljca_transfer);

int ljca_transfer_noack(struct platform_device *pdev, u8 cmd, const void *obuf,
			int obuf_len)
{
	return ljca_transfer_internal(pdev, cmd, obuf, obuf_len, NULL, NULL,
				      false);
}
EXPORT_SYMBOL_GPL(ljca_transfer_noack);

int ljca_register_event_cb(struct platform_device *pdev,
			   ljca_event_cb_t event_cb)
{
	struct ljca_platform_data *ljca_pdata;
	struct ljca_dev *ljca;
	struct ljca_stub *stub;
	unsigned long flags;

	if (!pdev)
		return -EINVAL;

	ljca = dev_get_drvdata(pdev->dev.parent);
	ljca_pdata = dev_get_platdata(&pdev->dev);
	stub = ljca_stub_find(ljca, ljca_pdata->type);
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	spin_lock_irqsave(&stub->event_cb_lock, flags);
	stub->event_entry.notify = event_cb;
	stub->event_entry.pdev = pdev;
	spin_unlock_irqrestore(&stub->event_cb_lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(ljca_register_event_cb);

void ljca_unregister_event_cb(struct platform_device *pdev)
{
	struct ljca_platform_data *ljca_pdata;
	struct ljca_dev *ljca;
	struct ljca_stub *stub;
	unsigned long flags;

	ljca = dev_get_drvdata(pdev->dev.parent);
	ljca_pdata = dev_get_platdata(&pdev->dev);
	stub = ljca_stub_find(ljca, ljca_pdata->type);
	if (IS_ERR(stub))
		return;

	spin_lock_irqsave(&stub->event_cb_lock, flags);
	stub->event_entry.notify = NULL;
	stub->event_entry.pdev = NULL;
	spin_unlock_irqrestore(&stub->event_cb_lock, flags);
}
EXPORT_SYMBOL_GPL(ljca_unregister_event_cb);

static void ljca_stub_cleanup(struct ljca_dev *ljca)
{
	struct ljca_stub *stub;
	struct ljca_stub *next;

	list_for_each_entry_safe (stub, next, &ljca->stubs_list, list) {
		list_del_init(&stub->list);
		kfree(stub);
	}
}

static void ljca_read_complete(struct urb *urb)
{
	struct ljca_dev *ljca = urb->context;
	struct ljca_msg *header = urb->transfer_buffer;
	int len = urb->actual_length;
	int ret;

	dev_dbg(&ljca->intf->dev,
		"bulk read urb got message from fw, status:%d data_len:%d\n",
		urb->status, urb->actual_length);

	BUG_ON(!ljca);
	BUG_ON(!header);

	if (urb->status) {
		/* sync/async unlink faults aren't errors */
		if (urb->status == -ENOENT || urb->status == -ECONNRESET ||
		    urb->status == -ESHUTDOWN)
			return;

		dev_err(&ljca->intf->dev, "read bulk urb transfer failed: %d\n",
			urb->status);
		goto resubmit;
	}

	dev_dbg(&ljca->intf->dev, "receive: type:%d cmd:%d flags:%d len:%d\n",
		header->type, header->cmd, header->flags, header->len);
	ljca_dump(ljca, header->data, header->len);

	if (!ljca_validate(header, len)) {
		dev_err(&ljca->intf->dev,
			"data not correct header->len:%d payload_len:%d\n ",
			header->len, len);
		goto resubmit;
	}

	ret = ljca_parse(ljca, header);
	if (ret)
		dev_err(&ljca->intf->dev,
			"failed to parse data: ret:%d type:%d len: %d", ret,
			header->type, header->len);

resubmit:
	ret = usb_submit_urb(urb, GFP_KERNEL);
	if (ret)
		dev_err(&ljca->intf->dev,
			"failed submitting read urb, error %d\n", ret);
}

static int ljca_start(struct ljca_dev *ljca)
{
	int ret;

	usb_fill_bulk_urb(ljca->in_urb, ljca->udev,
			  usb_rcvbulkpipe(ljca->udev, ljca->in_ep), ljca->ibuf,
			  ljca->ibuf_len, ljca_read_complete, ljca);

	ret = usb_submit_urb(ljca->in_urb, GFP_KERNEL);
	if (ret) {
		dev_err(&ljca->intf->dev,
			"failed submitting read urb, error %d\n", ret);
	}
	return ret;
}

struct ljca_mng_priv {
	long reset_id;
};

static int ljca_mng_reset_handshake(struct ljca_stub *stub)
{
	int ret;
	struct ljca_mng_priv *priv;
	__le32 reset_id;
	__le32 reset_id_ret = 0;
	int ilen;

	priv = ljca_priv(stub);
	reset_id = cpu_to_le32(priv->reset_id++);
	ret = ljca_stub_write(stub, MNG_RESET_NOTIFY, &reset_id,
			      sizeof(reset_id), &reset_id_ret, &ilen, true,
			      USB_WRITE_ACK_TIMEOUT);
	if (ret || ilen != sizeof(reset_id_ret) || reset_id_ret != reset_id) {
		dev_err(&stub->intf->dev,
			"MNG_RESET_NOTIFY failed reset_id:%d/%d ret:%d\n",
			le32_to_cpu(reset_id_ret), le32_to_cpu(reset_id), ret);
		return -EIO;
	}

	return 0;
}

static inline int ljca_mng_reset(struct ljca_stub *stub)
{
	return ljca_stub_write(stub, MNG_RESET, NULL, 0, NULL, NULL, true,
			       USB_WRITE_ACK_TIMEOUT);
}

static int ljca_add_mfd_cell(struct ljca_dev *ljca, struct mfd_cell *cell)
{
	struct mfd_cell *new_cells;

	/* Enumerate the device even if it does not appear in DSDT */
	if (!cell->acpi_match->pnpid)
		dev_warn(&ljca->intf->dev,
			 "The HID of cell %s does not exist in DSDT\n",
			 cell->name);

	new_cells = krealloc_array(ljca->cells, (ljca->cell_count + 1),
				   sizeof(struct mfd_cell), GFP_KERNEL);
	if (!new_cells)
		return -ENOMEM;

	memcpy(&new_cells[ljca->cell_count], cell, sizeof(*cell));
	ljca->cells = new_cells;
	ljca->cell_count++;

	return 0;
}

static int ljca_gpio_stub_init(struct ljca_dev *ljca,
			       struct ljca_gpio_descriptor *desc)
{
	struct ljca_stub *stub;
	struct mfd_cell cell = { 0 };
	struct ljca_platform_data *pdata;
	int gpio_num = desc->pins_per_bank * desc->bank_num;
	int i;
	u32 valid_pin[MAX_GPIO_NUM / (sizeof(u32) * BITS_PER_BYTE)];

	if (gpio_num > MAX_GPIO_NUM)
		return -EINVAL;

	stub = ljca_stub_alloc(ljca, sizeof(*pdata));
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	stub->type = GPIO_STUB;
	stub->intf = ljca->intf;

	pdata = ljca_priv(stub);
	pdata->type = stub->type;
	pdata->gpio_info.num = gpio_num;

	for (i = 0; i < desc->bank_num; i++)
		valid_pin[i] = desc->bank_desc[i].valid_pins;

	bitmap_from_arr32(pdata->gpio_info.valid_pin_map, valid_pin, gpio_num);

	cell.name = "ljca-gpio";
	cell.platform_data = pdata;
	cell.pdata_size = sizeof(*pdata);
	cell.acpi_match = &ljca_acpi_match_gpio;

	return ljca_add_mfd_cell(ljca, &cell);
}

static int ljca_mng_enum_gpio(struct ljca_stub *stub)
{
	struct ljca_dev *ljca = usb_get_intfdata(stub->intf);
	struct ljca_gpio_descriptor *desc;
	int ret;
	int len;

	desc = kzalloc(MAX_PAYLOAD_SIZE, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	ret = ljca_stub_write(stub, MNG_ENUM_GPIO, NULL, 0, desc, &len, true,
			      USB_ENUM_STUB_TIMEOUT);
	if (ret || len != sizeof(*desc) + desc->bank_num *
						  sizeof(desc->bank_desc[0])) {
		dev_err(&stub->intf->dev,
			"enum gpio failed ret:%d len:%d bank_num:%d\n", ret,
			len, desc->bank_num);
		kfree(desc);
		return -EIO;
	}

	ret = ljca_gpio_stub_init(ljca, desc);
	kfree(desc);
	return ret;
}

static int ljca_i2c_stub_init(struct ljca_dev *ljca,
			      struct ljca_i2c_descriptor *desc)
{
	struct ljca_stub *stub;
	struct ljca_platform_data *pdata;
	int i;
	int ret;

	stub = ljca_stub_alloc(ljca, desc->num * sizeof(*pdata));
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	stub->type = I2C_STUB;
	stub->intf = ljca->intf;
	pdata = ljca_priv(stub);

	for (i = 0; i < desc->num; i++) {
		struct mfd_cell cell = { 0 };
		pdata[i].type = stub->type;

		pdata[i].i2c_info.id = desc->info[i].id;
		pdata[i].i2c_info.capacity = desc->info[i].capacity;
		pdata[i].i2c_info.intr_pin = desc->info[i].intr_pin;

		cell.name = "ljca-i2c";
		cell.platform_data = &pdata[i];
		cell.pdata_size = sizeof(pdata[i]);
		if (i < ARRAY_SIZE(ljca_acpi_match_i2cs))
			cell.acpi_match = &ljca_acpi_match_i2cs[i];

		ret = ljca_add_mfd_cell(ljca, &cell);
		if (ret)
			return ret;
	}

	return 0;
}

static int ljca_mng_enum_i2c(struct ljca_stub *stub)
{
	struct ljca_dev *ljca = usb_get_intfdata(stub->intf);
	struct ljca_i2c_descriptor *desc;
	int ret;
	int len;

	desc = kzalloc(MAX_PAYLOAD_SIZE, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	ret = ljca_stub_write(stub, MNG_ENUM_I2C, NULL, 0, desc, &len, true,
			      USB_ENUM_STUB_TIMEOUT);
	if (ret) {
		dev_err(&stub->intf->dev,
			"MNG_ENUM_I2C failed ret:%d len:%d num:%d\n", ret, len,
			desc->num);
		kfree(desc);
		return -EIO;
	}

	ret = ljca_i2c_stub_init(ljca, desc);
	kfree(desc);
	return ret;
}

static int ljca_spi_stub_init(struct ljca_dev *ljca,
			      struct ljca_spi_descriptor *desc)
{
	struct ljca_stub *stub;
	struct ljca_platform_data *pdata;
	int i;
	int ret;

	stub = ljca_stub_alloc(ljca, desc->num * sizeof(*pdata));
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	stub->type = SPI_STUB;
	stub->intf = ljca->intf;
	pdata = ljca_priv(stub);

	for (i = 0; i < desc->num; i++) {
		struct mfd_cell cell = { 0 };
		pdata[i].type = stub->type;

		pdata[i].spi_info.id = desc->info[i].id;
		pdata[i].spi_info.capacity = desc->info[i].capacity;

		cell.name = "ljca-spi";
		cell.platform_data = &pdata[i];
		cell.pdata_size = sizeof(pdata[i]);
		if (i < ARRAY_SIZE(ljca_acpi_match_spis))
			cell.acpi_match = &ljca_acpi_match_spis[i];

		ret = ljca_add_mfd_cell(ljca, &cell);
		if (ret)
			return ret;
	}

	return 0;
}

static int ljca_mng_enum_spi(struct ljca_stub *stub)
{
	struct ljca_dev *ljca = usb_get_intfdata(stub->intf);
	struct ljca_spi_descriptor *desc;
	int ret;
	int len;

	desc = kzalloc(MAX_PAYLOAD_SIZE, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	ret = ljca_stub_write(stub, MNG_ENUM_SPI, NULL, 0, desc, &len, true,
			      USB_ENUM_STUB_TIMEOUT);
	if (ret) {
		dev_err(&stub->intf->dev,
			"MNG_ENUM_SPI failed ret:%d len:%d num:%d\n", ret, len,
			desc->num);
		kfree(desc);
		return -EIO;
	}

	ret = ljca_spi_stub_init(ljca, desc);
	kfree(desc);
	return ret;
}

static int ljca_mng_get_version(struct ljca_stub *stub, char *buf)
{
	struct fw_version version = { 0 };
	int ret;
	int len;

	if (!buf)
		return -EINVAL;

	ret = ljca_stub_write(stub, MNG_GET_VERSION, NULL, 0, &version, &len,
			      true, USB_WRITE_ACK_TIMEOUT);
	if (ret || len < sizeof(struct fw_version)) {
		dev_err(&stub->intf->dev,
			"MNG_GET_VERSION failed ret:%d len:%d\n", ret, len);
		return ret;
	}

	return sysfs_emit(buf, "%d.%d.%d.%d\n", version.major, version.minor,
			  le16_to_cpu(version.patch),
			  le16_to_cpu(version.build));
}

static inline int ljca_mng_set_dfu_mode(struct ljca_stub *stub)
{
	return ljca_stub_write(stub, MNG_SET_DFU_MODE, NULL, 0, NULL, NULL,
			       true, USB_WRITE_ACK_TIMEOUT);
}

static int ljca_mng_link(struct ljca_dev *ljca, struct ljca_stub *stub)
{
	int ret;

	ret = ljca_mng_reset_handshake(stub);
	if (ret)
		return ret;

	ljca->state = LJCA_RESET_SYNCED;

	/* workaround for FW limitation, ignore return value of enum result */
	ljca_mng_enum_gpio(stub);
	ljca->state = LJCA_ENUM_GPIO_COMPLETE;

	ljca_mng_enum_i2c(stub);
	ljca->state = LJCA_ENUM_I2C_COMPLETE;

	ljca_mng_enum_spi(stub);
	ljca->state = LJCA_ENUM_SPI_COMPLETE;

	return 0;
}

static int ljca_mng_init(struct ljca_dev *ljca)
{
	struct ljca_stub *stub;
	struct ljca_mng_priv *priv;
	int ret;

	stub = ljca_stub_alloc(ljca, sizeof(*priv));
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	priv = ljca_priv(stub);
	if (!priv)
		return -ENOMEM;

	priv->reset_id = 0;
	stub->type = MNG_STUB;
	stub->intf = ljca->intf;

	ret = ljca_mng_link(ljca, stub);
	if (ret)
		dev_err(&ljca->intf->dev,
			"mng stub link done ret:%d state:%d\n", ret,
			ljca->state);

	return ret;
}

static inline int ljca_diag_get_fw_log(struct ljca_stub *stub, void *buf)
{
	int ret;
	int len;

	if (!buf)
		return -EINVAL;

	ret = ljca_stub_write(stub, DIAG_GET_FW_LOG, NULL, 0, buf, &len, true,
			      USB_WRITE_ACK_TIMEOUT);
	if (ret)
		return ret;

	return len;
}

static inline int ljca_diag_get_coredump(struct ljca_stub *stub, void *buf)
{
	int ret;
	int len;

	if (!buf)
		return -EINVAL;

	ret = ljca_stub_write(stub, DIAG_GET_FW_COREDUMP, NULL, 0, buf, &len,
			      true, USB_WRITE_ACK_TIMEOUT);
	if (ret)
		return ret;

	return len;
}

static inline int ljca_diag_set_trace_level(struct ljca_stub *stub, u8 level)
{
	return ljca_stub_write(stub, DIAG_SET_TRACE_LEVEL, &level,
			       sizeof(level), NULL, NULL, true,
			       USB_WRITE_ACK_TIMEOUT);
}

static int ljca_diag_init(struct ljca_dev *ljca)
{
	struct ljca_stub *stub;

	stub = ljca_stub_alloc(ljca, 0);
	if (IS_ERR(stub))
		return PTR_ERR(stub);

	stub->type = DIAG_STUB;
	stub->intf = ljca->intf;
	return 0;
}

static void ljca_delete(struct ljca_dev *ljca)
{
	mutex_destroy(&ljca->mutex);
	usb_free_urb(ljca->in_urb);
	usb_put_intf(ljca->intf);
	usb_put_dev(ljca->udev);
	kfree(ljca->ibuf);
	kfree(ljca->cells);
	kfree(ljca);
}

static int ljca_init(struct ljca_dev *ljca)
{
	mutex_init(&ljca->mutex);
	init_waitqueue_head(&ljca->ack_wq);
	INIT_LIST_HEAD(&ljca->stubs_list);

	ljca->state = LJCA_INITED;

	return 0;
}

static void ljca_stop(struct ljca_dev *ljca)
{
	usb_kill_urb(ljca->in_urb);
}

static ssize_t cmd_store(struct device *dev, struct device_attribute *attr,
			 const char *buf, size_t count)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct ljca_dev *ljca = usb_get_intfdata(intf);
	struct ljca_stub *mng_stub = ljca_stub_find(ljca, MNG_STUB);
	struct ljca_stub *diag_stub = ljca_stub_find(ljca, DIAG_STUB);

	if (sysfs_streq(buf, "dfu"))
		ljca_mng_set_dfu_mode(mng_stub);
	else if (sysfs_streq(buf, "reset"))
		ljca_mng_reset(mng_stub);
	else if (sysfs_streq(buf, "debug"))
		ljca_diag_set_trace_level(diag_stub, 3);

	return count;
}

static ssize_t cmd_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	return sysfs_emit(buf, "%s\n", "supported cmd: [dfu, reset, debug]");
}
static DEVICE_ATTR_RW(cmd);

static ssize_t version_show(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct ljca_dev *ljca = usb_get_intfdata(intf);
	struct ljca_stub *stub = ljca_stub_find(ljca, MNG_STUB);

	return ljca_mng_get_version(stub, buf);
}
static DEVICE_ATTR_RO(version);

static ssize_t log_show(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct ljca_dev *ljca = usb_get_intfdata(intf);
	struct ljca_stub *diag_stub = ljca_stub_find(ljca, DIAG_STUB);

	return ljca_diag_get_fw_log(diag_stub, buf);
}
static DEVICE_ATTR_RO(log);

static ssize_t coredump_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct usb_interface *intf = to_usb_interface(dev);
	struct ljca_dev *ljca = usb_get_intfdata(intf);
	struct ljca_stub *diag_stub = ljca_stub_find(ljca, DIAG_STUB);

	return ljca_diag_get_coredump(diag_stub, buf);
}
static DEVICE_ATTR_RO(coredump);

static struct attribute *ljca_attrs[] = {
	&dev_attr_version.attr,
	&dev_attr_cmd.attr,
	&dev_attr_log.attr,
	&dev_attr_coredump.attr,
	NULL,
};
ATTRIBUTE_GROUPS(ljca);

static int ljca_probe(struct usb_interface *intf,
		      const struct usb_device_id *id)
{
	struct ljca_dev *ljca;
	struct usb_endpoint_descriptor *bulk_in, *bulk_out;
	int ret;

	ret = precheck_acpi_hid(intf);
	if (ret)
		return ret;

	/* allocate memory for our device state and initialize it */
	ljca = kzalloc(sizeof(*ljca), GFP_KERNEL);
	if (!ljca)
		return -ENOMEM;

	ljca_init(ljca);
	ljca->udev = usb_get_dev(interface_to_usbdev(intf));
	ljca->intf = usb_get_intf(intf);

	/* set up the endpoint information use only the first bulk-in and bulk-out endpoints */
	ret = usb_find_common_endpoints(intf->cur_altsetting, &bulk_in,
					&bulk_out, NULL, NULL);
	if (ret) {
		dev_err(&intf->dev,
			"Could not find both bulk-in and bulk-out endpoints\n");
		goto error;
	}

	ljca->ibuf_len = usb_endpoint_maxp(bulk_in);
	ljca->in_ep = bulk_in->bEndpointAddress;
	ljca->ibuf = kzalloc(ljca->ibuf_len, GFP_KERNEL);
	if (!ljca->ibuf) {
		ret = -ENOMEM;
		goto error;
	}

	ljca->in_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!ljca->in_urb) {
		ret = -ENOMEM;
		goto error;
	}

	ljca->out_ep = bulk_out->bEndpointAddress;
	dev_dbg(&intf->dev, "bulk_in size:%zu addr:%d bulk_out addr:%d\n",
		ljca->ibuf_len, ljca->in_ep, ljca->out_ep);

	/* save our data pointer in this intf device */
	usb_set_intfdata(intf, ljca);
	ret = ljca_start(ljca);
	if (ret) {
		dev_err(&intf->dev, "bridge read start failed ret %d\n", ret);
		goto error;
	}

	ret = ljca_mng_init(ljca);
	if (ret) {
		dev_err(&intf->dev, "register mng stub failed ret %d\n", ret);
		goto error_stop;
	}

	ret = ljca_diag_init(ljca);
	if (ret) {
		dev_err(&intf->dev, "register diag stub failed ret %d\n", ret);
		goto error_stop;
	}

	ret = mfd_add_hotplug_devices(&intf->dev, ljca->cells,
				      ljca->cell_count);
	if (ret) {
		dev_err(&intf->dev, "failed to add mfd devices to core %d\n",
			ljca->cell_count);
		goto error_stop;
	}

	ljca->state = LJCA_STARTED;
	dev_info(&intf->dev, "LJCA USB device init success\n");
	return 0;
error_stop:
	ljca_stop(ljca);
error:
	dev_err(&intf->dev, "LJCA USB device init failed\n");
	/* this frees allocated memory */
	ljca_stub_cleanup(ljca);
	ljca_delete(ljca);
	return ret;
}

static void ljca_disconnect(struct usb_interface *intf)
{
	struct ljca_dev *ljca;

	ljca = usb_get_intfdata(intf);

	ljca_stop(ljca);
	ljca->state = LJCA_STOPPED;
	mfd_remove_devices(&intf->dev);
	ljca_stub_cleanup(ljca);
	usb_set_intfdata(intf, NULL);
	ljca_delete(ljca);
	dev_info(&intf->dev, "LJCA disconnected\n");
}

static int ljca_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct ljca_dev *ljca = usb_get_intfdata(intf);

	ljca_stop(ljca);
	ljca->state = LJCA_SUSPEND;

	dev_dbg(&intf->dev, "LJCA suspend\n");
	return 0;
}

static int ljca_resume(struct usb_interface *intf)
{
	struct ljca_dev *ljca = usb_get_intfdata(intf);

	ljca->state = LJCA_STARTED;
	dev_dbg(&intf->dev, "LJCA resume\n");
	return ljca_start(ljca);
}

static const struct usb_device_id ljca_table[] = {
	{USB_DEVICE(0x8086, 0x0b63)},
	{}
};
MODULE_DEVICE_TABLE(usb, ljca_table);

static struct usb_driver ljca_driver = {
	.name = "ljca",
	.probe = ljca_probe,
	.disconnect = ljca_disconnect,
	.suspend = ljca_suspend,
	.resume = ljca_resume,
	.id_table = ljca_table,
	.dev_groups = ljca_groups,
	.supports_autosuspend = 1,
};

module_usb_driver(ljca_driver);

MODULE_AUTHOR("Ye Xiang <xiang.ye@intel.com>");
MODULE_AUTHOR("Zhang Lixu <lixu.zhang@intel.com>");
MODULE_DESCRIPTION("Intel La Jolla Cove Adapter USB driver");
MODULE_LICENSE("GPL v2");
