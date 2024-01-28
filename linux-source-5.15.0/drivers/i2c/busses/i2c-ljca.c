// SPDX-License-Identifier: GPL-2.0-only
/*
 * Intel La Jolla Cove Adapter USB-I2C driver
 *
 * Copyright (c) 2021, Intel Corporation.
 */

#include <linux/acpi.h>
#include <linux/i2c.h>
#include <linux/mfd/ljca.h>
#include <linux/module.h>
#include <linux/platform_device.h>

/* I2C commands */
enum i2c_cmd {
	I2C_INIT = 1,
	I2C_XFER,
	I2C_START,
	I2C_STOP,
	I2C_READ,
	I2C_WRITE,
};

enum i2c_address_mode {
	I2C_ADDRESS_MODE_7BIT,
	I2C_ADDRESS_MODE_10BIT,
};

enum xfer_type {
	READ_XFER_TYPE,
	WRITE_XFER_TYPE,
};

#define DEFAULT_I2C_CONTROLLER_ID 1
#define DEFAULT_I2C_CAPACITY 0
#define DEFAULT_I2C_INTR_PIN 0

/* I2C r/w Flags */
#define I2C_SLAVE_TRANSFER_WRITE (0)
#define I2C_SLAVE_TRANSFER_READ (1)

/* i2c init flags */
#define I2C_INIT_FLAG_MODE_MASK (0x1 << 0)
#define I2C_INIT_FLAG_MODE_POLLING (0x0 << 0)
#define I2C_INIT_FLAG_MODE_INTERRUPT (0x1 << 0)

#define I2C_FLAG_ADDR_16BIT (0x1 << 0)

#define I2C_INIT_FLAG_FREQ_MASK (0x3 << 1)
#define I2C_FLAG_FREQ_100K (0x0 << 1)
#define I2C_FLAG_FREQ_400K (0x1 << 1)
#define I2C_FLAG_FREQ_1M (0x2 << 1)

/* I2C Transfer */
struct i2c_xfer {
	u8 id;
	u8 slave;
	u16 flag; /* speed, 8/16bit addr, addr increase, etc */
	u16 addr;
	u16 len;
	u8 data[];
} __packed;

/* I2C raw commands: Init/Start/Read/Write/Stop */
struct i2c_rw_packet {
	u8 id;
	__le16 len;
	u8 data[];
} __packed;

#define LJCA_I2C_MAX_XFER_SIZE 256
#define LJCA_I2C_BUF_SIZE                                                      \
	(LJCA_I2C_MAX_XFER_SIZE + sizeof(struct i2c_rw_packet))

struct ljca_i2c_dev {
	struct platform_device *pdev;
	struct ljca_i2c_info *ctr_info;
	struct i2c_adapter adap;

	u8 obuf[LJCA_I2C_BUF_SIZE];
	u8 ibuf[LJCA_I2C_BUF_SIZE];
};

static u8 ljca_i2c_format_slave_addr(u8 slave_addr, enum i2c_address_mode mode)
{
	if (mode == I2C_ADDRESS_MODE_7BIT)
		return slave_addr << 1;

	return 0xFF;
}

static int ljca_i2c_init(struct ljca_i2c_dev *ljca_i2c, u8 id)
{
	struct i2c_rw_packet *w_packet = (struct i2c_rw_packet *)ljca_i2c->obuf;

	memset(w_packet, 0, sizeof(*w_packet));
	w_packet->id = id;
	w_packet->len = cpu_to_le16(1);
	w_packet->data[0] = I2C_FLAG_FREQ_400K;

	return ljca_transfer(ljca_i2c->pdev, I2C_INIT, w_packet,
			     sizeof(*w_packet) + 1, NULL, NULL);
}

static int ljca_i2c_start(struct ljca_i2c_dev *ljca_i2c, u8 slave_addr,
			  enum xfer_type type)
{
	struct i2c_rw_packet *w_packet = (struct i2c_rw_packet *)ljca_i2c->obuf;
	struct i2c_rw_packet *r_packet = (struct i2c_rw_packet *)ljca_i2c->ibuf;
	int ret;
	int ibuf_len;

	memset(w_packet, 0, sizeof(*w_packet));
	w_packet->id = ljca_i2c->ctr_info->id;
	w_packet->len = cpu_to_le16(1);
	w_packet->data[0] =
		ljca_i2c_format_slave_addr(slave_addr, I2C_ADDRESS_MODE_7BIT);
	w_packet->data[0] |= (type == READ_XFER_TYPE) ?
					   I2C_SLAVE_TRANSFER_READ :
					   I2C_SLAVE_TRANSFER_WRITE;

	ret = ljca_transfer(ljca_i2c->pdev, I2C_START, w_packet,
			    sizeof(*w_packet) + 1, r_packet, &ibuf_len);

	if (ret || ibuf_len < sizeof(*r_packet))
		return -EIO;

	if ((s16)le16_to_cpu(r_packet->len) < 0 ||
	    r_packet->id != w_packet->id) {
		dev_err(&ljca_i2c->adap.dev,
			"i2c start failed len:%d id:%d %d\n",
			(s16)le16_to_cpu(r_packet->len), r_packet->id,
			w_packet->id);
		return -EIO;
	}

	return 0;
}

static int ljca_i2c_stop(struct ljca_i2c_dev *ljca_i2c, u8 slave_addr)
{
	struct i2c_rw_packet *w_packet = (struct i2c_rw_packet *)ljca_i2c->obuf;
	struct i2c_rw_packet *r_packet = (struct i2c_rw_packet *)ljca_i2c->ibuf;
	int ret;
	int ibuf_len;

	memset(w_packet, 0, sizeof(*w_packet));
	w_packet->id = ljca_i2c->ctr_info->id;
	w_packet->len = cpu_to_le16(1);
	w_packet->data[0] = 0;

	ret = ljca_transfer(ljca_i2c->pdev, I2C_STOP, w_packet,
			    sizeof(*w_packet) + 1, r_packet, &ibuf_len);

	if (ret || ibuf_len < sizeof(*r_packet))
		return -EIO;

	if ((s16)le16_to_cpu(r_packet->len) < 0 ||
	    r_packet->id != w_packet->id) {
		dev_err(&ljca_i2c->adap.dev,
			"i2c stop failed len:%d id:%d %d\n",
			(s16)le16_to_cpu(r_packet->len), r_packet->id,
			w_packet->id);
		return -EIO;
	}

	return 0;
}

static int ljca_i2c_pure_read(struct ljca_i2c_dev *ljca_i2c, u8 *data, int len)
{
	struct i2c_rw_packet *w_packet = (struct i2c_rw_packet *)ljca_i2c->obuf;
	struct i2c_rw_packet *r_packet = (struct i2c_rw_packet *)ljca_i2c->ibuf;
	int ibuf_len;
	int ret;

	if (len > LJCA_I2C_MAX_XFER_SIZE)
		return -EINVAL;

	memset(w_packet, 0, sizeof(*w_packet));
	w_packet->id = ljca_i2c->ctr_info->id;
	w_packet->len = cpu_to_le16(len);
	ret = ljca_transfer(ljca_i2c->pdev, I2C_READ, w_packet,
			    sizeof(*w_packet) + 1, r_packet, &ibuf_len);
	if (ret) {
		dev_err(&ljca_i2c->adap.dev, "I2C_READ failed ret:%d\n", ret);
		return ret;
	}

	if (ibuf_len < sizeof(*r_packet))
		return -EIO;

	if ((s16)le16_to_cpu(r_packet->len) != len ||
	    r_packet->id != w_packet->id) {
		dev_err(&ljca_i2c->adap.dev,
			"i2c raw read failed len:%d id:%d %d\n",
			(s16)le16_to_cpu(r_packet->len), r_packet->id,
			w_packet->id);
		return -EIO;
	}

	memcpy(data, r_packet->data, len);

	return 0;
}

static int ljca_i2c_read(struct ljca_i2c_dev *ljca_i2c, u8 slave_addr, u8 *data,
			 u8 len)
{
	int ret;

	ret = ljca_i2c_start(ljca_i2c, slave_addr, READ_XFER_TYPE);
	if (ret)
		return ret;

	ret = ljca_i2c_pure_read(ljca_i2c, data, len);
	if (ret) {
		dev_err(&ljca_i2c->adap.dev, "i2c raw read failed ret:%d\n",
			ret);

		return ret;
	}

	return ljca_i2c_stop(ljca_i2c, slave_addr);
}

static int ljca_i2c_pure_write(struct ljca_i2c_dev *ljca_i2c, u8 *data, u8 len)
{
	struct i2c_rw_packet *w_packet = (struct i2c_rw_packet *)ljca_i2c->obuf;
	struct i2c_rw_packet *r_packet = (struct i2c_rw_packet *)ljca_i2c->ibuf;
	int ret;
	int ibuf_len;

	if (len > LJCA_I2C_MAX_XFER_SIZE)
		return -EINVAL;

	memset(w_packet, 0, sizeof(*w_packet));
	w_packet->id = ljca_i2c->ctr_info->id;
	w_packet->len = cpu_to_le16(len);
	memcpy(w_packet->data, data, len);

	ret = ljca_transfer(ljca_i2c->pdev, I2C_WRITE, w_packet,
			    sizeof(*w_packet) + w_packet->len, r_packet,
			    &ibuf_len);

	if (ret || ibuf_len < sizeof(*r_packet))
		return -EIO;

	if ((s16)le16_to_cpu(r_packet->len) != len ||
	    r_packet->id != w_packet->id) {
		dev_err(&ljca_i2c->adap.dev,
			"i2c write failed len:%d id:%d/%d\n",
			(s16)le16_to_cpu(r_packet->len), r_packet->id,
			w_packet->id);
		return -EIO;
	}

	return 0;
}

static int ljca_i2c_write(struct ljca_i2c_dev *ljca_i2c, u8 slave_addr,
			  u8 *data, u8 len)
{
	int ret;

	if (!data)
		return -EINVAL;

	ret = ljca_i2c_start(ljca_i2c, slave_addr, WRITE_XFER_TYPE);
	if (ret)
		return ret;

	ret = ljca_i2c_pure_write(ljca_i2c, data, len);
	if (ret)
		return ret;

	return ljca_i2c_stop(ljca_i2c, slave_addr);
}

static int ljca_i2c_xfer(struct i2c_adapter *adapter, struct i2c_msg *msg,
			 int num)
{
	struct ljca_i2c_dev *ljca_i2c;
	struct i2c_msg *cur_msg;
	int i, ret;

	ljca_i2c = i2c_get_adapdata(adapter);
	if (!ljca_i2c)
		return -EINVAL;

	for (i = 0; i < num; i++) {
		cur_msg = &msg[i];
		dev_dbg(&adapter->dev, "i:%d msg:(%d %d)\n", i, cur_msg->flags,
			cur_msg->len);
		if (cur_msg->flags & I2C_M_RD)
			ret = ljca_i2c_read(ljca_i2c, cur_msg->addr,
					    cur_msg->buf, cur_msg->len);

		else
			ret = ljca_i2c_write(ljca_i2c, cur_msg->addr,
					     cur_msg->buf, cur_msg->len);

		if (ret)
			return ret;
	}

	return num;
}

static u32 ljca_i2c_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static const struct i2c_adapter_quirks ljca_i2c_quirks = {
	.max_read_len = LJCA_I2C_MAX_XFER_SIZE,
	.max_write_len = LJCA_I2C_MAX_XFER_SIZE,
};

static const struct i2c_algorithm ljca_i2c_algo = {
	.master_xfer = ljca_i2c_xfer,
	.functionality = ljca_i2c_func,
};

static void try_bind_acpi(struct platform_device *pdev,
			  struct ljca_i2c_dev *ljca_i2c)
{
	struct acpi_device *parent, *child;
	struct acpi_device *cur = ACPI_COMPANION(&pdev->dev);
	const char *hid1;
	const char *uid1;
	char uid2[2] = { 0 };

	if (!cur)
		return;

	hid1 = acpi_device_hid(cur);
	uid1 = acpi_device_uid(cur);
	snprintf(uid2, sizeof(uid2), "%d", ljca_i2c->ctr_info->id);

	/*
	* If the pdev is bound to the right acpi device, just forward it to the
	* adapter. Otherwise, we find that of current adapter manually.
	*/
	if (!uid1 || !strcmp(uid1, uid2)) {
		ACPI_COMPANION_SET(&ljca_i2c->adap.dev, cur);
		return;
	}

	dev_dbg(&pdev->dev, "hid %s uid %s new uid%s\n", hid1, uid1, uid2);
	parent = ACPI_COMPANION(pdev->dev.parent);
	if (!parent)
		return;

	list_for_each_entry(child, &parent->children, node) {
		if (acpi_dev_hid_uid_match(child, hid1, uid2)) {
			ACPI_COMPANION_SET(&ljca_i2c->adap.dev, child);
			return;
		}
	}
}

static int ljca_i2c_probe(struct platform_device *pdev)
{
	struct ljca_i2c_dev *ljca_i2c;
	struct ljca_platform_data *pdata = dev_get_platdata(&pdev->dev);
	int ret;

	ljca_i2c = devm_kzalloc(&pdev->dev, sizeof(*ljca_i2c), GFP_KERNEL);
	if (!ljca_i2c)
		return -ENOMEM;

	ljca_i2c->pdev = pdev;
	ljca_i2c->ctr_info = &pdata->i2c_info;

	ljca_i2c->adap.owner = THIS_MODULE;
	ljca_i2c->adap.class = I2C_CLASS_HWMON;
	ljca_i2c->adap.algo = &ljca_i2c_algo;
	ljca_i2c->adap.dev.parent = &pdev->dev;

	try_bind_acpi(pdev, ljca_i2c);

	ljca_i2c->adap.dev.of_node = pdev->dev.of_node;
	i2c_set_adapdata(&ljca_i2c->adap, ljca_i2c);
	snprintf(ljca_i2c->adap.name, sizeof(ljca_i2c->adap.name), "%s-%s-%d",
		 "ljca-i2c", dev_name(pdev->dev.parent),
		 ljca_i2c->ctr_info->id);

	platform_set_drvdata(pdev, ljca_i2c);

	ret = ljca_i2c_init(ljca_i2c, ljca_i2c->ctr_info->id);
	if (ret) {
		dev_err(&pdev->dev, "i2c init failed id:%d\n",
			ljca_i2c->ctr_info->id);
		return -EIO;
	}

	return i2c_add_adapter(&ljca_i2c->adap);
}

static int ljca_i2c_remove(struct platform_device *pdev)
{
	struct ljca_i2c_dev *ljca_i2c = platform_get_drvdata(pdev);

	i2c_del_adapter(&ljca_i2c->adap);

	return 0;
}

static struct platform_driver ljca_i2c_driver = {
	.driver.name = "ljca-i2c",
	.probe = ljca_i2c_probe,
	.remove = ljca_i2c_remove,
};

module_platform_driver(ljca_i2c_driver);

MODULE_AUTHOR("Ye Xiang <xiang.ye@intel.com>");
MODULE_AUTHOR("Zhang Lixu <lixu.zhang@intel.com>");
MODULE_DESCRIPTION("Intel La Jolla Cove Adapter USB-I2C driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:ljca-i2c");
