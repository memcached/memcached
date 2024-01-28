// SPDX-License-Identifier: GPL-2.0-only
/*
 * Intel La Jolla Cove Adapter USB-SPI driver
 *
 * Copyright (c) 2021, Intel Corporation.
 */

#include <linux/acpi.h>
#include <linux/mfd/ljca.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/spi/spi.h>

/* SPI commands */
enum ljca_spi_cmd {
	LJCA_SPI_INIT = 1,
	LJCA_SPI_READ,
	LJCA_SPI_WRITE,
	LJCA_SPI_WRITEREAD,
	LJCA_SPI_DEINIT,
};

#define LJCA_SPI_BUS_MAX_HZ 48000000
enum {
	LJCA_SPI_BUS_SPEED_24M,
	LJCA_SPI_BUS_SPEED_12M,
	LJCA_SPI_BUS_SPEED_8M,
	LJCA_SPI_BUS_SPEED_6M,
	LJCA_SPI_BUS_SPEED_4_8M, /*4.8MHz*/
	LJCA_SPI_BUS_SPEED_MIN = LJCA_SPI_BUS_SPEED_4_8M,
};

enum {
	LJCA_SPI_CLOCK_LOW_POLARITY,
	LJCA_SPI_CLOCK_HIGH_POLARITY,
};

enum {
	LJCA_SPI_CLOCK_FIRST_PHASE,
	LJCA_SPI_CLOCK_SECOND_PHASE,
};

#define LJCA_SPI_BUF_SIZE 60
#define LJCA_SPI_MAX_XFER_SIZE                                                 \
	(LJCA_SPI_BUF_SIZE - sizeof(struct spi_xfer_packet))
union spi_clock_mode {
	struct {
		u8 polarity : 1;
		u8 phrase : 1;
		u8 reserved : 6;
	} u;

	u8 mode;
} __packed;

struct spi_init_packet {
	u8 index;
	u8 speed;
	union spi_clock_mode mode;
} __packed;

struct spi_xfer_indicator {
	u8 id : 6;
	u8 cmpl : 1;
	u8 index : 1;
};

struct spi_xfer_packet {
	struct spi_xfer_indicator indicator;
	s8 len;
	u8 data[];
} __packed;

struct ljca_spi_dev {
	struct platform_device *pdev;
	struct ljca_spi_info *ctr_info;
	struct spi_master *master;
	u8 speed;
	u8 mode;

	u8 obuf[LJCA_SPI_BUF_SIZE];
	u8 ibuf[LJCA_SPI_BUF_SIZE];
};

static int ljca_spi_read_write(struct ljca_spi_dev *ljca_spi, const u8 *w_data,
			       u8 *r_data, int len, int id, int complete,
			       int cmd)
{
	struct spi_xfer_packet *w_packet =
		(struct spi_xfer_packet *)ljca_spi->obuf;
	struct spi_xfer_packet *r_packet =
		(struct spi_xfer_packet *)ljca_spi->ibuf;
	int ret;
	int ibuf_len;

	w_packet->indicator.index = ljca_spi->ctr_info->id;
	w_packet->indicator.id = id;
	w_packet->indicator.cmpl = complete;

	if (cmd == LJCA_SPI_READ) {
		w_packet->len = sizeof(u16);
		*(u16 *)&w_packet->data[0] = len;
	} else {
		w_packet->len = len;
		memcpy(w_packet->data, w_data, len);
	}

	ret = ljca_transfer(ljca_spi->pdev, cmd, w_packet,
			    sizeof(*w_packet) + w_packet->len, r_packet,
			    &ibuf_len);
	if (ret)
		return ret;

	if (ibuf_len < sizeof(*r_packet) || r_packet->len <= 0) {
		dev_err(&ljca_spi->pdev->dev, "receive patcket error len %d\n",
			r_packet->len);
		return -EIO;
	}

	if (r_data)
		memcpy(r_data, r_packet->data, r_packet->len);

	return 0;
}

static int ljca_spi_init(struct ljca_spi_dev *ljca_spi, int div, int mode)
{
	struct spi_init_packet w_packet = { 0 };
	int ret;

	if (ljca_spi->mode == mode && ljca_spi->speed == div)
		return 0;

	if (mode & SPI_CPOL)
		w_packet.mode.u.polarity = LJCA_SPI_CLOCK_HIGH_POLARITY;
	else
		w_packet.mode.u.polarity = LJCA_SPI_CLOCK_LOW_POLARITY;

	if (mode & SPI_CPHA)
		w_packet.mode.u.phrase = LJCA_SPI_CLOCK_SECOND_PHASE;
	else
		w_packet.mode.u.phrase = LJCA_SPI_CLOCK_FIRST_PHASE;

	w_packet.index = ljca_spi->ctr_info->id;
	w_packet.speed = div;
	ret = ljca_transfer(ljca_spi->pdev, LJCA_SPI_INIT, &w_packet,
			    sizeof(w_packet), NULL, NULL);
	if (ret)
		return ret;

	ljca_spi->mode = mode;
	ljca_spi->speed = div;
	return 0;
}

static int ljca_spi_deinit(struct ljca_spi_dev *ljca_spi)
{
	struct spi_init_packet w_packet = { 0 };

	w_packet.index = ljca_spi->ctr_info->id;
	return ljca_transfer(ljca_spi->pdev, LJCA_SPI_DEINIT, &w_packet,
			     sizeof(w_packet), NULL, NULL);
}

static int ljca_spi_transfer(struct ljca_spi_dev *ljca_spi, const u8 *tx_data,
			     u8 *rx_data, u16 len)
{
	int ret;
	int remaining = len;
	int offset = 0;
	int cur_len;
	int complete = 0;
	int i;

	for (i = 0; remaining > 0;
	     offset += cur_len, remaining -= cur_len, i++) {
		dev_dbg(&ljca_spi->pdev->dev,
			"fragment %d offset %d remaining %d ret %d\n", i,
			offset, remaining, ret);

		if (remaining > LJCA_SPI_MAX_XFER_SIZE) {
			cur_len = LJCA_SPI_MAX_XFER_SIZE;
		} else {
			cur_len = remaining;
			complete = 1;
		}

		if (tx_data && rx_data)
			ret = ljca_spi_read_write(ljca_spi, tx_data + offset,
						  rx_data + offset, cur_len, i,
						  complete, LJCA_SPI_WRITEREAD);
		else if (tx_data)
			ret = ljca_spi_read_write(ljca_spi, tx_data + offset,
						  NULL, cur_len, i, complete,
						  LJCA_SPI_WRITE);
		else if (rx_data)
			ret = ljca_spi_read_write(ljca_spi, NULL,
						  rx_data + offset, cur_len, i,
						  complete, LJCA_SPI_READ);
		else
			return -EINVAL;

		if (ret)
			return ret;
	}

	return 0;
}

static int ljca_spi_prepare_message(struct spi_master *master,
				    struct spi_message *message)
{
	struct ljca_spi_dev *ljca_spi = spi_master_get_devdata(master);
	struct spi_device *spi = message->spi;

	dev_dbg(&ljca_spi->pdev->dev, "cs %d\n", spi->chip_select);
	return 0;
}

static int ljca_spi_transfer_one(struct spi_master *master,
				 struct spi_device *spi,
				 struct spi_transfer *xfer)
{
	struct ljca_spi_dev *ljca_spi = spi_master_get_devdata(master);
	int ret;
	int div;

	div = DIV_ROUND_UP(master->max_speed_hz, xfer->speed_hz) / 2 - 1;
	if (div > LJCA_SPI_BUS_SPEED_MIN)
		div = LJCA_SPI_BUS_SPEED_MIN;

	ret = ljca_spi_init(ljca_spi, div, spi->mode);
	if (ret < 0) {
		dev_err(&ljca_spi->pdev->dev,
			"cannot initialize transfer ret %d\n", ret);
		return ret;
	}

	ret = ljca_spi_transfer(ljca_spi, xfer->tx_buf, xfer->rx_buf,
				xfer->len);
	if (ret < 0)
		dev_err(&ljca_spi->pdev->dev, "ljca spi transfer failed!\n");

	return ret;
}

static int ljca_spi_probe(struct platform_device *pdev)
{
	struct spi_master *master;
	struct ljca_spi_dev *ljca_spi;
	struct ljca_platform_data *pdata = dev_get_platdata(&pdev->dev);
	int ret;

	master = spi_alloc_master(&pdev->dev, sizeof(*ljca_spi));
	if (!master)
		return -ENOMEM;

	platform_set_drvdata(pdev, master);
	ljca_spi = spi_master_get_devdata(master);

	ljca_spi->ctr_info = &pdata->spi_info;
	ljca_spi->master = master;
	ljca_spi->master->dev.of_node = pdev->dev.of_node;
	ljca_spi->pdev = pdev;

	ACPI_COMPANION_SET(&ljca_spi->master->dev, ACPI_COMPANION(&pdev->dev));

	master->bus_num = -1;
	master->mode_bits = SPI_CPHA | SPI_CPOL;
	master->prepare_message = ljca_spi_prepare_message;
	master->transfer_one = ljca_spi_transfer_one;
	master->auto_runtime_pm = false;
	master->max_speed_hz = LJCA_SPI_BUS_MAX_HZ;

	ret = devm_spi_register_master(&pdev->dev, master);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to register master\n");
		goto exit_free_master;
	}

	return ret;

exit_free_master:
	spi_master_put(master);
	return ret;
}

static int ljca_spi_dev_remove(struct platform_device *pdev)
{
	struct spi_master *master = spi_master_get(platform_get_drvdata(pdev));
	struct ljca_spi_dev *ljca_spi = spi_master_get_devdata(master);

	ljca_spi_deinit(ljca_spi);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int ljca_spi_dev_suspend(struct device *dev)
{
	struct spi_master *master = dev_get_drvdata(dev);

	return spi_master_suspend(master);
}

static int ljca_spi_dev_resume(struct device *dev)
{
	struct spi_master *master = dev_get_drvdata(dev);

	return spi_master_resume(master);
}
#endif /* CONFIG_PM_SLEEP */

static const struct dev_pm_ops ljca_spi_pm = {
	SET_SYSTEM_SLEEP_PM_OPS(ljca_spi_dev_suspend, ljca_spi_dev_resume)
};

static struct platform_driver spi_ljca_driver = {
	.driver = {
		.name	= "ljca-spi",
		.pm	= &ljca_spi_pm,
	},
	.probe		= ljca_spi_probe,
	.remove		= ljca_spi_dev_remove,
};

module_platform_driver(spi_ljca_driver);

MODULE_AUTHOR("Ye Xiang <xiang.ye@intel.com>");
MODULE_DESCRIPTION("Intel La Jolla Cove Adapter USB-SPI driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:ljca-spi");
