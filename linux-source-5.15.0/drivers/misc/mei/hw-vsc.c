// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021, Intel Corporation. All rights reserved.
 * Intel Management Engine Interface (Intel MEI) Linux driver
 */
#include <linux/crc32.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/sizes.h>
#include <linux/swap.h>
#include <linux/types.h>

#include "hw-vsc.h"

static int spi_dev_xfer(struct mei_vsc_hw *hw, void *out_data, void *in_data,
			int len)
{
	hw->xfer.tx_buf = out_data;
	hw->xfer.rx_buf = in_data;
	hw->xfer.len = len;

	spi_message_init_with_transfers(&hw->msg, &hw->xfer, 1);
	return spi_sync_locked(hw->spi, &hw->msg);
}

#define SPI_XFER_PACKET_CRC(pkt) (*(u32 *)(pkt->buf + pkt->hdr.len))
static int spi_validate_packet(struct mei_vsc_hw *hw,
			       struct spi_xfer_packet *pkt)
{
	u32 base_crc;
	u32 crc;
	struct spi_xfer_hdr *hdr = &pkt->hdr;

	base_crc = SPI_XFER_PACKET_CRC(pkt);
	crc = ~crc32(~0, (u8 *)pkt, sizeof(struct spi_xfer_hdr) + pkt->hdr.len);

	if (base_crc != crc) {
		dev_err(&hw->spi->dev, "%s crc error cmd %x 0x%x 0x%x\n",
			__func__, hdr->cmd, base_crc, crc);
		return -EINVAL;
	}

	if (hdr->cmd == CMD_SPI_FATAL_ERR) {
		dev_err(&hw->spi->dev,
			"receive fatal error from FW cmd %d %d %d.\nCore dump: %s\n",
			hdr->cmd, hdr->seq, hw->seq, (char *)pkt->buf);
		return -EIO;
	} else if (hdr->cmd == CMD_SPI_NACK || hdr->cmd == CMD_SPI_BUSY ||
		   hdr->seq != hw->seq) {
		dev_err(&hw->spi->dev, "receive error from FW cmd %d %d %d\n",
			hdr->cmd, hdr->seq, hw->seq);
		return -EAGAIN;
	}

	return 0;
}

static inline bool spi_rom_xfer_asserted(struct mei_vsc_hw *hw)
{
	return gpiod_get_value_cansleep(hw->wakeuphost);
}

static inline bool spi_xfer_asserted(struct mei_vsc_hw *hw)
{
	return atomic_read(&hw->lock_cnt) > 0 &&
	       gpiod_get_value_cansleep(hw->wakeuphost);
}

static void spi_xfer_lock(struct mei_vsc_hw *hw)
{
	gpiod_set_value_cansleep(hw->wakeupfw, 0);
}

static void spi_xfer_unlock(struct mei_vsc_hw *hw)
{
	atomic_dec_if_positive(&hw->lock_cnt);
	gpiod_set_value_cansleep(hw->wakeupfw, 1);
}

static bool spi_xfer_locked(struct mei_vsc_hw *hw)
{
	return !gpiod_get_value_cansleep(hw->wakeupfw);
}

static bool spi_need_read(struct mei_vsc_hw *hw)
{
	return spi_xfer_asserted(hw) && !spi_xfer_locked(hw);
}

#define WAIT_FW_ASSERTED_TIMEOUT (2 * HZ)
static int spi_xfer_wait_asserted(struct mei_vsc_hw *hw)
{
	wait_event_timeout(hw->xfer_wait, spi_xfer_asserted(hw),
			   WAIT_FW_ASSERTED_TIMEOUT);

	dev_dbg(&hw->spi->dev, "%s %d %d %d\n", __func__,
		atomic_read(&hw->lock_cnt),
		gpiod_get_value_cansleep(hw->wakeupfw),
		gpiod_get_value_cansleep(hw->wakeuphost));
	if (!spi_xfer_asserted(hw))
		return -ETIME;
	else
		return 0;
}

static int spi_wakeup_request(struct mei_vsc_hw *hw)
{
	/* wakeup spi slave and wait for response */
	spi_xfer_lock(hw);
	return spi_xfer_wait_asserted(hw);
}

static void spi_wakeup_release(struct mei_vsc_hw *hw)
{
	return spi_xfer_unlock(hw);
}

static int find_sync_byte(u8 *buf, int len)
{
	int i;

	for (i = 0; i < len; i++)
		if (buf[i] == PACKET_SYNC)
			return i;

	return -1;
}

#define PACKET_PADDING_SIZE 1
#define MAX_XFER_COUNT 5
static int mei_vsc_xfer_internal(struct mei_vsc_hw *hw,
				 struct spi_xfer_packet *pkt,
				 struct spi_xfer_packet *ack_pkt)
{
	u8 *rx_buf = hw->rx_buf1;
	u8 *tx_buf = hw->tx_buf1;
	int next_xfer_len = PACKET_SIZE(pkt) + XFER_TIMEOUT_BYTES;
	int offset = 0;
	bool synced = false;
	int len;
	int count_down = MAX_XFER_COUNT;
	int ret = 0;
	int i;

	dev_dbg(&hw->spi->dev, "spi tx pkt begin: %s %d %d\n", __func__,
		spi_xfer_asserted(hw), gpiod_get_value_cansleep(hw->wakeupfw));
	memcpy(tx_buf, pkt, PACKET_SIZE(pkt));
	memset(rx_buf, 0, MAX_XFER_BUFFER_SIZE);

	do {
		dev_dbg(&hw->spi->dev,
			"spi tx pkt partial ing: %s %d %d %d %d\n", __func__,
			spi_xfer_asserted(hw),
			gpiod_get_value_cansleep(hw->wakeupfw), next_xfer_len,
			synced);

		count_down--;
		ret = spi_dev_xfer(hw, tx_buf, rx_buf, next_xfer_len);
		if (ret)
			return ret;

		memset(tx_buf, 0, MAX_XFER_BUFFER_SIZE);
		if (!synced) {
			i = find_sync_byte(rx_buf, next_xfer_len);
			if (i >= 0) {
				synced = true;
				len = next_xfer_len - i;
			} else {
				continue;
			}

		} else {
			i = 0;
			len = min_t(int, next_xfer_len,
				    sizeof(*ack_pkt) - offset);
		}

		memcpy(&ack_pkt[offset], &rx_buf[i], len);
		offset += len;

		if (offset >= sizeof(ack_pkt->hdr))
			next_xfer_len = PACKET_SIZE(ack_pkt) - offset +
					PACKET_PADDING_SIZE;

	} while (next_xfer_len > 0 && count_down > 0);

	dev_dbg(&hw->spi->dev, "spi tx pkt done: %s %d %d cmd %d %d %d %d\n",
		__func__, next_xfer_len, count_down, ack_pkt->hdr.sync,
		ack_pkt->hdr.cmd, ack_pkt->hdr.len, ack_pkt->hdr.seq);

	if (next_xfer_len > 0)
		return -EAGAIN;

	return spi_validate_packet(hw, ack_pkt);
}

static int mei_vsc_xfer(struct mei_vsc_hw *hw, u8 cmd, void *tx, u32 tx_len,
			void *rx, int rx_max_len, u32 *rx_len)
{
	struct spi_xfer_packet *pkt;
	struct spi_xfer_packet *ack_pkt;
	u32 *crc;
	int ret;

	if (!tx || !rx || tx_len > MAX_SPI_MSG_SIZE)
		return -EINVAL;

	if (rx_len)
		*rx_len = 0;

	pkt = kzalloc(sizeof(*pkt) + sizeof(*ack_pkt), GFP_KERNEL);
	ack_pkt = pkt + 1;
	if (!pkt || !ack_pkt)
		return -ENOMEM;

	pkt->hdr.sync = PACKET_SYNC;
	pkt->hdr.cmd = cmd;
	pkt->hdr.seq = ++hw->seq;
	pkt->hdr.len = tx_len;

	memcpy(pkt->buf, tx, tx_len);
	crc = (u32 *)(pkt->buf + tx_len);
	*crc = ~crc32(~0, (u8 *)pkt, sizeof(pkt->hdr) + tx_len);

	mutex_lock(&hw->mutex);

	ret = spi_wakeup_request(hw);
	if (ret) {
		dev_err(&hw->spi->dev, "wakeup vsc FW failed\n");
		goto out;
	}

	ret = mei_vsc_xfer_internal(hw, pkt, ack_pkt);
	if (ret)
		goto out;

	if (ack_pkt->hdr.len > 0) {
		int len;

		len = (ack_pkt->hdr.len < rx_max_len) ? ack_pkt->hdr.len :
							      rx_max_len;
		memcpy(rx, ack_pkt->buf, len);
		if (rx_len)
			*rx_len = len;
	}

out:
	spi_wakeup_release(hw);
	mutex_unlock(&hw->mutex);
	kfree(pkt);
	return ret;
}

static int mei_vsc_read_raw(struct mei_vsc_hw *hw, u8 *buf, u32 max_len,
			    u32 *len)
{
	struct host_timestamp ts = { 0 };

	ts.realtime = ktime_to_ns(ktime_get_real());
	ts.boottime = ktime_to_ns(ktime_get_boottime());

	return mei_vsc_xfer(hw, CMD_SPI_READ, &ts, sizeof(ts), buf, max_len,
			    len);
}

static int mei_vsc_write_raw(struct mei_vsc_hw *hw, u8 *buf, u32 len)
{
	u8 status = 0;
	int rx_len;

	return mei_vsc_xfer(hw, CMD_SPI_WRITE, buf, len, &status,
			    sizeof(status), &rx_len);
}

#define LOADER_XFER_RETRY_COUNT 25
static int spi_rom_dev_xfer(struct mei_vsc_hw *hw, void *out_data,
			    void *in_data, int len)
{
	int ret;
	int i;
	u32 *tmp = out_data;
	int retry = 0;

	if (len % 4 != 0)
		return -EINVAL;

	for (i = 0; i < len / 4; i++)
		tmp[i] = ___constant_swab32(tmp[i]);

	mutex_lock(&hw->mutex);
	while (retry < LOADER_XFER_RETRY_COUNT) {
		if (!spi_rom_xfer_asserted(hw))
			break;

		msleep(20);
		retry++;
	}

	if (retry >= LOADER_XFER_RETRY_COUNT) {
		dev_err(&hw->spi->dev, "%s retry %d times gpio %d\n", __func__,
			retry, spi_rom_xfer_asserted(hw));
		mutex_unlock(&hw->mutex);
		return -EAGAIN;
	}

	ret = spi_dev_xfer(hw, out_data, in_data, len);
	mutex_unlock(&hw->mutex);
	if (!in_data || ret)
		return ret;

	tmp = in_data;
	for (i = 0; i < len / 4; i++)
		tmp[i] = ___constant_swab32(tmp[i]);

	return 0;
}

#define VSC_RESET_PIN_TOGGLE_INTERVAL 20
#define VSC_ROM_BOOTUP_DELAY_TIME 10
static int vsc_reset(struct mei_device *dev)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);

	gpiod_set_value_cansleep(hw->resetfw, 1);
	msleep(VSC_RESET_PIN_TOGGLE_INTERVAL);
	gpiod_set_value_cansleep(hw->resetfw, 0);
	msleep(VSC_RESET_PIN_TOGGLE_INTERVAL);
	gpiod_set_value_cansleep(hw->resetfw, 1);
	msleep(VSC_ROM_BOOTUP_DELAY_TIME);
	/* set default host wake pin to 1, which try to avoid unexpected host irq interrupt */
	gpiod_set_value_cansleep(hw->wakeupfw, 1);
	return 0;
}

/* %s is sensor name, need to be get and format in runtime */
static char *fw_name_template[][3] = {
	{
		"vsc/soc_a1/ivsc_fw_a1.bin",
		"vsc/soc_a1/ivsc_pkg_%s_0_a1.bin",
		"vsc/soc_a1/ivsc_skucfg_%s_0_1_a1.bin",
	},
	{
		"vsc/soc_a1_prod/ivsc_fw_a1_prod.bin",
		"vsc/soc_a1_prod/ivsc_pkg_%s_0_a1_prod.bin",
		"vsc/soc_a1_prod/ivsc_skucfg_%s_0_1_a1_prod.bin",
	},
};

static int check_silicon(struct mei_device *dev)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	struct vsc_rom_master_frame *frame =
		(struct vsc_rom_master_frame *)hw->fw.tx_buf;
	struct vsc_rom_slave_token *token =
		(struct vsc_rom_slave_token *)hw->fw.rx_buf;
	int ret;
	u32 efuse1;
	u32 strap;

	dev_dbg(dev->dev, "%s size %zu %zu\n", __func__, sizeof(*frame),
		sizeof(*token));
	frame->magic = VSC_MAGIC_NUM;
	frame->cmd = VSC_CMD_DUMP_MEM;

	frame->data.dump_mem.addr = EFUSE1_ADDR;
	frame->data.dump_mem.len = 4;

	ret = spi_rom_dev_xfer(hw, frame, token, VSC_ROM_SPI_PKG_SIZE);
	if (ret || token->token == VSC_TOKEN_ERROR) {
		dev_err(dev->dev, "%s %d %d %d\n", __func__, __LINE__, ret,
			token->token);
		return ret;
	}

	memset(frame, 0, sizeof(*frame));
	memset(token, 0, sizeof(*token));
	frame->magic = VSC_MAGIC_NUM;
	frame->cmd = VSC_CMD_RESERVED;
	ret = spi_rom_dev_xfer(hw, frame, token, VSC_ROM_SPI_PKG_SIZE);
	if (ret || token->token == VSC_TOKEN_ERROR ||
	    token->token != VSC_TOKEN_DUMP_RESP) {
		dev_err(dev->dev, "%s %d %d %d\n", __func__, __LINE__, ret,
			token->token);
		return -EIO;
	}

	efuse1 = *(u32 *)token->payload;
	dev_dbg(dev->dev, "%s efuse1=%d\n", __func__, efuse1);

	/* to check the silicon main and sub version */
	hw->fw.main_ver = (efuse1 >> SI_MAINSTEPPING_VERSION_OFFSET) &
			  SI_MAINSTEPPING_VERSION_MASK;
	hw->fw.sub_ver = (efuse1 >> SI_SUBSTEPPING_VERSION_OFFSET) &
			 SI_SUBSTEPPING_VERSION_MASK;
	if (hw->fw.main_ver != SI_MAINSTEPPING_VERSION_A) {
		dev_err(dev->dev, "%s:  silicon main version error(%d)\n",
			__func__, hw->fw.main_ver);
		return -EINVAL;
	}
	if (hw->fw.sub_ver != SI_SUBSTEPPING_VERSION_0 &&
	    hw->fw.sub_ver != SI_SUBSTEPPING_VERSION_1) {
		dev_dbg(dev->dev, "%s: silicon sub version error(%d)\n", __func__,
			hw->fw.sub_ver);
		return -EINVAL;
	}

	/* to get the silicon strap key: debug or production ? */
	memset(frame, 0, sizeof(*frame));
	memset(token, 0, sizeof(*token));
	frame->magic = VSC_MAGIC_NUM;
	frame->cmd = VSC_CMD_DUMP_MEM;
	frame->data.dump_mem.addr = STRAP_ADDR;
	frame->data.dump_mem.len = 4;

	ret = spi_rom_dev_xfer(hw, frame, token, VSC_ROM_SPI_PKG_SIZE);
	if (ret || token->token == VSC_TOKEN_ERROR) {
		dev_err(dev->dev, "%s: transfer failed or invalid token\n",
			__func__);
		return ret;
	}

	frame->magic = VSC_MAGIC_NUM;
	frame->cmd = VSC_CMD_RESERVED;
	ret = spi_rom_dev_xfer(hw, frame, token, VSC_ROM_SPI_PKG_SIZE);
	if (ret || token->token == VSC_TOKEN_ERROR ||
	    token->token != VSC_TOKEN_DUMP_RESP) {
		dev_err(dev->dev,
			"%s: transfer failed or invalid token-> (token = %d)\n",
			__func__, token->token);
		return -EINVAL;
	}

	dev_dbg(dev->dev,
		"%s:  getting the memory(0x%0x), step 2 payload: 0x%0x\n",
		__func__, STRAP_ADDR, *(u32 *)token->payload);

	strap = *(u32 *)token->payload;
	dev_dbg(dev->dev, "%s:  strap = 0x%x\n", __func__, strap);

	/* to check the silicon strap key source */
	hw->fw.key_src =
		(strap >> SI_STRAP_KEY_SRC_OFFSET) & SI_STRAP_KEY_SRC_MASK;

	dev_dbg(dev->dev, "%s: silicon version check done: %s%s\n", __func__,
		hw->fw.sub_ver == SI_SUBSTEPPING_VERSION_0 ? "A0" : "A1",
		hw->fw.key_src == SI_STRAP_KEY_SRC_DEBUG ? "" : "-prod");
	if (hw->fw.sub_ver == SI_SUBSTEPPING_VERSION_1) {
		if (hw->fw.key_src == SI_STRAP_KEY_SRC_DEBUG) {
			snprintf(hw->fw.fw_file_name,
				 sizeof(hw->fw.fw_file_name),
				 fw_name_template[0][0]);
			snprintf(hw->fw.sensor_file_name,
				 sizeof(hw->fw.sensor_file_name),
				 fw_name_template[0][1], hw->cam_sensor_name);
			snprintf(hw->fw.sku_cnf_file_name,
				 sizeof(hw->fw.sku_cnf_file_name),
				 fw_name_template[0][2], hw->cam_sensor_name);
		} else {
			snprintf(hw->fw.fw_file_name,
				 sizeof(hw->fw.fw_file_name),
				 fw_name_template[1][0]);
			snprintf(hw->fw.sensor_file_name,
				 sizeof(hw->fw.sensor_file_name),
				 fw_name_template[1][1], hw->cam_sensor_name);
			snprintf(hw->fw.sku_cnf_file_name,
				 sizeof(hw->fw.sku_cnf_file_name),
				 fw_name_template[1][2], hw->cam_sensor_name);
		}
	}

	return 0;
}

static int parse_main_fw(struct mei_device *dev, const struct firmware *fw)
{
	struct bootloader_sign *bootloader = NULL;
	struct firmware_sign *arc_sem = NULL;
	struct firmware_sign *em7d = NULL;
	struct firmware_sign *ace_run = NULL;
	struct firmware_sign *ace_vis = NULL;
	struct firmware_sign *ace_conf = NULL;
	struct vsc_boot_img *img = (struct vsc_boot_img *)fw->data;
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	struct manifest *man = NULL;
	struct fragment *bootl_frag = &hw->fw.frags[BOOT_IMAGE_TYPE];
	struct fragment *arcsem_frag = &hw->fw.frags[ARC_SEM_IMG_TYPE];
	struct fragment *acer_frag = &hw->fw.frags[ACER_IMG_TYPE];
	struct fragment *acev_frag = &hw->fw.frags[ACEV_IMG_TYPE];
	struct fragment *acec_frag = &hw->fw.frags[ACEC_IMG_TYPE];
	struct fragment *em7d_frag = &hw->fw.frags[EM7D_IMG_TYPE];
	struct firmware_sign *firmwares[IMG_CNT_MAX];
	int i;

	if (!img || img->magic != VSC_FILE_MAGIC) {
		dev_err(dev->dev, "image file error\n");
		return -EINVAL;
	}

	if (img->image_count < IMG_BOOT_ARC_EM7D ||
	    img->image_count > IMG_CNT_MAX) {
		dev_err(dev->dev, "%s: image count error: image_count=0x%x\n",
			__func__, img->image_count);
		return -EINVAL;
	}

	dev_dbg(dev->dev, "%s: img->image_count=%d\n", __func__,
		img->image_count);

	/* only two lower bytes are used */
	hw->fw.fw_option = img->option & 0xFFFF;
	/* image not include bootloader */
	hw->fw.fw_cnt = img->image_count - 1;

	bootloader =
		(struct bootloader_sign *)(img->image_loc + img->image_count);
	if ((u8 *)bootloader > (fw->data + fw->size))
		return -EINVAL;

	if (bootloader->magic != VSC_FW_MAGIC) {
		dev_err(dev->dev,
			"bootloader signed magic error! magic number 0x%08x, image size 0x%08x\n",
			bootloader->magic, bootloader->image_size);
		return -EINVAL;
	}

	man = (struct manifest *)((char *)bootloader->image +
				  bootloader->image_size - SIG_SIZE -
				  sizeof(struct manifest) - CSSHEADER_SIZE);
	if (man->svn == MAX_SVN_VALUE)
		hw->fw.svn = MAX_SVN_VALUE;
	else if (hw->fw.svn == 0)
		hw->fw.svn = man->svn;

	dev_dbg(dev->dev, "%s: svn: 0x%08X", __func__, hw->fw.svn);
	/* currently only support silicon versoin A0 | A1 */
	if ((hw->fw.sub_ver == SI_SUBSTEPPING_VERSION_0 &&
	     hw->fw.svn != MAX_SVN_VALUE) ||
	    (hw->fw.sub_ver == SI_SUBSTEPPING_VERSION_1 &&
	     hw->fw.svn == MAX_SVN_VALUE)) {
		dev_err(dev->dev,
			"silicon version and image svn not matched(A%s:0x%x)\n",
			hw->fw.sub_ver == SI_SUBSTEPPING_VERSION_0 ? "0" : "1",
			hw->fw.svn);
		return -EINVAL;
	}

	for (i = 0; i < img->image_count - 1; i++) {
		if (i == 0) {
			firmwares[i] =
				(struct firmware_sign *)(bootloader->image +
							 bootloader->image_size);
			dev_dbg(dev->dev,
				"FW (%d/%d) magic number 0x%08x, image size 0x%08x\n",
				i, img->image_count, firmwares[i]->magic,
				firmwares[i]->image_size);
			continue;
		}

		firmwares[i] =
			(struct firmware_sign *)(firmwares[i - 1]->image +
						 firmwares[i - 1]->image_size);

		if ((u8 *)firmwares[i] > fw->data + fw->size)
			return -EINVAL;

		dev_dbg(dev->dev,
			"FW (%d/%d) magic number 0x%08x, image size 0x%08x\n", i,
			img->image_count, firmwares[i]->magic,
			firmwares[i]->image_size);
		if (firmwares[i]->magic != VSC_FW_MAGIC) {
			dev_err(dev->dev,
				"FW (%d/%d) magic error! magic number 0x%08x, image size 0x%08x\n",
				i, img->image_count, firmwares[i]->magic,
				firmwares[i]->image_size);

			return -EINVAL;
		}
	}

	arc_sem = firmwares[0];
	if (img->image_count >= IMG_BOOT_ARC_EM7D)
		em7d = firmwares[img->image_count - 2];

	if (img->image_count >= IMG_BOOT_ARC_ACER_EM7D)
		ace_run = firmwares[1];

	if (img->image_count >= IMG_BOOT_ARC_ACER_ACEV_EM7D)
		ace_vis = firmwares[2];

	if (img->image_count >= IMG_BOOT_ARC_ACER_ACEV_ACECNF_EM7D)
		ace_conf = firmwares[3];

	bootl_frag->data = bootloader->image;
	bootl_frag->size = bootloader->image_size;
	bootl_frag->location = img->image_loc[0];
	if (!bootl_frag->location)
		return -EINVAL;

	if (!arc_sem)
		return -EINVAL;
	arcsem_frag->data = arc_sem->image;
	arcsem_frag->size = arc_sem->image_size;
	arcsem_frag->location = img->image_loc[1];
	if (!arcsem_frag->location)
		return -EINVAL;

	if (ace_run) {
		acer_frag->data = ace_run->image;
		acer_frag->size = ace_run->image_size;
		acer_frag->location = img->image_loc[2];
		if (!acer_frag->location)
			return -EINVAL;

		if (ace_vis) {
			acev_frag->data = ace_vis->image;
			acev_frag->size = ace_vis->image_size;
			/* Align to 4K boundary */
			acev_frag->location = ((acer_frag->location +
						acer_frag->size + 0xFFF) &
					       ~(0xFFF));
			if (img->image_loc[3] &&
			    acer_frag->location != img->image_loc[3]) {
				dev_err(dev->dev,
					"ACE vision image location error. img->image_loc[3] = 0x%x, calculated is 0x%x\n",
					img->image_loc[3], acev_frag->location);
				/* when location mismatch, use the one from image file. */
				acev_frag->location = img->image_loc[3];
			}
		}

		if (ace_conf) {
			acec_frag->data = ace_conf->image;
			acec_frag->size = ace_conf->image_size;
			/* Align to 4K boundary */
			acec_frag->location = ((acev_frag->location +
						acev_frag->size + 0xFFF) &
					       ~(0xFFF));
			if (img->image_loc[4] &&
			    acec_frag->location != img->image_loc[4]) {
				dev_err(dev->dev,
					"ACE vision image location error. img->image_loc[4] = 0x%x, calculated is 0x%x\n",
					img->image_loc[4], acec_frag->location);
				/* when location mismatch, use the one from image file. */
				acec_frag->location = img->image_loc[4];
			}
		}
	}

	em7d_frag->data = em7d->image;
	em7d_frag->size = em7d->image_size;
	/* em7d is the last firmware */
	em7d_frag->location = img->image_loc[img->image_count - 1];
	if (!em7d_frag->location)
		return -EINVAL;

	return 0;
}

static int parse_sensor_fw(struct mei_device *dev, const struct firmware *fw)
{
	struct firmware_sign *ace_vis = NULL;
	struct firmware_sign *ace_conf = NULL;
	struct vsc_boot_img *img = (struct vsc_boot_img *)fw->data;
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	struct fragment *acer_frag = &hw->fw.frags[ACER_IMG_TYPE];
	struct fragment *acev_frag = &hw->fw.frags[ACEV_IMG_TYPE];
	struct fragment *acec_frag = &hw->fw.frags[ACEC_IMG_TYPE];

	if (!img || img->magic != VSC_FILE_MAGIC ||
	    img->image_count < IMG_ACEV_ACECNF ||
	    img->image_count > IMG_CNT_MAX)
		return -EINVAL;

	dev_dbg(dev->dev, "%s: img->image_count=%d\n", __func__,
		img->image_count);

	hw->fw.fw_cnt += img->image_count;
	if (hw->fw.fw_cnt > IMG_CNT_MAX)
		return -EINVAL;

	ace_vis = (struct firmware_sign *)(img->image_loc + img->image_count);
	ace_conf =
		(struct firmware_sign *)(ace_vis->image + ace_vis->image_size);

	dev_dbg(dev->dev,
		"ACE vision signed magic number 0x%08x, image size 0x%08x\n",
		ace_vis->magic, ace_vis->image_size);
	if (ace_vis->magic != VSC_FW_MAGIC) {
		dev_err(dev->dev,
			"ACE vision signed magic error! magic number 0x%08x, image size 0x%08x\n",
			ace_vis->magic, ace_vis->image_size);
		return -EINVAL;
	}

	acev_frag->data = ace_vis->image;
	acev_frag->size = ace_vis->image_size;
	/* Align to 4K boundary */
	acev_frag->location =
		((acer_frag->location + acer_frag->size + 0xFFF) & ~(0xFFF));
	if (img->image_loc[0] && acer_frag->location != img->image_loc[0]) {
		dev_err(dev->dev,
			"ACE vision image location error. img->image_loc[0] = 0x%x, calculated is 0x%x\n",
			img->image_loc[0], acev_frag->location);
		/* when location mismatch, use the one from image file. */
		acev_frag->location = img->image_loc[0];
	}

	dev_dbg(dev->dev,
		"ACE config signed magic number 0x%08x, image size 0x%08x\n",
		ace_conf->magic, ace_conf->image_size);
	if (ace_conf->magic != VSC_FW_MAGIC) {
		dev_err(dev->dev,
			"ACE config signed magic error! magic number 0x%08x, image size 0x%08x\n",
			ace_conf->magic, ace_conf->image_size);
		return -EINVAL;
	}

	acec_frag->data = ace_conf->image;
	acec_frag->size = ace_conf->image_size;
	/* Align to 4K boundary */
	acec_frag->location =
		((acev_frag->location + acev_frag->size + 0xFFF) & ~(0xFFF));
	if (img->image_loc[1] && acec_frag->location != img->image_loc[1]) {
		dev_err(dev->dev,
			"ACE vision image location error. img->image_loc[1] = 0x%x, calculated is 0x%x\n",
			img->image_loc[1], acec_frag->location);
		/* when location mismatch, use the one from image file. */
		acec_frag->location = img->image_loc[1];
	}

	return 0;
}

static int parse_sku_cnf_fw(struct mei_device *dev, const struct firmware *fw)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	struct fragment *skucnf_frag = &hw->fw.frags[SKU_CONF_TYPE];

	if (fw->size <= sizeof(u32))
		return -EINVAL;

	skucnf_frag->data = fw->data;
	skucnf_frag->size = *((u32 *)fw->data) + sizeof(u32);
	/* SKU config use fixed location */
	skucnf_frag->location = SKU_CONFIG_LOC;
	if (fw->size != skucnf_frag->size || fw->size > SKU_MAX_SIZE) {
		dev_err(dev->dev,
			"sku config file size is not config size + 4, config size = 0x%x, file size=0x%zx\n",
			skucnf_frag->size, fw->size);
		return -EINVAL;
	}
	return 0;
}

static u32 sum_CRC(void *data, int size)
{
	int i;
	u32 crc = 0;

	for (i = 0; i < size; i++)
		crc += *((u8 *)data + i);

	return crc;
}

static int load_boot(struct mei_device *dev, const void *data, int size)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	struct vsc_rom_master_frame *frame =
		(struct vsc_rom_master_frame *)hw->fw.tx_buf;
	struct vsc_rom_slave_token *token =
		(struct vsc_rom_slave_token *)hw->fw.rx_buf;
	const u8 *ptr = data;
	u32 remain;
	int ret;

	if (!data || !size)
		return -EINVAL;

	dev_dbg(dev->dev, "==== %s: image payload size : %d\n", __func__, size);
	remain = size;
	while (remain > 0) {
		u32 max_len = sizeof(frame->data.dl_cont.payload);
		u32 len = remain > max_len ? max_len : remain;

		memset(frame, 0, sizeof(*frame));
		memset(token, 0, sizeof(*token));
		frame->magic = VSC_MAGIC_NUM;
		frame->cmd = VSC_CMD_DL_CONT;

		frame->data.dl_cont.len = (u16)len;
		frame->data.dl_cont.end_flag = (remain == len ? 1 : 0);
		memcpy(frame->data.dl_cont.payload, ptr, len);

		ret = spi_rom_dev_xfer(hw, frame, NULL, VSC_ROM_SPI_PKG_SIZE);
		if (ret) {
			dev_err(dev->dev, "%s: transfer failed\n", __func__);
			break;
		}

		ptr += len;
		remain -= len;
	}

	return ret;
}

static int load_bootloader(struct mei_device *dev)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	struct vsc_rom_master_frame *frame =
		(struct vsc_rom_master_frame *)hw->fw.tx_buf;
	struct vsc_rom_slave_token *token =
		(struct vsc_rom_slave_token *)hw->fw.rx_buf;
	struct fragment *fragment = &hw->fw.frags[BOOT_IMAGE_TYPE];
	int ret;

	if (!fragment->size)
		return -EINVAL;

	dev_dbg(dev->dev, "verify bootloader token ...\n");
	frame->magic = VSC_MAGIC_NUM;
	frame->cmd = VSC_CMD_QUERY;
	ret = spi_rom_dev_xfer(hw, frame, token, VSC_ROM_SPI_PKG_SIZE);
	if (ret)
		return ret;

	if (token->token != VSC_TOKEN_BOOTLOADER_REQ &&
	    token->token != VSC_TOKEN_DUMP_RESP) {
		dev_err(dev->dev,
			"failed to load bootloader, invalid token 0x%x\n",
			token->token);
		return -EINVAL;
	}
	dev_dbg(dev->dev, "bootloader token has been verified\n");

	dev_dbg(dev->dev, "start download, image len: %u ...\n", fragment->size);
	memset(frame, 0, sizeof(*frame));
	memset(token, 0, sizeof(*token));

	frame->magic = VSC_MAGIC_NUM;
	frame->cmd = VSC_CMD_DL_START;
	frame->data.dl_start.img_type = IMG_BOOTLOADER;
	frame->data.dl_start.img_len = fragment->size;
	frame->data.dl_start.img_loc = fragment->location;
	frame->data.dl_start.option = (u16)hw->fw.fw_option;
	frame->data.dl_start.crc =
		sum_CRC(frame, (int)offsetof(struct vsc_rom_master_frame,
					     data.dl_start.crc));
	ret = spi_rom_dev_xfer(hw, frame, NULL, VSC_ROM_SPI_PKG_SIZE);
	if (ret)
		return ret;

	dev_dbg(dev->dev, "load bootloader payload ...\n");
	ret = load_boot(dev, fragment->data, fragment->size);
	if (ret)
		dev_err(dev->dev, "failed to load bootloader, err : 0x%0x\n",
			ret);

	return ret;
}

static int load_fw_bin(struct mei_device *dev, const void *data, int size)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	struct vsc_master_frame_fw_cont *frame =
		(struct vsc_master_frame_fw_cont *)hw->fw.tx_buf;
	struct vsc_bol_slave_token *token =
		(struct vsc_bol_slave_token *)hw->fw.rx_buf;
	const u8 *ptr = data;
	int ret;
	u32 remain;

	if (!data || !size)
		return -EINVAL;

	dev_dbg(dev->dev, "==== %s: image payload size : %d\n", __func__, size);
	remain = size;
	while (remain > 0) {
		u32 len = remain > FW_SPI_PKG_SIZE ? FW_SPI_PKG_SIZE : remain;

		memset(frame, 0, sizeof(*frame));
		memset(token, 0, sizeof(*token));
		memcpy(frame->payload, ptr, len);

		ret = spi_rom_dev_xfer(hw, frame, NULL, FW_SPI_PKG_SIZE);
		if (ret) {
			dev_err(dev->dev, "transfer failed\n");
			break;
		}

		ptr += len;
		remain -= len;
	}

	return ret;
}

static int load_fw_frag(struct mei_device *dev, struct fragment *frag, int type)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	struct vsc_fw_master_frame *frame =
		(struct vsc_fw_master_frame *)hw->fw.tx_buf;
	struct vsc_bol_slave_token *token =
		(struct vsc_bol_slave_token *)hw->rx_buf;
	int ret;

	dev_dbg(dev->dev,
		"start download firmware type %d ... loc:0x%08x, size:0x%08x\n",
		type, frag->location, frag->size);
	memset(frame, 0, sizeof(*frame));
	memset(token, 0, sizeof(*token));
	frame->magic = VSC_MAGIC_NUM;
	frame->cmd = VSC_CMD_DL_START;
	frame->data.dl_start.img_type = type;
	frame->data.dl_start.img_len = frag->size;
	frame->data.dl_start.img_loc = frag->location;
	frame->data.dl_start.option = (u16)hw->fw.fw_option;
	frame->data.dl_start.crc = sum_CRC(
		frame, offsetof(struct vsc_fw_master_frame, data.dl_start.crc));
	ret = spi_rom_dev_xfer(hw, frame, NULL, FW_SPI_PKG_SIZE);
	if (ret)
		return ret;

	return load_fw_bin(dev, frag->data, frag->size);
}

static int load_fw(struct mei_device *dev)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	struct vsc_fw_master_frame *frame =
		(struct vsc_fw_master_frame *)hw->fw.tx_buf;
	struct vsc_bol_slave_token *token =
		(struct vsc_bol_slave_token *)hw->rx_buf;
	struct fragment *arcsem_frag = NULL;
	struct fragment *em7d_frag = NULL;
	struct fragment *acer_frag = NULL;
	struct fragment *acev_frag = NULL;
	struct fragment *acec_frag = NULL;
	struct fragment *skucnf_frag = NULL;
	int index = 0;
	int ret;

	if (hw->fw.frags[ARC_SEM_IMG_TYPE].size > 0)
		arcsem_frag = &hw->fw.frags[ARC_SEM_IMG_TYPE];

	if (hw->fw.frags[EM7D_IMG_TYPE].size > 0)
		em7d_frag = &hw->fw.frags[EM7D_IMG_TYPE];

	if (hw->fw.frags[ACER_IMG_TYPE].size > 0)
		acer_frag = &hw->fw.frags[ACER_IMG_TYPE];

	if (hw->fw.frags[ACEV_IMG_TYPE].size > 0)
		acev_frag = &hw->fw.frags[ACEV_IMG_TYPE];

	if (hw->fw.frags[ACEC_IMG_TYPE].size > 0)
		acec_frag = &hw->fw.frags[ACEC_IMG_TYPE];

	if (hw->fw.frags[SKU_CONF_TYPE].size > 0)
		skucnf_frag = &hw->fw.frags[SKU_CONF_TYPE];

	if (!arcsem_frag || !em7d_frag) {
		dev_err(dev->dev, "invalid image or signature data\n");
		return -EINVAL;
	}

	/* send dl_set frame */
	dev_dbg(dev->dev, "send dl_set frame ...\n");
	memset(frame, 0, sizeof(*frame));
	memset(token, 0, sizeof(*token));

	frame->magic = VSC_MAGIC_NUM;
	frame->cmd = VSC_CMD_DL_SET;
	frame->data.dl_set.option = (u16)hw->fw.fw_option;
	frame->data.dl_set.img_cnt = (u8)hw->fw.fw_cnt;
	dev_dbg(dev->dev, "%s: img_cnt = %d ...\n", __func__,
		frame->data.dl_set.img_cnt);

	frame->data.dl_set.payload[index++] = arcsem_frag->location;
	frame->data.dl_set.payload[index++] = arcsem_frag->size;
	if (acer_frag) {
		frame->data.dl_set.payload[index++] = acer_frag->location;
		frame->data.dl_set.payload[index++] = acer_frag->size;
		if (acev_frag) {
			frame->data.dl_set.payload[index++] =
				acev_frag->location;
			frame->data.dl_set.payload[index++] = acev_frag->size;
		}
		if (acec_frag) {
			frame->data.dl_set.payload[index++] =
				acec_frag->location;
			frame->data.dl_set.payload[index++] = acec_frag->size;
		}
	}
	frame->data.dl_set.payload[index++] = em7d_frag->location;
	frame->data.dl_set.payload[index++] = em7d_frag->size;
	frame->data.dl_set.payload[hw->fw.fw_cnt * 2] = sum_CRC(
		frame, (int)offsetof(struct vsc_fw_master_frame,
				     data.dl_set.payload[hw->fw.fw_cnt * 2]));

	ret = spi_rom_dev_xfer(hw, frame, NULL, FW_SPI_PKG_SIZE);
	if (ret)
		return ret;

	/* load ARC-SEM FW image */
	if (arcsem_frag) {
		ret = load_fw_frag(dev, arcsem_frag, IMG_ARCSEM);
		if (ret)
			return ret;
	}

	/* load ACE FW image */
	if (acer_frag) {
		ret = load_fw_frag(dev, acer_frag, IMG_ACE_RUNTIME);
		if (ret)
			return ret;
	}

	if (acev_frag) {
		ret = load_fw_frag(dev, acev_frag, IMG_ACE_VISION);
		if (ret)
			return ret;
	}

	if (acec_frag) {
		ret = load_fw_frag(dev, acec_frag, IMG_ACE_CONFIG);
		if (ret)
			return ret;
	}

	/* load EM7D FW image */
	if (em7d_frag) {
		ret = load_fw_frag(dev, em7d_frag, IMG_EM7D);
		if (ret)
			return ret;
	}

	/* load SKU Config */
	if (skucnf_frag) {
		ret = load_fw_frag(dev, skucnf_frag, IMG_SKU_CONFIG);
		if (ret)
			return ret;
	}

	memset(frame, 0, sizeof(*frame));
	frame->magic = VSC_MAGIC_NUM;
	frame->cmd = VSC_TOKEN_CAM_BOOT;
	frame->data.boot.check_sum = sum_CRC(
		frame, offsetof(struct vsc_fw_master_frame, data.dl_start.crc));
	ret = spi_rom_dev_xfer(hw, frame, NULL, FW_SPI_PKG_SIZE);
	if (ret)
		dev_err(dev->dev, "failed to boot fw, err : 0x%x\n", ret);

	return ret;
}

static int init_hw(struct mei_device *dev)
{
	int ret;
	const struct firmware *fw = NULL;
	const struct firmware *sensor_fw = NULL;
	const struct firmware *sku_cnf_fw = NULL;
	struct mei_vsc_hw *hw = to_vsc_hw(dev);

	ret = check_silicon(dev);
	if (ret)
		return ret;

	dev_dbg(dev->dev,
		"%s: FW files. Firmware Boot File: %s, Sensor FW File: %s, Sku Config File: %s\n",
		__func__, hw->fw.fw_file_name, hw->fw.sensor_file_name,
		hw->fw.sku_cnf_file_name);
	ret = request_firmware(&fw, hw->fw.fw_file_name, dev->dev);
	if (ret < 0 || !fw) {
		dev_err(&hw->spi->dev, "file not found %s\n",
			hw->fw.fw_file_name);
		return ret;
	}

	ret = parse_main_fw(dev, fw);
	if (ret || !fw) {
		dev_err(&hw->spi->dev, "parse fw %s failed\n",
			hw->fw.fw_file_name);
		goto release;
	}

	if (hw->fw.fw_cnt < IMG_ARC_ACER_ACEV_ACECNF_EM7D) {
		ret = request_firmware(&sensor_fw, hw->fw.sensor_file_name,
				       dev->dev);
		if (ret < 0 || !sensor_fw) {
			dev_err(&hw->spi->dev, "file not found %s\n",
				hw->fw.sensor_file_name);
			goto release;
		}
		ret = parse_sensor_fw(dev, sensor_fw);
		if (ret) {
			dev_err(&hw->spi->dev, "parse fw %s failed\n",
				hw->fw.sensor_file_name);
			goto release_sensor;
		}
	}

	ret = request_firmware(&sku_cnf_fw, hw->fw.sku_cnf_file_name, dev->dev);
	if (ret < 0 || !sku_cnf_fw) {
		dev_err(&hw->spi->dev, "file not found %s\n",
			hw->fw.sku_cnf_file_name);
		goto release_sensor;
	}

	ret = parse_sku_cnf_fw(dev, sku_cnf_fw);
	if (ret) {
		dev_err(&hw->spi->dev, "parse fw %s failed\n",
			hw->fw.sensor_file_name);
		goto release_cnf;
	}

	ret = load_bootloader(dev);
	if (ret)
		goto release_cnf;

	ret = load_fw(dev);
	if (ret)
		goto release_cnf;

	return 0;

release_cnf:
	release_firmware(sku_cnf_fw);
release_sensor:
	release_firmware(sensor_fw);
release:
	release_firmware(fw);
	return ret;
}

/**
 * mei_vsc_fw_status - read fw status register from pci config space
 *
 * @dev: mei device
 * @fw_status: fw status
 *
 * Return: 0 on success, error otherwise
 */
static int mei_vsc_fw_status(struct mei_device *dev,
			     struct mei_fw_status *fw_status)
{
	if (!fw_status)
		return -EINVAL;

	fw_status->count = 0;
	return 0;
}

/**
 * mei_vsc_pg_state  - translate internal pg state
 *   to the mei power gating state
 *
 * @dev:  mei device
 *
 * Return: MEI_PG_OFF if aliveness is on and MEI_PG_ON otherwise
 */
static inline enum mei_pg_state mei_vsc_pg_state(struct mei_device *dev)
{
	return MEI_PG_OFF;
}

/**
 * mei_vsc_intr_enable - enables mei device interrupts
 *
 * @dev: the device structure
 */
static void mei_vsc_intr_enable(struct mei_device *dev)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);

	enable_irq(hw->wakeuphostint);
}

/**
 * mei_vsc_intr_disable - disables mei device interrupts
 *
 * @dev: the device structure
 */
static void mei_vsc_intr_disable(struct mei_device *dev)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);

	disable_irq(hw->wakeuphostint);
}

/**
 * mei_vsc_intr_clear - clear and stop interrupts
 *
 * @dev: the device structure
 */
static void mei_vsc_intr_clear(struct mei_device *dev)
{
	;
}

/**
 * mei_vsc_synchronize_irq - wait for pending IRQ handlers
 *
 * @dev: the device structure
 */
static void mei_vsc_synchronize_irq(struct mei_device *dev)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);

	synchronize_irq(hw->wakeuphostint);
}

/**
 * mei_vsc_hw_config - configure hw dependent settings
 *
 * @dev: mei device
 *
 * Return:
 *  * -EINVAL when read_fws is not set
 *  * 0 on success
 *
 */
static int mei_vsc_hw_config(struct mei_device *dev)
{
	return 0;
}

/**
 * mei_vsc_host_set_ready - enable device
 *
 * @dev: mei device
 */
static void mei_vsc_host_set_ready(struct mei_device *dev)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);

	hw->host_ready = true;
}

/**
 * mei_vsc_host_is_ready - check whether the host has turned ready
 *
 * @dev: mei device
 * Return: bool
 */
static bool mei_vsc_host_is_ready(struct mei_device *dev)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);

	return hw->host_ready;
}

/**
 * mei_vsc_hw_is_ready - check whether the me(hw) has turned ready
 *
 * @dev: mei device
 * Return: bool
 */
static bool mei_vsc_hw_is_ready(struct mei_device *dev)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);

	return hw->fw_ready;
}

/**
 * mei_vsc_hw_start - hw start routine
 *
 * @dev: mei device
 * Return: 0 on success, error otherwise
 */
#define MEI_SPI_START_TIMEOUT 200
static int mei_vsc_hw_start(struct mei_device *dev)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	u8 buf;
	int len;
	int ret;
	int timeout = MEI_SPI_START_TIMEOUT;

	mei_vsc_host_set_ready(dev);
	atomic_set(&hw->lock_cnt, 0);
	mei_vsc_intr_enable(dev);

	/* wait for FW ready */
	while (timeout > 0) {
		msleep(50);
		timeout -= 50;
		ret = mei_vsc_read_raw(hw, &buf, sizeof(buf), &len);
		if (!ret && ret != -EAGAIN)
			break;
	}

	if (timeout <= 0)
		return -ENODEV;

	dev_dbg(dev->dev, "hw is ready\n");
	hw->fw_ready = true;
	return 0;
}

/**
 * mei_vsc_hbuf_is_ready - checks if host buf is empty.
 *
 * @dev: the device structure
 *
 * Return: true if empty, false - otherwise.
 */
static bool mei_vsc_hbuf_is_ready(struct mei_device *dev)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);

	return hw->write_lock_cnt == 0;
}

/**
 * mei_vsc_hbuf_empty_slots - counts write empty slots.
 *
 * @dev: the device structure
 *
 * Return:  empty slots count
 */
static int mei_vsc_hbuf_empty_slots(struct mei_device *dev)
{
	return MAX_MEI_MSG_SIZE / MEI_SLOT_SIZE;
}

/**
 * mei_vsc_hbuf_depth - returns depth of the hw buf.
 *
 * @dev: the device structure
 *
 * Return: size of hw buf in slots
 */
static u32 mei_vsc_hbuf_depth(const struct mei_device *dev)
{
	return MAX_MEI_MSG_SIZE / MEI_SLOT_SIZE;
}

/**
 * mei_vsc_write - writes a message to FW.
 *
 * @dev: the device structure
 * @hdr: header of message
 * @hdr_len: header length in bytes: must be multiplication of a slot (4bytes)
 * @data: payload
 * @data_len: payload length in bytes
 *
 * Return: 0 if success, < 0 - otherwise.
 */
static int mei_vsc_write(struct mei_device *dev, const void *hdr,
			 size_t hdr_len, const void *data, size_t data_len)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	int ret;
	char *buf = hw->tx_buf;

	if (WARN_ON(!hdr || !data || hdr_len & 0x3 ||
		    data_len > MAX_SPI_MSG_SIZE)) {
		dev_err(dev->dev,
			"%s error write msg hdr_len %zu data_len %zu\n",
			__func__, hdr_len, data_len);
		return -EINVAL;
	}

	hw->write_lock_cnt++;
	memcpy(buf, hdr, hdr_len);
	memcpy(buf + hdr_len, data, data_len);
	dev_dbg(dev->dev, "%s %d" MEI_HDR_FMT, __func__, hw->write_lock_cnt,
		MEI_HDR_PRM((struct mei_msg_hdr *)hdr));

	ret = mei_vsc_write_raw(hw, buf, hdr_len + data_len);
	if (ret)
		dev_err(dev->dev, MEI_HDR_FMT "hdr_len %zu data len %zu\n",
			MEI_HDR_PRM((struct mei_msg_hdr *)hdr), hdr_len,
			data_len);

	hw->write_lock_cnt--;
	return ret;
}

/**
 * mei_vsc_read
 *  read spi message
 *
 * @dev: the device structure
 *
 * Return: mei hdr value (u32)
 */
static inline u32 mei_vsc_read(const struct mei_device *dev)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	int ret;

	ret = mei_vsc_read_raw(hw, hw->rx_buf, sizeof(hw->rx_buf), &hw->rx_len);
	if (ret || hw->rx_len < sizeof(u32))
		return 0;

	return *(u32 *)hw->rx_buf;
}

/**
 * mei_vsc_count_full_read_slots - counts read full slots.
 *
 * @dev: the device structure
 *
 * Return: -EOVERFLOW if overflow, otherwise filled slots count
 */
static int mei_vsc_count_full_read_slots(struct mei_device *dev)
{
	return MAX_MEI_MSG_SIZE / MEI_SLOT_SIZE;
}

/**
 * mei_vsc_read_slots - reads a message from mei device.
 *
 * @dev: the device structure
 * @buf: message buf will be written
 * @len: message size will be read
 *
 * Return: always 0
 */
static int mei_vsc_read_slots(struct mei_device *dev, unsigned char *buf,
			      unsigned long len)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	struct mei_msg_hdr *hdr;

	hdr = (struct mei_msg_hdr *)hw->rx_buf;
	WARN_ON(len != hdr->length || hdr->length + sizeof(*hdr) != hw->rx_len);
	memcpy(buf, hw->rx_buf + sizeof(*hdr), len);
	return 0;
}

/**
 * mei_vsc_pg_in_transition - is device now in pg transition
 *
 * @dev: the device structure
 *
 * Return: true if in pg transition, false otherwise
 */
static bool mei_vsc_pg_in_transition(struct mei_device *dev)
{
	return dev->pg_event >= MEI_PG_EVENT_WAIT &&
	       dev->pg_event <= MEI_PG_EVENT_INTR_WAIT;
}

/**
 * mei_vsc_pg_is_enabled - detect if PG is supported by HW
 *
 * @dev: the device structure
 *
 * Return: true is pg supported, false otherwise
 */
static bool mei_vsc_pg_is_enabled(struct mei_device *dev)
{
	return false;
}

/**
 * mei_vsc_hw_reset - resets fw.
 *
 * @dev: the device structure
 * @intr_enable: if interrupt should be enabled after reset.
 *
 * Return: 0 on success an error code otherwise
 */
static int mei_vsc_hw_reset(struct mei_device *dev, bool intr_enable)
{
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	int ret;

	mei_vsc_intr_disable(dev);
	ret = vsc_reset(dev);
	if (ret)
		return ret;

	if (hw->disconnect)
		return 0;

	ret = init_hw(dev);
	if (ret)
		return -ENODEV;

	hw->seq = 0;
	return 0;
}

/**
 * mei_vsc_irq_quick_handler - The ISR of the MEI device
 *
 * @irq: The irq number
 * @dev_id: pointer to the device structure
 *
 * Return: irqreturn_t
 */
irqreturn_t mei_vsc_irq_quick_handler(int irq, void *dev_id)
{
	struct mei_device *dev = (struct mei_device *)dev_id;
	struct mei_vsc_hw *hw = to_vsc_hw(dev);

	dev_dbg(dev->dev, "interrupt top half lock_cnt %d state %d\n",
		atomic_read(&hw->lock_cnt), dev->dev_state);

	atomic_inc(&hw->lock_cnt);
	wake_up(&hw->xfer_wait);
	if (dev->dev_state == MEI_DEV_INITIALIZING ||
	    dev->dev_state == MEI_DEV_RESETTING)
		return IRQ_HANDLED;

	return IRQ_WAKE_THREAD;
}

/**
 * mei_vsc_irq_thread_handler - function called after ISR to handle the interrupt
 * processing.
 *
 * @irq: The irq number
 * @dev_id: pointer to the device structure
 *
 * Return: irqreturn_t
 *
 */
irqreturn_t mei_vsc_irq_thread_handler(int irq, void *dev_id)
{
	struct mei_device *dev = (struct mei_device *)dev_id;
	struct mei_vsc_hw *hw = to_vsc_hw(dev);
	struct list_head cmpl_list;
	s32 slots;
	int rets = 0;

	dev_dbg(dev->dev,
		"function called after ISR to handle the interrupt processing dev->dev_state=%d.\n",
		dev->dev_state);

	/* initialize our complete list */
	mutex_lock(&dev->device_lock);
	INIT_LIST_HEAD(&cmpl_list);

	/* check slots available for reading */
	slots = mei_count_full_read_slots(dev);
	dev_dbg(dev->dev, "slots to read = %08x\n", slots);

reread:
	while (spi_need_read(hw)) {
		dev_dbg(dev->dev, "slots to read in = %08x\n", slots);
		rets = mei_irq_read_handler(dev, &cmpl_list, &slots);
		/* There is a race between ME write and interrupt delivery:
		 * Not all data is always available immediately after the
		 * interrupt, so try to read again on the next interrupt.
		 */
		if (rets == -ENODATA)
			break;

		if (rets && (dev->dev_state != MEI_DEV_RESETTING &&
			     dev->dev_state != MEI_DEV_POWER_DOWN)) {
			dev_err(dev->dev, "mei_irq_read_handler ret = %d.\n",
				rets);
			schedule_work(&dev->reset_work);
			goto end;
		}
	}
	dev_dbg(dev->dev, "slots to read out = %08x\n", slots);

	dev->hbuf_is_ready = mei_hbuf_is_ready(dev);
	rets = mei_irq_write_handler(dev, &cmpl_list);

	dev->hbuf_is_ready = mei_hbuf_is_ready(dev);
	mei_irq_compl_handler(dev, &cmpl_list);

	if (spi_need_read(hw))
		goto reread;

end:
	dev_dbg(dev->dev, "interrupt thread end ret = %d\n", rets);
	mutex_unlock(&dev->device_lock);
	return IRQ_HANDLED;
}

static const struct mei_hw_ops mei_vsc_hw_ops = {

	.fw_status = mei_vsc_fw_status,
	.pg_state = mei_vsc_pg_state,

	.host_is_ready = mei_vsc_host_is_ready,

	.hw_is_ready = mei_vsc_hw_is_ready,
	.hw_reset = mei_vsc_hw_reset,
	.hw_config = mei_vsc_hw_config,
	.hw_start = mei_vsc_hw_start,

	.pg_in_transition = mei_vsc_pg_in_transition,
	.pg_is_enabled = mei_vsc_pg_is_enabled,

	.intr_clear = mei_vsc_intr_clear,
	.intr_enable = mei_vsc_intr_enable,
	.intr_disable = mei_vsc_intr_disable,
	.synchronize_irq = mei_vsc_synchronize_irq,

	.hbuf_free_slots = mei_vsc_hbuf_empty_slots,
	.hbuf_is_ready = mei_vsc_hbuf_is_ready,
	.hbuf_depth = mei_vsc_hbuf_depth,
	.write = mei_vsc_write,

	.rdbuf_full_slots = mei_vsc_count_full_read_slots,
	.read_hdr = mei_vsc_read,
	.read = mei_vsc_read_slots
};

/**
 * mei_vsc_dev_init - allocates and initializes the mei device structure
 *
 * @parent: device associated with physical device (spi/platform)
 *
 * Return: The mei_device pointer on success, NULL on failure.
 */
struct mei_device *mei_vsc_dev_init(struct device *parent)
{
	struct mei_device *dev;
	struct mei_vsc_hw *hw;

	dev = devm_kzalloc(parent, sizeof(*dev) + sizeof(*hw), GFP_KERNEL);
	if (!dev)
		return NULL;

	mei_device_init(dev, parent, &mei_vsc_hw_ops);
	dev->fw_f_fw_ver_supported = 0;
	dev->kind = 0;
	return dev;
}
