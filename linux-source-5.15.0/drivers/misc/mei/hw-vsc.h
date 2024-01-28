/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021, Intel Corporation. All rights reserved.
 * Intel Management Engine Interface (Intel MEI) Linux driver
 */

#ifndef _MEI_HW_SPI_H_
#define _MEI_HW_SPI_H_

#include <linux/irqreturn.h>
#include <linux/spi/spi.h>
#include <linux/mei.h>
#include <linux/types.h>

#include "mei_dev.h"

struct mei_cfg {
	const struct mei_fw_status fw_status;
	const char *kind;
	u32 fw_ver_supported : 1;
	u32 hw_trc_supported : 1;
};

enum FRAG_TYPE {
	BOOT_IMAGE_TYPE,
	ARC_SEM_IMG_TYPE,
	EM7D_IMG_TYPE,
	ACER_IMG_TYPE,
	ACEV_IMG_TYPE,
	ACEC_IMG_TYPE,
	SKU_CONF_TYPE,
	FRAGMENT_TYPE_MAX,
};

struct fragment {
	enum FRAG_TYPE type;
	u32 location;
	const u8 *data;
	u32 size;
};

irqreturn_t mei_vsc_irq_quick_handler(int irq, void *dev_id);
irqreturn_t mei_vsc_irq_thread_handler(int irq, void *dev_id);
struct mei_device *mei_vsc_dev_init(struct device *parent);

#define VSC_MAGIC_NUM 0x49505343
#define VSC_FILE_MAGIC 0x46564353
#define VSC_FW_MAGIC 0x49574653
#define VSC_ROM_SPI_PKG_SIZE 256
#define FW_SPI_PKG_SIZE 512

#define IMG_MAX_LOC (0x50FFFFFF)
#define FW_MAX_SIZE (0x200000)
#define SKU_CONFIG_LOC (0x5001A000)
#define SKU_MAX_SIZE (4100)

#define IMG_DMA_ENABLE_OPTION (1 << 0)

#define SIG_SIZE 384
#define PUBKEY_SIZE 384
#define CSSHEADER_SIZE 128

#define VSC_CMD_QUERY 0
#define VSC_CMD_DL_SET 1
#define VSC_CMD_DL_START 2
#define VSC_CMD_DL_CONT 3
#define VSC_CMD_DUMP_MEM 4
#define VSC_CMD_SET_REG 5
#define VSC_CMD_PRINT_ROM_VERSION 6
#define VSC_CMD_WRITE_FLASH 7
#define VSC_CMD_RESERVED 8

enum IMAGE_TYPE {
	IMG_DEBUG,
	IMG_BOOTLOADER,
	IMG_EM7D,
	IMG_ARCSEM,
	IMG_ACE_RUNTIME,
	IMG_ACE_VISION,
	IMG_ACE_CONFIG,
	IMG_SKU_CONFIG
};

/*image count define, refer to Clover Fall Boot ROM HLD 1.0*/
#define IMG_ACEV_ACECNF 2
#define IMG_BOOT_ARC_EM7D 3
#define IMG_BOOT_ARC_ACER_EM7D 4
#define IMG_BOOT_ARC_ACER_ACEV_EM7D 5
#define IMG_BOOT_ARC_ACER_ACEV_ACECNF_EM7D 6
#define IMG_ARC_ACER_ACEV_ACECNF_EM7D (IMG_BOOT_ARC_ACER_ACEV_ACECNF_EM7D - 1)
#define IMG_CNT_MAX IMG_BOOT_ARC_ACER_ACEV_ACECNF_EM7D

#define VSC_TOKEN_BOOTLOADER_REQ 1
#define VSC_TOKEN_FIRMWARE_REQ 2
#define VSC_TOKEN_DOWNLOAD_CONT 3
#define VSC_TOKEN_DUMP_RESP 4
#define VSC_TOKEN_DUMP_CONT 5
#define VSC_TOKEN_SKU_CONFIG_REQ 6
#define VSC_TOKEN_ERROR 7
#define VSC_TOKEN_DUMMY 8
#define VSC_TOKEN_CAM_STATUS_RESP 9
#define VSC_TOKEN_CAM_BOOT 10

#define MAX_SVN_VALUE (0xFFFFFFFE)

#define EFUSE1_ADDR (0xE0030000 + 0x38)
#define STRAP_ADDR (0xE0030000 + 0x100)

#define SI_MAINSTEPPING_VERSION_OFFSET (4)
#define SI_MAINSTEPPING_VERSION_MASK (0xF)
#define SI_MAINSTEPPING_VERSION_A (0x0)
#define SI_MAINSTEPPING_VERSION_B (0x1)
#define SI_MAINSTEPPING_VERSION_C (0x2)

#define SI_SUBSTEPPING_VERSION_OFFSET (0x0)
#define SI_SUBSTEPPING_VERSION_MASK (0xF)
#define SI_SUBSTEPPING_VERSION_0 (0x0)
#define SI_SUBSTEPPING_VERSION_0_PRIME (0x1)
#define SI_SUBSTEPPING_VERSION_1 (0x2)
#define SI_SUBSTEPPING_VERSION_1_PRIME (0x3)

#define SI_STRAP_KEY_SRC_OFFSET (16)
#define SI_STRAP_KEY_SRC_MASK (0x1)

#define SI_STRAP_KEY_SRC_DEBUG (0x0)
#define SI_STRAP_KEY_SRC_PRODUCT (0x1)

struct vsc_rom_master_frame {
	u32 magic;
	u8 cmd;
	union {
		struct {
			u8 img_type;
			u16 option;
			u32 img_len;
			u32 img_loc;
			u32 crc;
			u8 res[0];
		} __packed dl_start;
		struct {
			u8 option;
			u16 img_cnt;
			u32 payload[(VSC_ROM_SPI_PKG_SIZE - 8) / 4];
		} __packed dl_set;
		struct {
			u8 end_flag;
			u16 len;
			u8 payload[VSC_ROM_SPI_PKG_SIZE - 8];
		} __packed dl_cont;
		struct {
			u8 res;
			u16 len;
			u32 addr;
#define ROM_DUMP_MEM_RESERVE_SIZE 12
			u8 payload[VSC_ROM_SPI_PKG_SIZE -
				   ROM_DUMP_MEM_RESERVE_SIZE];
		} __packed dump_mem;
		struct {
			u8 res[3];
			u32 addr;
			u32 val;
#define ROM_SET_REG_RESERVE_SIZE 16
			u8 payload[VSC_ROM_SPI_PKG_SIZE -
				   ROM_SET_REG_RESERVE_SIZE];
		} __packed set_reg;
		struct {
			u8 ins[0];
		} __packed undoc_f1;
		struct {
			u32 addr;
			u32 len;
			u8 payload[0];
		} __packed os_dump_mem;
		u8 reserve[VSC_ROM_SPI_PKG_SIZE - 5];
	} data;
} __packed;

struct vsc_fw_master_frame {
	u32 magic;
	u8 cmd;
	union {
		struct {
			u16 option;
			u8 img_type;
			u32 img_len;
			u32 img_loc;
			u32 crc;
			u8 res[0];
		} __packed dl_start;
		struct {
			u16 option;
			u8 img_cnt;
			u32 payload[(FW_SPI_PKG_SIZE - 8) / 4];
		} __packed dl_set;
		struct {
			u8 end_flag;
			u16 len;
			u8 payload[FW_SPI_PKG_SIZE - 8];
		} __packed dl_cont;
		struct {
			u32 addr;
			u8 len;
			u8 payload[0];
		} __packed dump_mem;
		struct {
			u32 addr;
			u32 val;
			u8 payload[0];
		} __packed set_reg;
		struct {
			u8 ins[0];
		} __packed undoc_f1;
		struct {
			u32 addr;
			u32 len;
			u8 payload[0];
		} __packed os_dump_mem;
		struct {
			u8 resv[3];
			u32 check_sum;
#define LOADER_BOOT_RESERVE_SIZE 12
			u8 payload[FW_SPI_PKG_SIZE - LOADER_BOOT_RESERVE_SIZE];
		} __packed boot;
		u8 reserve[FW_SPI_PKG_SIZE - 5];
	} data;
} __packed;

struct vsc_master_frame_fw_cont {
	u8 payload[FW_SPI_PKG_SIZE];
} __packed;

struct vsc_rom_slave_token {
	u32 magic;
	u8 token;
	u8 type;
	u8 res[2];
	u8 payload[VSC_ROM_SPI_PKG_SIZE - 8];
} __packed;

struct vsc_bol_slave_token {
	u32 magic;
	u8 token;
	u8 type;
	u8 res[2];
	u8 payload[FW_SPI_PKG_SIZE - 8];
} __packed;

struct vsc_boot_img {
	u32 magic;
	u32 option;
	u32 image_count;
	u32 image_loc[IMG_CNT_MAX];
} __packed;

struct vsc_sensor_img_t {
	u32 magic;
	u32 option;
	u32 image_count;
	u32 image_loc[IMG_ACEV_ACECNF];
} __packed;

struct bootloader_sign {
	u32 magic;
	u32 image_size;
	u8 image[0];
} __packed;

struct manifest {
	u32 svn;
	u32 header_ver;
	u32 comp_flags;
	u32 comp_name;
	u32 comp_vendor_name;
	u32 module_size;
	u32 module_addr;
} __packed;

struct firmware_sign {
	u32 magic;
	u32 image_size;
	u8 image[1];
} __packed;

/* spi transport layer */
#define PACKET_SYNC 0x31
#define MAX_SPI_MSG_SIZE 2048
#define MAX_MEI_MSG_SIZE 512

#define CRC_SIZE sizeof(u32)
#define PACKET_SIZE(pkt) (sizeof(pkt->hdr) + (pkt->hdr.len) + (CRC_SIZE))
#define MAX_PACKET_SIZE                                                        \
	(sizeof(struct spi_xfer_hdr) + MAX_SPI_MSG_SIZE + (CRC_SIZE))

/* SPI xfer timeout size definition */
#define XFER_TIMEOUT_BYTES 700
#define MAX_XFER_BUFFER_SIZE ((MAX_PACKET_SIZE) + (XFER_TIMEOUT_BYTES))

struct spi_xfer_hdr {
	u8 sync;
	u8 cmd;
	u16 len;
	u32 seq;
} __packed;

struct spi_xfer_packet {
	struct spi_xfer_hdr hdr;
	u8 buf[MAX_XFER_BUFFER_SIZE - sizeof(struct spi_xfer_hdr)];
} __packed;

#define CMD_SPI_WRITE 0x01
#define CMD_SPI_READ 0x02
#define CMD_SPI_RESET_NOTIFY 0x04

#define CMD_SPI_ACK 0x10
#define CMD_SPI_NACK 0x11
#define CMD_SPI_BUSY 0x12
#define CMD_SPI_FATAL_ERR 0x13

struct host_timestamp {
	u64 realtime;
	u64 boottime;
} __packed;

struct vsc_boot_fw {
	u32 main_ver;
	u32 sub_ver;
	u32 key_src;
	u32 svn;

	u8 tx_buf[FW_SPI_PKG_SIZE];
	u8 rx_buf[FW_SPI_PKG_SIZE];

	/* FirmwareBootFile */
	char fw_file_name[256];
	/* PkgBootFile */
	char sensor_file_name[256];
	/* SkuConfigBootFile */
	char sku_cnf_file_name[256];

	u32 fw_option;
	u32 fw_cnt;
	struct fragment frags[FRAGMENT_TYPE_MAX];
};

struct mei_vsc_hw {
	struct spi_device *spi;
	struct spi_transfer xfer;
	struct spi_message msg;
	u8 rx_buf[MAX_SPI_MSG_SIZE];
	u8 tx_buf[MAX_SPI_MSG_SIZE];
	u32 rx_len;

	int wakeuphostint;
	struct gpio_desc *wakeuphost;
	struct gpio_desc *resetfw;
	struct gpio_desc *wakeupfw;

	struct vsc_boot_fw fw;
	bool host_ready;
	bool fw_ready;

	/* mei transport layer */
	u32 seq;
	u8 tx_buf1[MAX_XFER_BUFFER_SIZE];
	u8 rx_buf1[MAX_XFER_BUFFER_SIZE];

	struct mutex mutex;
	bool disconnect;
	atomic_t lock_cnt;
	int write_lock_cnt;
	wait_queue_head_t xfer_wait;
	char cam_sensor_name[32];
};

#define to_vsc_hw(dev) ((struct mei_vsc_hw *)((dev)->hw))

#endif
