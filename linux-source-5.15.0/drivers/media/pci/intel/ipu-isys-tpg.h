/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2013 - 2020 Intel Corporation */

#ifndef IPU_ISYS_TPG_H
#define IPU_ISYS_TPG_H

#include <media/media-entity.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-device.h>

#include "ipu-isys-subdev.h"
#include "ipu-isys-video.h"
#include "ipu-isys-queue.h"

struct ipu_isys_tpg_pdata;
struct ipu_isys;

#define TPG_PAD_SOURCE			0
#define NR_OF_TPG_PADS			1
#define NR_OF_TPG_SOURCE_PADS		1
#define NR_OF_TPG_SINK_PADS		0
#define NR_OF_TPG_STREAMS		1

/*
 * PPC is 4 pixels for clock for RAW8, RAW10 and RAW12.
 * Source: FW validation test code.
 */
#define MIPI_GEN_PPC		4

#define MIPI_GEN_REG_COM_ENABLE				0x0
#define MIPI_GEN_REG_COM_DTYPE				0x4
/* RAW8, RAW10 or RAW12 */
#define MIPI_GEN_COM_DTYPE_RAW(n)			(((n) - 8) / 2)
#define MIPI_GEN_REG_COM_VTYPE				0x8
#define MIPI_GEN_REG_COM_VCHAN				0xc
#define MIPI_GEN_REG_COM_WCOUNT				0x10
#define MIPI_GEN_REG_PRBS_RSTVAL0			0x14
#define MIPI_GEN_REG_PRBS_RSTVAL1			0x18
#define MIPI_GEN_REG_SYNG_FREE_RUN			0x1c
#define MIPI_GEN_REG_SYNG_PAUSE				0x20
#define MIPI_GEN_REG_SYNG_NOF_FRAMES			0x24
#define MIPI_GEN_REG_SYNG_NOF_PIXELS			0x28
#define MIPI_GEN_REG_SYNG_NOF_LINES			0x2c
#define MIPI_GEN_REG_SYNG_HBLANK_CYC			0x30
#define MIPI_GEN_REG_SYNG_VBLANK_CYC			0x34
#define MIPI_GEN_REG_SYNG_STAT_HCNT			0x38
#define MIPI_GEN_REG_SYNG_STAT_VCNT			0x3c
#define MIPI_GEN_REG_SYNG_STAT_FCNT			0x40
#define MIPI_GEN_REG_SYNG_STAT_DONE			0x44
#define MIPI_GEN_REG_TPG_MODE				0x48
#define MIPI_GEN_REG_TPG_HCNT_MASK			0x4c
#define MIPI_GEN_REG_TPG_VCNT_MASK			0x50
#define MIPI_GEN_REG_TPG_XYCNT_MASK			0x54
#define MIPI_GEN_REG_TPG_HCNT_DELTA			0x58
#define MIPI_GEN_REG_TPG_VCNT_DELTA			0x5c
#define MIPI_GEN_REG_TPG_R1				0x60
#define MIPI_GEN_REG_TPG_G1				0x64
#define MIPI_GEN_REG_TPG_B1				0x68
#define MIPI_GEN_REG_TPG_R2				0x6c
#define MIPI_GEN_REG_TPG_G2				0x70
#define MIPI_GEN_REG_TPG_B2				0x74

/*
 * struct ipu_isys_tpg
 *
 * @nlanes: number of lanes in the receiver
 */
struct ipu_isys_tpg {
	struct ipu_isys_tpg_pdata *pdata;
	struct ipu_isys *isys;
	struct ipu_isys_subdev asd;
	struct ipu_isys_video av;

	void __iomem *base;
	void __iomem *sel;
	unsigned int index;
	int streaming;

	struct v4l2_ctrl *hblank;
	struct v4l2_ctrl *vblank;
	struct v4l2_ctrl *pixel_rate;
	struct v4l2_ctrl *store_csi2_header;
};

#define to_ipu_isys_tpg(sd)		\
	container_of(to_ipu_isys_subdev(sd), \
	struct ipu_isys_tpg, asd)
#ifdef IPU_TPG_FRAME_SYNC
void ipu_isys_tpg_sof_event(struct ipu_isys_tpg *tpg);
void ipu_isys_tpg_eof_event(struct ipu_isys_tpg *tpg);
#endif
int ipu_isys_tpg_init(struct ipu_isys_tpg *tpg,
		      struct ipu_isys *isys,
		      void __iomem *base, void __iomem *sel,
		      unsigned int index);
void ipu_isys_tpg_cleanup(struct ipu_isys_tpg *tpg);
int tpg_set_stream(struct v4l2_subdev *sd, int enable);

#endif /* IPU_ISYS_TPG_H */
