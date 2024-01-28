/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2013 - 2020 Intel Corporation
 */

#ifndef IPU6_ISYS_PHY_H
#define IPU6_ISYS_PHY_H

/* bridge to phy in buttress reg map, each phy has 16 kbytes
 * for tgl u/y, only 2 phys
 */
#define IPU6_ISYS_PHY_0_BASE			0x10000
#define IPU6_ISYS_PHY_1_BASE			0x14000
#define IPU6_ISYS_PHY_2_BASE			0x18000
#define IPU6_ISYS_PHY_BASE(i)			(0x10000 + (i) * 0x4000)

/* ppi mapping per phy :
 *
 * x4x4:
 * port0 - PPI range {0, 1, 2, 3, 4}
 * port2 - PPI range {6, 7, 8, 9, 10}
 *
 * x4x2:
 * port0 - PPI range {0, 1, 2, 3, 4}
 * port2 - PPI range {6, 7, 8}
 *
 * x2x4:
 * port0 - PPI range {0, 1, 2}
 * port2 - PPI range {6, 7, 8, 9, 10}
 *
 * x2x2:
 * port0 - PPI range {0, 1, 2}
 * port1 - PPI range {3, 4, 5}
 * port2 - PPI range {6, 7, 8}
 * port3 - PPI range {9, 10, 11}
 */

/* cbbs config regs */
#define PHY_CBBS1_BASE				0x0
/* register offset */
#define PHY_CBBS1_DFX_VMISCCTL			0x0
#define PHY_CBBS1_DFX_VBYTESEL0			0x4
#define PHY_CBBS1_DFX_VBYTESEL1			0x8
#define PHY_CBBS1_VISA2OBS_CTRL_REG		0xc
#define PHY_CBBS1_PGL_CTRL_REG			0x10
#define PHY_CBBS1_RCOMP_CTRL_REG_1		0x14
#define PHY_CBBS1_RCOMP_CTRL_REG_2		0x18
#define PHY_CBBS1_RCOMP_CTRL_REG_3		0x1c
#define PHY_CBBS1_RCOMP_CTRL_REG_4		0x20
#define PHY_CBBS1_RCOMP_CTRL_REG_5		0x24
#define PHY_CBBS1_RCOMP_STATUS_REG_1		0x28
#define PHY_CBBS1_RCOMP_STATUS_REG_2		0x2c
#define PHY_CBBS1_CLOCK_CTRL_REG		0x30
#define PHY_CBBS1_CBB_ISOLATION_REG		0x34
#define PHY_CBBS1_CBB_PLL_CONTROL		0x38
#define PHY_CBBS1_CBB_STATUS_REG		0x3c
#define PHY_CBBS1_AFE_CONTROL_REG_1		0x40
#define PHY_CBBS1_AFE_CONTROL_REG_2		0x44
#define PHY_CBBS1_CBB_SPARE			0x48
#define PHY_CBBS1_CRI_CLK_CONTROL		0x4c

/* dbbs shared, i = [0..11] */
#define PHY_DBBS_SHARED(ppi)			((ppi) * 0x200 + 0x200)
/* register offset */
#define PHY_DBBDFE_DFX_V1MISCCTL		0x0
#define PHY_DBBDFE_DFX_V1BYTESEL0		0x4
#define PHY_DBBDFE_DFX_V1BYTESEL1		0x8
#define PHY_DBBDFE_DFX_V2MISCCTL		0xc
#define PHY_DBBDFE_DFX_V2BYTESEL0		0x10
#define PHY_DBBDFE_DFX_V2BYTESEL1		0x14
#define PHY_DBBDFE_GBLCTL			0x18
#define PHY_DBBDFE_GBL_STATUS			0x1c

/* dbbs udln, i = [0..11] */
#define IPU6_ISYS_PHY_DBBS_UDLN(ppi)		((ppi) * 0x200 + 0x280)
/* register offset */
#define PHY_DBBUDLN_CTL				0x0
#define PHY_DBBUDLN_CLK_CTL			0x4
#define PHY_DBBUDLN_SOFT_RST_CTL		0x8
#define PHY_DBBUDLN_STRAP_VALUES		0xc
#define PHY_DBBUDLN_TXRX_CTL			0x10
#define PHY_DBBUDLN_MST_SLV_INIT_CTL		0x14
#define PHY_DBBUDLN_TX_TIMING_CTL0		0x18
#define PHY_DBBUDLN_TX_TIMING_CTL1		0x1c
#define PHY_DBBUDLN_TX_TIMING_CTL2		0x20
#define PHY_DBBUDLN_TX_TIMING_CTL3		0x24
#define PHY_DBBUDLN_RX_TIMING_CTL		0x28
#define PHY_DBBUDLN_PPI_STATUS_CTL		0x2c
#define PHY_DBBUDLN_PPI_STATUS			0x30
#define PHY_DBBUDLN_ERR_CTL			0x34
#define PHY_DBBUDLN_ERR_STATUS			0x38
#define PHY_DBBUDLN_DFX_LPBK_CTL		0x3c
#define PHY_DBBUDLN_DFX_PPI_CTL			0x40
#define PHY_DBBUDLN_DFX_TX_DPHY_CTL		0x44
#define PHY_DBBUDLN_DFX_TXRX_PRBSPAT_CTL	0x48
#define PHY_DBBUDLN_DFX_TXRX_PRBSPAT_SEED	0x4c
#define PHY_DBBUDLN_DFX_PRBSPAT_MAX_WRD_CNT	0x50
#define PHY_DBBUDLN_DFX_PRBSPAT_STATUS		0x54
#define PHY_DBBUDLN_DFX_PRBSPAT_WRD_CNT0_STATUS	0x58
#define PHY_DBBUDLN_DFX_PRBSPAT_WRD_CNT1_STATUS	0x5c
#define PHY_DBBUDLN_DFX_PRBSPAT_FF_ERR_STATUS	0x60
#define PHY_DBBUDLN_DFX_PRBSPAT_FF_REF_STATUS		0x64
#define PHY_DBBUDLN_DFX_PRBSPAT_FF_WRD_CNT0_STATUS	0x68
#define PHY_DBBUDLN_DFX_PRBSPAT_FF_WRD_CNT1_STATUS	0x6c
#define PHY_DBBUDLN_RSVD_CTL				0x70
#define PHY_DBBUDLN_TINIT_DONE				BIT(27)

/* dbbs supar, i = [0..11] */
#define IPU6_ISYS_PHY_DBBS_SUPAR(ppi)		((ppi) * 0x200 + 0x300)
/* register offset */
#define PHY_DBBSUPAR_TXRX_FUPAR_CTL		0x0
#define PHY_DBBSUPAR_TXHS_AFE_CTL		0x4
#define PHY_DBBSUPAR_TXHS_AFE_LEGDIS_CTL	0x8
#define PHY_DBBSUPAR_TXHS_AFE_EQ_CTL		0xc
#define PHY_DBBSUPAR_RXHS_AFE_CTL1		0x10
#define PHY_DBBSUPAR_RXHS_AFE_PICTL1		0x14
#define PHY_DBBSUPAR_TXRXLP_AFE_CTL		0x18
#define PHY_DBBSUPAR_DFX_TXRX_STATUS		0x1c
#define PHY_DBBSUPAR_DFX_TXRX_CTL		0x20
#define PHY_DBBSUPAR_DFX_DIGMON_CTL		0x24
#define PHY_DBBSUPAR_DFX_LOCMON_CTL		0x28
#define PHY_DBBSUPAR_DFX_RCOMP_CTL1		0x2c
#define PHY_DBBSUPAR_DFX_RCOMP_CTL2		0x30
#define PHY_DBBSUPAR_CAL_TOP1			0x34
#define PHY_DBBSUPAR_CAL_SHARED1		0x38
#define PHY_DBBSUPAR_CAL_SHARED2		0x3c
#define PHY_DBBSUPAR_CAL_CDR1			0x40
#define PHY_DBBSUPAR_CAL_OCAL1			0x44
#define PHY_DBBSUPAR_CAL_DCC_DLL1		0x48
#define PHY_DBBSUPAR_CAL_DLL2			0x4c
#define PHY_DBBSUPAR_CAL_DFX1			0x50
#define PHY_DBBSUPAR_CAL_DFX2			0x54
#define PHY_DBBSUPAR_CAL_DFX3			0x58
#define PHY_BBSUPAR_CAL_DFX4			0x5c
#define PHY_DBBSUPAR_CAL_DFX5			0x60
#define PHY_DBBSUPAR_CAL_DFX6			0x64
#define PHY_DBBSUPAR_CAL_DFX7			0x68
#define PHY_DBBSUPAR_DFX_AFE_SPARE_CTL1		0x6c
#define PHY_DBBSUPAR_DFX_AFE_SPARE_CTL2		0x70
#define	PHY_DBBSUPAR_SPARE			0x74

/* sai, i = [0..11] */
#define	IPU6_ISYS_PHY_SAI			0xf800
/* register offset */
#define PHY_SAI_CTRL_REG0                       0x40
#define PHY_SAI_CTRL_REG0_1                     0x44
#define PHY_SAI_WR_REG0                         0x48
#define PHY_SAI_WR_REG0_1                       0x4c
#define PHY_SAI_RD_REG0                         0x50
#define PHY_SAI_RD_REG0_1                       0x54

int ipu6_isys_phy_powerup_ack(struct ipu_isys *isys, unsigned int phy_id);
int ipu6_isys_phy_powerdown_ack(struct ipu_isys *isys, unsigned int phy_id);
int ipu6_isys_phy_reset(struct ipu_isys *isys, unsigned int phy_id,
			bool assert);
int ipu6_isys_phy_ready(struct ipu_isys *isys, unsigned int phy_id);
int ipu6_isys_phy_common_init(struct ipu_isys *isys);
int ipu6_isys_phy_config(struct ipu_isys *isys);
#endif
