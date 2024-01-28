// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2013 - 2020 Intel Corporation

#include <linux/clk.h>
#include <linux/clkdev.h>
#include <linux/clk-provider.h>
#include <linux/completion.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/elf.h>
#include <linux/errno.h>
#include <linux/firmware.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>

#include <media/ipu-isys.h>

#include "ipu.h"
#include "ipu-bus.h"
#include "ipu-buttress.h"
#include "ipu-platform-buttress-regs.h"
#include "ipu-cpd.h"

#define BOOTLOADER_STATUS_OFFSET       0x15c

#define BOOTLOADER_MAGIC_KEY		0xb00710ad

#define ENTRY	BUTTRESS_IU2CSECSR_IPC_PEER_COMP_ACTIONS_RST_PHASE1
#define EXIT	BUTTRESS_IU2CSECSR_IPC_PEER_COMP_ACTIONS_RST_PHASE2
#define QUERY	BUTTRESS_IU2CSECSR_IPC_PEER_QUERIED_IP_COMP_ACTIONS_RST_PHASE

#define BUTTRESS_TSC_SYNC_RESET_TRIAL_MAX	10

#define BUTTRESS_CSE_BOOTLOAD_TIMEOUT		5000000
#define BUTTRESS_CSE_AUTHENTICATE_TIMEOUT	10000000
#define BUTTRESS_CSE_FWRESET_TIMEOUT		100000

#define BUTTRESS_IPC_TX_TIMEOUT			1000
#define BUTTRESS_IPC_RESET_TIMEOUT		2000
#define BUTTRESS_IPC_RX_TIMEOUT			1000
#define BUTTRESS_IPC_VALIDITY_TIMEOUT		1000000
#define BUTTRESS_TSC_SYNC_TIMEOUT		5000

#define IPU_BUTTRESS_TSC_LIMIT	500	/* 26 us @ 19.2 MHz */
#define IPU_BUTTRESS_TSC_RETRY	10

#define BUTTRESS_CSE_IPC_RESET_RETRY	4

#define BUTTRESS_IPC_CMD_SEND_RETRY	1

static const u32 ipu_adev_irq_mask[] = {
	BUTTRESS_ISR_IS_IRQ, BUTTRESS_ISR_PS_IRQ
};

int ipu_buttress_ipc_reset(struct ipu_device *isp, struct ipu_buttress_ipc *ipc)
{
	struct ipu_buttress *b = &isp->buttress;
	unsigned int retries = BUTTRESS_IPC_RESET_TIMEOUT;
	u32 val = 0, csr_in_clr;

	if (!isp->secure_mode) {
		dev_info(&isp->pdev->dev, "Skip ipc reset for non-secure mode");
		return 0;
	}

	mutex_lock(&b->ipc_mutex);

	/* Clear-by-1 CSR (all bits), corresponding internal states. */
	val = readl(isp->base + ipc->csr_in);
	writel(val, isp->base + ipc->csr_in);

	/* Set peer CSR bit IPC_PEER_COMP_ACTIONS_RST_PHASE1 */
	writel(ENTRY, isp->base + ipc->csr_out);
	/*
	 * Clear-by-1 all CSR bits EXCEPT following
	 * bits:
	 * A. IPC_PEER_COMP_ACTIONS_RST_PHASE1.
	 * B. IPC_PEER_COMP_ACTIONS_RST_PHASE2.
	 * C. Possibly custom bits, depending on
	 * their role.
	 */
	csr_in_clr = BUTTRESS_IU2CSECSR_IPC_PEER_DEASSERTED_REG_VALID_REQ |
		BUTTRESS_IU2CSECSR_IPC_PEER_ACKED_REG_VALID |
		BUTTRESS_IU2CSECSR_IPC_PEER_ASSERTED_REG_VALID_REQ | QUERY;

	while (retries--) {
		usleep_range(400, 500);
		val = readl(isp->base + ipc->csr_in);
		switch (val) {
		case (ENTRY | EXIT):
		case (ENTRY | EXIT | QUERY):
			dev_dbg(&isp->pdev->dev,
				"%s:%s & %s\n", __func__,
				"IPC_PEER_COMP_ACTIONS_RST_PHASE1",
				"IPC_PEER_COMP_ACTIONS_RST_PHASE2");
			/*
			 * 1) Clear-by-1 CSR bits
			 * (IPC_PEER_COMP_ACTIONS_RST_PHASE1,
			 * IPC_PEER_COMP_ACTIONS_RST_PHASE2).
			 * 2) Set peer CSR bit
			 * IPC_PEER_QUERIED_IP_COMP_ACTIONS_RST_PHASE.
			 */
			writel(ENTRY | EXIT, isp->base + ipc->csr_in);
			writel(QUERY, isp->base + ipc->csr_out);
			break;
		case ENTRY:
		case (ENTRY | QUERY):
			dev_dbg(&isp->pdev->dev,
				"%s:IPC_PEER_COMP_ACTIONS_RST_PHASE1\n",
				__func__);
			/*
			 * 1) Clear-by-1 CSR bits
			 * (IPC_PEER_COMP_ACTIONS_RST_PHASE1,
			 * IPC_PEER_QUERIED_IP_COMP_ACTIONS_RST_PHASE).
			 * 2) Set peer CSR bit
			 * IPC_PEER_COMP_ACTIONS_RST_PHASE1.
			 */
			writel(ENTRY | QUERY, isp->base + ipc->csr_in);
			writel(ENTRY, isp->base + ipc->csr_out);
			break;
		case EXIT:
		case (EXIT | QUERY):
			dev_dbg(&isp->pdev->dev,
				"%s: IPC_PEER_COMP_ACTIONS_RST_PHASE2\n",
				__func__);
			/*
			 * Clear-by-1 CSR bit
			 * IPC_PEER_COMP_ACTIONS_RST_PHASE2.
			 * 1) Clear incoming doorbell.
			 * 2) Clear-by-1 all CSR bits EXCEPT following
			 * bits:
			 * A. IPC_PEER_COMP_ACTIONS_RST_PHASE1.
			 * B. IPC_PEER_COMP_ACTIONS_RST_PHASE2.
			 * C. Possibly custom bits, depending on
			 * their role.
			 * 3) Set peer CSR bit
			 * IPC_PEER_COMP_ACTIONS_RST_PHASE2.
			 */
			writel(EXIT, isp->base + ipc->csr_in);
			writel(0, isp->base + ipc->db0_in);
			writel(csr_in_clr, isp->base + ipc->csr_in);
			writel(EXIT, isp->base + ipc->csr_out);

			/*
			 * Read csr_in again to make sure if RST_PHASE2 is done.
			 * If csr_in is QUERY, it should be handled again.
			 */
			usleep_range(200, 300);
			val = readl(isp->base + ipc->csr_in);
			if (val & QUERY) {
				dev_dbg(&isp->pdev->dev,
					"%s: RST_PHASE2 retry csr_in = %x\n",
					__func__, val);
				break;
			}
			mutex_unlock(&b->ipc_mutex);
			return 0;
		case QUERY:
			dev_dbg(&isp->pdev->dev,
				"%s: %s\n", __func__,
				"IPC_PEER_QUERIED_IP_COMP_ACTIONS_RST_PHASE");
			/*
			 * 1) Clear-by-1 CSR bit
			 * IPC_PEER_QUERIED_IP_COMP_ACTIONS_RST_PHASE.
			 * 2) Set peer CSR bit
			 * IPC_PEER_COMP_ACTIONS_RST_PHASE1
			 */
			writel(QUERY, isp->base + ipc->csr_in);
			writel(ENTRY, isp->base + ipc->csr_out);
			break;
		default:
			dev_dbg_ratelimited(&isp->pdev->dev,
					    "%s: unexpected CSR 0x%x\n",
					    __func__, val);
			break;
		}
	}

	mutex_unlock(&b->ipc_mutex);
	dev_err(&isp->pdev->dev, "Timed out while waiting for CSE\n");

	return -ETIMEDOUT;
}

static void
ipu_buttress_ipc_validity_close(struct ipu_device *isp,
				struct ipu_buttress_ipc *ipc)
{
	/* Set bit 5 in CSE CSR */
	writel(BUTTRESS_IU2CSECSR_IPC_PEER_DEASSERTED_REG_VALID_REQ,
	       isp->base + ipc->csr_out);
}

static int
ipu_buttress_ipc_validity_open(struct ipu_device *isp,
			       struct ipu_buttress_ipc *ipc)
{
	unsigned int mask = BUTTRESS_IU2CSECSR_IPC_PEER_ACKED_REG_VALID;
	unsigned int tout = BUTTRESS_IPC_VALIDITY_TIMEOUT;
	void __iomem *addr;
	int ret;
	u32 val;

	/* Set bit 3 in CSE CSR */
	writel(BUTTRESS_IU2CSECSR_IPC_PEER_ASSERTED_REG_VALID_REQ,
	       isp->base + ipc->csr_out);

	addr = isp->base + ipc->csr_in;
	ret = readl_poll_timeout(addr, val, val & mask, 200, tout);
	if (ret) {
		val = readl(addr);
		dev_err(&isp->pdev->dev, "CSE validity timeout 0x%x\n", val);
		ipu_buttress_ipc_validity_close(isp, ipc);
	}

	return ret;
}

static void ipu_buttress_ipc_recv(struct ipu_device *isp,
				  struct ipu_buttress_ipc *ipc, u32 *ipc_msg)
{
	if (ipc_msg)
		*ipc_msg = readl(isp->base + ipc->data0_in);
	writel(0, isp->base + ipc->db0_in);
}

static int ipu_buttress_ipc_send_bulk(struct ipu_device *isp,
				      enum ipu_buttress_ipc_domain ipc_domain,
				      struct ipu_ipc_buttress_bulk_msg *msgs,
				      u32 size)
{
	struct ipu_buttress *b = &isp->buttress;
	struct ipu_buttress_ipc *ipc;
	unsigned long tx_timeout_jiffies, rx_timeout_jiffies;
	u32 val;
	int ret;
	int tout;
	unsigned int i, retry = BUTTRESS_IPC_CMD_SEND_RETRY;

	ipc = ipc_domain == IPU_BUTTRESS_IPC_CSE ? &b->cse : &b->ish;

	mutex_lock(&b->ipc_mutex);

	ret = ipu_buttress_ipc_validity_open(isp, ipc);
	if (ret) {
		dev_err(&isp->pdev->dev, "IPC validity open failed\n");
		goto out;
	}

	tx_timeout_jiffies = msecs_to_jiffies(BUTTRESS_IPC_TX_TIMEOUT);
	rx_timeout_jiffies = msecs_to_jiffies(BUTTRESS_IPC_RX_TIMEOUT);

	for (i = 0; i < size; i++) {
		reinit_completion(&ipc->send_complete);
		if (msgs[i].require_resp)
			reinit_completion(&ipc->recv_complete);

		dev_dbg(&isp->pdev->dev, "bulk IPC command: 0x%x\n",
			msgs[i].cmd);
		writel(msgs[i].cmd, isp->base + ipc->data0_out);

		val = BUTTRESS_IU2CSEDB0_BUSY | msgs[i].cmd_size;

		writel(val, isp->base + ipc->db0_out);

		tout = wait_for_completion_timeout(&ipc->send_complete,
						   tx_timeout_jiffies);
		if (!tout) {
			dev_err(&isp->pdev->dev, "send IPC response timeout\n");
			if (!retry--) {
				ret = -ETIMEDOUT;
				goto out;
			}

			/*
			 * WORKAROUND: Sometimes CSE is not
			 * responding on first try, try again.
			 */
			writel(0, isp->base + ipc->db0_out);
			i--;
			continue;
		}

		retry = BUTTRESS_IPC_CMD_SEND_RETRY;

		if (!msgs[i].require_resp)
			continue;

		tout = wait_for_completion_timeout(&ipc->recv_complete,
						   rx_timeout_jiffies);
		if (!tout) {
			dev_err(&isp->pdev->dev, "recv IPC response timeout\n");
			ret = -ETIMEDOUT;
			goto out;
		}

		if (ipc->nack_mask &&
		    (ipc->recv_data & ipc->nack_mask) == ipc->nack) {
			dev_err(&isp->pdev->dev,
				"IPC NACK for cmd 0x%x\n", msgs[i].cmd);
			ret = -ENODEV;
			goto out;
		}

		if (ipc->recv_data != msgs[i].expected_resp) {
			dev_err(&isp->pdev->dev,
				"expected resp: 0x%x, IPC response: 0x%x ",
				msgs[i].expected_resp, ipc->recv_data);
			ret = -EIO;
			goto out;
		}
	}

	dev_dbg(&isp->pdev->dev, "bulk IPC commands done\n");

out:
	ipu_buttress_ipc_validity_close(isp, ipc);
	mutex_unlock(&b->ipc_mutex);
	return ret;
}

static int
ipu_buttress_ipc_send(struct ipu_device *isp,
		      enum ipu_buttress_ipc_domain ipc_domain,
		      u32 ipc_msg, u32 size, bool require_resp,
		      u32 expected_resp)
{
	struct ipu_ipc_buttress_bulk_msg msg = {
		.cmd = ipc_msg,
		.cmd_size = size,
		.require_resp = require_resp,
		.expected_resp = expected_resp,
	};

	return ipu_buttress_ipc_send_bulk(isp, ipc_domain, &msg, 1);
}

static irqreturn_t ipu_buttress_call_isr(struct ipu_bus_device *adev)
{
	irqreturn_t ret = IRQ_WAKE_THREAD;

	if (!adev || !adev->adrv)
		return IRQ_NONE;

	if (adev->adrv->isr)
		ret = adev->adrv->isr(adev);

	if (ret == IRQ_WAKE_THREAD && !adev->adrv->isr_threaded)
		ret = IRQ_NONE;

	adev->adrv->wake_isr_thread = (ret == IRQ_WAKE_THREAD);

	return ret;
}

irqreturn_t ipu_buttress_isr(int irq, void *isp_ptr)
{
	struct ipu_device *isp = isp_ptr;
	struct ipu_bus_device *adev[] = { isp->isys, isp->psys };
	struct ipu_buttress *b = &isp->buttress;
	irqreturn_t ret = IRQ_NONE;
	u32 disable_irqs = 0;
	u32 irq_status;
	u32 reg_irq_sts = BUTTRESS_REG_ISR_STATUS;
	unsigned int i;

	pm_runtime_get(&isp->pdev->dev);

	if (!pm_runtime_active(&isp->pdev->dev)) {
		irq_status = readl(isp->base + reg_irq_sts);
		writel(irq_status, isp->base + BUTTRESS_REG_ISR_CLEAR);
		pm_runtime_put(&isp->pdev->dev);
		return IRQ_HANDLED;
	}

	irq_status = readl(isp->base + reg_irq_sts);
	if (!irq_status) {
		pm_runtime_put(&isp->pdev->dev);
		return IRQ_NONE;
	}

	do {
		writel(irq_status, isp->base + BUTTRESS_REG_ISR_CLEAR);

		for (i = 0; i < ARRAY_SIZE(ipu_adev_irq_mask); i++) {
			if (irq_status & ipu_adev_irq_mask[i]) {
				irqreturn_t r = ipu_buttress_call_isr(adev[i]);

				if (r == IRQ_WAKE_THREAD) {
					ret = IRQ_WAKE_THREAD;
					disable_irqs |= ipu_adev_irq_mask[i];
				} else if (ret == IRQ_NONE &&
					   r == IRQ_HANDLED) {
					ret = IRQ_HANDLED;
				}
			}
		}

		if (irq_status & (BUTTRESS_ISR_IPC_FROM_CSE_IS_WAITING |
				  BUTTRESS_ISR_IPC_FROM_ISH_IS_WAITING |
				  BUTTRESS_ISR_IPC_EXEC_DONE_BY_CSE |
				  BUTTRESS_ISR_IPC_EXEC_DONE_BY_ISH |
				  BUTTRESS_ISR_SAI_VIOLATION) &&
		    ret == IRQ_NONE)
			ret = IRQ_HANDLED;

		if (irq_status & BUTTRESS_ISR_IPC_FROM_CSE_IS_WAITING) {
			dev_dbg(&isp->pdev->dev,
				"BUTTRESS_ISR_IPC_FROM_CSE_IS_WAITING\n");
			ipu_buttress_ipc_recv(isp, &b->cse, &b->cse.recv_data);
			complete(&b->cse.recv_complete);
		}

		if (irq_status & BUTTRESS_ISR_IPC_FROM_ISH_IS_WAITING) {
			dev_dbg(&isp->pdev->dev,
				"BUTTRESS_ISR_IPC_FROM_ISH_IS_WAITING\n");
			ipu_buttress_ipc_recv(isp, &b->ish, &b->ish.recv_data);
			complete(&b->ish.recv_complete);
		}

		if (irq_status & BUTTRESS_ISR_IPC_EXEC_DONE_BY_CSE) {
			dev_dbg(&isp->pdev->dev,
				"BUTTRESS_ISR_IPC_EXEC_DONE_BY_CSE\n");
			complete(&b->cse.send_complete);
		}

		if (irq_status & BUTTRESS_ISR_IPC_EXEC_DONE_BY_ISH) {
			dev_dbg(&isp->pdev->dev,
				"BUTTRESS_ISR_IPC_EXEC_DONE_BY_CSE\n");
			complete(&b->ish.send_complete);
		}

		if (irq_status & BUTTRESS_ISR_SAI_VIOLATION &&
		    ipu_buttress_get_secure_mode(isp)) {
			dev_err(&isp->pdev->dev,
				"BUTTRESS_ISR_SAI_VIOLATION\n");
			WARN_ON(1);
		}

		irq_status = readl(isp->base + reg_irq_sts);
	} while (irq_status && !isp->flr_done);

	if (disable_irqs)
		writel(BUTTRESS_IRQS & ~disable_irqs,
		       isp->base + BUTTRESS_REG_ISR_ENABLE);

	pm_runtime_put(&isp->pdev->dev);

	return ret;
}

irqreturn_t ipu_buttress_isr_threaded(int irq, void *isp_ptr)
{
	struct ipu_device *isp = isp_ptr;
	struct ipu_bus_device *adev[] = { isp->isys, isp->psys };
	irqreturn_t ret = IRQ_NONE;
	unsigned int i;

	dev_dbg(&isp->pdev->dev, "isr: Buttress threaded interrupt handler\n");

	for (i = 0; i < ARRAY_SIZE(ipu_adev_irq_mask); i++) {
		if (adev[i] && adev[i]->adrv &&
		    adev[i]->adrv->wake_isr_thread &&
		    adev[i]->adrv->isr_threaded(adev[i]) == IRQ_HANDLED)
			ret = IRQ_HANDLED;
	}

	writel(BUTTRESS_IRQS, isp->base + BUTTRESS_REG_ISR_ENABLE);

	return ret;
}

int ipu_buttress_power(struct device *dev,
		       struct ipu_buttress_ctrl *ctrl, bool on)
{
	struct ipu_device *isp = to_ipu_bus_device(dev)->isp;
	u32 pwr_sts, val;
	int ret = 0;

	if (!ctrl)
		return 0;

	/* Until FLR completion nothing is expected to work */
	if (isp->flr_done)
		return 0;

	mutex_lock(&isp->buttress.power_mutex);

	if (!on) {
		val = 0;
		pwr_sts = ctrl->pwr_sts_off << ctrl->pwr_sts_shift;
	} else {
		val = BUTTRESS_FREQ_CTL_START |
			ctrl->divisor << ctrl->divisor_shift |
			ctrl->qos_floor << BUTTRESS_FREQ_CTL_QOS_FLOOR_SHIFT |
			BUTTRESS_FREQ_CTL_ICCMAX_LEVEL;

		pwr_sts = ctrl->pwr_sts_on << ctrl->pwr_sts_shift;
	}

	writel(val, isp->base + ctrl->freq_ctl);

	ret = readl_poll_timeout(isp->base + BUTTRESS_REG_PWR_STATE,
				 val, ((val & ctrl->pwr_sts_mask) == pwr_sts),
				 100, BUTTRESS_POWER_TIMEOUT);
	if (ret)
		dev_err(&isp->pdev->dev,
			"Change power status timeout with 0x%x\n", val);

	ctrl->started = !ret && on;

	mutex_unlock(&isp->buttress.power_mutex);

	return ret;
}

static bool secure_mode_enable = 1;
module_param(secure_mode_enable, bool, 0660);
MODULE_PARM_DESC(secure_mode, "IPU secure mode enable");

void ipu_buttress_set_secure_mode(struct ipu_device *isp)
{
	u8 retry = 100;
	u32 val, read;

	/*
	 * HACK to disable possible secure mode. This can be
	 * reverted when CSE is disabling the secure mode
	 */
	read = readl(isp->base + BUTTRESS_REG_SECURITY_CTL);

	if (secure_mode_enable)
		val = read |= BUTTRESS_SECURITY_CTL_FW_SECURE_MODE;
	else
		val = read & ~BUTTRESS_SECURITY_CTL_FW_SECURE_MODE;

	if (val == read)
		return;

	writel(val, isp->base + BUTTRESS_REG_SECURITY_CTL);

	/* In B0, for some registers in buttress, because of a hw bug, write
	 * might not succeed at first attempt. Write twice until the
	 * write is successful
	 */
	writel(val, isp->base + BUTTRESS_REG_SECURITY_CTL);

	while (retry--) {
		read = readl(isp->base + BUTTRESS_REG_SECURITY_CTL);
		if (read == val)
			break;

		writel(val, isp->base + BUTTRESS_REG_SECURITY_CTL);

		if (retry == 0)
			dev_err(&isp->pdev->dev,
				"update security control register failed\n");
	}
}

bool ipu_buttress_get_secure_mode(struct ipu_device *isp)
{
	u32 val;

	val = readl(isp->base + BUTTRESS_REG_SECURITY_CTL);

	return val & BUTTRESS_SECURITY_CTL_FW_SECURE_MODE;
}

bool ipu_buttress_auth_done(struct ipu_device *isp)
{
	u32 val;

	if (!isp->secure_mode)
		return 1;

	val = readl(isp->base + BUTTRESS_REG_SECURITY_CTL);

	return (val & BUTTRESS_SECURITY_CTL_FW_SETUP_MASK) ==
	    BUTTRESS_SECURITY_CTL_AUTH_DONE;
}
EXPORT_SYMBOL(ipu_buttress_auth_done);

static void ipu_buttress_set_psys_ratio(struct ipu_device *isp,
					unsigned int psys_divisor,
					unsigned int psys_qos_floor)
{
	struct ipu_buttress_ctrl *ctrl = isp->psys->ctrl;

	mutex_lock(&isp->buttress.power_mutex);

	if (ctrl->divisor == psys_divisor && ctrl->qos_floor == psys_qos_floor)
		goto out_mutex_unlock;

	ctrl->divisor = psys_divisor;
	ctrl->qos_floor = psys_qos_floor;

	if (ctrl->started) {
		/*
		 * According to documentation driver initiates DVFS
		 * transition by writing wanted ratio, floor ratio and start
		 * bit. No need to stop PS first
		 */
		writel(BUTTRESS_FREQ_CTL_START |
		       ctrl->qos_floor << BUTTRESS_FREQ_CTL_QOS_FLOOR_SHIFT |
		       psys_divisor, isp->base + BUTTRESS_REG_PS_FREQ_CTL);
	}

out_mutex_unlock:
	mutex_unlock(&isp->buttress.power_mutex);
}

static void ipu_buttress_set_isys_ratio(struct ipu_device *isp,
					unsigned int isys_divisor)
{
	struct ipu_buttress_ctrl *ctrl = isp->isys->ctrl;

	mutex_lock(&isp->buttress.power_mutex);

	if (ctrl->divisor == isys_divisor)
		goto out_mutex_unlock;

	ctrl->divisor = isys_divisor;

	if (ctrl->started) {
		writel(BUTTRESS_FREQ_CTL_START |
		       ctrl->qos_floor << BUTTRESS_FREQ_CTL_QOS_FLOOR_SHIFT |
		       isys_divisor, isp->base + BUTTRESS_REG_IS_FREQ_CTL);
	}

out_mutex_unlock:
	mutex_unlock(&isp->buttress.power_mutex);
}

static void ipu_buttress_set_psys_freq(struct ipu_device *isp,
				       unsigned int freq)
{
	unsigned int psys_ratio = freq / BUTTRESS_PS_FREQ_STEP;

	if (isp->buttress.psys_force_ratio)
		return;

	ipu_buttress_set_psys_ratio(isp, psys_ratio, psys_ratio);
}

void
ipu_buttress_add_psys_constraint(struct ipu_device *isp,
				 struct ipu_buttress_constraint *constraint)
{
	struct ipu_buttress *b = &isp->buttress;

	mutex_lock(&b->cons_mutex);
	list_add(&constraint->list, &b->constraints);

	if (constraint->min_freq > b->psys_min_freq) {
		isp->buttress.psys_min_freq = min(constraint->min_freq,
						  b->psys_fused_freqs.max_freq);
		ipu_buttress_set_psys_freq(isp, b->psys_min_freq);
	}
	mutex_unlock(&b->cons_mutex);
}
EXPORT_SYMBOL_GPL(ipu_buttress_add_psys_constraint);

void
ipu_buttress_remove_psys_constraint(struct ipu_device *isp,
				    struct ipu_buttress_constraint *constraint)
{
	struct ipu_buttress *b = &isp->buttress;
	struct ipu_buttress_constraint *c;
	unsigned int min_freq = 0;

	mutex_lock(&b->cons_mutex);
	list_del(&constraint->list);

	if (constraint->min_freq >= b->psys_min_freq) {
		list_for_each_entry(c, &b->constraints, list)
			if (c->min_freq > min_freq)
				min_freq = c->min_freq;

		b->psys_min_freq = clamp(min_freq,
					 b->psys_fused_freqs.efficient_freq,
					 b->psys_fused_freqs.max_freq);
		ipu_buttress_set_psys_freq(isp, b->psys_min_freq);
	}
	mutex_unlock(&b->cons_mutex);
}
EXPORT_SYMBOL_GPL(ipu_buttress_remove_psys_constraint);

int ipu_buttress_reset_authentication(struct ipu_device *isp)
{
	int ret;
	u32 val;

	if (!isp->secure_mode) {
		dev_dbg(&isp->pdev->dev,
			"Non-secure mode -> skip authentication\n");
		return 0;
	}

	writel(BUTTRESS_FW_RESET_CTL_START, isp->base +
	       BUTTRESS_REG_FW_RESET_CTL);

	ret = readl_poll_timeout(isp->base + BUTTRESS_REG_FW_RESET_CTL, val,
				 val & BUTTRESS_FW_RESET_CTL_DONE, 500,
				 BUTTRESS_CSE_FWRESET_TIMEOUT);
	if (ret) {
		dev_err(&isp->pdev->dev,
			"Time out while resetting authentication state\n");
	} else {
		dev_info(&isp->pdev->dev,
			 "FW reset for authentication done\n");
		writel(0, isp->base + BUTTRESS_REG_FW_RESET_CTL);
		/* leave some time for HW restore */
		usleep_range(800, 1000);
	}

	return ret;
}

int ipu_buttress_map_fw_image(struct ipu_bus_device *sys,
			      const struct firmware *fw, struct sg_table *sgt)
{
	struct page **pages;
	const void *addr;
	unsigned long n_pages, i;
	int rval;

	n_pages = PAGE_ALIGN(fw->size) >> PAGE_SHIFT;

	pages = kmalloc_array(n_pages, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	addr = fw->data;
	for (i = 0; i < n_pages; i++) {
		struct page *p = vmalloc_to_page(addr);

		if (!p) {
			rval = -ENODEV;
			goto out;
		}
		pages[i] = p;
		addr += PAGE_SIZE;
	}

	rval = sg_alloc_table_from_pages(sgt, pages, n_pages, 0, fw->size,
					 GFP_KERNEL);
	if (rval) {
		rval = -ENOMEM;
		goto out;
	}

	n_pages = dma_map_sg(&sys->dev, sgt->sgl, sgt->nents, DMA_TO_DEVICE);
	if (n_pages != sgt->nents) {
		rval = -ENOMEM;
		sg_free_table(sgt);
		goto out;
	}

	dma_sync_sg_for_device(&sys->dev, sgt->sgl, sgt->nents, DMA_TO_DEVICE);

out:
	kfree(pages);

	return rval;
}
EXPORT_SYMBOL_GPL(ipu_buttress_map_fw_image);

int ipu_buttress_unmap_fw_image(struct ipu_bus_device *sys,
				struct sg_table *sgt)
{
	dma_unmap_sg(&sys->dev, sgt->sgl, sgt->nents, DMA_TO_DEVICE);
	sg_free_table(sgt);

	return 0;
}
EXPORT_SYMBOL_GPL(ipu_buttress_unmap_fw_image);

int ipu_buttress_authenticate(struct ipu_device *isp)
{
	struct ipu_psys_pdata *psys_pdata;
	struct ipu_buttress *b = &isp->buttress;
	u32 data, mask, done, fail;
	int rval;

	if (!isp->secure_mode) {
		dev_dbg(&isp->pdev->dev,
			"Non-secure mode -> skip authentication\n");
		return 0;
	}

	psys_pdata = isp->psys->pdata;

	mutex_lock(&b->auth_mutex);

	if (ipu_buttress_auth_done(isp)) {
		rval = 0;
		goto iunit_power_off;
	}

	/*
	 * Write address of FIT table to FW_SOURCE register
	 * Let's use fw address. I.e. not using FIT table yet
	 */
	data = lower_32_bits(isp->pkg_dir_dma_addr);
	writel(data, isp->base + BUTTRESS_REG_FW_SOURCE_BASE_LO);

	data = upper_32_bits(isp->pkg_dir_dma_addr);
	writel(data, isp->base + BUTTRESS_REG_FW_SOURCE_BASE_HI);

	/*
	 * Write boot_load into IU2CSEDATA0
	 * Write sizeof(boot_load) | 0x2 << CLIENT_ID to
	 * IU2CSEDB.IU2CSECMD and set IU2CSEDB.IU2CSEBUSY as
	 */
	dev_info(&isp->pdev->dev, "Sending BOOT_LOAD to CSE\n");
	rval = ipu_buttress_ipc_send(isp, IPU_BUTTRESS_IPC_CSE,
				     BUTTRESS_IU2CSEDATA0_IPC_BOOT_LOAD,
				     1, 1,
				     BUTTRESS_CSE2IUDATA0_IPC_BOOT_LOAD_DONE);
	if (rval) {
		dev_err(&isp->pdev->dev, "CSE boot_load failed\n");
		goto iunit_power_off;
	}

	mask = BUTTRESS_SECURITY_CTL_FW_SETUP_MASK;
	done = BUTTRESS_SECURITY_CTL_FW_SETUP_DONE;
	fail = BUTTRESS_SECURITY_CTL_AUTH_FAILED;
	rval = readl_poll_timeout(isp->base + BUTTRESS_REG_SECURITY_CTL, data,
				  ((data & mask) == done ||
				   (data & mask) == fail), 500,
				  BUTTRESS_CSE_BOOTLOAD_TIMEOUT);
	if (rval) {
		dev_err(&isp->pdev->dev, "CSE boot_load timeout\n");
		goto iunit_power_off;
	}

	data = readl(isp->base + BUTTRESS_REG_SECURITY_CTL) & mask;
	if (data == fail) {
		dev_err(&isp->pdev->dev, "CSE auth failed\n");
		rval = -EINVAL;
		goto iunit_power_off;
	}

	rval = readl_poll_timeout(psys_pdata->base + BOOTLOADER_STATUS_OFFSET,
				  data, data == BOOTLOADER_MAGIC_KEY, 500,
				  BUTTRESS_CSE_BOOTLOAD_TIMEOUT);
	if (rval) {
		dev_err(&isp->pdev->dev, "Expect magic number timeout 0x%x\n",
			data);
		goto iunit_power_off;
	}

	/*
	 * Write authenticate_run into IU2CSEDATA0
	 * Write sizeof(boot_load) | 0x2 << CLIENT_ID to
	 * IU2CSEDB.IU2CSECMD and set IU2CSEDB.IU2CSEBUSY as
	 */
	dev_info(&isp->pdev->dev, "Sending AUTHENTICATE_RUN to CSE\n");
	rval = ipu_buttress_ipc_send(isp, IPU_BUTTRESS_IPC_CSE,
				     BUTTRESS_IU2CSEDATA0_IPC_AUTH_RUN,
				     1, 1,
				     BUTTRESS_CSE2IUDATA0_IPC_AUTH_RUN_DONE);
	if (rval) {
		dev_err(&isp->pdev->dev, "CSE authenticate_run failed\n");
		goto iunit_power_off;
	}

	done = BUTTRESS_SECURITY_CTL_AUTH_DONE;
	rval = readl_poll_timeout(isp->base + BUTTRESS_REG_SECURITY_CTL, data,
				  ((data & mask) == done ||
				   (data & mask) == fail), 500,
				  BUTTRESS_CSE_AUTHENTICATE_TIMEOUT);
	if (rval) {
		dev_err(&isp->pdev->dev, "CSE authenticate timeout\n");
		goto iunit_power_off;
	}

	data = readl(isp->base + BUTTRESS_REG_SECURITY_CTL) & mask;
	if (data == fail) {
		dev_err(&isp->pdev->dev, "CSE boot_load failed\n");
		rval = -EINVAL;
		goto iunit_power_off;
	}

	dev_info(&isp->pdev->dev, "CSE authenticate_run done\n");

iunit_power_off:
	mutex_unlock(&b->auth_mutex);

	return rval;
}

static int ipu_buttress_send_tsc_request(struct ipu_device *isp)
{
	u32 val, mask, shift, done;
	int ret;

	mask = BUTTRESS_PWR_STATE_HH_STATUS_MASK;
	shift = BUTTRESS_PWR_STATE_HH_STATUS_SHIFT;

	writel(BUTTRESS_FABRIC_CMD_START_TSC_SYNC,
	       isp->base + BUTTRESS_REG_FABRIC_CMD);

	val = readl(isp->base + BUTTRESS_REG_PWR_STATE);
	val = (val & mask) >> shift;
	if (val == BUTTRESS_PWR_STATE_HH_STATE_ERR) {
		dev_err(&isp->pdev->dev, "Start tsc sync failed\n");
		return -EINVAL;
	}

	done = BUTTRESS_PWR_STATE_HH_STATE_DONE;
	ret = readl_poll_timeout(isp->base + BUTTRESS_REG_PWR_STATE, val,
				 ((val & mask) >> shift == done), 500,
				 BUTTRESS_TSC_SYNC_TIMEOUT);
	if (ret)
		dev_err(&isp->pdev->dev, "Start tsc sync timeout\n");

	return ret;
}

int ipu_buttress_start_tsc_sync(struct ipu_device *isp)
{
	unsigned int i;

	for (i = 0; i < BUTTRESS_TSC_SYNC_RESET_TRIAL_MAX; i++) {
		int ret;

		ret = ipu_buttress_send_tsc_request(isp);
		if (ret == -ETIMEDOUT) {
			u32 val;
			/* set tsw soft reset */
			val = readl(isp->base + BUTTRESS_REG_TSW_CTL);
			val = val | BUTTRESS_TSW_CTL_SOFT_RESET;
			writel(val, isp->base + BUTTRESS_REG_TSW_CTL);
			/* clear tsw soft reset */
			val = val & (~BUTTRESS_TSW_CTL_SOFT_RESET);
			writel(val, isp->base + BUTTRESS_REG_TSW_CTL);

			continue;
		}
		return ret;
	}

	dev_err(&isp->pdev->dev, "TSC sync failed(timeout)\n");

	return -ETIMEDOUT;
}
EXPORT_SYMBOL(ipu_buttress_start_tsc_sync);

struct clk_ipu_sensor {
	struct ipu_device *isp;
	struct clk_hw hw;
	unsigned int id;
	unsigned long rate;
};

#define to_clk_ipu_sensor(_hw) container_of(_hw, struct clk_ipu_sensor, hw)

int ipu_buttress_tsc_read(struct ipu_device *isp, u64 *val)
{
	u32 tsc_hi_1, tsc_hi_2, tsc_lo;
	unsigned long flags;

	local_irq_save(flags);
	tsc_hi_1 = readl(isp->base + BUTTRESS_REG_TSC_HI);
	tsc_lo = readl(isp->base + BUTTRESS_REG_TSC_LO);
	tsc_hi_2 = readl(isp->base + BUTTRESS_REG_TSC_HI);
	if (tsc_hi_1 == tsc_hi_2) {
		*val = (u64)tsc_hi_1 << 32 | tsc_lo;
	} else {
		/* Check if TSC has rolled over */
		if (tsc_lo & BIT(31))
			*val = (u64)tsc_hi_1 << 32 | tsc_lo;
		else
			*val = (u64)tsc_hi_2 << 32 | tsc_lo;
	}
	local_irq_restore(flags);

	return 0;
}
EXPORT_SYMBOL_GPL(ipu_buttress_tsc_read);

#ifdef CONFIG_DEBUG_FS

static int ipu_buttress_reg_open(struct inode *inode, struct file *file)
{
	if (!inode->i_private)
		return -EACCES;

	file->private_data = inode->i_private;
	return 0;
}

static ssize_t ipu_buttress_reg_read(struct file *file, char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct debugfs_reg32 *reg = file->private_data;
	u8 tmp[11];
	u32 val = readl((void __iomem *)reg->offset);
	int len = scnprintf(tmp, sizeof(tmp), "0x%08x", val);

	return simple_read_from_buffer(buf, len, ppos, &tmp, len);
}

static ssize_t ipu_buttress_reg_write(struct file *file,
				      const char __user *buf,
				      size_t count, loff_t *ppos)
{
	struct debugfs_reg32 *reg = file->private_data;
	u32 val;
	int rval;

	rval = kstrtou32_from_user(buf, count, 0, &val);
	if (rval)
		return rval;

	writel(val, (void __iomem *)reg->offset);

	return count;
}

static struct debugfs_reg32 buttress_regs[] = {
	{"IU2CSEDB0", BUTTRESS_REG_IU2CSEDB0},
	{"IU2CSEDATA0", BUTTRESS_REG_IU2CSEDATA0},
	{"CSE2IUDB0", BUTTRESS_REG_CSE2IUDB0},
	{"CSE2IUDATA0", BUTTRESS_REG_CSE2IUDATA0},
	{"CSE2IUCSR", BUTTRESS_REG_CSE2IUCSR},
	{"IU2CSECSR", BUTTRESS_REG_IU2CSECSR},
};

static const struct file_operations ipu_buttress_reg_fops = {
	.owner = THIS_MODULE,
	.open = ipu_buttress_reg_open,
	.read = ipu_buttress_reg_read,
	.write = ipu_buttress_reg_write,
};

static int ipu_buttress_start_tsc_sync_set(void *data, u64 val)
{
	struct ipu_device *isp = data;

	return ipu_buttress_start_tsc_sync(isp);
}

DEFINE_SIMPLE_ATTRIBUTE(ipu_buttress_start_tsc_sync_fops, NULL,
			ipu_buttress_start_tsc_sync_set, "%llu\n");

static int ipu_buttress_tsc_get(void *data, u64 *val)
{
	return ipu_buttress_tsc_read(data, val);
}
DEFINE_SIMPLE_ATTRIBUTE(ipu_buttress_tsc_fops, ipu_buttress_tsc_get,
			NULL, "%llu\n");

static int ipu_buttress_psys_force_freq_get(void *data, u64 *val)
{
	struct ipu_device *isp = data;

	*val = isp->buttress.psys_force_ratio * BUTTRESS_PS_FREQ_STEP;

	return 0;
}

static int ipu_buttress_psys_force_freq_set(void *data, u64 val)
{
	struct ipu_device *isp = data;

	if (val && (val < BUTTRESS_MIN_FORCE_PS_FREQ ||
		    val > BUTTRESS_MAX_FORCE_PS_FREQ))
		return -EINVAL;

	do_div(val, BUTTRESS_PS_FREQ_STEP);
	isp->buttress.psys_force_ratio = val;

	if (isp->buttress.psys_force_ratio)
		ipu_buttress_set_psys_ratio(isp,
					    isp->buttress.psys_force_ratio,
					    isp->buttress.psys_force_ratio);
	else
		ipu_buttress_set_psys_freq(isp, isp->buttress.psys_min_freq);

	return 0;
}

static int ipu_buttress_isys_freq_get(void *data, u64 *val)
{
	struct ipu_device *isp = data;
	u32 reg_val;
	int rval;

	rval = pm_runtime_get_sync(&isp->isys->dev);
	if (rval < 0) {
		pm_runtime_put(&isp->isys->dev);
		dev_err(&isp->pdev->dev, "Runtime PM failed (%d)\n", rval);
		return rval;
	}

	reg_val = readl(isp->base + BUTTRESS_REG_IS_FREQ_CTL);

	pm_runtime_put(&isp->isys->dev);

	*val = IPU_IS_FREQ_RATIO_BASE *
	    (reg_val & IPU_BUTTRESS_IS_FREQ_CTL_DIVISOR_MASK);

	return 0;
}

static int ipu_buttress_isys_freq_set(void *data, u64 val)
{
	struct ipu_device *isp = data;
	int rval;

	if (val < BUTTRESS_MIN_FORCE_IS_FREQ ||
	    val > BUTTRESS_MAX_FORCE_IS_FREQ)
		return -EINVAL;

	rval = pm_runtime_get_sync(&isp->isys->dev);
	if (rval < 0) {
		pm_runtime_put(&isp->isys->dev);
		dev_err(&isp->pdev->dev, "Runtime PM failed (%d)\n", rval);
		return rval;
	}

	do_div(val, BUTTRESS_IS_FREQ_STEP);
	if (val)
		ipu_buttress_set_isys_ratio(isp, val);

	pm_runtime_put(&isp->isys->dev);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(ipu_buttress_psys_force_freq_fops,
			ipu_buttress_psys_force_freq_get,
			ipu_buttress_psys_force_freq_set, "%llu\n");

DEFINE_SIMPLE_ATTRIBUTE(ipu_buttress_psys_freq_fops,
			ipu_buttress_psys_freq_get, NULL, "%llu\n");

DEFINE_SIMPLE_ATTRIBUTE(ipu_buttress_isys_freq_fops,
			ipu_buttress_isys_freq_get,
			ipu_buttress_isys_freq_set, "%llu\n");

int ipu_buttress_debugfs_init(struct ipu_device *isp)
{
	struct debugfs_reg32 *reg =
	    devm_kcalloc(&isp->pdev->dev, ARRAY_SIZE(buttress_regs),
			 sizeof(*reg), GFP_KERNEL);
	struct dentry *dir, *file;
	int i;

	if (!reg)
		return -ENOMEM;

	dir = debugfs_create_dir("buttress", isp->ipu_dir);
	if (!dir)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(buttress_regs); i++, reg++) {
		reg->offset = (unsigned long)isp->base +
		    buttress_regs[i].offset;
		reg->name = buttress_regs[i].name;
		file = debugfs_create_file(reg->name, 0700,
					   dir, reg, &ipu_buttress_reg_fops);
		if (!file)
			goto err;
	}

	file = debugfs_create_file("start_tsc_sync", 0200, dir, isp,
				   &ipu_buttress_start_tsc_sync_fops);
	if (!file)
		goto err;
	file = debugfs_create_file("tsc", 0400, dir, isp,
				   &ipu_buttress_tsc_fops);
	if (!file)
		goto err;
	file = debugfs_create_file("psys_force_freq", 0700, dir, isp,
				   &ipu_buttress_psys_force_freq_fops);
	if (!file)
		goto err;

	file = debugfs_create_file("psys_freq", 0400, dir, isp,
				   &ipu_buttress_psys_freq_fops);
	if (!file)
		goto err;

	file = debugfs_create_file("isys_freq", 0700, dir, isp,
				   &ipu_buttress_isys_freq_fops);
	if (!file)
		goto err;

	return 0;
err:
	debugfs_remove_recursive(dir);
	return -ENOMEM;
}

#endif /* CONFIG_DEBUG_FS */

u64 ipu_buttress_tsc_ticks_to_ns(u64 ticks, const struct ipu_device *isp)
{
	u64 ns = ticks * 10000;

	/*
	 * converting TSC tick count to ns is calculated by:
	 * Example (TSC clock frequency is 19.2MHz):
	 * ns = ticks * 1000 000 000 / 19.2Mhz
	 *    = ticks * 1000 000 000 / 19200000Hz
	 *    = ticks * 10000 / 192 ns
	 */
	do_div(ns, isp->buttress.ref_clk);

	return ns;
}
EXPORT_SYMBOL_GPL(ipu_buttress_tsc_ticks_to_ns);

static ssize_t psys_fused_min_freq_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct ipu_device *isp = pci_get_drvdata(to_pci_dev(dev));

	return snprintf(buf, PAGE_SIZE, "%u\n",
			isp->buttress.psys_fused_freqs.min_freq);
}

static DEVICE_ATTR_RO(psys_fused_min_freq);

static ssize_t psys_fused_max_freq_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct ipu_device *isp = pci_get_drvdata(to_pci_dev(dev));

	return snprintf(buf, PAGE_SIZE, "%u\n",
			isp->buttress.psys_fused_freqs.max_freq);
}

static DEVICE_ATTR_RO(psys_fused_max_freq);

static ssize_t psys_fused_efficient_freq_show(struct device *dev,
					      struct device_attribute *attr,
					      char *buf)
{
	struct ipu_device *isp = pci_get_drvdata(to_pci_dev(dev));

	return snprintf(buf, PAGE_SIZE, "%u\n",
			isp->buttress.psys_fused_freqs.efficient_freq);
}

static DEVICE_ATTR_RO(psys_fused_efficient_freq);

int ipu_buttress_restore(struct ipu_device *isp)
{
	struct ipu_buttress *b = &isp->buttress;

	writel(BUTTRESS_IRQS, isp->base + BUTTRESS_REG_ISR_CLEAR);
	writel(BUTTRESS_IRQS, isp->base + BUTTRESS_REG_ISR_ENABLE);
	writel(b->wdt_cached_value, isp->base + BUTTRESS_REG_WDT);

	return 0;
}

int ipu_buttress_init(struct ipu_device *isp)
{
	struct ipu_buttress *b = &isp->buttress;
	u32 val;
	int rval, ipc_reset_retry = BUTTRESS_CSE_IPC_RESET_RETRY;

	mutex_init(&b->power_mutex);
	mutex_init(&b->auth_mutex);
	mutex_init(&b->cons_mutex);
	mutex_init(&b->ipc_mutex);
	init_completion(&b->ish.send_complete);
	init_completion(&b->cse.send_complete);
	init_completion(&b->ish.recv_complete);
	init_completion(&b->cse.recv_complete);

	b->cse.nack = BUTTRESS_CSE2IUDATA0_IPC_NACK;
	b->cse.nack_mask = BUTTRESS_CSE2IUDATA0_IPC_NACK_MASK;
	b->cse.csr_in = BUTTRESS_REG_CSE2IUCSR;
	b->cse.csr_out = BUTTRESS_REG_IU2CSECSR;
	b->cse.db0_in = BUTTRESS_REG_CSE2IUDB0;
	b->cse.db0_out = BUTTRESS_REG_IU2CSEDB0;
	b->cse.data0_in = BUTTRESS_REG_CSE2IUDATA0;
	b->cse.data0_out = BUTTRESS_REG_IU2CSEDATA0;

	/* no ISH on IPU6 */
	memset(&b->ish, 0, sizeof(b->ish));
	INIT_LIST_HEAD(&b->constraints);

	ipu_buttress_set_secure_mode(isp);
	isp->secure_mode = ipu_buttress_get_secure_mode(isp);
	if (isp->secure_mode != secure_mode_enable)
		dev_warn(&isp->pdev->dev, "Unable to set secure mode\n");

	dev_info(&isp->pdev->dev, "IPU in %s mode\n",
		 isp->secure_mode ? "secure" : "non-secure");

	b->wdt_cached_value = readl(isp->base + BUTTRESS_REG_WDT);
	writel(BUTTRESS_IRQS, isp->base + BUTTRESS_REG_ISR_CLEAR);
	writel(BUTTRESS_IRQS, isp->base + BUTTRESS_REG_ISR_ENABLE);

	/* get ref_clk frequency by reading the indication in btrs control */
	val = readl(isp->base + BUTTRESS_REG_BTRS_CTRL);
	val &= BUTTRESS_REG_BTRS_CTRL_REF_CLK_IND;
	val >>= 8;

	switch (val) {
	case 0x0:
		b->ref_clk = 240;
		break;
	case 0x1:
		b->ref_clk = 192;
		break;
	case 0x2:
		b->ref_clk = 384;
		break;
	default:
		dev_warn(&isp->pdev->dev,
			 "Unsupported ref clock, use 19.2Mhz by default.\n");
		b->ref_clk = 192;
		break;
	}

	rval = device_create_file(&isp->pdev->dev,
				  &dev_attr_psys_fused_min_freq);
	if (rval) {
		dev_err(&isp->pdev->dev, "Create min freq file failed\n");
		goto err_mutex_destroy;
	}

	rval = device_create_file(&isp->pdev->dev,
				  &dev_attr_psys_fused_max_freq);
	if (rval) {
		dev_err(&isp->pdev->dev, "Create max freq file failed\n");
		goto err_remove_min_freq_file;
	}

	rval = device_create_file(&isp->pdev->dev,
				  &dev_attr_psys_fused_efficient_freq);
	if (rval) {
		dev_err(&isp->pdev->dev, "Create efficient freq file failed\n");
		goto err_remove_max_freq_file;
	}

	/*
	 * We want to retry couple of time in case CSE initialization
	 * is delayed for reason or another.
	 */
	do {
		rval = ipu_buttress_ipc_reset(isp, &b->cse);
		if (rval) {
			dev_warn(&isp->pdev->dev,
				 "IPC reset protocol failed, retrying\n");
		} else {
			dev_info(&isp->pdev->dev, "IPC reset done\n");
			return 0;
		}
	} while (ipc_reset_retry--);

	dev_err(&isp->pdev->dev, "IPC reset protocol failed\n");

err_remove_max_freq_file:
	device_remove_file(&isp->pdev->dev, &dev_attr_psys_fused_max_freq);
err_remove_min_freq_file:
	device_remove_file(&isp->pdev->dev, &dev_attr_psys_fused_min_freq);
err_mutex_destroy:
	mutex_destroy(&b->power_mutex);
	mutex_destroy(&b->auth_mutex);
	mutex_destroy(&b->cons_mutex);
	mutex_destroy(&b->ipc_mutex);

	return rval;
}

void ipu_buttress_exit(struct ipu_device *isp)
{
	struct ipu_buttress *b = &isp->buttress;

	writel(0, isp->base + BUTTRESS_REG_ISR_ENABLE);

	device_remove_file(&isp->pdev->dev,
			   &dev_attr_psys_fused_efficient_freq);
	device_remove_file(&isp->pdev->dev, &dev_attr_psys_fused_max_freq);
	device_remove_file(&isp->pdev->dev, &dev_attr_psys_fused_min_freq);

	mutex_destroy(&b->power_mutex);
	mutex_destroy(&b->auth_mutex);
	mutex_destroy(&b->cons_mutex);
	mutex_destroy(&b->ipc_mutex);
}
