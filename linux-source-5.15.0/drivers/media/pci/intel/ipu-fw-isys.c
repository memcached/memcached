// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2013 - 2021 Intel Corporation

#include <asm/cacheflush.h>

#include <linux/kernel.h>
#include <linux/delay.h>

#include "ipu.h"
#include "ipu-trace.h"
#include "ipu-platform-regs.h"
#include "ipu-platform.h"
#include "ipu-fw-isys.h"
#include "ipu-fw-com.h"
#include "ipu-isys.h"

#define IPU_FW_UNSUPPORTED_DATA_TYPE	0
static const uint32_t
extracted_bits_per_pixel_per_mipi_data_type[N_IPU_FW_ISYS_MIPI_DATA_TYPE] = {
	64,	/* [0x00]   IPU_FW_ISYS_MIPI_DATA_TYPE_FRAME_START_CODE */
	64,	/* [0x01]   IPU_FW_ISYS_MIPI_DATA_TYPE_FRAME_END_CODE */
	64,	/* [0x02]   IPU_FW_ISYS_MIPI_DATA_TYPE_LINE_START_CODE */
	64,	/* [0x03]   IPU_FW_ISYS_MIPI_DATA_TYPE_LINE_END_CODE */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x04] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x05] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x06] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x07] */
	64,	/* [0x08]   IPU_FW_ISYS_MIPI_DATA_TYPE_GENERIC_SHORT1 */
	64,	/* [0x09]   IPU_FW_ISYS_MIPI_DATA_TYPE_GENERIC_SHORT2 */
	64,	/* [0x0A]   IPU_FW_ISYS_MIPI_DATA_TYPE_GENERIC_SHORT3 */
	64,	/* [0x0B]   IPU_FW_ISYS_MIPI_DATA_TYPE_GENERIC_SHORT4 */
	64,	/* [0x0C]   IPU_FW_ISYS_MIPI_DATA_TYPE_GENERIC_SHORT5 */
	64,	/* [0x0D]   IPU_FW_ISYS_MIPI_DATA_TYPE_GENERIC_SHORT6 */
	64,	/* [0x0E]   IPU_FW_ISYS_MIPI_DATA_TYPE_GENERIC_SHORT7 */
	64,	/* [0x0F]   IPU_FW_ISYS_MIPI_DATA_TYPE_GENERIC_SHORT8 */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x10] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x11] */
	8,	/* [0x12]    IPU_FW_ISYS_MIPI_DATA_TYPE_EMBEDDED */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x13] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x14] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x15] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x16] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x17] */
	12,	/* [0x18]   IPU_FW_ISYS_MIPI_DATA_TYPE_YUV420_8 */
	15,	/* [0x19]   IPU_FW_ISYS_MIPI_DATA_TYPE_YUV420_10 */
	12,	/* [0x1A]   IPU_FW_ISYS_MIPI_DATA_TYPE_YUV420_8_LEGACY */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x1B] */
	12,	/* [0x1C]   IPU_FW_ISYS_MIPI_DATA_TYPE_YUV420_8_SHIFT */
	15,	/* [0x1D]   IPU_FW_ISYS_MIPI_DATA_TYPE_YUV420_10_SHIFT */
	16,	/* [0x1E]   IPU_FW_ISYS_MIPI_DATA_TYPE_YUV422_8 */
	20,	/* [0x1F]   IPU_FW_ISYS_MIPI_DATA_TYPE_YUV422_10 */
	16,	/* [0x20]   IPU_FW_ISYS_MIPI_DATA_TYPE_RGB_444 */
	16,	/* [0x21]   IPU_FW_ISYS_MIPI_DATA_TYPE_RGB_555 */
	16,	/* [0x22]   IPU_FW_ISYS_MIPI_DATA_TYPE_RGB_565 */
	18,	/* [0x23]   IPU_FW_ISYS_MIPI_DATA_TYPE_RGB_666 */
	24,	/* [0x24]   IPU_FW_ISYS_MIPI_DATA_TYPE_RGB_888 */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x25] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x26] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x27] */
	6,	/* [0x28]    IPU_FW_ISYS_MIPI_DATA_TYPE_RAW_6 */
	7,	/* [0x29]    IPU_FW_ISYS_MIPI_DATA_TYPE_RAW_7 */
	8,	/* [0x2A]    IPU_FW_ISYS_MIPI_DATA_TYPE_RAW_8 */
	10,	/* [0x2B]   IPU_FW_ISYS_MIPI_DATA_TYPE_RAW_10 */
	12,	/* [0x2C]   IPU_FW_ISYS_MIPI_DATA_TYPE_RAW_12 */
	14,	/* [0x2D]   IPU_FW_ISYS_MIPI_DATA_TYPE_RAW_14 */
	16,	/* [0x2E]   IPU_FW_ISYS_MIPI_DATA_TYPE_RAW_16 */
	8,	/* [0x2F]    IPU_FW_ISYS_MIPI_DATA_TYPE_BINARY_8 */
	8,	/* [0x30]    IPU_FW_ISYS_MIPI_DATA_TYPE_USER_DEF1 */
	8,	/* [0x31]    IPU_FW_ISYS_MIPI_DATA_TYPE_USER_DEF2 */
	8,	/* [0x32]    IPU_FW_ISYS_MIPI_DATA_TYPE_USER_DEF3 */
	8,	/* [0x33]    IPU_FW_ISYS_MIPI_DATA_TYPE_USER_DEF4 */
	8,	/* [0x34]    IPU_FW_ISYS_MIPI_DATA_TYPE_USER_DEF5 */
	8,	/* [0x35]    IPU_FW_ISYS_MIPI_DATA_TYPE_USER_DEF6 */
	8,	/* [0x36]    IPU_FW_ISYS_MIPI_DATA_TYPE_USER_DEF7 */
	8,	/* [0x37]    IPU_FW_ISYS_MIPI_DATA_TYPE_USER_DEF8 */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x38] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x39] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x3A] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x3B] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x3C] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x3D] */
	IPU_FW_UNSUPPORTED_DATA_TYPE,	/* [0x3E] */
	IPU_FW_UNSUPPORTED_DATA_TYPE	/* [0x3F] */
};

static const char send_msg_types[N_IPU_FW_ISYS_SEND_TYPE][32] = {
	"STREAM_OPEN",
	"STREAM_START",
	"STREAM_START_AND_CAPTURE",
	"STREAM_CAPTURE",
	"STREAM_STOP",
	"STREAM_FLUSH",
	"STREAM_CLOSE"
};

static int handle_proxy_response(struct ipu_isys *isys, unsigned int req_id)
{
	struct ipu_fw_isys_proxy_resp_info_abi *resp;
	int rval = -EIO;

	resp = (struct ipu_fw_isys_proxy_resp_info_abi *)
	    ipu_recv_get_token(isys->fwcom, IPU_BASE_PROXY_RECV_QUEUES);
	if (!resp)
		return 1;

	dev_dbg(&isys->adev->dev,
		"Proxy response: id 0x%x, error %d, details %d\n",
		resp->request_id, resp->error_info.error,
		resp->error_info.error_details);

	if (req_id == resp->request_id)
		rval = 0;

	ipu_recv_put_token(isys->fwcom, IPU_BASE_PROXY_RECV_QUEUES);
	return rval;
}

/* Simple blocking proxy send function */
int ipu_fw_isys_send_proxy_token(struct ipu_isys *isys,
				 unsigned int req_id,
				 unsigned int index,
				 unsigned int offset, u32 value)
{
	struct ipu_fw_com_context *ctx = isys->fwcom;
	struct ipu_fw_proxy_send_queue_token *token;
	unsigned int timeout = 1000;
	int rval = -EBUSY;

	dev_dbg(&isys->adev->dev,
		"proxy send token: req_id 0x%x, index %d, offset 0x%x, value 0x%x\n",
		req_id, index, offset, value);

	token = ipu_send_get_token(ctx, IPU_BASE_PROXY_SEND_QUEUES);
	if (!token)
		goto leave;

	token->request_id = req_id;
	token->region_index = index;
	token->offset = offset;
	token->value = value;
	ipu_send_put_token(ctx, IPU_BASE_PROXY_SEND_QUEUES);

	/* Currently proxy doesn't support irq based service. Poll */
	do {
		usleep_range(100, 110);
		rval = handle_proxy_response(isys, req_id);
		if (!rval)
			break;
		if (rval == -EIO) {
			dev_err(&isys->adev->dev,
				"Proxy response received with unexpected id\n");
			break;
		}
		timeout--;
	} while (rval && timeout);

	if (!timeout)
		dev_err(&isys->adev->dev, "Proxy response timed out\n");
leave:
	return rval;
}

int
ipu_fw_isys_complex_cmd(struct ipu_isys *isys,
			const unsigned int stream_handle,
			void *cpu_mapped_buf,
			dma_addr_t dma_mapped_buf,
			size_t size, enum ipu_fw_isys_send_type send_type)
{
	struct ipu_fw_com_context *ctx = isys->fwcom;
	struct ipu_fw_send_queue_token *token;

	if (send_type >= N_IPU_FW_ISYS_SEND_TYPE)
		return -EINVAL;

	dev_dbg(&isys->adev->dev, "send_token: %s\n",
		send_msg_types[send_type]);

	/*
	 * Time to flush cache in case we have some payload. Not all messages
	 * have that
	 */
	if (cpu_mapped_buf)
		clflush_cache_range(cpu_mapped_buf, size);

	token = ipu_send_get_token(ctx,
				   stream_handle + IPU_BASE_MSG_SEND_QUEUES);
	if (!token)
		return -EBUSY;

	token->payload = dma_mapped_buf;
	token->buf_handle = (unsigned long)cpu_mapped_buf;
	token->send_type = send_type;

	ipu_send_put_token(ctx, stream_handle + IPU_BASE_MSG_SEND_QUEUES);

	return 0;
}

int ipu_fw_isys_simple_cmd(struct ipu_isys *isys,
			   const unsigned int stream_handle,
			   enum ipu_fw_isys_send_type send_type)
{
	return ipu_fw_isys_complex_cmd(isys, stream_handle, NULL, 0, 0,
				       send_type);
}

int ipu_fw_isys_close(struct ipu_isys *isys)
{
	struct device *dev = &isys->adev->dev;
	int timeout = IPU_ISYS_TURNOFF_TIMEOUT;
	int rval;
	unsigned long flags;
	void *fwcom;

	/*
	 * Stop the isys fw. Actual close takes
	 * some time as the FW must stop its actions including code fetch
	 * to SP icache.
	 * spinlock to wait the interrupt handler to be finished
	 */
	spin_lock_irqsave(&isys->power_lock, flags);
	rval = ipu_fw_com_close(isys->fwcom);
	fwcom = isys->fwcom;
	isys->fwcom = NULL;
	spin_unlock_irqrestore(&isys->power_lock, flags);
	if (rval)
		dev_err(dev, "Device close failure: %d\n", rval);

	/* release probably fails if the close failed. Let's try still */
	do {
		usleep_range(IPU_ISYS_TURNOFF_DELAY_US,
			     2 * IPU_ISYS_TURNOFF_DELAY_US);
		rval = ipu_fw_com_release(fwcom, 0);
		timeout--;
	} while (rval != 0 && timeout);

	if (rval) {
		dev_err(dev, "Device release time out %d\n", rval);
		spin_lock_irqsave(&isys->power_lock, flags);
		isys->fwcom = fwcom;
		spin_unlock_irqrestore(&isys->power_lock, flags);
	}

	return rval;
}

void ipu_fw_isys_cleanup(struct ipu_isys *isys)
{
	int ret;

	ret = ipu_fw_com_release(isys->fwcom, 1);
	if (ret < 0)
		dev_err(&isys->adev->dev,
			"Device busy, fw_com release failed.");
	isys->fwcom = NULL;
}

static void start_sp(struct ipu_bus_device *adev)
{
	struct ipu_isys *isys = ipu_bus_get_drvdata(adev);
	void __iomem *spc_regs_base = isys->pdata->base +
	    isys->pdata->ipdata->hw_variant.spc_offset;
	u32 val = 0;

	val |= IPU_ISYS_SPC_STATUS_START |
	    IPU_ISYS_SPC_STATUS_RUN |
	    IPU_ISYS_SPC_STATUS_CTRL_ICACHE_INVALIDATE;
	val |= isys->icache_prefetch ? IPU_ISYS_SPC_STATUS_ICACHE_PREFETCH : 0;

	writel(val, spc_regs_base + IPU_ISYS_REG_SPC_STATUS_CTRL);
}

static int query_sp(struct ipu_bus_device *adev)
{
	struct ipu_isys *isys = ipu_bus_get_drvdata(adev);
	void __iomem *spc_regs_base = isys->pdata->base +
	    isys->pdata->ipdata->hw_variant.spc_offset;
	u32 val = readl(spc_regs_base + IPU_ISYS_REG_SPC_STATUS_CTRL);

	/* return true when READY == 1, START == 0 */
	val &= IPU_ISYS_SPC_STATUS_READY | IPU_ISYS_SPC_STATUS_START;

	return val == IPU_ISYS_SPC_STATUS_READY;
}

static int ipu6_isys_fwcom_cfg_init(struct ipu_isys *isys,
				    struct ipu_fw_com_cfg *fwcom,
				    unsigned int num_streams)
{
	int i;
	unsigned int size;
	struct ipu_fw_syscom_queue_config *input_queue_cfg;
	struct ipu_fw_syscom_queue_config *output_queue_cfg;
	struct ipu6_fw_isys_fw_config *isys_fw_cfg;
	int num_out_message_queues = 1;
	int type_proxy = IPU_FW_ISYS_QUEUE_TYPE_PROXY;
	int type_dev = IPU_FW_ISYS_QUEUE_TYPE_DEV;
	int type_msg = IPU_FW_ISYS_QUEUE_TYPE_MSG;
	int base_dev_send = IPU_BASE_DEV_SEND_QUEUES;
	int base_msg_send = IPU_BASE_MSG_SEND_QUEUES;
	int base_msg_recv = IPU_BASE_MSG_RECV_QUEUES;
	int num_in_message_queues;
	unsigned int max_streams;
	unsigned int max_send_queues, max_sram_blocks, max_devq_size;

	max_streams = IPU6_ISYS_NUM_STREAMS;
	max_send_queues = IPU6_N_MAX_SEND_QUEUES;
	max_sram_blocks = IPU6_NOF_SRAM_BLOCKS_MAX;
	max_devq_size = IPU6_DEV_SEND_QUEUE_SIZE;
	if (ipu_ver == IPU_VER_6SE) {
		max_streams = IPU6SE_ISYS_NUM_STREAMS;
		max_send_queues = IPU6SE_N_MAX_SEND_QUEUES;
		max_sram_blocks = IPU6SE_NOF_SRAM_BLOCKS_MAX;
		max_devq_size = IPU6SE_DEV_SEND_QUEUE_SIZE;
	}

	num_in_message_queues = clamp_t(unsigned int, num_streams, 1,
					max_streams);
	isys_fw_cfg = devm_kzalloc(&isys->adev->dev, sizeof(*isys_fw_cfg),
				   GFP_KERNEL);
	if (!isys_fw_cfg)
		return -ENOMEM;

	isys_fw_cfg->num_send_queues[IPU_FW_ISYS_QUEUE_TYPE_PROXY] =
		IPU_N_MAX_PROXY_SEND_QUEUES;
	isys_fw_cfg->num_send_queues[IPU_FW_ISYS_QUEUE_TYPE_DEV] =
		IPU_N_MAX_DEV_SEND_QUEUES;
	isys_fw_cfg->num_send_queues[IPU_FW_ISYS_QUEUE_TYPE_MSG] =
		num_in_message_queues;
	isys_fw_cfg->num_recv_queues[IPU_FW_ISYS_QUEUE_TYPE_PROXY] =
		IPU_N_MAX_PROXY_RECV_QUEUES;
	/* Common msg/dev return queue */
	isys_fw_cfg->num_recv_queues[IPU_FW_ISYS_QUEUE_TYPE_DEV] = 0;
	isys_fw_cfg->num_recv_queues[IPU_FW_ISYS_QUEUE_TYPE_MSG] =
		num_out_message_queues;

	size = sizeof(*input_queue_cfg) * max_send_queues;
	input_queue_cfg = devm_kzalloc(&isys->adev->dev, size, GFP_KERNEL);
	if (!input_queue_cfg)
		return -ENOMEM;

	size = sizeof(*output_queue_cfg) * IPU_N_MAX_RECV_QUEUES;
	output_queue_cfg = devm_kzalloc(&isys->adev->dev, size, GFP_KERNEL);
	if (!output_queue_cfg)
		return -ENOMEM;

	fwcom->input = input_queue_cfg;
	fwcom->output = output_queue_cfg;

	fwcom->num_input_queues =
		isys_fw_cfg->num_send_queues[type_proxy] +
		isys_fw_cfg->num_send_queues[type_dev] +
		isys_fw_cfg->num_send_queues[type_msg];

	fwcom->num_output_queues =
		isys_fw_cfg->num_recv_queues[type_proxy] +
		isys_fw_cfg->num_recv_queues[type_dev] +
		isys_fw_cfg->num_recv_queues[type_msg];

	/* SRAM partitioning. Equal partitioning is set. */
	for (i = 0; i < max_sram_blocks; i++) {
		if (i < num_in_message_queues)
			isys_fw_cfg->buffer_partition.num_gda_pages[i] =
				(IPU_DEVICE_GDA_NR_PAGES *
				 IPU_DEVICE_GDA_VIRT_FACTOR) /
				num_in_message_queues;
		else
			isys_fw_cfg->buffer_partition.num_gda_pages[i] = 0;
	}

	/* FW assumes proxy interface at fwcom queue 0 */
	for (i = 0; i < isys_fw_cfg->num_send_queues[type_proxy]; i++) {
		input_queue_cfg[i].token_size =
			sizeof(struct ipu_fw_proxy_send_queue_token);
		input_queue_cfg[i].queue_size = IPU_ISYS_SIZE_PROXY_SEND_QUEUE;
	}

	for (i = 0; i < isys_fw_cfg->num_send_queues[type_dev]; i++) {
		input_queue_cfg[base_dev_send + i].token_size =
			sizeof(struct ipu_fw_send_queue_token);
		input_queue_cfg[base_dev_send + i].queue_size = max_devq_size;
	}

	for (i = 0; i < isys_fw_cfg->num_send_queues[type_msg]; i++) {
		input_queue_cfg[base_msg_send + i].token_size =
			sizeof(struct ipu_fw_send_queue_token);
		input_queue_cfg[base_msg_send + i].queue_size =
			IPU_ISYS_SIZE_SEND_QUEUE;
	}

	for (i = 0; i < isys_fw_cfg->num_recv_queues[type_proxy]; i++) {
		output_queue_cfg[i].token_size =
			sizeof(struct ipu_fw_proxy_resp_queue_token);
		output_queue_cfg[i].queue_size = IPU_ISYS_SIZE_PROXY_RECV_QUEUE;
	}
	/* There is no recv DEV queue */
	for (i = 0; i < isys_fw_cfg->num_recv_queues[type_msg]; i++) {
		output_queue_cfg[base_msg_recv + i].token_size =
			sizeof(struct ipu_fw_resp_queue_token);
		output_queue_cfg[base_msg_recv + i].queue_size =
			IPU_ISYS_SIZE_RECV_QUEUE;
	}

	fwcom->dmem_addr = isys->pdata->ipdata->hw_variant.dmem_offset;
	fwcom->specific_addr = isys_fw_cfg;
	fwcom->specific_size = sizeof(*isys_fw_cfg);

	return 0;
}

int ipu_fw_isys_init(struct ipu_isys *isys, unsigned int num_streams)
{
	int retry = IPU_ISYS_OPEN_RETRY;

	struct ipu_fw_com_cfg fwcom = {
		.cell_start = start_sp,
		.cell_ready = query_sp,
		.buttress_boot_offset = SYSCOM_BUTTRESS_FW_PARAMS_ISYS_OFFSET,
	};

	struct device *dev = &isys->adev->dev;
	int rval;

	ipu6_isys_fwcom_cfg_init(isys, &fwcom, num_streams);

	isys->fwcom = ipu_fw_com_prepare(&fwcom, isys->adev, isys->pdata->base);
	if (!isys->fwcom) {
		dev_err(dev, "isys fw com prepare failed\n");
		return -EIO;
	}

	rval = ipu_fw_com_open(isys->fwcom);
	if (rval) {
		dev_err(dev, "isys fw com open failed %d\n", rval);
		return rval;
	}

	do {
		usleep_range(IPU_ISYS_OPEN_TIMEOUT_US,
			     IPU_ISYS_OPEN_TIMEOUT_US + 10);
		rval = ipu_fw_com_ready(isys->fwcom);
		if (!rval)
			break;
		retry--;
	} while (retry > 0);

	if (!retry && rval) {
		dev_err(dev, "isys port open ready failed %d\n", rval);
		ipu_fw_isys_close(isys);
	}

	return rval;
}

struct ipu_fw_isys_resp_info_abi *
ipu_fw_isys_get_resp(void *context, unsigned int queue,
		     struct ipu_fw_isys_resp_info_abi *response)
{
	return (struct ipu_fw_isys_resp_info_abi *)
	    ipu_recv_get_token(context, queue);
}

void ipu_fw_isys_put_resp(void *context, unsigned int queue)
{
	ipu_recv_put_token(context, queue);
}

void ipu_fw_isys_set_params(struct ipu_fw_isys_stream_cfg_data_abi *stream_cfg)
{
	unsigned int i;
	unsigned int idx;

	for (i = 0; i < stream_cfg->nof_input_pins; i++) {
		idx = stream_cfg->input_pins[i].dt;
		stream_cfg->input_pins[i].bits_per_pix =
		    extracted_bits_per_pixel_per_mipi_data_type[idx];
		stream_cfg->input_pins[i].mapped_dt =
		    N_IPU_FW_ISYS_MIPI_DATA_TYPE;
		stream_cfg->input_pins[i].mipi_decompression =
		    IPU_FW_ISYS_MIPI_COMPRESSION_TYPE_NO_COMPRESSION;
		/*
		 * CSI BE can be used to crop and change bayer order.
		 * NOTE: currently it only crops first and last lines in height.
		 */
		if (stream_cfg->crop.top_offset & 1)
			stream_cfg->input_pins[i].crop_first_and_last_lines = 1;
		stream_cfg->input_pins[i].capture_mode =
			IPU_FW_ISYS_CAPTURE_MODE_REGULAR;
	}
}

void
ipu_fw_isys_dump_stream_cfg(struct device *dev,
			    struct ipu_fw_isys_stream_cfg_data_abi *stream_cfg)
{
	unsigned int i;

	dev_dbg(dev, "---------------------------\n");
	dev_dbg(dev, "IPU_FW_ISYS_STREAM_CFG_DATA\n");
	dev_dbg(dev, "---------------------------\n");

	dev_dbg(dev, "Source %d\n", stream_cfg->src);
	dev_dbg(dev, "VC %d\n", stream_cfg->vc);
	dev_dbg(dev, "Nof input pins %d\n", stream_cfg->nof_input_pins);
	dev_dbg(dev, "Nof output pins %d\n", stream_cfg->nof_output_pins);

	for (i = 0; i < stream_cfg->nof_input_pins; i++) {
		dev_dbg(dev, "Input pin %d\n", i);
		dev_dbg(dev, "Mipi data type 0x%0x\n",
			stream_cfg->input_pins[i].dt);
		dev_dbg(dev, "Mipi store mode %d\n",
			stream_cfg->input_pins[i].mipi_store_mode);
		dev_dbg(dev, "Bits per pixel %d\n",
			stream_cfg->input_pins[i].bits_per_pix);
		dev_dbg(dev, "Mapped data type 0x%0x\n",
			stream_cfg->input_pins[i].mapped_dt);
		dev_dbg(dev, "Input res width %d\n",
			stream_cfg->input_pins[i].input_res.width);
		dev_dbg(dev, "Input res height %d\n",
			stream_cfg->input_pins[i].input_res.height);
		dev_dbg(dev, "mipi decompression %d\n",
			stream_cfg->input_pins[i].mipi_decompression);
		dev_dbg(dev, "capture_mode %d\n",
			stream_cfg->input_pins[i].capture_mode);
	}

	dev_dbg(dev, "Crop info\n");
	dev_dbg(dev, "Crop.top_offset %d\n", stream_cfg->crop.top_offset);
	dev_dbg(dev, "Crop.left_offset %d\n", stream_cfg->crop.left_offset);
	dev_dbg(dev, "Crop.bottom_offset %d\n",
		stream_cfg->crop.bottom_offset);
	dev_dbg(dev, "Crop.right_offset %d\n", stream_cfg->crop.right_offset);
	dev_dbg(dev, "----------------\n");

	for (i = 0; i < stream_cfg->nof_output_pins; i++) {
		dev_dbg(dev, "Output pin %d\n", i);
		dev_dbg(dev, "Output input pin id %d\n",
			stream_cfg->output_pins[i].input_pin_id);
		dev_dbg(dev, "Output res width %d\n",
			stream_cfg->output_pins[i].output_res.width);
		dev_dbg(dev, "Output res height %d\n",
			stream_cfg->output_pins[i].output_res.height);
		dev_dbg(dev, "Stride %d\n", stream_cfg->output_pins[i].stride);
		dev_dbg(dev, "Pin type %d\n", stream_cfg->output_pins[i].pt);
		dev_dbg(dev, "Payload %d\n",
			stream_cfg->output_pins[i].payload_buf_size);
		dev_dbg(dev, "Ft %d\n", stream_cfg->output_pins[i].ft);
		dev_dbg(dev, "Watermar in lines %d\n",
			stream_cfg->output_pins[i].watermark_in_lines);
		dev_dbg(dev, "Send irq %d\n",
			stream_cfg->output_pins[i].send_irq);
		dev_dbg(dev, "Reserve compression %d\n",
			stream_cfg->output_pins[i].reserve_compression);
		dev_dbg(dev, "snoopable %d\n",
			stream_cfg->output_pins[i].snoopable);
		dev_dbg(dev, "error_handling_enable %d\n",
			stream_cfg->output_pins[i].error_handling_enable);
		dev_dbg(dev, "sensor type %d\n",
			stream_cfg->output_pins[i].sensor_type);
		dev_dbg(dev, "----------------\n");
	}

	dev_dbg(dev, "Isl_use %d\n", stream_cfg->isl_use);
	dev_dbg(dev, "stream sensor_type %d\n", stream_cfg->sensor_type);

}

void ipu_fw_isys_dump_frame_buff_set(struct device *dev,
				     struct ipu_fw_isys_frame_buff_set_abi *buf,
				     unsigned int outputs)
{
	unsigned int i;

	dev_dbg(dev, "--------------------------\n");
	dev_dbg(dev, "IPU_FW_ISYS_FRAME_BUFF_SET\n");
	dev_dbg(dev, "--------------------------\n");

	for (i = 0; i < outputs; i++) {
		dev_dbg(dev, "Output pin %d\n", i);
		dev_dbg(dev, "out_buf_id %llu\n",
			buf->output_pins[i].out_buf_id);
		dev_dbg(dev, "addr 0x%x\n", buf->output_pins[i].addr);
		dev_dbg(dev, "compress %u\n", buf->output_pins[i].compress);

		dev_dbg(dev, "----------------\n");
	}

	dev_dbg(dev, "send_irq_sof 0x%x\n", buf->send_irq_sof);
	dev_dbg(dev, "send_irq_eof 0x%x\n", buf->send_irq_eof);
	dev_dbg(dev, "send_resp_sof 0x%x\n", buf->send_resp_sof);
	dev_dbg(dev, "send_resp_eof 0x%x\n", buf->send_resp_eof);
	dev_dbg(dev, "send_irq_capture_ack 0x%x\n", buf->send_irq_capture_ack);
	dev_dbg(dev, "send_irq_capture_done 0x%x\n",
		buf->send_irq_capture_done);
	dev_dbg(dev, "send_resp_capture_ack 0x%x\n",
		buf->send_resp_capture_ack);
	dev_dbg(dev, "send_resp_capture_done 0x%x\n",
		buf->send_resp_capture_done);
}
