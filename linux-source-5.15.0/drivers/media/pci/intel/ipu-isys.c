// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2013 - 2021 Intel Corporation

#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/version.h>

#include <media/ipu-isys.h>
#include <media/v4l2-mc.h>
#include <media/v4l2-subdev.h>
#include <media/v4l2-fwnode.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-device.h>
#include <media/v4l2-event.h>
#include <media/v4l2-ioctl.h>
#include <media/v4l2-async.h>
#include "ipu.h"
#include "ipu-bus.h"
#include "ipu-cpd.h"
#include "ipu-mmu.h"
#include "ipu-dma.h"
#include "ipu-isys.h"
#include "ipu-isys-csi2.h"
#include "ipu-isys-video.h"
#include "ipu-platform-regs.h"
#include "ipu-buttress.h"
#include "ipu-platform.h"
#include "ipu-platform-buttress-regs.h"

#define ISYS_PM_QOS_VALUE	300

#define IPU_BUTTRESS_FABIC_CONTROL	    0x68
#define GDA_ENABLE_IWAKE_INDEX		    2
#define GDA_IWAKE_THRESHOLD_INDEX           1
#define GDA_IRQ_CRITICAL_THRESHOLD_INDEX    0

/* LTR & DID value are 10 bit at most */
#define LTR_DID_VAL_MAX		1023
#define LTR_DEFAULT_VALUE	0x70503C19
#define FILL_TIME_DEFAULT_VALUE 0xFFF0783C
#define LTR_DID_PKGC_2R		20
#define LTR_DID_PKGC_8		100
#define LTR_SCALE_DEFAULT	5
#define LTR_SCALE_1024NS	2
#define REG_PKGC_PMON_CFG	0xB00

#define VAL_PKGC_PMON_CFG_RESET 0x38
#define VAL_PKGC_PMON_CFG_START 0x7

#define IS_PIXEL_BUFFER_PAGES		0x80
/* BIOS provides the driver the LTR and threshold information in IPU,
 * IS pixel buffer is 256KB, MaxSRAMSize is 200KB on IPU6.
 */
#define IPU6_MAX_SRAM_SIZE			(200 << 10)
/* IS pixel buffer is 128KB, MaxSRAMSize is 96KB on IPU6SE.
 */
#define IPU6SE_MAX_SRAM_SIZE			(96 << 10)
/* When iwake mode is disabled the critical threshold is statically set to 75%
 * of the IS pixel buffer criticalThreshold = (128 * 3) / 4
 */
#define CRITICAL_THRESHOLD_IWAKE_DISABLE	(IS_PIXEL_BUFFER_PAGES * 3 / 4)

union fabric_ctrl {
	struct {
		u16 ltr_val   : 10;
		u16 ltr_scale : 3;
		u16 RSVD1     : 3;
		u16 did_val   : 10;
		u16 did_scale : 3;
		u16 RSVD2     : 1;
		u16 keep_power_in_D0   : 1;
		u16 keep_power_override : 1;
	} bits;
	u32 value;
};

enum ltr_did_type {
	LTR_IWAKE_ON,
	LTR_IWAKE_OFF,
	LTR_ISYS_ON,
	LTR_ISYS_OFF,
	LTR_TYPE_MAX
};

static int
isys_complete_ext_device_registration(struct ipu_isys *isys,
				      struct v4l2_subdev *sd,
				      struct ipu_isys_csi2_config *csi2)
{
	unsigned int i;
	int rval;

	v4l2_set_subdev_hostdata(sd, csi2);

	for (i = 0; i < sd->entity.num_pads; i++) {
		if (sd->entity.pads[i].flags & MEDIA_PAD_FL_SOURCE)
			break;
	}

	if (i == sd->entity.num_pads) {
		dev_warn(&isys->adev->dev,
			 "no source pad in external entity\n");
		rval = -ENOENT;
		goto skip_unregister_subdev;
	}

	rval = media_create_pad_link(&sd->entity, i,
				     &isys->csi2[csi2->port].asd.sd.entity,
				     0, 0);
	if (rval) {
		dev_warn(&isys->adev->dev, "can't create link\n");
		goto skip_unregister_subdev;
	}

	isys->csi2[csi2->port].nlanes = csi2->nlanes;
	return 0;

skip_unregister_subdev:
	v4l2_device_unregister_subdev(sd);
	return rval;
}

static void isys_unregister_subdevices(struct ipu_isys *isys)
{
	const struct ipu_isys_internal_csi2_pdata *csi2 =
	    &isys->pdata->ipdata->csi2;
	unsigned int i;

	for (i = 0; i < NR_OF_CSI2_BE_SOC_DEV; i++)
		ipu_isys_csi2_be_soc_cleanup(&isys->csi2_be_soc[i]);

	for (i = 0; i < csi2->nports; i++)
		ipu_isys_csi2_cleanup(&isys->csi2[i]);
}

static int isys_register_subdevices(struct ipu_isys *isys)
{
	const struct ipu_isys_internal_csi2_pdata *csi2 =
	    &isys->pdata->ipdata->csi2;
	struct ipu_isys_csi2_be_soc *csi2_be_soc;
	unsigned int i, k;
	int rval;

	isys->csi2 = devm_kcalloc(&isys->adev->dev, csi2->nports,
				  sizeof(*isys->csi2), GFP_KERNEL);
	if (!isys->csi2) {
		rval = -ENOMEM;
		goto fail;
	}

	for (i = 0; i < csi2->nports; i++) {
		rval = ipu_isys_csi2_init(&isys->csi2[i], isys,
					  isys->pdata->base +
					  csi2->offsets[i], i);
		if (rval)
			goto fail;

		isys->isr_csi2_bits |= IPU_ISYS_UNISPART_IRQ_CSI2(i);
	}

	for (k = 0; k < NR_OF_CSI2_BE_SOC_DEV; k++) {
		rval = ipu_isys_csi2_be_soc_init(&isys->csi2_be_soc[k],
						 isys, k);
		if (rval) {
			dev_info(&isys->adev->dev,
				 "can't register csi2 soc be device %d\n", k);
			goto fail;
		}
	}

	for (i = 0; i < csi2->nports; i++) {
		for (k = 0; k < NR_OF_CSI2_BE_SOC_DEV; k++) {
			csi2_be_soc = &isys->csi2_be_soc[k];
			rval =
			    media_create_pad_link(&isys->csi2[i].asd.sd.entity,
						  CSI2_PAD_SOURCE,
						  &csi2_be_soc->asd.sd.entity,
						  CSI2_BE_SOC_PAD_SINK, 0);
			if (rval) {
				dev_info(&isys->adev->dev,
					 "can't create link csi2->be_soc\n");
				goto fail;
			}
		}
	}

	return 0;

fail:
	isys_unregister_subdevices(isys);
	return rval;
}

/* read ltrdid threshold values from BIOS or system configuration */
static void get_lut_ltrdid(struct ipu_isys *isys, struct ltr_did *pltr_did)
{
	struct isys_iwake_watermark *iwake_watermark = isys->iwake_watermark;
	/* default values*/
	struct ltr_did ltrdid_default;

	ltrdid_default.lut_ltr.value = LTR_DEFAULT_VALUE;
	ltrdid_default.lut_fill_time.value = FILL_TIME_DEFAULT_VALUE;

	if (iwake_watermark->ltrdid.lut_ltr.value)
		*pltr_did = iwake_watermark->ltrdid;
	else
		*pltr_did = ltrdid_default;
}

static int set_iwake_register(struct ipu_isys *isys, u32 index, u32 value)
{
	int ret = 0;
	u32 req_id = index;
	u32 offset = 0;

	ret = ipu_fw_isys_send_proxy_token(isys, req_id, index, offset, value);
	if (ret)
		dev_err(&isys->adev->dev, "write %d failed %d", index, ret);

	return ret;
}

/*
 * When input system is powered up and before enabling any new sensor capture,
 * or after disabling any sensor capture the following values need to be set:
 * LTR_value = LTR(usec) from calculation;
 * LTR_scale = 2;
 * DID_value = DID(usec) from calculation;
 * DID_scale = 2;
 *
 * When input system is powered down, the LTR and DID values
 * must be returned to the default values:
 * LTR_value = 1023;
 * LTR_scale = 5;
 * DID_value = 1023;
 * DID_scale = 2;
 */
static void set_iwake_ltrdid(struct ipu_isys *isys,
			     u16 ltr,
			     u16 did,
			     enum ltr_did_type use)
{
	/* did_scale will set to 2= 1us */
	u16 ltr_val, ltr_scale, did_val;
	union fabric_ctrl fc;
	struct ipu_device *isp = isys->adev->isp;

	switch (use) {
	case LTR_IWAKE_ON:
		ltr_val = min_t(u16, ltr, (u16)LTR_DID_VAL_MAX);
		did_val = min_t(u16, did, (u16)LTR_DID_VAL_MAX);
		ltr_scale = (ltr == LTR_DID_VAL_MAX &&
				did == LTR_DID_VAL_MAX) ?
				LTR_SCALE_DEFAULT : LTR_SCALE_1024NS;
		break;
	case LTR_ISYS_ON:
	case LTR_IWAKE_OFF:
		ltr_val = LTR_DID_PKGC_2R;
		did_val = LTR_DID_PKGC_2R;
		ltr_scale = LTR_SCALE_1024NS;
		break;
	case LTR_ISYS_OFF:
		ltr_val   = LTR_DID_VAL_MAX;
		did_val   = LTR_DID_VAL_MAX;
		ltr_scale = LTR_SCALE_DEFAULT;
		break;
	default:
		return;
	}

	fc.value = readl(isp->base + IPU_BUTTRESS_FABIC_CONTROL);
	fc.bits.ltr_val = ltr_val;
	fc.bits.ltr_scale = ltr_scale;
	fc.bits.did_val = did_val;
	fc.bits.did_scale = 2;
	dev_dbg(&isys->adev->dev,
		"%s ltr: %d  did: %d", __func__, ltr_val, did_val);
	writel(fc.value, isp->base + IPU_BUTTRESS_FABIC_CONTROL);
}

/* SW driver may clear register GDA_ENABLE_IWAKE before the FW configures the
 * stream for debug purposes. Otherwise SW should not access this register.
 */
static int enable_iwake(struct ipu_isys *isys, bool enable)
{
	int ret = 0;
	struct isys_iwake_watermark *iwake_watermark = isys->iwake_watermark;

	mutex_lock(&iwake_watermark->mutex);
	if (iwake_watermark->iwake_enabled == enable) {
		mutex_unlock(&iwake_watermark->mutex);
		return ret;
	}
	ret = set_iwake_register(isys, GDA_ENABLE_IWAKE_INDEX, enable);
	if (!ret)
		iwake_watermark->iwake_enabled = enable;
	mutex_unlock(&iwake_watermark->mutex);
	return ret;
}

void update_watermark_setting(struct ipu_isys *isys)
{
	struct isys_iwake_watermark *iwake_watermark = isys->iwake_watermark;
	struct list_head *stream_node;
	struct video_stream_watermark *p_watermark;
	struct ltr_did ltrdid;
	u16 calc_fill_time_us = 0;
	u16 ltr = 0;
	u16 did = 0;
	u32 iwake_threshold, iwake_critical_threshold;
	u64 threshold_bytes;
	u64 isys_pb_datarate_mbs = 0;
	u16 sram_granulrity_shift =
		(ipu_ver == IPU_VER_6 || ipu_ver == IPU_VER_6EP) ?
		IPU6_SRAM_GRANULRITY_SHIFT : IPU6SE_SRAM_GRANULRITY_SHIFT;
	int max_sram_size =
		(ipu_ver == IPU_VER_6 || ipu_ver == IPU_VER_6EP) ?
		IPU6_MAX_SRAM_SIZE : IPU6SE_MAX_SRAM_SIZE;

	mutex_lock(&iwake_watermark->mutex);
	if (iwake_watermark->force_iwake_disable) {
		set_iwake_ltrdid(isys, 0, 0, LTR_IWAKE_OFF);
		set_iwake_register(isys, GDA_IRQ_CRITICAL_THRESHOLD_INDEX,
				   CRITICAL_THRESHOLD_IWAKE_DISABLE);
		mutex_unlock(&iwake_watermark->mutex);
		return;
	}

	if (list_empty(&iwake_watermark->video_list)) {
		isys_pb_datarate_mbs = 0;
	} else {
		list_for_each(stream_node, &iwake_watermark->video_list)
		{
			p_watermark = list_entry(stream_node,
						 struct video_stream_watermark,
						 stream_node);
			isys_pb_datarate_mbs += p_watermark->stream_data_rate;
		}
	}
	mutex_unlock(&iwake_watermark->mutex);

	if (!isys_pb_datarate_mbs) {
		enable_iwake(isys, false);
		set_iwake_ltrdid(isys, 0, 0, LTR_IWAKE_OFF);
		mutex_lock(&iwake_watermark->mutex);
		set_iwake_register(isys, GDA_IRQ_CRITICAL_THRESHOLD_INDEX,
				   CRITICAL_THRESHOLD_IWAKE_DISABLE);
		mutex_unlock(&iwake_watermark->mutex);
	} else {
		/* should enable iwake by default according to FW */
		enable_iwake(isys, true);
		calc_fill_time_us = (u16)(max_sram_size / isys_pb_datarate_mbs);
		get_lut_ltrdid(isys, &ltrdid);

		if (calc_fill_time_us <= ltrdid.lut_fill_time.bits.th0)
			ltr = 0;
		else if (calc_fill_time_us <= ltrdid.lut_fill_time.bits.th1)
			ltr = ltrdid.lut_ltr.bits.val0;
		else if (calc_fill_time_us <= ltrdid.lut_fill_time.bits.th2)
			ltr = ltrdid.lut_ltr.bits.val1;
		else if (calc_fill_time_us <= ltrdid.lut_fill_time.bits.th3)
			ltr = ltrdid.lut_ltr.bits.val2;
		else
			ltr = ltrdid.lut_ltr.bits.val3;

		did = calc_fill_time_us - ltr;

		threshold_bytes = did * isys_pb_datarate_mbs;
		/* calculate iwake threshold with 2KB granularity pages */
		iwake_threshold =
			max_t(u32, 1, threshold_bytes >> sram_granulrity_shift);

		iwake_threshold = min_t(u32, iwake_threshold, max_sram_size);

		/* set the critical threshold to halfway between
		 * iwake threshold and the full buffer.
		 */
		iwake_critical_threshold = iwake_threshold +
			(IS_PIXEL_BUFFER_PAGES - iwake_threshold) / 2;

		dev_dbg(&isys->adev->dev, "%s threshold: %u  critical: %u",
			__func__, iwake_threshold, iwake_critical_threshold);
		set_iwake_ltrdid(isys, ltr, did, LTR_IWAKE_ON);
		mutex_lock(&iwake_watermark->mutex);
		set_iwake_register(isys,
				   GDA_IWAKE_THRESHOLD_INDEX, iwake_threshold);

		set_iwake_register(isys,
				   GDA_IRQ_CRITICAL_THRESHOLD_INDEX,
				   iwake_critical_threshold);
		mutex_unlock(&iwake_watermark->mutex);

		writel(VAL_PKGC_PMON_CFG_RESET,
		       isys->adev->isp->base + REG_PKGC_PMON_CFG);
		writel(VAL_PKGC_PMON_CFG_START,
		       isys->adev->isp->base + REG_PKGC_PMON_CFG);
	}
}

static int isys_iwake_watermark_init(struct ipu_isys *isys)
{
	struct isys_iwake_watermark *iwake_watermark;

	if (isys->iwake_watermark)
		return 0;

	iwake_watermark = devm_kzalloc(&isys->adev->dev,
				       sizeof(*iwake_watermark), GFP_KERNEL);
	if (!iwake_watermark)
		return -ENOMEM;
	INIT_LIST_HEAD(&iwake_watermark->video_list);
	mutex_init(&iwake_watermark->mutex);

	iwake_watermark->ltrdid.lut_ltr.value = 0;
	isys->iwake_watermark = iwake_watermark;
	iwake_watermark->isys = isys;
	iwake_watermark->iwake_enabled = false;
	iwake_watermark->force_iwake_disable = false;
	return 0;
}

static int isys_iwake_watermark_cleanup(struct ipu_isys *isys)
{
	struct isys_iwake_watermark *iwake_watermark = isys->iwake_watermark;

	if (!iwake_watermark)
		return -EINVAL;
	mutex_lock(&iwake_watermark->mutex);
	list_del(&iwake_watermark->video_list);
	mutex_unlock(&iwake_watermark->mutex);
	mutex_destroy(&iwake_watermark->mutex);
	isys->iwake_watermark = NULL;
	return 0;
}

/* The .bound() notifier callback when a match is found */
static int isys_notifier_bound(struct v4l2_async_notifier *notifier,
			       struct v4l2_subdev *sd,
			       struct v4l2_async_subdev *asd)
{
	struct ipu_isys *isys = container_of(notifier,
					struct ipu_isys, notifier);
	struct sensor_async_subdev *s_asd = container_of(asd,
					struct sensor_async_subdev, asd);

	dev_info(&isys->adev->dev, "bind %s nlanes is %d port is %d\n",
		 sd->name, s_asd->csi2.nlanes, s_asd->csi2.port);
	isys_complete_ext_device_registration(isys, sd, &s_asd->csi2);

	return v4l2_device_register_subdev_nodes(&isys->v4l2_dev);
}

static void isys_notifier_unbind(struct v4l2_async_notifier *notifier,
				 struct v4l2_subdev *sd,
				 struct v4l2_async_subdev *asd)
{
	struct ipu_isys *isys = container_of(notifier,
					struct ipu_isys, notifier);

	dev_info(&isys->adev->dev, "unbind %s\n", sd->name);
}

static int isys_notifier_complete(struct v4l2_async_notifier *notifier)
{
	struct ipu_isys *isys = container_of(notifier,
					struct ipu_isys, notifier);

	dev_info(&isys->adev->dev, "All sensor registration completed.\n");

	return v4l2_device_register_subdev_nodes(&isys->v4l2_dev);
}

static const struct v4l2_async_notifier_operations isys_async_ops = {
	.bound = isys_notifier_bound,
	.unbind = isys_notifier_unbind,
	.complete = isys_notifier_complete,
};

static int isys_fwnode_parse(struct device *dev,
			     struct v4l2_fwnode_endpoint *vep,
			     struct v4l2_async_subdev *asd)
{
	struct sensor_async_subdev *s_asd =
			container_of(asd, struct sensor_async_subdev, asd);

	s_asd->csi2.port = vep->base.port;
	s_asd->csi2.nlanes = vep->bus.mipi_csi2.num_data_lanes;

	return 0;
}

static int isys_notifier_init(struct ipu_isys *isys)
{
	struct ipu_device *isp = isys->adev->isp;
	size_t asd_struct_size = sizeof(struct sensor_async_subdev);
	int ret;

	v4l2_async_notifier_init(&isys->notifier);
	ret = v4l2_async_notifier_parse_fwnode_endpoints(&isp->pdev->dev,
							 &isys->notifier,
							 asd_struct_size,
							 isys_fwnode_parse);

	if (ret < 0) {
		dev_err(&isys->adev->dev,
			"v4l2 parse_fwnode_endpoints() failed: %d\n", ret);
		return ret;
	}

	if (list_empty(&isys->notifier.asd_list)) {
		/* isys probe could continue with async subdevs missing */
		dev_warn(&isys->adev->dev, "no subdev found in graph\n");
		return 0;
	}

	isys->notifier.ops = &isys_async_ops;
	ret = v4l2_async_notifier_register(&isys->v4l2_dev, &isys->notifier);
	if (ret) {
		dev_err(&isys->adev->dev,
			"failed to register async notifier : %d\n", ret);
		v4l2_async_notifier_cleanup(&isys->notifier);
	}

	return ret;
}

static void isys_notifier_cleanup(struct ipu_isys *isys)
{
	v4l2_async_notifier_unregister(&isys->notifier);
	v4l2_async_notifier_cleanup(&isys->notifier);
}

static struct media_device_ops isys_mdev_ops = {
	.link_notify = v4l2_pipeline_link_notify,
};

static int isys_register_devices(struct ipu_isys *isys)
{
	int rval;

	isys->media_dev.dev = &isys->adev->dev;
	isys->media_dev.ops = &isys_mdev_ops;
	strlcpy(isys->media_dev.model,
		IPU_MEDIA_DEV_MODEL_NAME, sizeof(isys->media_dev.model));
	snprintf(isys->media_dev.bus_info, sizeof(isys->media_dev.bus_info),
		 "pci:%s", dev_name(isys->adev->dev.parent->parent));
	strlcpy(isys->v4l2_dev.name, isys->media_dev.model,
		sizeof(isys->v4l2_dev.name));

	media_device_init(&isys->media_dev);

	rval = media_device_register(&isys->media_dev);
	if (rval < 0) {
		dev_info(&isys->adev->dev, "can't register media device\n");
		goto out_media_device_unregister;
	}

	isys->v4l2_dev.mdev = &isys->media_dev;

	rval = v4l2_device_register(&isys->adev->dev, &isys->v4l2_dev);
	if (rval < 0) {
		dev_info(&isys->adev->dev, "can't register v4l2 device\n");
		goto out_media_device_unregister;
	}

	rval = isys_register_subdevices(isys);
	if (rval)
		goto out_v4l2_device_unregister;

	rval = isys_notifier_init(isys);
	if (rval)
		goto out_isys_unregister_subdevices;

	rval = v4l2_device_register_subdev_nodes(&isys->v4l2_dev);
	if (rval)
		goto out_isys_notifier_cleanup;

	return 0;

out_isys_notifier_cleanup:
	isys_notifier_cleanup(isys);

out_isys_unregister_subdevices:
	isys_unregister_subdevices(isys);

out_v4l2_device_unregister:
	v4l2_device_unregister(&isys->v4l2_dev);

out_media_device_unregister:
	media_device_unregister(&isys->media_dev);
	media_device_cleanup(&isys->media_dev);

	return rval;
}

static void isys_unregister_devices(struct ipu_isys *isys)
{
	isys_unregister_subdevices(isys);
	v4l2_device_unregister(&isys->v4l2_dev);
	media_device_unregister(&isys->media_dev);
	media_device_cleanup(&isys->media_dev);
}

#ifdef CONFIG_PM
static int isys_runtime_pm_resume(struct device *dev)
{
	struct ipu_bus_device *adev = to_ipu_bus_device(dev);
	struct ipu_device *isp = adev->isp;
	struct ipu_isys *isys = ipu_bus_get_drvdata(adev);
	unsigned long flags;
	int ret;

	if (!isys)
		return 0;

	ret = ipu_mmu_hw_init(adev->mmu);
	if (ret)
		return ret;

	ipu_trace_restore(dev);

	cpu_latency_qos_update_request(&isys->pm_qos, ISYS_PM_QOS_VALUE);

	ret = ipu_buttress_start_tsc_sync(isp);
	if (ret)
		return ret;

	spin_lock_irqsave(&isys->power_lock, flags);
	isys->power = 1;
	spin_unlock_irqrestore(&isys->power_lock, flags);

	if (isys->short_packet_source == IPU_ISYS_SHORT_PACKET_FROM_TUNIT) {
		mutex_lock(&isys->short_packet_tracing_mutex);
		isys->short_packet_tracing_count = 0;
		mutex_unlock(&isys->short_packet_tracing_mutex);
	}
	isys_setup_hw(isys);

	set_iwake_ltrdid(isys, 0, 0, LTR_ISYS_ON);
	return 0;
}

static int isys_runtime_pm_suspend(struct device *dev)
{
	struct ipu_bus_device *adev = to_ipu_bus_device(dev);
	struct ipu_isys *isys = ipu_bus_get_drvdata(adev);
	unsigned long flags;

	if (!isys)
		return 0;

	spin_lock_irqsave(&isys->power_lock, flags);
	isys->power = 0;
	spin_unlock_irqrestore(&isys->power_lock, flags);

	ipu_trace_stop(dev);
	mutex_lock(&isys->mutex);
	isys->reset_needed = false;
	mutex_unlock(&isys->mutex);

	cpu_latency_qos_update_request(&isys->pm_qos, PM_QOS_DEFAULT_VALUE);

	ipu_mmu_hw_cleanup(adev->mmu);

	set_iwake_ltrdid(isys, 0, 0, LTR_ISYS_OFF);
	return 0;
}

static int isys_suspend(struct device *dev)
{
	struct ipu_bus_device *adev = to_ipu_bus_device(dev);
	struct ipu_isys *isys = ipu_bus_get_drvdata(adev);

	/* If stream is open, refuse to suspend */
	if (isys->stream_opened)
		return -EBUSY;

	return 0;
}

static int isys_resume(struct device *dev)
{
	return 0;
}

static const struct dev_pm_ops isys_pm_ops = {
	.runtime_suspend = isys_runtime_pm_suspend,
	.runtime_resume = isys_runtime_pm_resume,
	.suspend = isys_suspend,
	.resume = isys_resume,
};

#define ISYS_PM_OPS (&isys_pm_ops)
#else
#define ISYS_PM_OPS NULL
#endif

static void isys_remove(struct ipu_bus_device *adev)
{
	struct ipu_isys *isys = ipu_bus_get_drvdata(adev);
	struct ipu_device *isp = adev->isp;
	struct isys_fw_msgs *fwmsg, *safe;

	dev_info(&adev->dev, "removed\n");
#ifdef CONFIG_DEBUG_FS
	if (isp->ipu_dir)
		debugfs_remove_recursive(isys->debugfsdir);
#endif

	list_for_each_entry_safe(fwmsg, safe, &isys->framebuflist, head) {
		dma_free_attrs(&adev->dev, sizeof(struct isys_fw_msgs),
			       fwmsg, fwmsg->dma_addr,
			       0);
	}

	list_for_each_entry_safe(fwmsg, safe, &isys->framebuflist_fw, head) {
		dma_free_attrs(&adev->dev, sizeof(struct isys_fw_msgs),
			       fwmsg, fwmsg->dma_addr,
			       0
		    );
	}

	isys_iwake_watermark_cleanup(isys);

	ipu_trace_uninit(&adev->dev);
	isys_notifier_cleanup(isys);
	isys_unregister_devices(isys);

	cpu_latency_qos_remove_request(&isys->pm_qos);

	if (!isp->secure_mode) {
		ipu_cpd_free_pkg_dir(adev, isys->pkg_dir,
				     isys->pkg_dir_dma_addr,
				     isys->pkg_dir_size);
		ipu_buttress_unmap_fw_image(adev, &isys->fw_sgt);
		release_firmware(isys->fw);
	}

	mutex_destroy(&isys->stream_mutex);
	mutex_destroy(&isys->mutex);

	if (isys->short_packet_source == IPU_ISYS_SHORT_PACKET_FROM_TUNIT) {
		u32 trace_size = IPU_ISYS_SHORT_PACKET_TRACE_BUFFER_SIZE;

		dma_free_coherent(&adev->dev, trace_size,
				  isys->short_packet_trace_buffer,
				  isys->short_packet_trace_buffer_dma_addr);
	}
}

#ifdef CONFIG_DEBUG_FS
static int ipu_isys_icache_prefetch_get(void *data, u64 *val)
{
	struct ipu_isys *isys = data;

	*val = isys->icache_prefetch;
	return 0;
}

static int ipu_isys_icache_prefetch_set(void *data, u64 val)
{
	struct ipu_isys *isys = data;

	if (val != !!val)
		return -EINVAL;

	isys->icache_prefetch = val;

	return 0;
}

static int isys_iwake_control_get(void *data, u64 *val)
{
	struct ipu_isys *isys = data;
	struct isys_iwake_watermark *iwake_watermark = isys->iwake_watermark;

	mutex_lock(&iwake_watermark->mutex);
	*val = isys->iwake_watermark->force_iwake_disable;
	mutex_unlock(&iwake_watermark->mutex);
	return 0;
}

static int isys_iwake_control_set(void *data, u64 val)
{
	struct ipu_isys *isys = data;
	struct isys_iwake_watermark *iwake_watermark;

	if (val != !!val)
		return -EINVAL;
	/* If stream is open, refuse to set iwake */
	if (isys->stream_opened)
		return -EBUSY;

	iwake_watermark = isys->iwake_watermark;
	mutex_lock(&iwake_watermark->mutex);
	isys->iwake_watermark->force_iwake_disable = !!val;
	mutex_unlock(&iwake_watermark->mutex);
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(isys_icache_prefetch_fops,
			ipu_isys_icache_prefetch_get,
			ipu_isys_icache_prefetch_set, "%llu\n");

DEFINE_SIMPLE_ATTRIBUTE(isys_iwake_control_fops,
			isys_iwake_control_get,
			isys_iwake_control_set, "%llu\n");

static int ipu_isys_init_debugfs(struct ipu_isys *isys)
{
	struct dentry *file;
	struct dentry *dir;
#ifdef IPU_ISYS_GPC
	int ret;
#endif

	dir = debugfs_create_dir("isys", isys->adev->isp->ipu_dir);
	if (IS_ERR(dir))
		return -ENOMEM;

	file = debugfs_create_file("icache_prefetch", 0600,
				   dir, isys, &isys_icache_prefetch_fops);
	if (IS_ERR(file))
		goto err;

	file = debugfs_create_file("iwake_disable", 0600,
				   dir, isys, &isys_iwake_control_fops);
	if (IS_ERR(file))
		goto err;

	isys->debugfsdir = dir;

#ifdef IPU_ISYS_GPC
	ret = ipu_isys_gpc_init_debugfs(isys);
	if (ret)
		return ret;
#endif

	return 0;
err:
	debugfs_remove_recursive(dir);
	return -ENOMEM;
}
#endif

static int alloc_fw_msg_bufs(struct ipu_isys *isys, int amount)
{
	dma_addr_t dma_addr;
	struct isys_fw_msgs *addr;
	unsigned int i;
	unsigned long flags;

	for (i = 0; i < amount; i++) {
		addr = dma_alloc_attrs(&isys->adev->dev,
				       sizeof(struct isys_fw_msgs),
				       &dma_addr, GFP_KERNEL,
				       0);
		if (!addr)
			break;
		addr->dma_addr = dma_addr;

		spin_lock_irqsave(&isys->listlock, flags);
		list_add(&addr->head, &isys->framebuflist);
		spin_unlock_irqrestore(&isys->listlock, flags);
	}
	if (i == amount)
		return 0;
	spin_lock_irqsave(&isys->listlock, flags);
	while (!list_empty(&isys->framebuflist)) {
		addr = list_first_entry(&isys->framebuflist,
					struct isys_fw_msgs, head);
		list_del(&addr->head);
		spin_unlock_irqrestore(&isys->listlock, flags);
		dma_free_attrs(&isys->adev->dev,
			       sizeof(struct isys_fw_msgs),
			       addr, addr->dma_addr,
			       0);
		spin_lock_irqsave(&isys->listlock, flags);
	}
	spin_unlock_irqrestore(&isys->listlock, flags);
	return -ENOMEM;
}

struct isys_fw_msgs *ipu_get_fw_msg_buf(struct ipu_isys_pipeline *ip)
{
	struct ipu_isys_video *pipe_av =
	    container_of(ip, struct ipu_isys_video, ip);
	struct ipu_isys *isys;
	struct isys_fw_msgs *msg;
	unsigned long flags;

	isys = pipe_av->isys;

	spin_lock_irqsave(&isys->listlock, flags);
	if (list_empty(&isys->framebuflist)) {
		spin_unlock_irqrestore(&isys->listlock, flags);
		dev_dbg(&isys->adev->dev, "Frame list empty - Allocate more");

		alloc_fw_msg_bufs(isys, 5);

		spin_lock_irqsave(&isys->listlock, flags);
		if (list_empty(&isys->framebuflist)) {
			spin_unlock_irqrestore(&isys->listlock, flags);
			dev_err(&isys->adev->dev, "Frame list empty");
			return NULL;
		}
	}
	msg = list_last_entry(&isys->framebuflist, struct isys_fw_msgs, head);
	list_move(&msg->head, &isys->framebuflist_fw);
	spin_unlock_irqrestore(&isys->listlock, flags);
	memset(&msg->fw_msg, 0, sizeof(msg->fw_msg));

	return msg;
}

void ipu_cleanup_fw_msg_bufs(struct ipu_isys *isys)
{
	struct isys_fw_msgs *fwmsg, *fwmsg0;
	unsigned long flags;

	spin_lock_irqsave(&isys->listlock, flags);
	list_for_each_entry_safe(fwmsg, fwmsg0, &isys->framebuflist_fw, head)
		list_move(&fwmsg->head, &isys->framebuflist);
	spin_unlock_irqrestore(&isys->listlock, flags);
}

void ipu_put_fw_mgs_buf(struct ipu_isys *isys, u64 data)
{
	struct isys_fw_msgs *msg;
	unsigned long flags;
	u64 *ptr = (u64 *)(unsigned long)data;

	if (!ptr)
		return;

	spin_lock_irqsave(&isys->listlock, flags);
	msg = container_of(ptr, struct isys_fw_msgs, fw_msg.dummy);
	list_move(&msg->head, &isys->framebuflist);
	spin_unlock_irqrestore(&isys->listlock, flags);
}

static int isys_probe(struct ipu_bus_device *adev)
{
	struct ipu_isys *isys;
	struct ipu_device *isp = adev->isp;
	const struct firmware *fw;
	int rval = 0;

	isys = devm_kzalloc(&adev->dev, sizeof(*isys), GFP_KERNEL);
	if (!isys)
		return -ENOMEM;

	rval = ipu_mmu_hw_init(adev->mmu);
	if (rval)
		return rval;

	/* By default, short packet is captured from T-Unit. */
	isys->short_packet_source = IPU_ISYS_SHORT_PACKET_FROM_RECEIVER;
	isys->adev = adev;
	isys->pdata = adev->pdata;

	/* initial streamID for different sensor types */
	if (ipu_ver == IPU_VER_6 || ipu_ver == IPU_VER_6EP) {
		isys->sensor_info.vc1_data_start =
			IPU6_FW_ISYS_VC1_SENSOR_DATA_START;
		isys->sensor_info.vc1_data_end =
			IPU6_FW_ISYS_VC1_SENSOR_DATA_END;
		isys->sensor_info.vc0_data_start =
			IPU6_FW_ISYS_VC0_SENSOR_DATA_START;
		isys->sensor_info.vc0_data_end =
			IPU6_FW_ISYS_VC0_SENSOR_DATA_END;
		isys->sensor_info.vc1_pdaf_start =
			IPU6_FW_ISYS_VC1_SENSOR_PDAF_START;
		isys->sensor_info.vc1_pdaf_end =
			IPU6_FW_ISYS_VC1_SENSOR_PDAF_END;
		isys->sensor_info.sensor_metadata =
			IPU6_FW_ISYS_SENSOR_METADATA;

		isys->sensor_types[IPU_FW_ISYS_VC1_SENSOR_DATA] =
			IPU6_FW_ISYS_VC1_SENSOR_DATA_START;
		isys->sensor_types[IPU_FW_ISYS_VC1_SENSOR_PDAF] =
			IPU6_FW_ISYS_VC1_SENSOR_PDAF_START;
		isys->sensor_types[IPU_FW_ISYS_VC0_SENSOR_DATA] =
			IPU6_FW_ISYS_VC0_SENSOR_DATA_START;
	} else if (ipu_ver == IPU_VER_6SE) {
		isys->sensor_info.vc1_data_start =
			IPU6SE_FW_ISYS_VC1_SENSOR_DATA_START;
		isys->sensor_info.vc1_data_end =
			IPU6SE_FW_ISYS_VC1_SENSOR_DATA_END;
		isys->sensor_info.vc0_data_start =
			IPU6SE_FW_ISYS_VC0_SENSOR_DATA_START;
		isys->sensor_info.vc0_data_end =
			IPU6SE_FW_ISYS_VC0_SENSOR_DATA_END;
		isys->sensor_info.vc1_pdaf_start =
			IPU6SE_FW_ISYS_VC1_SENSOR_PDAF_START;
		isys->sensor_info.vc1_pdaf_end =
			IPU6SE_FW_ISYS_VC1_SENSOR_PDAF_END;
		isys->sensor_info.sensor_metadata =
			IPU6SE_FW_ISYS_SENSOR_METADATA;

		isys->sensor_types[IPU_FW_ISYS_VC1_SENSOR_DATA] =
			IPU6SE_FW_ISYS_VC1_SENSOR_DATA_START;
		isys->sensor_types[IPU_FW_ISYS_VC1_SENSOR_PDAF] =
			IPU6SE_FW_ISYS_VC1_SENSOR_PDAF_START;
		isys->sensor_types[IPU_FW_ISYS_VC0_SENSOR_DATA] =
			IPU6SE_FW_ISYS_VC0_SENSOR_DATA_START;
	}

	INIT_LIST_HEAD(&isys->requests);

	spin_lock_init(&isys->lock);
	spin_lock_init(&isys->power_lock);
	isys->power = 0;

	mutex_init(&isys->mutex);
	mutex_init(&isys->stream_mutex);
	mutex_init(&isys->lib_mutex);

	spin_lock_init(&isys->listlock);
	INIT_LIST_HEAD(&isys->framebuflist);
	INIT_LIST_HEAD(&isys->framebuflist_fw);

	dev_dbg(&adev->dev, "isys probe %p %p\n", adev, &adev->dev);
	ipu_bus_set_drvdata(adev, isys);

	isys->line_align = IPU_ISYS_2600_MEM_LINE_ALIGN;
	isys->icache_prefetch = 0;

#ifndef CONFIG_PM
	isys_setup_hw(isys);
#endif

	if (!isp->secure_mode) {
		fw = isp->cpd_fw;
		rval = ipu_buttress_map_fw_image(adev, fw, &isys->fw_sgt);
		if (rval)
			goto release_firmware;

		isys->pkg_dir =
		    ipu_cpd_create_pkg_dir(adev, isp->cpd_fw->data,
					   sg_dma_address(isys->fw_sgt.sgl),
					   &isys->pkg_dir_dma_addr,
					   &isys->pkg_dir_size);
		if (!isys->pkg_dir) {
			rval = -ENOMEM;
			goto remove_shared_buffer;
		}
	}

#ifdef CONFIG_DEBUG_FS
	/* Debug fs failure is not fatal. */
	ipu_isys_init_debugfs(isys);
#endif

	ipu_trace_init(adev->isp, isys->pdata->base, &adev->dev,
		       isys_trace_blocks);

	cpu_latency_qos_add_request(&isys->pm_qos, PM_QOS_DEFAULT_VALUE);
	alloc_fw_msg_bufs(isys, 20);

	rval = isys_register_devices(isys);
	if (rval)
		goto out_remove_pkg_dir_shared_buffer;
	rval = isys_iwake_watermark_init(isys);
	if (rval)
		goto out_unregister_devices;

	ipu_mmu_hw_cleanup(adev->mmu);

	return 0;

out_unregister_devices:
	isys_iwake_watermark_cleanup(isys);
	isys_unregister_devices(isys);
out_remove_pkg_dir_shared_buffer:
	if (!isp->secure_mode)
		ipu_cpd_free_pkg_dir(adev, isys->pkg_dir,
				     isys->pkg_dir_dma_addr,
				     isys->pkg_dir_size);
remove_shared_buffer:
	if (!isp->secure_mode)
		ipu_buttress_unmap_fw_image(adev, &isys->fw_sgt);
release_firmware:
	if (!isp->secure_mode)
		release_firmware(isys->fw);
	ipu_trace_uninit(&adev->dev);

	mutex_destroy(&isys->mutex);
	mutex_destroy(&isys->stream_mutex);

	if (isys->short_packet_source == IPU_ISYS_SHORT_PACKET_FROM_TUNIT)
		mutex_destroy(&isys->short_packet_tracing_mutex);

	ipu_mmu_hw_cleanup(adev->mmu);

	return rval;
}

struct fwmsg {
	int type;
	char *msg;
	bool valid_ts;
};

static const struct fwmsg fw_msg[] = {
	{IPU_FW_ISYS_RESP_TYPE_STREAM_OPEN_DONE, "STREAM_OPEN_DONE", 0},
	{IPU_FW_ISYS_RESP_TYPE_STREAM_CLOSE_ACK, "STREAM_CLOSE_ACK", 0},
	{IPU_FW_ISYS_RESP_TYPE_STREAM_START_ACK, "STREAM_START_ACK", 0},
	{IPU_FW_ISYS_RESP_TYPE_STREAM_START_AND_CAPTURE_ACK,
	 "STREAM_START_AND_CAPTURE_ACK", 0},
	{IPU_FW_ISYS_RESP_TYPE_STREAM_STOP_ACK, "STREAM_STOP_ACK", 0},
	{IPU_FW_ISYS_RESP_TYPE_STREAM_FLUSH_ACK, "STREAM_FLUSH_ACK", 0},
	{IPU_FW_ISYS_RESP_TYPE_PIN_DATA_READY, "PIN_DATA_READY", 1},
	{IPU_FW_ISYS_RESP_TYPE_STREAM_CAPTURE_ACK, "STREAM_CAPTURE_ACK", 0},
	{IPU_FW_ISYS_RESP_TYPE_STREAM_START_AND_CAPTURE_DONE,
	 "STREAM_START_AND_CAPTURE_DONE", 1},
	{IPU_FW_ISYS_RESP_TYPE_STREAM_CAPTURE_DONE, "STREAM_CAPTURE_DONE", 1},
	{IPU_FW_ISYS_RESP_TYPE_FRAME_SOF, "FRAME_SOF", 1},
	{IPU_FW_ISYS_RESP_TYPE_FRAME_EOF, "FRAME_EOF", 1},
	{IPU_FW_ISYS_RESP_TYPE_STATS_DATA_READY, "STATS_READY", 1},
	{-1, "UNKNOWN MESSAGE", 0},
};

static int resp_type_to_index(int type)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(fw_msg); i++)
		if (fw_msg[i].type == type)
			return i;

	return i - 1;
}

int isys_isr_one(struct ipu_bus_device *adev)
{
	struct ipu_isys *isys = ipu_bus_get_drvdata(adev);
	struct ipu_fw_isys_resp_info_abi resp_data;
	struct ipu_fw_isys_resp_info_abi *resp;
	struct ipu_isys_pipeline *pipe;
	u64 ts;
	unsigned int i;

	if (!isys->fwcom)
		return 0;

	resp = ipu_fw_isys_get_resp(isys->fwcom, IPU_BASE_MSG_RECV_QUEUES,
				    &resp_data);
	if (!resp)
		return 1;

	ts = (u64)resp->timestamp[1] << 32 | resp->timestamp[0];

	if (resp->error_info.error == IPU_FW_ISYS_ERROR_STREAM_IN_SUSPENSION)
		/* Suspension is kind of special case: not enough buffers */
		dev_dbg(&adev->dev,
			"hostlib: error resp %02d %s, stream %u, error SUSPENSION, details %d, timestamp 0x%16.16llx, pin %d\n",
			resp->type,
			fw_msg[resp_type_to_index(resp->type)].msg,
			resp->stream_handle,
			resp->error_info.error_details,
			fw_msg[resp_type_to_index(resp->type)].valid_ts ?
			ts : 0, resp->pin_id);
	else if (resp->error_info.error)
		dev_dbg(&adev->dev,
			"hostlib: error resp %02d %s, stream %u, error %d, details %d, timestamp 0x%16.16llx, pin %d\n",
			resp->type,
			fw_msg[resp_type_to_index(resp->type)].msg,
			resp->stream_handle,
			resp->error_info.error, resp->error_info.error_details,
			fw_msg[resp_type_to_index(resp->type)].valid_ts ?
			ts : 0, resp->pin_id);
	else
		dev_dbg(&adev->dev,
			"hostlib: resp %02d %s, stream %u, timestamp 0x%16.16llx, pin %d\n",
			resp->type,
			fw_msg[resp_type_to_index(resp->type)].msg,
			resp->stream_handle,
			fw_msg[resp_type_to_index(resp->type)].valid_ts ?
			ts : 0, resp->pin_id);

	if (resp->stream_handle >= IPU_ISYS_MAX_STREAMS) {
		dev_err(&adev->dev, "bad stream handle %u\n",
			resp->stream_handle);
		goto leave;
	}

	pipe = isys->pipes[resp->stream_handle];
	if (!pipe) {
		dev_err(&adev->dev, "no pipeline for stream %u\n",
			resp->stream_handle);
		goto leave;
	}
	pipe->error = resp->error_info.error;

	switch (resp->type) {
	case IPU_FW_ISYS_RESP_TYPE_STREAM_OPEN_DONE:
		ipu_put_fw_mgs_buf(ipu_bus_get_drvdata(adev), resp->buf_id);
		complete(&pipe->stream_open_completion);
		break;
	case IPU_FW_ISYS_RESP_TYPE_STREAM_CLOSE_ACK:
		complete(&pipe->stream_close_completion);
		break;
	case IPU_FW_ISYS_RESP_TYPE_STREAM_START_ACK:
		complete(&pipe->stream_start_completion);
		break;
	case IPU_FW_ISYS_RESP_TYPE_STREAM_START_AND_CAPTURE_ACK:
		ipu_put_fw_mgs_buf(ipu_bus_get_drvdata(adev), resp->buf_id);
		complete(&pipe->stream_start_completion);
		break;
	case IPU_FW_ISYS_RESP_TYPE_STREAM_STOP_ACK:
		complete(&pipe->stream_stop_completion);
		break;
	case IPU_FW_ISYS_RESP_TYPE_STREAM_FLUSH_ACK:
		complete(&pipe->stream_stop_completion);
		break;
	case IPU_FW_ISYS_RESP_TYPE_PIN_DATA_READY:
		if (resp->pin_id < IPU_ISYS_OUTPUT_PINS &&
		    pipe->output_pins[resp->pin_id].pin_ready)
			pipe->output_pins[resp->pin_id].pin_ready(pipe, resp);
		else
			dev_err(&adev->dev,
				"%d:No data pin ready handler for pin id %d\n",
				resp->stream_handle, resp->pin_id);
		if (pipe->csi2)
			ipu_isys_csi2_error(pipe->csi2);

		break;
	case IPU_FW_ISYS_RESP_TYPE_STREAM_CAPTURE_ACK:
		break;
	case IPU_FW_ISYS_RESP_TYPE_STREAM_START_AND_CAPTURE_DONE:
	case IPU_FW_ISYS_RESP_TYPE_STREAM_CAPTURE_DONE:
		if (pipe->interlaced) {
			struct ipu_isys_buffer *ib, *ib_safe;
			struct list_head list;
			unsigned long flags;
			unsigned int *ts = resp->timestamp;

			if (pipe->isys->short_packet_source ==
			    IPU_ISYS_SHORT_PACKET_FROM_TUNIT)
				pipe->cur_field =
				    ipu_isys_csi2_get_current_field(pipe, ts);

			/*
			 * Move the pending buffers to a local temp list.
			 * Then we do not need to handle the lock during
			 * the loop.
			 */
			spin_lock_irqsave(&pipe->short_packet_queue_lock,
					  flags);
			list_cut_position(&list,
					  &pipe->pending_interlaced_bufs,
					  pipe->pending_interlaced_bufs.prev);
			spin_unlock_irqrestore(&pipe->short_packet_queue_lock,
					       flags);

			list_for_each_entry_safe(ib, ib_safe, &list, head) {
				struct vb2_buffer *vb;

				vb = ipu_isys_buffer_to_vb2_buffer(ib);
				to_vb2_v4l2_buffer(vb)->field = pipe->cur_field;
				list_del(&ib->head);

				ipu_isys_queue_buf_done(ib);
			}
		}
		for (i = 0; i < IPU_NUM_CAPTURE_DONE; i++)
			if (pipe->capture_done[i])
				pipe->capture_done[i] (pipe, resp);

		break;
	case IPU_FW_ISYS_RESP_TYPE_FRAME_SOF:
		if (pipe->csi2)
			ipu_isys_csi2_sof_event(pipe->csi2);

		pipe->seq[pipe->seq_index].sequence =
		    atomic_read(&pipe->sequence) - 1;
		pipe->seq[pipe->seq_index].timestamp = ts;
		dev_dbg(&adev->dev,
			"sof: handle %d: (index %u), timestamp 0x%16.16llx\n",
			resp->stream_handle,
			pipe->seq[pipe->seq_index].sequence, ts);
		pipe->seq_index = (pipe->seq_index + 1)
		    % IPU_ISYS_MAX_PARALLEL_SOF;
		break;
	case IPU_FW_ISYS_RESP_TYPE_FRAME_EOF:
		if (pipe->csi2)
			ipu_isys_csi2_eof_event(pipe->csi2);

		dev_dbg(&adev->dev,
			"eof: handle %d: (index %u), timestamp 0x%16.16llx\n",
			resp->stream_handle,
			pipe->seq[pipe->seq_index].sequence, ts);
		break;
	case IPU_FW_ISYS_RESP_TYPE_STATS_DATA_READY:
		break;
	default:
		dev_err(&adev->dev, "%d:unknown response type %u\n",
			resp->stream_handle, resp->type);
		break;
	}

leave:
	ipu_fw_isys_put_resp(isys->fwcom, IPU_BASE_MSG_RECV_QUEUES);
	return 0;
}

static struct ipu_bus_driver isys_driver = {
	.probe = isys_probe,
	.remove = isys_remove,
	.isr = isys_isr,
	.wanted = IPU_ISYS_NAME,
	.drv = {
		.name = IPU_ISYS_NAME,
		.owner = THIS_MODULE,
		.pm = ISYS_PM_OPS,
	},
};

module_ipu_bus_driver(isys_driver);

static const struct pci_device_id ipu_pci_tbl[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, IPU6_PCI_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, IPU6SE_PCI_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, IPU6EP_ADL_P_PCI_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, IPU6EP_ADL_N_PCI_ID)},
	{PCI_DEVICE(PCI_VENDOR_ID_INTEL, IPU6EP_RPL_P_PCI_ID)},
	{0,}
};
MODULE_DEVICE_TABLE(pci, ipu_pci_tbl);

MODULE_AUTHOR("Sakari Ailus <sakari.ailus@linux.intel.com>");
MODULE_AUTHOR("Samu Onkalo <samu.onkalo@intel.com>");
MODULE_AUTHOR("Jouni Högander <jouni.hogander@intel.com>");
MODULE_AUTHOR("Jouni Ukkonen <jouni.ukkonen@intel.com>");
MODULE_AUTHOR("Jianxu Zheng <jian.xu.zheng@intel.com>");
MODULE_AUTHOR("Tianshu Qiu <tian.shu.qiu@intel.com>");
MODULE_AUTHOR("Renwei Wu <renwei.wu@intel.com>");
MODULE_AUTHOR("Bingbu Cao <bingbu.cao@intel.com>");
MODULE_AUTHOR("Yunliang Ding <yunliang.ding@intel.com>");
MODULE_AUTHOR("Zaikuo Wang <zaikuo.wang@intel.com>");
MODULE_AUTHOR("Leifu Zhao <leifu.zhao@intel.com>");
MODULE_AUTHOR("Xia Wu <xia.wu@intel.com>");
MODULE_AUTHOR("Kun Jiang <kun.jiang@intel.com>");
MODULE_AUTHOR("Yu Xia <yu.y.xia@intel.com>");
MODULE_AUTHOR("Jerry Hu <jerry.w.hu@intel.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Intel ipu input system driver");
