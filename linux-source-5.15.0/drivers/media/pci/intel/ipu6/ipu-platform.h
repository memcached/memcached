/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2013 - 2020 Intel Corporation */

#ifndef IPU_PLATFORM_H
#define IPU_PLATFORM_H

#define IPU_NAME			"intel-ipu6"

#define IPU6SE_FIRMWARE_NAME		"intel/ipu6se_fw.bin"
#define IPU6EP_FIRMWARE_NAME		"intel/ipu6ep_fw.bin"
#define IPU6EPES_FIRMWARE_NAME		"intel/ipu6epes_fw.bin"
#define IPU6_FIRMWARE_NAME		"intel/ipu6_fw.bin"

/*
 * The following definitions are encoded to the media_device's model field so
 * that the software components which uses IPU driver can get the hw stepping
 * information.
 */
#define IPU_MEDIA_DEV_MODEL_NAME		"ipu6"

#define IPU6SE_ISYS_NUM_STREAMS          IPU6SE_NONSECURE_STREAM_ID_MAX
#define IPU6_ISYS_NUM_STREAMS            IPU6_NONSECURE_STREAM_ID_MAX

/* declearations, definitions in ipu6.c */
extern struct ipu_isys_internal_pdata isys_ipdata;
extern struct ipu_psys_internal_pdata psys_ipdata;
extern const struct ipu_buttress_ctrl isys_buttress_ctrl;
extern const struct ipu_buttress_ctrl psys_buttress_ctrl;

/* definitions in ipu6-isys.c */
extern struct ipu_trace_block isys_trace_blocks[];
/* definitions in ipu6-psys.c */
extern struct ipu_trace_block psys_trace_blocks[];

#endif
