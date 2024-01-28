/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_VSC_H_
#define _LINUX_VSC_H_

#include <linux/types.h>

/**
 * @brief VSC camera ownership definition
 */
enum vsc_camera_owner {
	VSC_CAMERA_NONE = 0,
	VSC_CAMERA_CVF,
	VSC_CAMERA_IPU,
};

/**
 * @brief VSC privacy status definition
 */
enum vsc_privacy_status {
	VSC_PRIVACY_ON = 0,
	VSC_PRIVACY_OFF,
};

/**
 * @brief VSC MIPI configuration definition
 */
struct vsc_mipi_config {
	uint32_t freq;
	uint32_t lane_num;
};

/**
 * @brief VSC camera status definition
 */
struct vsc_camera_status {
	enum vsc_camera_owner owner;
	enum vsc_privacy_status status;
	uint32_t exposure_level;
};

/**
 * @brief VSC privacy callback type definition
 *
 * @param context Privacy callback handle
 * @param status Current privacy status
 */
typedef void (*vsc_privacy_callback_t)(void *handle,
				       enum vsc_privacy_status status);

/**
 * @brief Acquire camera sensor ownership to IPU
 *
 * @param config[IN] The pointer of MIPI configuration going to set
 * @param callback[IN] The pointer of privacy callback function
 * @param handle[IN] Privacy callback function runtime handle from IPU driver
 * @param status[OUT] The pointer of camera status after the acquire
 *
 * @retval 0 If success
 * @retval -EIO IO error
 * @retval -EINVAL Invalid argument
 * @retval -EAGAIN VSC device not ready
 * @retval negative values for other errors
 */
int vsc_acquire_camera_sensor(struct vsc_mipi_config *config,
			      vsc_privacy_callback_t callback,
			      void *handle,
			      struct vsc_camera_status *status);

/**
 * @brief Release camera sensor ownership
 *
 * @param status[OUT] Camera status after the release
 *
 * @retval 0 If success
 * @retval -EIO IO error
 * @retval -EINVAL Invalid argument
 * @retval -EAGAIN VSC device not ready
 * @retval negative values for other errors
 */
int vsc_release_camera_sensor(struct vsc_camera_status *status);

#endif
