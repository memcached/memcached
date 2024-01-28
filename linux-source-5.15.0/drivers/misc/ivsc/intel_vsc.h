/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _INTEL_VSC_H_
#define _INTEL_VSC_H_

#include <linux/types.h>

/* csi power state definition */
enum csi_power_state {
	POWER_OFF = 0,
	POWER_ON,
};

/* csi ownership definition */
enum csi_owner {
	CSI_FW = 0,
	CSI_IPU,
};

/* mipi configuration structure */
struct mipi_conf {
	uint32_t lane_num;
	uint32_t freq;

	/* for future use */
	uint32_t rsvd[2];
} __packed;

/* camera status structure */
struct camera_status {
	uint8_t camera_owner : 2;
	uint8_t privacy_stat : 2;

	/* for future use */
	uint8_t rsvd : 4;

	uint32_t exposure_level;
} __packed;

struct vsc_ace_ops {
	/**
	 * @brief ace own camera ownership
	 *
	 * @param ace The pointer of ace client device
	 * @param status The pointer of camera status
	 *
	 * @return 0 on success, negative on failure
	 */
	int (*ace_own_camera)(void *ace, struct camera_status *status);

	/**
	 * @brief ipu own camera ownership
	 *
	 * @param ace The pointer of ace client device
	 * @param status The pointer of camera status
	 *
	 * @return 0 on success, negative on failure
	 */
	int (*ipu_own_camera)(void *ace, struct camera_status *status);

	/**
	 * @brief get current camera status
	 *
	 * @param ace The pointer of ace client device
	 * @param status The pointer of camera status
	 *
	 * @return 0 on success, negative on failure
	 */
	int (*get_camera_status)(void *ace, struct camera_status *status);
};

struct vsc_csi_ops {
	/**
	 * @brief set csi ownership
	 *
	 * @param csi The pointer of csi client device
	 * @param owner The csi ownership going to set
	 *
	 * @return 0 on success, negative on failure
	 */
	int (*set_owner)(void *csi, enum csi_owner owner);

	/**
	 * @brief get current csi ownership
	 *
	 * @param csi The pointer of csi client device
	 * @param owner The pointer of csi ownership
	 *
	 * @return 0 on success, negative on failure
	 */
	int (*get_owner)(void *csi, enum csi_owner *owner);

	/**
	 * @brief configure csi with provided parameter
	 *
	 * @param csi The pointer of csi client device
	 * @param config The pointer of csi configuration
	 *        parameter going to set
	 *
	 * @return 0 on success, negative on failure
	 */
	int (*set_mipi_conf)(void *csi, struct mipi_conf *conf);

	/**
	 * @brief get the current csi configuration
	 *
	 * @param csi The pointer of csi client device
	 * @param config The pointer of csi configuration parameter
	 *        holding the returned result
	 *
	 * @return 0 on success, negative on failure
	 */
	int (*get_mipi_conf)(void *csi, struct mipi_conf *conf);

	/**
	 * @brief set csi power state
	 *
	 * @param csi The pointer of csi client device
	 * @param status csi power status going to set
	 *
	 * @return 0 on success, negative on failure
	 */
	int (*set_power_state)(void *csi, enum csi_power_state state);

	/**
	 * @brief get csi power state
	 *
	 * @param csi The pointer of csi client device
	 * @param status The pointer of variable holding csi power status
	 *
	 * @return 0 on success, negative on failure
	 */
	int (*get_power_state)(void *csi, enum csi_power_state *state);

	/**
	 * @brief set csi privacy callback
	 *
	 * @param csi The pointer of csi client device
	 * @param callback The pointer of privacy callback function
	 * @param handle Privacy callback runtime context
	 */
	void (*set_privacy_callback)(void *csi,
				     vsc_privacy_callback_t callback,
				     void *handle);
};

/**
 * @brief register ace client
 *
 * @param ace The pointer of ace client device
 * @param ops The pointer of ace ops
 *
 * @return 0 on success, negative on failure
 */
int vsc_register_ace(void *ace, struct vsc_ace_ops *ops);

/**
 * @brief unregister ace client
 */
void vsc_unregister_ace(void);

/**
 * @brief register csi client
 *
 * @param csi The pointer of csi client device
 * @param ops The pointer of csi ops
 *
 * @return 0 on success, negative on failure
 */
int vsc_register_csi(void *csi, struct vsc_csi_ops *ops);

/**
 * @brief unregister csi client
 */
void vsc_unregister_csi(void);

#endif
