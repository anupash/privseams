/*
 * esp_prot_fw_msg.c
 *
 *  Created on: Jul 20, 2008
 *      Author: Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#include "utils.h"
#include "esp_prot_common.h"
#include "icomm.h"
#include "debug.h"
#include "ife.h"

/* this sends the prefered transform to hipd implicitely turning on
 * the esp protection extension there */
int send_esp_protection_to_hipd(int active)
{
	int err = 0;
	struct hip_common *msg = NULL;
	uint8_t transform = 0;

	// for now this is the only transform we support
	if (active > 0)
		transform = ESP_PROT_TRANSFORM_DEFAULT;
	else
		transform = ESP_PROT_TRANSFORM_UNUSED;

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "alloc memory for adding sa entry\n");

	hip_msg_init(msg);

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ESP_PROT_EXT_TRANSFORM, 0), -1,
		 "build hdr failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (void *)&transform, HIP_PARAM_UINT,
					  sizeof(uint8_t)), -1,
					  "build param contents failed\n");

	HIP_DEBUG("sending esp protection transform %i to hipd...\n", active);
	HIP_DUMP_MSG(msg);

	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

	HIP_DEBUG("send_recv msg succeeded\n");
	HIP_DEBUG("esp extension transform successfully set up\n");

 out_err:
	if (msg)
		free(msg);
	return err;
}

/* sends a list of all available anchor elements in the bex store
 * to the hipd, which then draws the element used in the bex from
 * this list */
int send_anchor_list_update_to_hipd(uint8_t transform)
{
	int err = 0;
	struct hip_common *msg = NULL;

	HIP_IFEL(!(msg = (struct hip_common *)create_bexstore_anchors_message(esp_prot_transforms[transform])), -1,
			"failed to create bex store anchors update message\n");

	HIP_DUMP_MSG(msg);

	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

	HIP_DEBUG("send_recv msg succeeded\n");

 out_err:
	if (msg)
		free(msg);
	return err;
}

/* invoke an UPDATE message containing the next anchor element to be used */
int send_next_anchor_to_hipd(unsigned char *anchor, uint8_t transform)
{
	int err = 0;
	struct hip_common *msg = NULL;

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "alloc memory for adding sa entry\n");

	hip_msg_init(msg);

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_IPSEC_NEXT_ANCHOR, 0), -1,
		 "build hdr failed\n");

	HIP_HEXDUMP("anchor: ", anchor, esp_prot_transforms[transform]);
	HIP_IFEL(hip_build_param_contents(msg, (void *)anchor, HIP_PARAM_HCHAIN_ANCHOR,
			esp_prot_transforms[transform]), -1, "build param contents failed\n");

	HIP_DUMP_MSG(msg);

	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

	HIP_DEBUG("send_recv msg succeeded\n");

 out_err:
	if (msg)
		free(msg);

	return err;
}
