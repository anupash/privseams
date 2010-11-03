/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * hipd messages to the hipfw and additional parameters for BEX and
 * UPDATE messages.
 *
 * @brief Messaging with hipfw and other HIP instances
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>

#include "lib/core/common.h"
#include "lib/core/debug.h"
#include "lib/core/builder.h"
#include "lib/core/ife.h"

#include "modules/signaling/lib/signaling_builder.h"
#include "modules/signaling/lib/signaling_prot_common.h"
#include "signaling_prot_hipd_msg.h"



/*
 * Get the next tlv from a appinfo parameter
 */
static const struct hip_tlv_common *signaling_get_param_next_tlv(const void *param, const void *last_tlv) {
	const struct hip_tlv_common *next_tlv = NULL;
	const uint8_t *pos = (const uint8_t *) last_tlv;

    if (!param) {
        HIP_ERROR("No contents given (null)\n");
        goto out;
    }

	if(last_tlv == NULL) {
		pos = hip_get_param_contents_direct(param);
	} else {
		pos += sizeof(struct hip_tlv_common) + hip_get_param_contents_len(last_tlv);
	}

	next_tlv = (const struct hip_tlv_common *) pos;

	/* Check we are still inside the message */
	if(((const char *) next_tlv) - ((const char *) hip_get_param_contents_direct(param)) >= hip_get_param_contents_len(param))
		next_tlv = NULL;

out:
	return next_tlv;
}

/*
 * Print all application information included in the packet.
 */
int signaling_handle_appinfo(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx)
{
	int err = -1;
	int field_length;
	char *info;
	const struct hip_tlv_common *appinfo = NULL;
	const struct hip_tlv_common *tlv = NULL;

	/* Get the parameter */
	appinfo = (const struct hip_tlv_common *) hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_APPINFO);
	if(appinfo == NULL) {
		HIP_DEBUG("No parameter of type %d found.\n", HIP_PARAM_SIGNALING_APPINFO);
		goto out;
	}

	/* Iterate over the contents */
	tlv = signaling_get_param_next_tlv(appinfo, tlv);
	while(tlv != NULL) {
		field_length = hip_get_param_contents_len(tlv);
		/* Append string terminator to be sure...*/
		info = (char *)malloc(field_length+1);
		memset(info, 0, field_length+1);
		memcpy(info, hip_get_param_contents_direct(tlv), field_length);
		HIP_DEBUG("SIGNALING(%i/%i): Field %s: %s.\n", ha_state, packet_type, signaling_get_param_field_type_name(hip_get_param_type(tlv)), info);
		tlv = signaling_get_param_next_tlv(appinfo, tlv);
	}

out:
	return err;
}

int signaling_i2_add_appinfo(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx)
{
	int err = 0;
    HIP_IFEL(signaling_build_param_appinfo(ctx->output_msg), -1, "Building of APP Name Param for I2 failed\n");
    printf("SIGNALING(%i/%i):::: Successfully included Appinfo into I2 Packet.\n", ha_state, packet_type);
out_err:
	return err;
}

int signaling_r2_add_appinfo(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx)
{
	int err = 0;
	HIP_DEBUG("SIGNALING:: Adding r2 information. \n");
    HIP_IFEL(signaling_build_param_appinfo(ctx->output_msg), -1, "Building of APP Name Param for R2 failed\n");
    printf("SIGNALING(%i/%i):::: Successfully included Appinfo into R2 Packet.\n", ha_state, packet_type);

out_err:
	return err;
}
