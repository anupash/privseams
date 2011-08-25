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
#include "signaling_builder.h"
#include "signaling_prot_hipd_msg.h"
#include "modules/signaling/lib/signaling_prot_common.h"


/*
 * Print all application information included in the packet.
 */
int hip_signaling_handle_appinfo(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx)
{
	int err = -1;
	int length;
	char *info;
	const struct hip_signaling_prot_appinfo *appname = NULL;
	const struct hip_signaling_prot_appinfo *appdev = NULL;
	const struct hip_signaling_prot_appinfo *appserial = NULL;
	printf("Entering appinfo function on packet type %i \n", packet_type);

	/* Look up app name */
	appname = (const struct hip_signaling_prot_appinfo *) hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_APPNAME);
	if(appname == NULL) {
		printf("SIGNALING(%i/%i): Application Name: No name found.\n", ha_state, packet_type);
	} else {
		err = 0;
		length = ntohs(appname->length);
		info = (char *)malloc(length);
		memcpy(info, &appname->info[0], length);
		printf("SIGNALING(%i/%i): Application Name: %s.\n", ha_state, packet_type, info);
	}

	/* Look up developer */
	appdev = (const struct hip_signaling_prot_appinfo *) hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_APPDEVELOPER);
	if(appdev == NULL) {
		printf("SIGNALING(%i/%i): Application Developer: No name found.\n", ha_state, packet_type);
	} else {
		err = 0;
		length = ntohs(appdev->length);
		info = (char *)malloc(length);
		memcpy(info, &appdev->info[0], length);
		printf("SIGNALING(%i/%i): Application Developer: %s.\n", ha_state, packet_type, info);
	}

	/* Look up Serial */
	appserial = (const struct hip_signaling_prot_appinfo *) hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_APPSERIAL);
	if(appserial == NULL) {
		printf("SIGNALING(%i/%i): Application Serial: No name found.\n", ha_state, packet_type);
	} else {
		err = 0;
		length = ntohs(appserial->length);
		info = (char *)malloc(length);
		memcpy(info, &appserial->info[0], length);
		printf("SIGNALING(%i/%i): Application Serial: %s.\n", ha_state, packet_type, info);
	}

	return err;
}

int hip_signaling_i2_add_appinfo(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx)
{
	int err = 0;
	HIP_DEBUG("SIGNALING:: Adding i2 information. \n");
    HIP_IFEL(hip_build_param_signaling_prot_appinfo(ctx->output_msg, HIP_PARAM_SIGNALING_APPNAME, "Firefox", 7), -1, "Building of APP Name Param for I2 failed\n");
    HIP_IFEL(hip_build_param_signaling_prot_appinfo(ctx->output_msg, HIP_PARAM_SIGNALING_APPDEVELOPER, "Mozilla", 7), -1, "Building of APP Developer Param for I2 failed\n");
    HIP_IFEL(hip_build_param_signaling_prot_appinfo(ctx->output_msg, HIP_PARAM_SIGNALING_APPSERIAL, "3.2.1", 5), -1, "Building of APP Serial Param for I2 failed\n");
    printf("SIGNALING(%i/%i):::: Successfully included Appinfo into I2 Packet.\n", ha_state, packet_type);
out_err:
	return err;
}

int hip_signaling_r2_add_appinfo(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx)
{
	int err = 0;
	HIP_DEBUG("SIGNALING:: Adding r2 information. \n");
    HIP_IFEL(hip_build_param_signaling_prot_appinfo(ctx->output_msg, HIP_PARAM_SIGNALING_APPNAME, "Firefox", 7), -1, "Building of APP Name Param for R2 failed\n");
    HIP_IFEL(hip_build_param_signaling_prot_appinfo(ctx->output_msg, HIP_PARAM_SIGNALING_APPDEVELOPER, "Mozilla", 7), -1, "Building of APP Developer Param for R2 failed\n");
    HIP_IFEL(hip_build_param_signaling_prot_appinfo(ctx->output_msg, HIP_PARAM_SIGNALING_APPSERIAL, "3.2.1", 5), -1, "Building of APP Serial Param for R2 failed\n");
    printf("SIGNALING(%i/%i):::: Successfully included Appinfo into R2 Packet.\n", ha_state, packet_type);

out_err:
	return err;
}
