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
 * @author Henrik Ziegeldorf <henrik.ziegeldorf@rwth-aachen.de>
 *
 */

/* required for IFNAMSIZ in libipq headers */
#define _BSD_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "lib/core/builder.h"
#include "lib/core/ife.h"

#include "modules/signaling/lib/signaling_prot_common.h"
#include "signaling_hipfw.h"
#include "signaling_cdb.h"

/* Init connection tracking data base */
int signaling_hipfw_init(void) {
    int err = 0;
    err = signaling_cdb_init();

    return err;
}
/*
 * Print all application information included in the packet.
 */
int signaling_hipfw_handle_appinfo(const struct hip_common *common, UNUSED struct tuple *tuple, UNUSED const hip_fw_context_t *ctx)
{
	int err = 1;
	UNUSED const struct signaling_param_appinfo *appinfo = NULL;

	/* Get the parameter */
	HIP_IFEL(!(appinfo = (const struct signaling_param_appinfo *) hip_get_param(common, HIP_PARAM_SIGNALING_APPINFO)),
	        -1, "No application info parameter found in the message.\n");

	/* Print out contents */
	signaling_param_appinfo_print(appinfo);

out_err:
	return err;
}
