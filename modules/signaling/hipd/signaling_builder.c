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
 * @brief adds parameters according to the defined parameter structure to a
 *        packet
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#include <string.h>

#include "modules/signaling/lib/signaling_prot_common.h"
#include "lib/core/debug.h"
#include "lib/core/builder.h"
#include "lib/core/protodefs.h"
#include "lib/core/common.h"
#include "signaling_builder.h"
#include "lib/core/ife.h"



/**
 * Build a HIP SIGNALING APP INFO (= Name, Developer, Serial) parameter
 *
 * @param msg the message
 * @param type the info type
 * @param info the info (app name, devloper or serial)
 * @param length the length of the info
 * @return zero for success, or non-zero on error
 */
int hip_build_param_signaling_prot_appinfo(struct hip_common *msg, hip_tlv_type_t type, const char *info, hip_tlv_len_t length)
{
    struct hip_signaling_prot_appinfo appinfo;
    int err = 0;
    char *value;

    HIP_ASSERT(msg != NULL);

    /* Set type */
    hip_set_param_type((struct hip_tlv_common *) &appinfo, type);

    /* Set length */
    hip_set_param_contents_len((struct hip_tlv_common *) &appinfo, length);

    /* Set contents */
    HIP_IFEL(!(value = malloc(length)), -1, "Failed to alloc memory for app name\n");
    memcpy(value, info, length);

    err = hip_build_generic_param(msg, &appinfo, sizeof(struct hip_signaling_prot_appinfo), value);

out_err:
    return err;
}

