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

#ifndef MODULES_SIGNALING_HIPD_SIGNALING_BUILDER_H_
#define MODULES_SIGNALING_HIPD_SIGNALING_BUILDER_H_

/* Build an appinfo parameter. */
int signaling_build_param_appinfo(struct hip_common *msg);

/* Get the typename of a appinfo field */
const char *signaling_get_param_field_type_name(const hip_tlv_type_t param_type);

int signaling_build_param_portinfo(struct hip_common *msg, uint16_t src_port, uint16_t dest_port);

#endif /* MODULES_ESP_TOKENS_HIPD_ESP_TOKENS_BUILDER_H_ */
