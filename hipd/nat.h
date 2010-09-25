/** @file
 * A header file for nat.c
 *
 * @author  (version 1.0) Abhinav Pathak
 * @author  (version 1.1) Lauri Silvennoinen
 * @version 1.1
 * @date    27.10.2006
 * @note    Related drafts:
 *          <ul>
 *          <li><a href="http://www.ietf.org/internet-drafts/draft-schmitt-hip-nat-traversal-02.txt">
 *          draft-schmitt-hip-nat-traversal-02</a></li>
 *          <li><a href="http://www.ietf.org/internet-drafts/draft-irtf-hiprg-nat-03.txt">
 *          draft-irtf-hiprg-nat-03</a></li>
 *          </ul>
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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
 * @note    All Doxygen comments have been added in version 1.1.
 */

#ifndef HIP_HIPD_NAT_H
#define HIP_HIPD_NAT_H

#include "lib/core/protodefs.h"

/** Time interval between consecutive NAT Keep-Alive packets in seconds.
 *  @note According to [draft-schmitt-hip-nat-traversal-02], the default
 *  keep-alive interval for control channels must be 20 seconds. However, for
 *  debugging purposes a smaller value is used here.
 *  @todo Change this value. */
#define HIP_NAT_KEEP_ALIVE_INTERVAL 20
/** Port number for NAT traversal of hip control packets. */

hip_transform_suite_t hip_get_nat_mode(hip_ha_t *entry);
int hip_nat_refresh_port(void);
int hip_user_nat_mode(int nat_mode);

#endif /* HIP_HIPD_NAT_H */
