/*
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
 */

/**
 * @file
 * @brief Update DNS data for the hit-to-ip domain name.
 * @brief It executes an external perl script for each HIT
 * @brief and passes it a list of the current IP addresses.
 *
 * @brief hip_set_nsupdate_status and hip_get_nsupdate_status are usually invoked by hipconf
 * @brief and nsupdate by hip_send_locators_to_all_peers and hipd_init
 *
 * @author Oleg Ponomarev <oleg.ponomarev@hiit.fi>
 */

#ifndef HIP_HIPD_NSUPDATE_H
#define HIP_HIPD_NSUPDATE_H

void hip_set_nsupdate_status(int status);
int hip_get_nsupdate_status(void);

int nsupdate(int start);

#endif /* HIP_HIPD_NSUPDATE_H */
