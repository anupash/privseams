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

#ifndef HIP_HIPD_MAINTENANCE_H
#define HIP_HIPD_MAINTENANCE_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/time.h>


int hip_register_maint_function(int (*maint_function)(void),
                                const uint16_t priority);
int hip_unregister_maint_function(int (*maint_function)(void));
void hip_uninit_maint_functions(void);
int hip_periodic_maintenance(void);
void hip_set_firewall_status(void);
int hip_get_firewall_status(void);
int hip_firewall_is_alive(void);

/*Communication with firewall daemon*/
int hip_firewall_set_bex_data(int action, struct in6_addr *hit_s, struct in6_addr *hit_r);
int hip_firewall_set_esp_relay(int action);

#endif /* HIP_HIPD_MAINTENANCE_H */
