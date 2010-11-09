/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H
#define HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H

/* MAX = ? */
#define PATHBUF_SIZE            200

int signaling_netstat_get_application_path(uint16_t srcport, uint16_t destport, char *pathbuf);

#endif /* HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H */
