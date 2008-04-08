/** @file
 * A header file for registration.c.
 * 
 * @author  Lauri Silvennoinen
 * @version 1.0
 * @date    05.04.2008
 * @note    Related drafts:
 *          <a href="http://www.ietf.org/internet-drafts/draft-ietf-hip-registration-02.txt">
 *          draft-ietf-hip-registration-02</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 * @see     registration.c
 * @see     hiprelay.h
 * @see     escrow.h
 */
#ifndef REGISTRATION_H
#define REGISTRATION_H

#include "misc.h"

/** Possible service states. */
typedef enum{HIP_SERVICE_OFF = 0, HIP_SERVICE_ON = 1}hip_service_status_t;

/** HIP service. */
typedef struct{
	uint8_t service;
	hip_service_status_t status;
}hip_service_xxx_t;

void hip_reg_init_services();
int hip_reg_set_srv_status(uint8_t service, hip_service_status_t status);
#endif /* REGISTRATION_H*/
