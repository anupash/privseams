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
#ifndef HIP_REGISTRATION_H
#define HIP_REGISTRATION_H

#include "misc.h"
#include "hiprelay.h" // For relrec lifetimes.
#include "escrow.h" // For escrow lifetimes.

/** Possible service states. */
typedef enum{HIP_SERVICE_OFF = 0, HIP_SERVICE_ON = 1}hip_srv_status_t;

/** HIP service. */
typedef struct{
	hip_srv_status_t status;
	uint8_t type;
	uint8_t min_lifetime;
	uint8_t max_lifetime;
}hip_srv_t;

void hip_init_xxx_services();
int hip_set_srv_status(uint8_t type, hip_srv_status_t status);
int hip_set_srv_min_lifetime(uint8_t type, uint8_t lifetime);
int hip_set_srv_max_lifetime(uint8_t type, uint8_t lifetime);
int hip_get_active_services(hip_srv_t *active_services,
			    unsigned int *active_service_count);
void hip_srv_info(const hip_srv_t *srv, char *status);

/**
 * Translates a service life time from seconds to a 8-bit integer value. The
 * lifetime value in seconds is translated to a 8-bit integer value using
 * following formula: <code>lifetime = (8 * (log(seconds) / log(2)))
 * + 64</code> and truncated. The formula is the inverse of the formula given
 * in the registration draft.
 * 
 * @param  seconds  the lifetime to convert.
 * @param  lifetime a target buffer for the coverted lifetime.
 * @return          zero on success, -1 on error. Error occurs when @c seconds
 *                  is zero or greater than 15384774.
 */ 
int hip_get_lifetime_value(time_t seconds, uint8_t *lifetime);

/**
 * Translates a service life time from a 8-bit integer value to seconds. The
 * lifetime value is translated to a 8-bit integer value using following
 * formula: <code>seconds = 2^((lifetime - 64)/8)</code>.
 *
 * @param  lifetime the lifetime to convert.
 * @param  seconds  a target buffer for the converted lifetime.
 * @return          zero on success, -1 on error. Error occurs when @c lifetime
 *                  is zero.
 */ 
int hip_get_lifetime_seconds(uint8_t lifetime, time_t *seconds);

#endif /* HIP_REGISTRATION_H */
