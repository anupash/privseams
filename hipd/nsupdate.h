/**
 * @file ./hipd/nsupdate.h
 *
 *  <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
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

int nsupdate(const int start);

#endif /* HIP_HIPD_NSUPDATE_H */
