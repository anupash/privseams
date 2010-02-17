/** @file
 * This file defines TCP timeout parameters setting for the Host Identity
 * Protocol (HIP) in order to overcome the application time out when handover taking
 * long time.
 *
 * @author  Tao Wan  <twan_cc.hut.fi>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 * */

#ifndef HIP_HIPD_TCPTIMEOUT_H
#define HIP_HIPD_TCPTIMEOUT_H

int set_new_tcptimeout_parameters_value(void);

int reset_default_tcptimeout_parameters_value(void);


#endif /* HIP_HIPD_TCPTIMEOUT_H */
