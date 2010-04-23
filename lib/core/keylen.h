/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_LIB_CORE_KEYLEN_H
#define HIP_LIB_CORE_KEYLEN_H

int hip_auth_key_length_esp(int tid);
int hip_hmac_key_length(int tid);
int hip_enc_key_length(int tid);

#endif /* HIP_LIB_CORE_KEYLEN_H */
