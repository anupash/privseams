/**
 * @file hipd/pisa.h
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * This file contains function declarations  specific to PISA. They deal with the
 * certificate loading.
 *
 * @brief Functions declarations for certificate loading
 *
 * @author Thomas Jansen
 */
#ifndef HIP_HIPD_PISA_H
#define HIP_HIPD_PISA_H

/**
 * Get the certificate text that will be appended to R2 and U2 packets
 *
 * @return pointer to the certificate text
 */
char *hip_pisa_get_certificate(void);

#endif /* HIP_HIPD_PISA_H */
