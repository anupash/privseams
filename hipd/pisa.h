/** @file
 * A header file for pisa.c.
 *
 * @author Thomas Jansen
 */
#ifndef HIP_PISA_H
#define HIP_PISA_H

/**
 * Get the certificate text that will be appended to R2 and U2 packets
 *
 * @return pointer to the certificate text
 */
char *hip_pisa_get_certificate(void);

#endif /* HIP_PISA_H */
