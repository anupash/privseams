/** @file
 * A header file for pisa.c.
 *
 * @author Thomas Jansen
 */
#ifndef HIP_PISA_H
#define HIP_PISA_H

#ifdef CONFIG_HIP_MIDAUTH

/**
 * Get the certificate text that will be appended to R2 and U2 packets
 *
 * @return pointer to the certificate text
 */
char *hip_pisa_get_certificate(void);

#endif /* CONFIG_HIP_MIDAUTH */
#endif /* HIP_PISA_H */
