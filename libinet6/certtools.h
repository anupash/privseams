/** @file
 * A header file for certtools.c
 *
 * Certificate building, parseing and verification functions.
 * Syntax as follows, hip_cert_XX_YY_VV(), where 
 *   XX is the certificate type
 *   YY is build or verify
 *  VV is what the function really does like sign etc.
 *
 * @author Samu Varjonen
 * @version 0.1
 * @date 31.3.2008
 *
 */

/** Struct used to deliver the minimal needed information to build SPKI cert*/
struct hip_cert_spki_header{
	char cert[4096]; // just to be sure that the size is enough
	struct in6_addr * issuer;
	struct in6_addr * subject;
	struct timeval * not_before = NULL;
	struct timeval * not_after = NULL;
}

/************************************************************************************
 * BUILDING FUNCTIONS FOR SPKI                                                      *
 ***********************************************************************************/
	
int hip_cert_spki_build_cert(struct hip_cert_spki_header *);
int hip_cert_spki_build_signature(char *, char *);
int hip_cert_spki_inject(struct hip_cert_spki_header *, char *);

/************************************************************************************
 * VERIFICATION FUNCTIONS FOR SPKI                                                  *
 ***********************************************************************************/

int hip_cert_spki_verify_signature(char *);
