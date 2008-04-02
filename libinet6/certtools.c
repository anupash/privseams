/** @file
 * This file defines the certificate building and verification functions to use with HIP
 *
 * Syntax in the names of functions is as follows, hip_cert_XX_YY_VV(), where 
 *   XX is the certificate type
 *   YY is build or verify
 *   VV is what the function really does like sign etc.
 *
 * @author Samu Varjonen
 * @version 0.1
 * @date 31.3.2008
 *
 */

#include "certtools.h"

/************************************************************************************
 * BUILDING FUNCTIONS FOR SPKI                                                      *
 ***********************************************************************************/

/**
 * Function to build the basic cert object of SPKI
 * @param minimal_content holds the struct hip_cert_spki_header containing the minimal needed information for cert object, also contains the char table where the cert object is to be stored
 *
 * @return 0 if ok -1 if error
 */
int hip_cert_spki_build_cert(struct hip_cert_spki_header * minimal_content) {
	int err = 0;
	char needed = "(cert )";
	memset(minimal_content.cert, '\0', sizeof(minimal_content.cert));

out_err:
	return (err);
}

/**
 * Function to build the signature object for SPKI also builds 
 * the public key object and the surrounding sequence object
 *
 * @param key RSA struct containing the public key to be used in signature process
 * @param in char table containing the cert object to be signed
 * @param out char table where the resulting certificate will be stored
 *
 * @return 0 if ok -1 if error
 */
int hip_cert_spki_build_signature(char * in, char * out) {
	int err = 0;

out_err:
	return (err);
}

/**
 * Function for injecting objects to cert object
 *
 * @param in char table of waht is to inserted
 * @param to hip_cert_spki_header containing the char table where to insert
 *
 * @return 0 if ok and negative if error
 */
int hip_cert_spki_inject(struct hip_cert_spki_header * to, char * in) {
	int err = 0;
	
out_err:
	return (err);
}

/************************************************************************************
 * VERIFICATION FUNCTIONS FOR SPKI                                                  *
 ***********************************************************************************/

/**
 * Function that verifies the signature in the SPKI certificate
 *
 * @param in char table containing the certificate to be verified
 *
 * @return 0 if signature matches, -1 if error or signature did NOT match
 */
int hip_cert_spki_verify_signature(char * in) {
	int err = 0;
	
out_err:
	return (err);
}
