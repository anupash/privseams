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
#include <sys/types.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include "certtools.h"
#include "debug.h"
#include "ife.h"

/*******************************************************************************
 * BUILDING FUNCTIONS FOR SPKI                                                 *
 *******************************************************************************/

/**
 * Function to build the basic cert object of SPKI
 * @param minimal_content holds the struct hip_cert_spki_header containing 
 *                        the minimal needed information for cert object, 
 *                        also contains the char table where the cert object 
 *                        is to be stored
 *
 * @return 0 if ok -1 if error
 */
int hip_cert_spki_build_cert(struct hip_cert_spki_header * minimal_content) {
	int err = 0;
	char needed[] = "(cert )";
	memset(minimal_content->cert, '\0', sizeof(minimal_content->cert));
        sprintf(minimal_content->cert, "%s", needed);

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
 * @param to hip_cert_spki_header containing the char table where to insert
 * @param after is a char pointer for the regcomp after which the inject happens
 * @param what is char pointer of what to 
 *
 * @return 0 if ok and negative if error. -1 returned for example when after is NOT found
 */
int hip_cert_spki_inject(struct hip_cert_spki_header * to, 
                         char * after, char * what) {
	int err = 0, status = 0;
        regex_t re;
        regmatch_t pm[1];
        char * tmp_cert;        

        HIP_DEBUG("Before inject:\n"
                  "%s\n",to->cert);
        HIP_DEBUG("Inserting \"%s\" after \"%s\"\n", what, after);       
        tmp_cert = malloc(strlen(to->cert) + strlen(what) + 1);
        if (!tmp_cert) return(-1);
        HIP_IFEL(!memset(tmp_cert, 0, sizeof(tmp_cert)), -1,
                 "Failed to memset temporary workspace\n");        
        /* Compiling the regular expression */
        HIP_IFEL(regcomp(&re, after, REG_EXTENDED), -1, 
                 "Compilation of the regular expression failed\n");       
        /* Running the regular expression */
        HIP_IFEL((status = regexec(&re, to->cert, 1, pm, 0)), -1,
                 "Handling of regular expression failed\n");
        HIP_DEBUG("Found \"%s\" at %d and it ends at %d\n",
                  what, pm[0].rm_so, pm[0].rm_eo);
        snprintf(tmp_cert, pm[0].rm_eo, "%s", to->cert); 
        snprintf(&tmp_cert[pm[0].rm_eo - 1], strlen(what), "%s", what);
        snprintf(&tmp_cert[pm[0].rm_eo + strlen(what) -1 ], 
                (strlen(to->cert) - pm[0].rm_eo), "%s", to->cert);
        sprintf(to->cert, "%s", tmp_cert);
        HIP_DEBUG("After inject:\n"
                  "%s\n",to->cert);
out_err:
        regfree(&re);
        free(tmp_cert);
	return (err);
}

/*******************************************************************************
 * VERIFICATION FUNCTIONS FOR SPKI                                             *
 *******************************************************************************/

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
