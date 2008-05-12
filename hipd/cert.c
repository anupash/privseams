/** @file
 * This file defines the certificate signing and verification functions to use with HIP
 *
 * Syntax in the names of functions is as follows, hip_cert_XX_YY_VV(), where 
 *   XX is the certificate type
 *   YY is build or verify
 *   VV is what the function really does like sign etc.
 *
 * @author Samu Varjonen
 * @version 0.1
 * @date 12.5.2008
 *
 */
#include "cert.h"

/**
 * Function that extracts the key from hidb entry and constructs a RSA struct from it
 *
 * @param db is the db to query for the hostid entry
 * @param hit is a pointer to a host identity tag to be searched
 * @param rsa is the resulting struct that contains the key material
 *
 * @return 0 if signature matches, -1 if error or signature did NOT match
 */
int hip_cert_spki_construct_keys(HIP_HASHTABLE * db, hip_hit_t * hit, RSA * rsa) {
        int err = 0;
        struct hip_host_id * pub = NULL;
        struct hip_host_id * priv = NULL;
        
        /* Get the keys for the cert->issuer_hit */
        pub = hip_get_hostid_entry_by_lhi_and_algo(db, 
                                                   hit,
                                                   HIP_HI_RSA, -1);
        //pub = hip_get_rsa_public_key(pub);
        priv = hip_get_hostid_entry_by_lhi_and_algo(db, 
                                                    hit, 
                                                    HIP_HI_RSA, -1);

 out_err: 
        return(err);
}
