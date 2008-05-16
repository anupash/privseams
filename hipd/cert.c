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
 * Function that signs the cert sequence and creates the public key sequence
 *
 * @param msg points to the msg gotten from "client"
 * @param db is the db to query for the hostid entry
 *
 * @return 0 if signature matches, -1 if error or signature did NOT match
 */
int hip_cert_spki_sign(struct hip_common * msg, HIP_HASHTABLE * db) {
        int err = 0;
        struct hip_cert_spki_info *cert;
        char sha_digest[21];
        unsigned char *sha_retval;
        RSA *rsa = NULL;
        
        rsa = RSA_new();
        HIP_IFEL(!rsa, -1, "Failed to malloc RSA\n");
        
        memset(sha_digest, '\0', sizeof(sha_digest));
        
        HIP_IFEL(!(cert = hip_get_param(msg,HIP_PARAM_CERT_SPKI_INFO)), 
                 -1, "No cert_info struct found\n");
        _HIP_DEBUG("\n\n** CONTENTS of cert sequence to be signed **\n"
                   "%s\n\n", cert->cert);
        
        HIP_DEBUG_HIT("Getting keys for HIT",&cert->issuer_hit);
        
        HIP_IFEL((err = hip_cert_spki_construct_keys(hip_local_hostid_db,
                                            &cert->issuer_hit, rsa)), -1, 
                "Error constructing the keys from hidb entry\n");
        
        /* build sha1 digest that will be signed */
        HIP_IFEL(!(sha_retval = SHA1(cert->cert, strlen(cert->cert), sha_digest)),
                 -1, "SHA1 error when creating digest.\n");        
        _HIP_HEXDUMP("SHA1 digest of cert sequence ", sha_digest, 20);             

        /* copy needed info back to public-key and signature 
           sequences and let the daemon send it back */
 out_err:
        RSA_free(rsa);
        return err;
}

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
        int err = 0, s = 1;
        struct hip_host_id_entry * hostid_entry = NULL;
        struct hip_host_id * hostid = NULL;
        struct hip_lhi * lhi = NULL;
        u8 *p;
        /* 
           Get the corresponding host id for the HIT.
           It will contain both the public and the private key
        */
        hostid_entry = hip_get_hostid_entry_by_lhi_and_algo(db, 
                                                            hit,
                                                            HIP_HI_RSA, -1);  
        /* Point to the rdata correctly ? */
        lhi = &hostid_entry->lhi;
        hostid = hostid_entry->host_id;
        p = (u8 *)(hostid + 1);

        _HIP_DEBUG_HIT("HIT from hostid entry", &lhi->hit);
        HIP_DEBUG("type = %d len = %d\n", htons(hostid->type), hostid->hi_length);

        /*
          Order of the key material in the host id rdata is the following
           HIP_RSA_PUBLIC_EXPONENT_E_LEN 
           HIP_RSA_PUBLIC_MODULUS_N_LEN 
           HIP_RSA_PRIVATE_EXPONENT_D_LEN 
           HIP_RSA_SECRET_PRIME_FACTOR_P_LEN
           HIP_RSA_SECRET_PRIME_FACTOR_Q_LEN  
        */
        
        /* Public part of the key */
        /* s starts from the first byt after the rdata struct thats why 1*/
        _HIP_DEBUG("s = %d\n",s);
        rsa->e = BN_bin2bn(&p[s], HIP_RSA_PUBLIC_EXPONENT_E_LEN, 0);       
        s += HIP_RSA_PUBLIC_EXPONENT_E_LEN;
        _HIP_DEBUG("s = %d\n",s);
        rsa->n = BN_bin2bn(&p[s], HIP_RSA_PUBLIC_MODULUS_N_LEN, 0);
        s += HIP_RSA_PUBLIC_MODULUS_N_LEN;
        _HIP_DEBUG("s = %d\n",s);
        /* Private part of the key */
        rsa->d = BN_bin2bn(&p[s], HIP_RSA_PRIVATE_EXPONENT_D_LEN, 0);
        s += HIP_RSA_PRIVATE_EXPONENT_D_LEN;
        _HIP_DEBUG("s = %d\n",s);
        rsa->p = BN_bin2bn(&p[s], HIP_RSA_SECRET_PRIME_FACTOR_P_LEN, 0);
        s += HIP_RSA_SECRET_PRIME_FACTOR_P_LEN;
        _HIP_DEBUG("s = %d\n",s);
        rsa->q = BN_bin2bn(&p[s], HIP_RSA_SECRET_PRIME_FACTOR_Q_LEN, 0);
        
        HIP_DEBUG("Hostid converted to RSA e=%s\n", BN_bn2hex(rsa->e));
        HIP_DEBUG("Hostid converted to RSA n=%s\n", BN_bn2hex(rsa->n));
        HIP_DEBUG("Hostid converted to RSA d=%s\n", BN_bn2hex(rsa->d));
        HIP_DEBUG("Hostid converted to RSA p=%s\n", BN_bn2hex(rsa->p));
        HIP_DEBUG("Hostid converted to RSA q=%s\n", BN_bn2hex(rsa->q));

 out_err: 
        return(err);
}
