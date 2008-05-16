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
        int err = 0, sig_len = 0, hex_len = 0;
        struct hip_cert_spki_info *cert;
        char sha_digest[21];
        char * sig_sequence;
        unsigned char *sha_retval;
        unsigned char e_bin[HIP_RSA_PUBLIC_EXPONENT_E_LEN + 1];
        char * signature_b64;
        char * digest_b64;
        char * e_hex;
        char * n_b64;
        char n[HIP_RSA_PUBLIC_MODULUS_N_LEN];
        char e[HIP_RSA_PUBLIC_EXPONENT_E_LEN];
        u8 signature[HIP_RSA_SIGNATURE_LEN];
        RSA *rsa = NULL;
        
        /* 
           XX FIXME
           sizes for the mallocs are just estimates, 
           the signature is 128 bytes + the 
           bytes from base64 and the sequence stuff 
        */
        sig_sequence = malloc(256); 
        HIP_IFEL((!sig_sequence), -1, "Malloc for sig_sequence failed\n");
        memset(sig_sequence, 0, sizeof(sig_sequence));

        digest_b64 = malloc(30); 
        HIP_IFEL((!digest_b64), -1, "Malloc for digest_b64 failed\n");
        memset(digest_b64, 0, sizeof(digest_b64));
                
        signature_b64 = malloc(256); 
        HIP_IFEL((!signature_b64), -1, "Malloc for signature_b64 failed\n");
        memset(signature_b64, 0, sizeof(signature_b64));

        e_hex = malloc(256); 
        HIP_IFEL((!e_hex), -1, "Malloc for e_hex failed\n");
        memset(e_hex, 0, sizeof(e_hex));

        /*XX FIXME just a guestimate calculate correctly */
        n_b64 = malloc(sizeof(n)+20);  
        HIP_IFEL((!n_b64), -1, "Malloc for n_b64 failed\n");
        memset(n_b64, 0, sizeof(n_b64));

        /* malloc space for new rsa */
        rsa = RSA_new();
        HIP_IFEL(!rsa, -1, "Failed to malloc RSA\n");
        
        memset(sha_digest, '\0', sizeof(sha_digest));
        memset(e_bin, 0, sizeof(e_bin));
        
        HIP_IFEL(!(cert = hip_get_param(msg,HIP_PARAM_CERT_SPKI_INFO)), 
                 -1, "No cert_info struct found\n");
        _HIP_DEBUG("\n\n** CONTENTS of cert sequence to be signed **\n"
                   "%s\n\n", cert->cert);
        
        _HIP_DEBUG_HIT("Getting keys for HIT",&cert->issuer_hit);
        
        HIP_IFEL((err = hip_cert_spki_construct_keys(hip_local_hostid_db,
                                            &cert->issuer_hit, rsa)), -1, 
                "Error constructing the keys from hidb entry\n");
        
        /* build sha1 digest that will be signed */
        HIP_IFEL(!(sha_retval = SHA1(cert->cert, strlen(cert->cert), sha_digest)),
                 -1, "SHA1 error when creating digest.\n");        
        _HIP_HEXDUMP("SHA1 digest of cert sequence ", sha_digest, 20);          

        /* sign the digest */
        sig_len = RSA_size(rsa);
	memset(signature, 0, sig_len);
	err = RSA_sign(NID_sha1, sha_digest, SHA_DIGEST_LENGTH, signature,
		       &sig_len, rsa);
        HIP_IFEL((err = err == 0 ? -1 : 0), -1, "RSA_sign error\n");
        
        _HIP_HEXDUMP("Signature created for the certificate ", signature, sig_len);
        _HIP_DEBUG("Siglen %d, err :%d\n", sig_len, err);
        
        /* we got the signature lets build the sequence for it */
        HIP_IFEL((err = hip_cert_spki_build_signature(signature, sig_sequence)), -1,
                 "Building signature sequence failed\n");

        /* clearing signature field just to be sure */
        memset(cert->signature, '\0', sizeof(cert->signature));
        digest_b64 = (char *)base64_encode((unsigned char *)sha_digest, 
                                         (unsigned int)sizeof(sha_digest));
        signature_b64 = (char *)base64_encode((unsigned char *)signature, 
                                         (unsigned int)sizeof(signature));

        /* create (signature (hash sha1 |digest|)|signature|) */
        sprintf(cert->signature, "(signature (hash sha1 |%s|)|%s|)", 
                digest_b64, signature_b64);
        
        _HIP_DEBUG("Sig sequence \n%s\n",cert->signature); 
               
        sprintf(cert->signature, "%s", sig_sequence);

        /* Create the public key sequence */
        n_b64 = (char *)base64_encode((unsigned char *)rsa->n, 
                                         (unsigned int)sizeof(n));
        
        HIP_IFEL(!(BN_bn2bin(rsa->e, e_bin)), -1,
                 "Error in converting public exponent from BN to bin\n");
        HIP_HEXDUMP("Exponent in hex ", e_bin, 
                    HIP_RSA_PUBLIC_EXPONENT_E_LEN);
        /* XX FIXME HEX conversion tells the result all wrong */
        hex_len = snprintf(e_hex, HIP_RSA_PUBLIC_EXPONENT_E_LEN *2 + 1, "%02x", &e_bin);
        HIP_DEBUG("This hex conversion returned", hex_len);
        sprintf(cert->public_key, "(public_key (rsa-pkcs1-sha1 (e #%s#)(n |%s|)))", 
                e_hex, n_b64);

        HIP_DEBUG("Public-key sequence\n%s\n",cert->public_key);
        
 out_err:
        if (sig_sequence) free(sig_sequence);
        if (rsa) RSA_free(rsa);
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
        _HIP_DEBUG("type = %d len = %d\n", htons(hostid->type), hostid->hi_length);

        /*
          Order of the key material in the host id rdata is the following
           HIP_RSA_PUBLIC_EXPONENT_E_LEN 
           HIP_RSA_PUBLIC_MODULUS_N_LEN 
           HIP_RSA_PRIVATE_EXPONENT_D_LEN 
           HIP_RSA_SECRET_PRIME_FACTOR_P_LEN
           HIP_RSA_SECRET_PRIME_FACTOR_Q_LEN  
        */
        
        /* Public part of the key */
        /* s starts from the first byte after the rdata struct thats why 1*/
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
        
        _HIP_DEBUG("Hostid converted to RSA e=%s\n", BN_bn2hex(rsa->e));
        _HIP_DEBUG("Hostid converted to RSA n=%s\n", BN_bn2hex(rsa->n));
        _HIP_DEBUG("Hostid converted to RSA d=%s\n", BN_bn2hex(rsa->d));
        _HIP_DEBUG("Hostid converted to RSA p=%s\n", BN_bn2hex(rsa->p));
        _HIP_DEBUG("Hostid converted to RSA q=%s\n", BN_bn2hex(rsa->q));

 out_err: 
        return(err);
}
