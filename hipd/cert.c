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
 * @return 0 if signature was created without errors negative otherwise
 */
int hip_cert_spki_sign(struct hip_common * msg, HIP_HASHTABLE * db) {
        int err = 0, sig_len = 0, hex_len = 0, evpret = 0;
        struct hip_cert_spki_info * p_cert;
        struct hip_cert_spki_info * cert;
        char sha_digest[21];
        char * sig_sequence;
        unsigned char *sha_retval;
        char e_bin[HIP_RSA_PUBLIC_EXPONENT_E_LEN + 1];
        char n_bin[HIP_RSA_PUBLIC_MODULUS_N_LEN + 1];
        char * signature_b64;
        char * digest_b64;
        char * e_hex;
        char * n_b64;
        char key_n[HIP_RSA_PUBLIC_MODULUS_N_LEN];
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

        cert = malloc(sizeof(struct hip_cert_spki_info));
        HIP_IFEL((!cert), -1, "Malloc for cert failed\n");
        memset(cert, 0, sizeof(struct hip_cert_spki_info));

        /*XX FIXME just a guestimate calculate correctly */
        n_b64 = malloc(sizeof(n)+20);  
        HIP_IFEL((!n_b64), -1, "Malloc for n_b64 failed\n");
        memset(n_b64, 0, sizeof(n_b64));

        /* malloc space for new rsa */
        rsa = RSA_new();
        HIP_IFEL(!rsa, -1, "Failed to malloc RSA\n");
        
        memset(sha_digest, '\0', sizeof(sha_digest));
        memset(e_bin, 0, sizeof(e_bin));
        
        HIP_IFEL(!(p_cert = hip_get_param(msg,HIP_PARAM_CERT_SPKI_INFO)), 
                 -1, "No cert_info struct found\n");
        memcpy(cert, p_cert, sizeof(struct hip_cert_spki_info));
	_HIP_DEBUG("\n\n** CONTENTS of public key sequence **\n"
                   "%s\n\n",cert->public_key);
        _HIP_DEBUG("\n\n** CONTENTS of cert sequence to be signed **\n"
                   "%s\n\n", cert->cert);
	_HIP_DEBUG("\n\n** CONTENTS of public key sequence **\n"
                   "%s\n\n",cert->signature);

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
        
        /* clearing signature field just to be sure */
        memset(cert->signature, '\0', sizeof(cert->signature));
        /* 
           compiler warning for the next 2 lines
	   cert.c:103: warning: cast to pointer from integer of different size
	   cert.c:105: warning: cast to pointer from integer of different size
	*/
        digest_b64 = (char *)base64_encode((unsigned char *)sha_digest, 
                                         (unsigned int)sizeof(sha_digest));
        signature_b64 = (char *)base64_encode((unsigned char *)signature, 
                                         (unsigned int)sizeof(signature));

        /* create (signature (hash sha1 |digest|)|signature|) */
        sprintf(cert->signature, "(signature (hash sha1 |%s|)|%s|)", 
                digest_b64, signature_b64);
        
        _HIP_DEBUG("Sig sequence \n%s\n",cert->signature); 
               
        /* Create the public key sequence */
	/*
	  compiler warning for the next line
	  cert.c:117: warning: cast to pointer from integer of different size
	*/
        HIP_IFEL(!(BN_bn2bin(rsa->n, n_bin)), -1,
                 "Error in converting public exponent from BN to bin\n");
        n_b64 = (char *)base64_encode((unsigned char *)n_bin, 
				      HIP_RSA_PUBLIC_MODULUS_N_LEN);
        /* FOR DEBUGGING, just checking we can decode the base 64 */
        evpret = EVP_DecodeBlock(key_n, n_b64, strlen(n_b64));
        _HIP_HEXDUMP("Key N ", key_n, HIP_RSA_PUBLIC_MODULUS_N_LEN);

        HIP_IFEL(!(BN_bn2bin(rsa->e, e_bin)), -1,
                 "Error in converting public exponent from BN to bin\n");
	e_hex = BN_bn2hex(rsa->e);
        sprintf(cert->public_key, "(public_key (rsa-pkcs1-sha1 (e #%s#)(n |%s|)))", 
                e_hex, n_b64);

        _HIP_DEBUG("\n\nPublic-key sequence:\n%s\n\n",cert->public_key);
        _HIP_DEBUG("\n\nCert sequence:\n%s\n\n",cert->cert);
        _HIP_DEBUG("\n\nSignature sequence:\n%s\n\n",cert->signature);
 	
        /* Put the results into the msg back */

	_HIP_DEBUG("Len public-key (%d) + cert (%d) + signature (%d) = %d\n"
                  "Sizeof hip_cert_spki_info %d\n",
		  strlen(cert->public_key), strlen(cert->cert), strlen(cert->signature),
                  (strlen(cert->public_key)+strlen(cert->cert)+strlen(cert->signature)),
                  sizeof(struct hip_cert_spki_info));

        hip_msg_init(msg);

        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_CERT_SPKI_SIGN, 0), -1, 
                 "Failed to build user header\n");
        HIP_IFEL(hip_build_param_cert_spki_info(msg, cert), -1,
                 "Failed to build cert_info\n");                 

        _HIP_DUMP_MSG(msg);
        
 out_err:

	/* free malloced memory */
	if (digest_b64) free(digest_b64);
	if (signature_b64) free(signature_b64);
	if (n_b64) free(n_b64);
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

/**
 * Function that verifies the signature in the given SPKI cert sent by the "client"
 *
 * @param msg points to the msg gotten from "client"
 *
 * @return 0 if signature matches, -1 if error or signature did NOT match
 */
int hip_cert_spki_verify(struct hip_common * msg) {
	int err = 0, start = 0, stop = 0, evpret = 0;
        char buf[200];
        char sha_digest[21];
        char e_hex[7];
        char * signature_hash = NULL;
        char * signature_hash_b64 = NULL;
        char * signature_b64 = NULL;
        char * modulus_b64 = NULL;
        char * modulus = NULL;
        unsigned long e_code;
        unsigned char *sha_retval;
        struct hip_cert_spki_info * p_cert;
        struct hip_cert_spki_info * cert;
        RSA *rsa = NULL;
        char signature[HIP_RSA_SIGNATURE_LEN];
 
        /* rules for regular expressions */
        
        /* 
           rule to get the public exponent. 
           Look for the part that says # and after that some hex blob and #
        */
        char e_rule[] = "[#][0-9A-Fa-f]*[#]";

        /* 
           rule to get the public modulus 
           Look for the part that starts with '|' and after that anything
           that is in base 64 char set and then '|' again
        */
        char n_rule[] = "[|][A-Za-z0-9+/()#=-]*[|]";

        /* 
           rule to get the signature hash 
           Look for the similar than the n_rule
        */
        char h_rule[] = "[|][A-Za-z0-9+/()#=-]*[|]";

        /* 
           rule to get the signature 
           Look for part that starts ")|" and base 64 blob after it
           and stops to '|' char remember to add and substract 2 from 
           the indexes below
        */
        char s_rule[] = "[)][|][A-Za-z0-9+/()#=-]*[|]";

        cert = malloc(sizeof(struct hip_cert_spki_info));
        HIP_IFEL((!cert), -1, "Malloc for cert failed\n");
        memset(cert, 0, sizeof(struct hip_cert_spki_info));

        /* malloc space for new rsa */
        rsa = RSA_new();
        HIP_IFEL(!rsa, -1, "Failed to malloc RSA\n");
        memset(sha_digest, '\0', sizeof(sha_digest));        

        HIP_IFEL(!(p_cert = hip_get_param(msg,HIP_PARAM_CERT_SPKI_INFO)), 
                 -1, "No cert_info struct found\n");
        memcpy(cert, p_cert, sizeof(struct hip_cert_spki_info));
	_HIP_DEBUG("\n\n** CONTENTS of public key sequence **\n"
                   "%s\n\n",cert->public_key); 

        /* build sha1 digest that will be signed */
        HIP_IFEL(!(sha_retval = SHA1(cert->cert, 
                                     strlen(cert->cert), sha_digest)),
                 -1, "SHA1 error when creating digest.\n");        
        _HIP_HEXDUMP("SHA1 digest of cert sequence ", sha_digest, 20);          
        
        /* extract the public-key from cert to rsa */

        /* public exponent first */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(e_rule, cert->public_key, &start, &stop), -1,
                 "Failed to run hip_cert_regex (exponent)\n");
        _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
        snprintf(e_hex, (stop-start-1), "%s", &cert->public_key[start + 1]);       
        _HIP_DEBUG("E_HEX %s\n",e_hex);
        
        /* public modulus second */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(n_rule, cert->public_key, &start, &stop), -1,
                 "Failed to run hip_cert_regex (modulus)\n");
        _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
        modulus_b64 = malloc(stop-start+1);
        HIP_IFEL((!modulus_b64), -1, "Malloc for modulus_b64 failed\n");
        memset(modulus_b64, 0, (stop-start+1));
        modulus = malloc(stop-start+1);
        HIP_IFEL((!modulus), -1, "Malloc for modulus failed\n");
        memset(modulus, 0, (stop-start+1));
        snprintf(modulus_b64, (stop-start-1), "%s", &cert->public_key[start + 1]);       
        _HIP_DEBUG("modulus_b64 %s\n",modulus_b64);

        /* put the stuff into the RSA struct */
        BN_hex2bn(&rsa->e, e_hex); 
        evpret = EVP_DecodeBlock(modulus, modulus_b64, 
                                        strlen(modulus_b64));
        rsa->n = BN_bin2bn(modulus, HIP_RSA_PUBLIC_MODULUS_N_LEN, 0); 
        _HIP_DEBUG("In verification RSA e=%s\n", BN_bn2hex(rsa->e));
        _HIP_DEBUG("In verification RSA n=%s\n", BN_bn2hex(rsa->n));

        /* Get the signature hash and compare it to the sha_digest we just made */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(h_rule, cert->signature, &start, &stop), -1,
                 "Failed to run hip_cert_regex (signature hash)\n");
        _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
        signature_hash_b64 = malloc(stop-start+1);
        HIP_IFEL((!signature_hash_b64), -1, "Failed to malloc signature_hash\n");
        memset(signature_hash_b64, '\0', (stop-start+1));        
        signature_hash = malloc(stop-start+1);
        HIP_IFEL((!signature_hash), -1, "Failed to malloc signature_hash\n");
        snprintf(signature_hash_b64, (stop-start-1), "%s", 
                 &cert->signature[start + 1]);       
        _HIP_DEBUG("SIG HASH B64 %s\n", signature_hash_b64);
        evpret = EVP_DecodeBlock(signature_hash, signature_hash_b64, 
                                 strlen(signature_hash_b64));
        HIP_IFEL(memcmp(sha_digest, signature_hash, 20), -1,
                 "Signature hash did not match of the one made from the"
                 "cert sequence in the certificate\n");

        /* memset signature and put it into its place */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(s_rule, cert->signature, &start, &stop), -1,
                 "Failed to run hip_cert_regex (signature)\n");
        _HIP_DEBUG("REGEX results from %d to %d\n", start, stop);
        signature_b64 = malloc(stop-start+1);
        HIP_IFEL((!signature_b64), -1, "Failed to malloc signature_b64\n");
        memset(signature_b64, '\0', HIP_RSA_SIGNATURE_LEN);        
        snprintf(signature_b64, (stop-start-2),"%s", &cert->signature[start + 2]);       
        _HIP_DEBUG("SIG_B64 %s\n", signature_b64);
        evpret = EVP_DecodeBlock(signature, signature_b64, 
                                 strlen(signature_b64));
        _HIP_HEXDUMP("SIG\n", signature, HIP_RSA_SIGNATURE_LEN); 
        /* do the verification */
        err = RSA_verify(NID_sha1, sha_digest, SHA_DIGEST_LENGTH,
                         signature, RSA_size(rsa), rsa);
   
        e_code = ERR_get_error();
        ERR_load_crypto_strings();
        ERR_error_string(e_code ,buf);

        _HIP_DEBUG("***********RSA ERROR*************\n");
        _HIP_DEBUG("RSA_size(rsa) = %d\n",RSA_size(rsa));
        _HIP_DEBUG("Signature length :%d\n",strlen(signature));
        _HIP_DEBUG("Error string :%s\n",buf);
        _HIP_DEBUG("LIB error :%s\n",ERR_lib_error_string(e_code));
        _HIP_DEBUG("func error :%s\n",ERR_func_error_string(e_code));
        _HIP_DEBUG("Reason error :%s\n",ERR_reason_error_string(e_code));
        _HIP_DEBUG("***********RSA ERROR*************\n");

        /* RSA_verify returns 1 if success. */
        cert->success = err == 1 ? 0 : -1;
        HIP_IFEL((err = err == 1 ? 0 : -1), -1, "RSA_verify error\n");

        hip_msg_init(msg);

        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_CERT_SPKI_SIGN, 0), -1, 
                 "Failed to build user header\n");
        HIP_IFEL(hip_build_param_cert_spki_info(msg, cert), -1,
                 "Failed to build cert_info\n");                 

        _HIP_DUMP_MSG(msg);
        
out_err:
        if (signature_hash_b64) free(signature_hash_b64);
        if (signature_hash) free(signature_hash);
        if (modulus_b64) free(modulus_b64);
        if (modulus) free(modulus);
        if (cert) free(cert);
        if (rsa) RSA_free(rsa);
	return (err);
}
