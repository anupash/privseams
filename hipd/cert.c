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

/****************************************************************************
 *
 * SPKI
 *
 ***************************************************************************/

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
        
        HIP_IFEL((err = hip_cert_rsa_construct_keys(hip_local_hostid_db,
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

/****************************************************************************
 *
 * X.509v3
 *
 ***************************************************************************/

/**
 * Function that creates the certificate and sends it to back to the client.
 *
 * @param msg is a pointer to the requesting msg
 * @param db is the db to query for the hostid entry
 *
 * @return 0 on success negative otherwise. 
 *
 * @note the request part is just for informational purposes, in practice it
 * is not needed
 */ 
int hip_cert_x509v3_handle_request_to_sign(struct hip_common * msg,  HIP_HASHTABLE * db) {
	int err = 0, i = 0, nid = 0, ret = 0, secs = 0;
	CONF * conf;
	CONF_VALUE *item;
	STACK_OF(CONF_VALUE) * sec = NULL;
	STACK_OF(CONF_VALUE) * sec_general = NULL;
	STACK_OF(CONF_VALUE) * sec_name = NULL;
	STACK_OF(CONF_VALUE) * sec_ext = NULL;

        X509_REQ * req = NULL;
        X509_NAME * issuer = NULL;
        X509_NAME * subj = NULL;
        X509_EXTENSION * ext = NULL;
        STACK_OF(X509_EXTENSION) * extlist = NULL;
        X509_NAME_ENTRY *ent;
        EVP_PKEY *pkey; 
        /** XX TODO THIS should come from a configuration file 
            monotonically increasing counter **/
        long serial = 0; 
        const EVP_MD * digest;
        X509 *cert;
        X509V3_CTX ctx;
        struct hip_cert_x509_req * subject;
        char subject_hit[41];
        char issuer_hit[41];
        struct in6_addr * issuer_hit_n;
        RSA * rsa = NULL;
        char cert_str_pem[1024];
        BIO *out;
        int read_bytes = 0;
        unsigned char * der_cert = NULL;
        int der_cert_len = 0;

        HIP_IFEL(!(subject = malloc(sizeof(struct in6_addr))), -1, 
                 "Malloc for subject failed\n");   
        HIP_IFEL(!(issuer_hit_n = malloc(sizeof(struct in6_addr))), -1, 
                 "Malloc for subject failed\n"); 
        HIP_IFEL(!(pkey = malloc(sizeof(EVP_PKEY))), -1, 
                 "Malloc for pkey failed\n");  
        HIP_IFEL(!memset(subject, 0, sizeof(subject)), -1,
                 "Failed to memset memory for subject\n");
        HIP_IFEL(!memset(issuer_hit_n, 0, sizeof(issuer_hit_n)), -1,
                 "Failed to memset memory for issuer\n");               
        HIP_IFEL(!memset(subject_hit, '\0', sizeof(subject_hit)), -1,
                 "Failed to memset memory for subject\n");                
        HIP_IFEL(!memset(issuer_hit_n, 0, sizeof(struct in6_addr)), -1,
                 "Failed to memser memory for issuer HIT\n");
        HIP_IFEL(!memset(cert_str_pem, 0, sizeof(cert_str_pem)), -1,
                 "Failed to memser memory for cert_str\n");

        /* malloc space for new rsa */
        rsa = RSA_new();
        HIP_IFEL(!rsa, -1, "Failed to malloc RSA\n");
       
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        
	HIP_DEBUG("Reading configuration file (%s)\n", HIP_CERT_CONF_PATH);
	conf = hip_cert_open_conf();
	sec_general = hip_cert_read_conf_section("hip_x509v3", conf);
        sec_name = hip_cert_read_conf_section("hip_x509v3_name", conf);
        sec_ext = hip_cert_read_conf_section("hip_x509v3_extensions", conf);
  	hip_cert_free_conf(conf);

        /* Get the general information */
        HIP_IFEL((sec_general == NULL), -1, 
                 "Failed to load general certificate information\n");
        HIP_IFEL(!(req = X509_REQ_new()), -1, "Failed to create X509_REQ object");

        HIP_IFEL((sec_name = NULL), -1,
                 "Failed to load issuer naming information for the certificate\n");
 
        /* Issuer naming */
        if (sec_general != NULL) {
                /* Loop through the conf stack for general information */
                extlist = sk_X509_EXTENSION_new_null();
                for (i = 0; i < sk_CONF_VALUE_num(sec_general); i++) {
                        item = sk_CONF_VALUE_value(sec_general, i);
                        _HIP_DEBUG("Sec: %s, Key; %s, Val %s\n", 
                                   item->section, item->name, item->value);
                        if(!strcmp(item->name, "issuerhit")) {
                                strcpy(issuer_hit, item->value);
                                ret = inet_pton(AF_INET6, item->value, issuer_hit_n);
                                HIP_IFEL((ret < 0 && errno == EAFNOSUPPORT), -1, 
                                         "Failed to convert issuer HIT to hip_hit_t\n");
                                HIP_DEBUG_HIT("Issuer HIT", issuer_hit_n);
                                /* on conversion more to get rid of padding 0s*/
                                memset(issuer_hit, 0, sizeof(issuer_hit));
                                HIP_IFEL((!inet_ntop(AF_INET6, issuer_hit_n, 
                                                     issuer_hit, sizeof(issuer_hit))),
                                         -1, "Failed to convert subject hit to "
                                         "presentation format\n");
                        }
                        if(!strcmp(item->name, "days")) 
                           secs = HIP_CERT_DAY * atoi(item->value);
                }
        } 
        HIP_IFEL(!(issuer = X509_NAME_new()), -1, "Failed to set create subject name");
        nid = OBJ_txt2nid("commonName");
        HIP_IFEL((nid == NID_undef), -1, "NID text not defined\n");
        HIP_IFEL(!(ent = X509_NAME_ENTRY_create_by_NID (NULL, nid, MBSTRING_ASC,
                                                        issuer_hit, -1)), -1,
                 "Failed to create name entry for issuer\n");
        HIP_IFEL((X509_NAME_add_entry(issuer, ent, -1, 0) != 1), -1,
                 "Failed to add entry to issuer name\n");
        
        /* Subject naming */
        /* Get the subject hit from msg */
        HIP_IFEL(!(subject = hip_get_param(msg, HIP_PARAM_CERT_X509_REQ)), 
                 -1, "No cert_info struct found\n");
        _HIP_DEBUG_HIT("Subject", &subject->addr);
        HIP_IFEL((!inet_ntop(AF_INET6, &subject->addr, subject_hit, sizeof(subject_hit))),
                 -1, "Failed to convert subject hit to presentation format\n");
        _HIP_DEBUG("Subject HIT is %s (id for commonName = %d)\n", subject_hit, nid);
        HIP_IFEL(!(subj = X509_NAME_new()), -1, "Failed to set create subject name");
        nid = OBJ_txt2nid("commonName");
        HIP_IFEL((nid == NID_undef), -1, "NID text not defined\n");
        HIP_IFEL(!(ent = X509_NAME_ENTRY_create_by_NID (NULL, nid, MBSTRING_ASC,
                                                        subject_hit, -1)), -1,
                 "Failed to create name entry for subject\n");
        HIP_IFEL((X509_NAME_add_entry(subj, ent, -1, 0) != 1), -1,
                 "Failed to add entry to subject name\n");
        HIP_IFEL((X509_REQ_set_subject_name (req, subj) != 1), -1,
                 "Failed to add subject name to certificate request\n");
          
        if (sec_ext != NULL) {
                /* Loop through the conf stack and add extensions to ext stack */
                extlist = sk_X509_EXTENSION_new_null();
                for (i = 0; i < sk_CONF_VALUE_num(sec_ext); i++) {
                        item = sk_CONF_VALUE_value(sec_ext, i);
                        _HIP_DEBUG("Sec: %s, Key; %s, Val %s\n", 
                                   item->section, item->name, item->value);
                        HIP_IFEL(!(ext = X509V3_EXT_conf(NULL, &ctx, 
                                                       item->name, item->value )), -1, 
                                 "Failed to create extension\n");
                        sk_X509_EXTENSION_push(extlist, ext);
                }
                HIP_IFEL((!X509_REQ_add_extensions(req, extlist)), -1,
                          "Failed to add extensions to the request\n");
        }
#if 0
        /* DEBUG PART START for the certificate request */
        HIP_DEBUG("x.509v3 certificate request in readable format\n\n");
        HIP_IFEL(!X509_REQ_print_fp(stdout, req), -1,
                 "Failed to print x.509v3 request in human readable format\n");
        HIP_DEBUG("x.509v3 certificate request in PEM format\n\n");
        HIP_IFEL((PEM_write_X509_REQ(stdout, req) != 1), -1 ,
                 "Failed to write the x509 request in PEM to stdout\n");
        /* DEBUG PART END for the certificate request*/
#endif     
   
        /** NOW WE ARE READY TO CREATE A CERTIFICATE FROM THE REQUEST **/        
        HIP_DEBUG("Starting the certificate creation\n");

        HIP_IFEL(!(cert = X509_new ()), -1,
                 "Failed to create X509 object\n");        

        HIP_IFEL((X509_set_version (cert, 2L) != 1), -1,
                  "Failed to set certificate version\n");
        /** XX TODO serial should be stored after increasing it **/
        ASN1_INTEGER_set (X509_get_serialNumber(cert), serial++);
        
        HIP_IFEL((X509_set_subject_name (cert, subj) != 1), -1,
                "Failed to set subject name of certificate\n");
        HIP_IFEL((X509_set_issuer_name (cert, issuer) != 1), -1,
                 "Failed to set issuer name of certificate\n");
        HIP_IFEL(!(X509_gmtime_adj (X509_get_notBefore (cert), 0)), -1,
                 "Error setting beginning time of the certificate");
        HIP_IFEL(!(X509_gmtime_adj (X509_get_notAfter (cert), secs)), -1, 
                 "Error setting ending time of the certificate");

        HIP_DEBUG("Getting the key\n");
        HIP_IFEL((err = hip_cert_rsa_construct_keys(hip_local_hostid_db,
                                            issuer_hit_n, rsa)), -1, 
                "Error constructing the keys from hidb entry\n");

        HIP_IFEL(!EVP_PKEY_assign_RSA(pkey, rsa), -1, 
                 "Failed to convert RSA to EVP_PKEY\n");
        HIP_IFEL((X509_set_pubkey (cert, pkey) != 1), -1, 
                 "Failed to set public key of the certificate\n");
        
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

        if (sec_ext != NULL) {
                for (i = 0; i < sk_CONF_VALUE_num(sec_ext); i++) {
                        item = sk_CONF_VALUE_value(sec_ext, i);
                        _HIP_DEBUG("Sec: %s, Key; %s, Val %s\n", 
                                   item->section, item->name, item->value);
                        HIP_IFEL(!(ext = X509V3_EXT_conf(NULL, &ctx, 
                                                       item->name, item->value )), -1, 
                                 "Failed to create extension\n");
                        HIP_IFEL((!X509_add_ext(cert, ext, -1)), -1,
                                 "Failed to add extensions to the cert\n");
                        if (!strcmp(item->name, "basicConstraints") &&
                            !strcmp(item->value, "CA:true")) {
                                /* We are writing a CA cert and in CA self-signed
                                   certificate you have to have subject key identifier
                                   present, when adding subjectKeyIdentifier give string
                                   hash to the */
                                HIP_IFEL(!(ext = X509V3_EXT_conf(NULL, &ctx, 
                                                                 "subjectKeyIdentifier", 
                                                                 "hash")), -1, 
                                         "Failed to create extension\n");
                                HIP_IFEL((!X509_add_ext(cert, ext, -1)), -1,
                                         "Failed to add extensions to the cert\n");
                        }
                }
        }

        digest = EVP_sha1();
        HIP_IFEL(!(X509_sign (cert, pkey, digest)), -1,
                 "Failed to sign x509v3 certificate\n"); 
#if 0
        /* DEBUG PART START for the certificate */
        HIP_DEBUG("x.509v3 certificate in readable format\n\n");
        HIP_IFEL(!X509_print_fp(stdout, cert), -1,
                 "Failed to print x.509v3 in human readable format\n");
        HIP_DEBUG("x.509v3 certificate in PEM format\n\n");
        HIP_IFEL((PEM_write_X509(stdout, cert) != 1), -1, 
                 "Failed to write the x509 in PEM to stdout\n");
        /* DEBUG PART END for the certificate */
#endif

        /** XX TODO Send the cert back to the client **/
        hip_msg_init(msg);

#if 0
        /* removed in favor of DER encoding on the wire 
         if enabled  again uncomment BIO stuff also from out_err */
        /* Write PEM to char array cert_str_pem */                
        out = BIO_new(BIO_s_mem());
        HIP_IFEL((PEM_write_bio_X509(out, cert) != 1), -1,
                 "Failed to write the x509 in PEM to stdout\n");
        read_bytes = BIO_read(out, cert_str_pem, sizeof(cert_str_pem));
        _HIP_DEBUG("Cert_str_pem:\n%s\nRead bytes %d\n", cert_str_pem, read_bytes);
#endif

        /** DER **/
        HIP_IFEL(((der_cert_len = i2d_X509(cert, &der_cert)) < 0), -1, 
                 "Failed to convert cert to DER\n");
        HIP_HEXDUMP("DER:\n", der_cert, der_cert_len);
        HIP_DEBUG("DER length %d\n", der_cert_len);
        /** end DER **/

        HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_CERT_X509V3_SIGN, 0), -1, 
                 "Failed to build user header\n");
        HIP_IFEL(hip_build_param_cert_x509_resp(msg, der_cert, der_cert_len), -1, 
                 "Failed to create x509 response parameter\n");        
        HIP_DUMP_MSG(msg);

out_err:
        if(req != NULL) X509_REQ_free(req);
        if(extlist != NULL) sk_X509_EXTENSION_pop_free (extlist, X509_EXTENSION_free);
        //BIO_flush(out);
        //BIO_free_all(out);
	return err;
} 

int verify_callback (int ok, X509_STORE_CTX * stor) {
  if (!ok) HIP_DEBUG("Error: %s\n", X509_verify_cert_error_string (stor->error));
  return ok;
}

/**
 * Function verifies the given certificate and sends it to back to the client.
 *
 * @param msg is a pointer to the requesting msg
 *
 * @return 0 on success negative otherwise. 
 */ 
int hip_cert_x509v3_handle_request_to_verify(struct hip_common * msg) {
        int err = 0;
        struct hip_cert_x509_resp verify;
        struct hip_cert_x509_resp * p;
	X509 *cert;
	X509_STORE *store;
	X509_STORE_CTX *verify_ctx;
        unsigned char *der_cert = NULL;

	OpenSSL_add_all_algorithms ();
	ERR_load_crypto_strings ();

        HIP_DUMP_MSG(msg);
        memset(&verify, 0, sizeof(struct hip_cert_x509_resp));
        HIP_IFEL(!(p = hip_get_param(msg, HIP_PARAM_CERT_X509_REQ)), -1,
                   "Failed to get cert info from the msg\n");
        memcpy(&verify, p, sizeof(struct hip_cert_x509_resp));
        der_cert = p;
        /* XX TODO check why the end contains extra fluff */

        HIP_HEXDUMP("DER:\n", p->der, p->der_len);
        HIP_DEBUG("DER length %d\n", p->der_len);
        HIP_IFEL(((cert = d2i_X509(NULL, &der_cert ,p->der_len)) == NULL), -1,
                 "Failed to convert cert from DER to internal format\n");
        

	HIP_IFEL(!X509_print_fp(stdout, cert), -1,
                 "Failed to print x.509v3 in human readable format\n"); 


	HIP_IFEL(!(store = X509_STORE_new ()), -1,
		"Failed to create X509_STORE_CTX object\n");
	X509_STORE_set_verify_cb_func(store, verify_callback);

	/* self signed so te cert itself should verify itself */

	HIP_IFEL(!X509_STORE_add_cert(store, cert), -1,
		 "Failed to add cert to ctx\n");
	
	HIP_IFEL((!(verify_ctx = X509_STORE_CTX_new ())), -1,
		"Failed to create X509_STORE_CTX object\n");

	HIP_IFEL((X509_STORE_CTX_init(verify_ctx, store, cert, NULL) != 1), -1,
		 "Failed to initialize verification context\n");

	if (X509_verify_cert(verify_ctx) != 1) {
		HIP_DEBUG("Error verifying the certificate\n");
		err = -1; 
	} else {
		HIP_DEBUG("Certificate verified correctly!\n");
		err = 0;
	}
	
	hip_msg_init(msg);
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_CERT_X509V3_SIGN, err), -1, 
                 "Failed to build user header\n");
        HIP_IFEL(hip_build_param_cert_x509_resp(msg, &der_cert, p->der_len), -1, 
                 "Failed to create x509 response parameter\n");        

        _HIP_DUMP_MSG(msg);	
 out_err:
	X509_STORE_CTX_cleanup(verify_ctx);
	if (store) X509_STORE_free(store);
	if (cert) X509_free(cert);
        return err;
}

/****************************************************************************
 *
 * Utilitary functions
 *
 ***************************************************************************/

/**
 * Function that extracts the key from hidb entry and constructs a RSA struct from it
 *
 * @param db is the db to query for the hostid entry
 * @param hit is a pointer to a host identity tag to be searched
 * @param rsa is the resulting struct that contains the key material
 *
 * @return 0 if signature matches, -1 if error or signature did NOT match
 */
int hip_cert_rsa_construct_keys(HIP_HASHTABLE * db, hip_hit_t * hit, RSA * rsa) {
        int err = 0, s = 1;
        struct hip_host_id_entry * hostid_entry = NULL;
        struct hip_host_id * hostid = NULL;
        struct hip_lhi * lhi = NULL;
        u8 *p;
        /* 
           Get the corresponding host id for the HIT.
           It will contain both the public and the private key
        */
	_HIP_DEBUG_HIT("HIT we are looking for ", hit);
        hostid_entry = hip_get_hostid_entry_by_lhi_and_algo(db, 
                                                            hit,
                                                            HIP_HI_RSA, -1);  
	if (hostid_entry == NULL) {
		err = -1;
		goto out_err;
	}
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
