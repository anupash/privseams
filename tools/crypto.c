/*
 * Crypto functions for HIP daemon.
 *
 * Authors:
 * - Mika Kousa <mkousa@cc.hut.fi>
 * - Miika Komu <miika@iki.fi>
 *
 * Licence: GNU/GPL
 *
 * TODO:
 * - Intergrate ERR_print_errors_fp somehow into HIP_INFO().
 * - No printfs! Daemon has no stderr.
 * - Return values should be from <errno.h>.
 * - Clean up the code!
 * - Use goto err_out, not return 1.
 * - Check that DH key is created exactly as stated in Jokela draft
 *   RFC2412?
 * - Create a function for calculating HIT from DER encoded DSA pubkey
 * - can alloc_and_extract_bin_XX_pubkey() be merged into one function
 * - more consistency in return values: all functions should always return
 *   _negative_, _symbolic_ values (with the exception of zero)
 *
 * BUGS:
 * - "Bad signature r or s size" occurs randomly. This should not happen.
 */

#include "crypto.h"


/**
 * create_dsa_key - generate DSA parameters and a new key pair
 * @bits: length of the prime
 *
 * The caller is responsible for freeing the allocated DSA key.
 *
 * Returns: the created DSA structure, otherwise NULL.
 *
 */
DSA *create_dsa_key(int bits) {
  DSA *dsa = NULL;
  int ok;

  if (bits < 1 || bits > HIP_MAX_DSA_KEY_LEN) {
    HIP_ERROR("create_dsa_key failed (illegal bits value %d)\n", bits);
    goto err_out;
  }

  dsa = DSA_generate_parameters(bits, NULL, 0, NULL, NULL, NULL, NULL);
  if (!dsa) {
    HIP_ERROR("create_dsa_key failed (DSA_generate_parameters): %s\n",
	     ERR_error_string(ERR_get_error(), NULL));
    goto err_out;
  }

  /* generate private and public keys */
  ok = DSA_generate_key(dsa);
  if (!ok) {
    HIP_ERROR("create_dsa_key failed (DSA_generate_key): %s\n",
	     ERR_error_string(ERR_get_error(), NULL));
    goto err_out;
  }

  return dsa;

 err_out:

  if (dsa)
    DSA_free(dsa);

  return NULL;
}

/**
 * dsa_to_hit - create HIT from DSA parameters
 * @dsa:            contains the DSA parameters from where the HIT is
 *                  calculated
 * @type:           the type of the HIT to be created
 * @hit:            where the resulting HIT is stored
 *
 * Currently only HIP_HIT_TYPE_HASH126 is supported for parameter
 * @type.
 *
 * Returns: 0 if HIT was created successfully, else negative.
 */
int dsa_to_hit(char *dsa, int type, struct in6_addr *hit) {
  int err = 0, pubkey_len = 405; // XX FIX
  //unsigned char *pubkey = NULL;
  char addrstr[INET6_ADDRSTRLEN];
  unsigned char *sha, sha_hash[SHA_DIGEST_LENGTH];
  int i;
  BIGNUM *bn, *tmp = NULL;

  /// XX FIXME
  /* if hipd was given a HIT to use from the command line it is used,
     else HIT is calculated from the HI. */
  //if (!IN6_IS_ADDR_UNSPECIFIED(&lhi->hit)) {
  //  HIP_INFO("Use given HIT\n");
  //  goto out_err

  HIP_INFO("Create HIT from HI\n");
  
  if (type == HIP_HIT_TYPE_HASH126) {
    HIP_DEBUG("HIT type is HASH126\n");
  } else if (type == HIP_HIT_TYPE_HAA_HASH) {
    HIP_ERROR("HIT type HAA hash not implemented\n");
    err = -ENOSYS;
    goto out_err;
  } else {
    HIP_ERROR("Unknown HIT type (%d)\n", type);
    err = -EINVAL;
    goto out_err;
  }

  /* If Bit 0 is zero and Bit 1 is one, then the rest of HIT is a 126
     bits of a Hash of the key.  For example, if the Identity is DSA, these
     bits MUST be the least significant 126 bits of the SHA-1 [FIPS-180-1]
     hash of the DSA public key Host Identity.  */
  sha = SHA1(dsa, pubkey_len, (unsigned char *) &sha_hash);
  if (!sha) {
    HIP_ERROR("sha hash failed\n");
    err = -EINVAL;
    goto out_err;
  }
  
  _HIP_DEBUG("sha_p=%p sha_hash_p=%p\n", sha, &sha_hash);
  HIP_HEXDUMP("hit hash:     ", &sha_hash, SHA_DIGEST_LENGTH);
  HIP_HEXDUMP("hit trunc hash:       ",
	      (unsigned char *)&sha_hash+(SHA_DIGEST_LENGTH-128/8), 128/8);
  _HIP_DEBUG("pos=%d\n", SHA_DIGEST_LENGTH - 128/8);
  
  bn = BN_bin2bn((const unsigned char *) &sha_hash + (SHA_DIGEST_LENGTH-128/8),
		 128/8, NULL);
  if (!bn) {
    HIP_ERROR("!bn\n");
    err = -EINVAL;
    goto out_err;
  }
  
  HIP_DEBUG("hit hash 128, len=%d bn=%s\n", BN_num_bytes(bn), BN_bn2hex(bn));
  
  if (!BN_clear_bit(bn, 127) || !BN_set_bit(bn, 126)) {
    HIP_ERROR("bn set/clear bit failed\n");
    err = -EINVAL;
    goto out_err;
  }
  HIP_DEBUG("hit hash 126, len=%d bn=%s\n", BN_num_bytes(bn), BN_bn2hex(bn));
  
  tmp = BN_new();
  /* store result to parameter hit */
  for (i = 0; i < 4; i++) {
    unsigned long l;
    
    BN_copy(tmp, bn); /* todo: if null ..*/
    _HIP_DEBUG("i=%d tmp=%s", i, BN_bn2hex(tmp));
    
    BN_rshift(tmp, tmp, (3-i)*32);
    _HIP_DEBUG("->%s", BN_bn2hex(tmp));
    
    BN_mask_bits(tmp, 32);
    _HIP_DEBUG("->mask32=%s\n", BN_bn2hex(tmp));
    
    l = BN_get_word(tmp);
    if (l == 0xffffffffL)
      HIP_ERROR("l == 0xffffffffL\n"); /* can this happen normally ? */
    
    _HIP_DEBUG("SET l=%lx ", l);
    l = ntohl(l);
    _HIP_DEBUG("ntohl(l)=%lx\n", l);
    hit->s6_addr32[i] = l;
    _HIP_DEBUG("\n");
  }

  inet_ntop(AF_INET6, hit, addrstr, sizeof(addrstr));
  HIP_DEBUG("*** HIT %s ***\n", addrstr);
  
 out_err:

   if (tmp)
    BN_free(tmp);

  return err;
}


/**
 * dsa_to_dns_key_rr - create DNS KEY RR record from host DSA key
 * @dsa:        the DSA structure from where the KEY RR record is to be created
 * @dsa_key_rr: where the resultin KEY RR is stored
 *
 * Caller must free @dsa_key_rr when it is not used anymore.
 *
 * Returns: On successful operation, the length of the KEY RR buffer is
 * returned (greater than zero) and pointer to the buffer containing
 * DNS KEY RR is stored at @dsa_key_rr. On error function returns negative
 * and sets @dsa_key_rr to NULL.
 */
int dsa_to_dns_key_rr(DSA *dsa, unsigned char **dsa_key_rr) {
  int err = 0;
  int dsa_key_rr_len = -1;
  signed char t; /* in units of 8 bytes */
  unsigned char *p;
  unsigned char *bn_buf = NULL;
  int bn_buf_len;
  int bn2bin_len;

  /* RFC2535 section 3.1 */
  //  char dsa_key_rr_hdr[] = {0x02, 0x00, 0xff, 0x03}; /* fix */

  HIP_ASSERT(dsa != NULL); /* should not happen */

  *dsa_key_rr = NULL;

  _HIP_DEBUG("numbytes dsa_key_rr_hdr=%d\n", sizeof(dsa_key_rr_hdr));
  _HIP_DEBUG("numbytes p=%d\n", BN_num_bytes(dsa->p));
  _HIP_DEBUG("numbytes q=%d\n", BN_num_bytes(dsa->q));
  _HIP_DEBUG("numbytes g=%d\n", BN_num_bytes(dsa->g));
  _HIP_DEBUG("numbytes pubkey=%d\n", BN_num_bytes(dsa->pub_key));
  _HIP_DEBUG("numbytes privkey=%d\n", BN_num_bytes(dsa_priv_key));

  _HIP_DEBUG("p=%s\n", BN_bn2hex(dsa->p));
  _HIP_DEBUG("q=%s\n", BN_bn2hex(dsa->q));
  _HIP_DEBUG("g=%s\n", BN_bn2hex(dsa->g));
  _HIP_DEBUG("pubkey=%s\n", BN_bn2hex(dsa->pub_key));
  _HIP_DEBUG("privkey=%s\n", BN_bn2hex(dsa->priv_key));

  /* ***** is use of BN_num_bytes ok ? ***** */
  t = (BN_num_bytes(dsa->p)-64)/8;
  if (t < 0 || t > 8) {
    HIP_ERROR("t=%d < 0 || t > 8\n", t);
    err = -EINVAL;
    goto out_err;
  }
  _HIP_DEBUG("t=%d\n", t);

  /* RFC 2536 section 2 */
  /*
           Field     Size
           -----     ----
            T         1  octet
            Q        20  octets
            P        64 + T*8  octets
            G        64 + T*8  octets
            Y        64 + T*8  octets
	    X        20  octets (krisu edition) :)
	
  */
  dsa_key_rr_len = 1+20+20+3*(64+t*8);
  HIP_INFO("dsa key rr len = %d\n", dsa_key_rr_len);
  *dsa_key_rr = malloc(dsa_key_rr_len);
  if (!*dsa_key_rr) {
    HIP_ERROR("malloc\n");
    err = -ENOMEM;
    goto out_err;
  }

  /* side-effect: does also padding for Q, P, G, and Y */
  memset(*dsa_key_rr, 0, dsa_key_rr_len);

  /* copy header */
  p = *dsa_key_rr;
  //  memcpy(p, &dsa_key_rr_hdr, sizeof(dsa_key_rr_hdr));
  //  p += sizeof(dsa_key_rr_hdr);
  //HIP_HEXDUMP("DSA KEY RR after header:", *dsa_key_rr, p-*dsa_key_rr);

  /* set T */
  memset(p, t, 1);
  p += 1;
  HIP_HEXDUMP("DSA KEY RR after T:", *dsa_key_rr, p-*dsa_key_rr);

  /* minimum number of bytes needed to store P, G or Y */
  bn_buf_len = BN_num_bytes(dsa->p);
  if (bn_buf_len <= 0) {
    HIP_ERROR("bn_buf_len p <= 0\n");
    err = -EINVAL;
    goto out_err_free_rr;
  }

  bn_buf = malloc(bn_buf_len);
  if (!bn_buf) {
    HIP_ERROR("malloc\n");
    err = -ENOMEM;
    goto out_err_free_rr;
  }
  
  /* Q */
  bn2bin_len = BN_bn2bin(dsa->q, bn_buf);
  _HIP_DEBUG("q len=%d\n", bn2bin_len);
  if (!bn2bin_len) {
    HIP_ERROR("bn2bin\n");
    err = -ENOMEM;
    goto out_err;
  }
  HIP_ASSERT(bn2bin_len == 20);
  memcpy(p, bn_buf, bn2bin_len);
  p += bn2bin_len;
  HIP_HEXDUMP("DSA KEY RR after Q:", *dsa_key_rr, p-*dsa_key_rr);

  /* add given dsa_param to the *dsa_key_rr */
#define DSA_ADD_PGY_PARAM_TO_RR(dsa_param)   \
  bn2bin_len = BN_bn2bin(dsa_param, bn_buf); \
  _HIP_DEBUG("len=%d\n", bn2bin_len);         \
  if (!bn2bin_len) {                         \
    HIP_ERROR("bn2bin\n");                   \
    err = -ENOMEM;                           \
    goto out_err_free_rr;                    \
  }                                          \
  HIP_ASSERT(bn_buf_len-bn2bin_len >= 0);    \
  p += bn_buf_len-bn2bin_len; /* skip pad */ \
  memcpy(p, bn_buf, bn2bin_len);             \
  p += bn2bin_len;

  /* padding + P */
  DSA_ADD_PGY_PARAM_TO_RR(dsa->p);
  HIP_HEXDUMP("DSA KEY RR after P:", *dsa_key_rr, p-*dsa_key_rr);
  /* padding + G */
  DSA_ADD_PGY_PARAM_TO_RR(dsa->g);
  HIP_HEXDUMP("DSA KEY RR after G:", *dsa_key_rr, p-*dsa_key_rr);
  /* padding + Y */
  DSA_ADD_PGY_PARAM_TO_RR(dsa->pub_key);
  HIP_HEXDUMP("DSA KEY RR after Y:", *dsa_key_rr, p-*dsa_key_rr);
  /* padding + X */

  bn2bin_len = BN_bn2bin(dsa->priv_key, bn_buf);
  memcpy(p,bn_buf,bn2bin_len);

  p += bn2bin_len;
  HIP_HEXDUMP("DSA KEY RR after X:", *dsa_key_rr, p-*dsa_key_rr);

  /*  _HIP_DEBUG("q len=%d\n", bn2bin_len);
  if (!bn2bin_len) {
    HIP_ERROR("bn2bin\n");
    err = -ENOMEM;
    goto out_err;
  }
  HIP_ASSERT(bn2bin_len == 20);
  memcpy(p, bn_buf, bn2bin_len);
  p += bn2bin_len;
  HIP_HEXDUMP("DSA KEY RR after Q:", *dsa_key_rr, p-*dsa_key_rr);
  */

  goto out_err;

#undef DSA_ADD_PGY_PARAM_TO_RR

 out_err_free_rr:
  if (*dsa_key_rr)
    free(*dsa_key_rr);
  if (bn_buf )
    free(bn_buf);

  if (dsa->priv_key != NULL) {
      BN_bn2bin(dsa->priv_key,p);
  } else {
      HIP_INFO("No Private key?");
  }
 out_err:
  return dsa_key_rr_len;
}


/**
 * save_dsa_keys - save host DSA keys to disk
 * @filename: the filename where DSA key should be saved
 * @dsa:      the DSA key structure
 *
 * The DSA keys from @dsa are saved in PEM format, public key to file
 * filename.pub, private key to file @filename and DSA parameters to
 * file @filename.params. If any of the files cannot be saved, all
 * files are deleted.
 *
 * Returns: 0 if all files were saved successfully, or non-zero if an error
 * occurred.
 */
int save_dsa_keys(char *filenamebase, DSA *dsa) {
  int err = 0;
  char *pubfilename;
  int pubfilename_len;
  char *paramsfilename;
  int paramsfilename_len;
  FILE *fp;

  if (!filenamebase) {
    HIP_ERROR("NULL filenamebase\n");
    return 1;
  }

  pubfilename_len = strlen(filenamebase)+strlen(DEFAULT_PUB_FILE_SUFFIX)+1;
  pubfilename = malloc(pubfilename_len);
  if (!pubfilename) {
    HIP_ERROR("malloc(%d) failed\n", pubfilename_len);
    goto out_err;
  }

  paramsfilename_len = strlen(filenamebase) +
    strlen(DEFAULT_PARAMS_FILE_SUFFIX)+1;
  paramsfilename = malloc(paramsfilename_len);
  if (!paramsfilename) {
    HIP_ERROR("malloc(%d) failed\n", paramsfilename_len);
    free(pubfilename);
    goto out_err;
  }

  /* check retval */
  snprintf(pubfilename, pubfilename_len, "%s%s", filenamebase,
	   DEFAULT_PUB_FILE_SUFFIX);
  snprintf(paramsfilename, paramsfilename_len, "%s%s", filenamebase,
	   DEFAULT_PARAMS_FILE_SUFFIX);

  HIP_INFO("Saving DSA keys to: pub='%s' priv='%s'\n", pubfilename,
	   filenamebase);
  HIP_INFO("Saving DSA params to '%s'\n", paramsfilename);
  HIP_INFO("Saving host DSA pubkey=%s\n", BN_bn2hex(dsa->pub_key));
  HIP_INFO("Saving host DSA privkey=%s\n", BN_bn2hex(dsa->priv_key));
  HIP_INFO("Saving host DSA p=%s\n", BN_bn2hex(dsa->p));
  HIP_INFO("Saving host DSA q=%s\n", BN_bn2hex(dsa->q));
  HIP_INFO("Saving host DSA g=%s\n", BN_bn2hex(dsa->g));

  /* rewrite using PEM_write_PKCS8PrivateKey */

  fp = fopen(pubfilename, "wb" /* mode */);
  if (!fp) {
    HIP_ERROR("Couldn't open public key file %s for writing\n", filenamebase);
    goto out_err;
  }

  err = PEM_write_DSA_PUBKEY(fp, dsa);
  if (!err) {
    HIP_ERROR("Write failed for %s\n", pubfilename);
    fclose(fp); /* add error check */
    goto out_err_pub;
  }
  fclose(fp); /* add error check */

  fp = fopen(filenamebase, "wb" /* mode */);
  if (!fp) {
    HIP_ERROR("Couldn't open private key file %s for writing\n", filenamebase);
    goto out_err_pub;
  }

  err = PEM_write_DSAPrivateKey(fp, dsa, NULL, NULL, 0, NULL, NULL);
  if (!err) {
    HIP_ERROR("Write failed for %s\n", filenamebase);
    fclose(fp); /* add error check */
    goto out_err_priv;
  }
  fclose(fp); /* add error check */

  fp = fopen(paramsfilename, "wb" /* mode */);
  if (!fp) {
    HIP_ERROR("Couldn't open params file %s for writing\n", paramsfilename);
    goto out_err_priv;
  }

  err = PEM_write_DSAparams(fp, dsa);
  if (!err) {
    HIP_ERROR("Write failed for %s\n", paramsfilename);
    fclose(fp); /* add error check */
    goto out_err_params;
  }
  fclose(fp); /* add error check */

  free(pubfilename);
  free(paramsfilename);
  return 0;

 out_err_params:
   unlink(paramsfilename); /* add error check */
 out_err_priv:
   unlink(filenamebase); /* add error check */
 out_err_pub:
   unlink(pubfilename); /* add error check */

   free(pubfilename);
   free(paramsfilename);
 out_err:
  return 1;
}

/**
 * load_dsa_keys - load host DSA keys from disk
 * @filename: the file name of the host DSA key
 *
 * Loads DSA public and private keys from the given files, public key
 * from file @filename.pub and private key from file @filename. DSA
 * struct will be allocated dynamically and it is the responsibility
 * of the caller to free it with DSA_free.
 *
 * Returns: NULL if the key could not be loaded (not in PEM format or file
 * not found, etc).
 */
DSA *load_dsa_keys(char *filenamebase) {
  DSA *dsa = NULL, *dsa_tmp = NULL;
  char *pubfilename;
  int pubfilename_len;
  char *paramsfilename;
  int paramsfilename_len;
  FILE *fp;

  if (!filenamebase) {
    HIP_ERROR("NULL filename\n");
    return NULL;
  }

  dsa = DSA_new();
  if (!dsa) {
    HIP_ERROR("!dsa\n");
    goto out_err;
  }
  dsa_tmp = DSA_new();
  if (!dsa_tmp) {
    HIP_ERROR("!dsa_tmp\n");
    goto out_err;
  }

  fp = fopen(filenamebase, "rb");
  if (!fp) {
    HIP_ERROR("Couldn't open public key file %s for reading\n", filenamebase);
    goto out_err;
  }

  dsa_tmp = PEM_read_DSAPrivateKey(fp, NULL, NULL, NULL);
  if (!dsa_tmp) {
    HIP_ERROR("Read failed for %s\n", filenamebase);
    fclose(fp); /* add error check */
    goto out_err;
  }

  dsa->pub_key = BN_dup(dsa_tmp->pub_key);
  dsa->priv_key = BN_dup(dsa_tmp->priv_key);
  dsa->p = BN_dup(dsa_tmp->p);
  dsa->q = BN_dup(dsa_tmp->q);
  dsa->g = BN_dup(dsa_tmp->g);
  if (!dsa->p || !dsa->q || !dsa->g || !dsa->pub_key || !dsa->priv_key ) {
    HIP_ERROR("BN_copy\n");
    fclose(fp); /* TODO: add error check */
    goto out_err;
  }
  fclose(fp); /* TODO: add error check */


  HIP_INFO("Loaded host DSA pubkey=%s\n", BN_bn2hex(dsa->pub_key));
  HIP_INFO("Loaded host DSA privkey=%s\n", BN_bn2hex(dsa->priv_key));
  HIP_INFO("Loaded host DSA p=%s\n", BN_bn2hex(dsa->p));
  HIP_INFO("Loaded host DSA q=%s\n", BN_bn2hex(dsa->q));
  HIP_INFO("Loaded host DSA g=%s\n", BN_bn2hex(dsa->g));

  DSA_free(dsa_tmp);
  return dsa;

 out_err:
  if (dsa)
    DSA_free(dsa);
  if (dsa_tmp)
    DSA_free(dsa_tmp);

  return NULL;
}

int alloc_and_set_host_id_param_hdr(struct hip_host_id **host_id,
				    unsigned int key_rr_len,
				    uint8_t algo,
				    const char *hostname)
{
  int err = 0;
  struct hip_host_id host_id_hdr;

  hip_build_param_host_id_hdr(&host_id_hdr, hostname,
			      key_rr_len, algo);

  *host_id = malloc(hip_get_param_total_len(&host_id_hdr));
  if (!host_id) {
    err = -ENOMEM;
  }  

  memcpy(*host_id, &host_id_hdr, sizeof(host_id_hdr));

  return err;
}
