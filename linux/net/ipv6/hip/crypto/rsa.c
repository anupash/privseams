/* rsa.c  -  RSA function
 *	Copyright (C) 1997, 1998, 1999 by Werner Koch (dd9jn)
 *	Copyright (C) 2000, 2001, 2002 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/* This code uses an algorithm protected by U.S. Patent #4,405,829
   which expired on September 20, 2000.  The patent holder placed that
   patent into the public domain on Sep 6th, 2000.
*/

#include <net/hip.h>

#include "kernel-interface.h"
#include "gcrypt.h"
#include "rsa.h"


typedef struct {
    MPI n;	    /* modulus */
    MPI e;	    /* exponent */
} RSA_public_key;


typedef struct {
    MPI n;	    /* public modulus */
    MPI e;	    /* public exponent */
    MPI d;	    /* exponent */
    MPI p;	    /* prime  p. */
    MPI q;	    /* prime  q. */
    MPI u;	    /* inverse of p mod q. */
} RSA_secret_key;


static void public(MPI output, MPI input, RSA_public_key *skey );
static void secret(MPI output, MPI input, RSA_secret_key *skey );


/****************
 * Public key operation. Encrypt INPUT with PKEY and put result into OUTPUT.
 *
 *	c = m^e mod n
 *
 * Where c is OUTPUT, m is INPUT and e,n are elements of PKEY.
 */
static void
public(MPI output, MPI input, RSA_public_key *pkey )
{
    if( output == input ) { /* powm doesn't like output and input the same */
	MPI x = mpi_alloc( mpi_get_nlimbs(input)*2 );
	mpi_powm( x, input, pkey->e, pkey->n );
	mpi_set(output, x);
	mpi_free(x);
    }
    else
	mpi_powm( output, input, pkey->e, pkey->n );
}

/****************
 * Secret key operation. Encrypt INPUT with SKEY and put result into OUTPUT.
 *
 *	m = c^d mod n
 *
 * Or faster:
 *
 *      m1 = c ^ (d mod (p-1)) mod p 
 *      m2 = c ^ (d mod (q-1)) mod q 
 *      h = u * (m2 - m1) mod q 
 *      m = m1 + h * p
 *
 * Where m is OUTPUT, c is INPUT and d,n,p,q,u are elements of SKEY.
 */
static void
secret(MPI output, MPI input, RSA_secret_key *skey )
{
  #if 0
    mpi_powm( output, input, skey->d, skey->n );
  #else
    MPI m1   = mpi_alloc_secure( mpi_get_nlimbs(skey->n)+1 );
    MPI m2   = mpi_alloc_secure( mpi_get_nlimbs(skey->n)+1 );
    MPI h    = mpi_alloc_secure( mpi_get_nlimbs(skey->n)+1 );

    /* m1 = c ^ (d mod (p-1)) mod p */
    mpi_sub_ui( h, skey->p, 1  );
    mpi_fdiv_r( h, skey->d, h );   
    mpi_powm( m1, input, h, skey->p );
    /* m2 = c ^ (d mod (q-1)) mod q */
    mpi_sub_ui( h, skey->q, 1  );
    mpi_fdiv_r( h, skey->d, h );
    mpi_powm( m2, input, h, skey->q );
    /* h = u * ( m2 - m1 ) mod q */
    mpi_sub( h, m2, m1 );
    if ( mpi_is_neg( h ) ) 
        mpi_add ( h, h, skey->q );
    mpi_mulm( h, skey->u, h, skey->q ); 
    /* m = m2 + h * p */
    mpi_mul ( h, h, skey->p );
    mpi_add ( output, m1, h );
    /* ready */
    
    mpi_free ( h );
    mpi_free ( m1 );
    mpi_free ( m2 );
  #endif
}



/*********************************************
 **************  interface  ******************
 *********************************************/

int
_gcry_rsa_encrypt( int algo, MPI *resarr, MPI data, MPI *pkey )
{
    RSA_public_key pk;

    if( algo != 1 && algo != 2 )
	return GCRYERR_INV_PK_ALGO;

    pk.n = pkey[0];
    pk.e = pkey[1];
    resarr[0] = mpi_alloc( mpi_get_nlimbs( pk.n ) );
    public( resarr[0], data, &pk );
    return 0;
}

int
_gcry_rsa_decrypt( int algo, MPI *result, MPI *data, MPI *skey )
{
    RSA_secret_key sk;

    if( algo != 1 && algo != 2 )
	return GCRYERR_INV_PK_ALGO;

    sk.n = skey[0];
    sk.e = skey[1];
    sk.d = skey[2];
    sk.p = skey[3];
    sk.q = skey[4];
    sk.u = skey[5];
    *result = mpi_alloc_secure( mpi_get_nlimbs( sk.n ) );
    secret( *result, data[0], &sk );
    return 0;
}

int
_gcry_rsa_sign( int algo, MPI *resarr, MPI data, MPI *skey )
{
    RSA_secret_key sk;

    if( algo != 1 && algo != 3 )
	return GCRYERR_INV_PK_ALGO;

    sk.n = skey[0];
    sk.e = skey[1];
    sk.d = skey[2];
    sk.p = skey[3];
    sk.q = skey[4];
    sk.u = skey[5];
    resarr[0] = mpi_alloc( mpi_get_nlimbs( sk.n ) );
    secret( resarr[0], data, &sk );

    return 0;
}

int
_gcry_rsa_verify( int algo, MPI hash, MPI *data, MPI *pkey,
	   int (*cmp)(void *opaque, MPI tmp), void *opaquev )
{
    RSA_public_key pk;
    MPI result;
    int rc;

    if( algo != 1 && algo != 3 )
	return GCRYERR_INV_PK_ALGO;
    pk.n = pkey[0];
    pk.e = pkey[1];
    result = gcry_mpi_new ( 160 );
    public( result, data[0], &pk );
    /*rc = (*cmp)( opaquev, result );*/
    rc = mpi_cmp( result, hash )? GCRYERR_BAD_SIGNATURE:0;
    gcry_mpi_release (result);

    return rc;
}

/****************
 * Return some information about the algorithm.  We need algo here to
 * distinguish different flavors of the algorithm.
 * Returns: A pointer to string describing the algorithm or NULL if
 *	    the ALGO is invalid.
 * Usage: Bit 0 set : allows signing
 *	      1 set : allows encryption
 */
const char *
_gcry_rsa_get_info( int algo,
	      int *npkey, int *nskey, int *nenc, int *nsig, int *r_usage )
{
    *npkey = 2;
    *nskey = 6;
    *nenc = 1;
    *nsig = 1;

    switch( algo ) {
      case 1: *r_usage = GCRY_PK_USAGE_SIGN | GCRY_PK_USAGE_ENCR; return "RSA";
      case 2: *r_usage = GCRY_PK_USAGE_ENCR; return "RSA-E";
      case 3: *r_usage = GCRY_PK_USAGE_SIGN; return "RSA-S";
      default:*r_usage = 0; return NULL;
    }
}

int hip_rsa_sign(u8 *digest, u8 *private_key, u8 *signature,
		 int priv_klen)
{
	RSA_secret_key rsk = {0};
	MPI data, msig;
	int err = 0, len, slice;
	u8 *c = private_key;
	u8 *buf = NULL;
	u8 asn_prefix[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B,
			    0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04,
			    0x14};

	HIP_DEBUG("private key len: %d\n",priv_klen);
	//	if (*c == 0)
	//len = 3;
	//else
	//len = 1;
	HIP_ASSERT(*c!=0);
	len = *c;

	c++;

	if (gcry_mpi_scan(&rsk.e, GCRYMPI_FMT_USG, c, &len) != 0) {
		log_error("Error parsing RSA private e\n");
		goto cleanup;
	}
	HIP_HEXDUMP("mpi scan", c, len);
	c += len;

	slice = (priv_klen - len) / 6;
	HIP_DEBUG("slice:%d\n",slice);
	len = 2 * slice;
	if (gcry_mpi_scan(&rsk.n, GCRYMPI_FMT_USG, c, &len) != 0) {
		log_error("Error parsing RSA private n\n");
		goto cleanup;
	}
	HIP_HEXDUMP("mpi scan", c, len);
	c += len;

	len = 2 * slice;
	if (gcry_mpi_scan(&rsk.d, GCRYMPI_FMT_USG, c, &len) != 0) {
		log_error("Error parsing RSA private d\n");
		goto cleanup;
	}
	HIP_HEXDUMP("mpi scan", c, len);
	c += len;
	
	len = slice;
	if (gcry_mpi_scan(&rsk.p, GCRYMPI_FMT_USG, c, &len) != 0) {
		log_error("Error parsing RSA private p\n");
		goto cleanup;
	}
	HIP_HEXDUMP("mpi scan", c, len);
	c += len;

	len = slice;
	if (gcry_mpi_scan(&rsk.q, GCRYMPI_FMT_USG, c, &len) != 0) {
		log_error("Error parsing RSA private q\n");
		goto cleanup;
	}
	HIP_HEXDUMP("mpi scan", c, len);
	c += len;

	rsk.u = gcry_mpi_new(mpi_get_nbits(rsk.d));
	mpi_invm(rsk.u,rsk.p,rsk.q);

	buf = kmalloc(mpi_get_nbits(rsk.n) / 8, GFP_KERNEL);
	if (!buf) {
		HIP_ERROR("Hajoo homo aamuihis\n");
		err = -1;
		goto cleanup;
	}

	/* shalen + asn prefix len + 01 00 */
	len = HIP_AH_SHA_LEN + 15 + 2;
	slice = mpi_get_nbits(rsk.n) / 8 - len;

	c = buf;
	*c = 1;
	c++;

	memset(c, 0xff, slice);
	c += slice;

	*c = 0;
	c++;

	memcpy(c, asn_prefix, 15);
	c += 15;

	memcpy(c, digest, HIP_AH_SHA_LEN);

	len = mpi_get_nbits(rsk.n) / 8;
	if (gcry_mpi_scan(&data, GCRYMPI_FMT_USG, buf, &len) != 0) {
		log_error("Error parsing signature data\n");
		goto cleanup;
	}
	HIP_HEXDUMP("mpi scan", buf, len);

	msig = mpi_alloc(mpi_get_nlimbs(rsk.n));
	secret(msig, data, &rsk);

	len = mpi_get_nbits(rsk.n) / 8;
	/* 8 must not be 27, it should be always 28. This should be
	    handled better */
	len += 1; /* rsk.n */
        if (gcry_mpi_print(GCRYMPI_FMT_USG, signature, 
			   &len, msig) != 0) {
		log_error("Error encoding RSA signature\n");
		goto cleanup;
	}
	HIP_HEXDUMP("mpi scan", signature, len);

 cleanup:
	/* XX TODO: free msig */
	if (buf)
	  kfree(buf);
	return err;
	
}

int hip_rsa_verify(u8 *digest, u8 *public_key, u8 *signature, int pub_klen)
{
	int err = 0;
	MPI result = NULL;
	MPI data;
	MPI orig;
	RSA_public_key rpk = {0};
	int len, slice;
	u8 *c = public_key; /* XX FIXME: IS THIS CORRECT? */
	u8 *buf = NULL, *debug_signature=NULL;
	u8 asn_prefix[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B,
			    0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04,
			    0x14};
	HIP_DEBUG("public key len: %d\n",pub_klen);
	//if (*c == 0) /* XX FIXME: WHAT'S THIS? */
	//len = 3;
	//else
	//len = 1;
	HIP_ASSERT(*c!=0);
	len = *c;

	c++;

	if (gcry_mpi_scan(&rpk.e, GCRYMPI_FMT_USG, c, &len) != 0) {
		log_error("Error parsing RSA public e\n");
		goto cleanup;
	}

	HIP_HEXDUMP("RSA public E", c, len);
	c += len;

	/* XX CHECK: should this be divided by 6 ?*/
	/*slice = (pub_klen - len);*/
	/* XX CHECK: should slice affect len ? */
	slice = (pub_klen - len) / 2;
	len = 2 * slice;

	HIP_DEBUG("slice:%d\n",slice);

	if (gcry_mpi_scan(&rpk.n, GCRYMPI_FMT_USG, c, &len) != 0) {
		log_error("Error parsing RSA public n\n");
		goto cleanup;
	}
	HIP_HEXDUMP("RSA public N", c, len);
	HIP_DEBUG("mpi_get_nbits:%d\n",mpi_get_nbits(rpk.n));
	buf = kmalloc(mpi_get_nbits(rpk.n) / 8, GFP_KERNEL);
	if (!buf) {
		HIP_ERROR("kmalloc failed\n");
		err = -1;
		goto cleanup;
	}

	/* shalen + asn prefix len + 01 00 */
	len = HIP_AH_SHA_LEN + 15 + 2;
	slice = mpi_get_nbits(rpk.n) / 8 - len;
	HIP_DEBUG("slice:%d,mpi_get_nbits:%d\n",slice,mpi_get_nbits(rpk.n));

	c = buf;
	*c = 1;
	c++;

	memset(c, 0xff, slice); 
	c += slice;

	*c = 0;
	c++;

	memcpy(c, asn_prefix, 15);
	c += 15;

	memcpy(c, digest, HIP_AH_SHA_LEN);

	len = mpi_get_nbits(rpk.n) / 8;
	if (gcry_mpi_scan(&data, GCRYMPI_FMT_USG, buf, &len) != 0) {
		log_error("Error parsing signature data\n");
		goto cleanup;
	}

	HIP_HEXDUMP("Signature data", buf, len);

	result = mpi_alloc(mpi_get_nlimbs(rpk.n));
	/* XX TODO: check return value */

	/* added this, is this correct? */
	len = mpi_get_nbits(rpk.n) / 8;
	if (gcry_mpi_scan(&result, GCRYMPI_FMT_USG, signature, &len) != 0)
	{
		log_error("Error reading signature data\n");
		goto cleanup;
	}

	public(result, data, &rpk); 

	debug_signature = kmalloc(mpi_get_nbits(rpk.n) / 8, GFP_KERNEL);
        /* XX TODO: check return value and free mem */
	
        if (gcry_mpi_print(GCRYMPI_FMT_USG, debug_signature, 
			   &len, result) != 0) {
		log_error("Error encoding RSA signature\n");
		goto cleanup;
	}
	HIP_HEXDUMP("mpi scan", debug_signature, len);

	len = mpi_get_nbits(rpk.n) / 8;
	if (gcry_mpi_scan(&orig, GCRYMPI_FMT_USG, signature, &len) != 0)
	{
		log_error("Error reading signature data\n");
		goto cleanup;
	}
	/* XX TODO: free result */
	if (buf)
		kfree(buf);

	return (mpi_cmp(orig, result));

 cleanup:
	/* XX TODO: free result */
	if (buf)
		kfree(buf);
	
	return -1;
}
