/* dsa.c  -  DSA signature scheme
 *	Copyright (C) 1998, 2000, 2001, 2002 Free Software Foundation, Inc.
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
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

#include "dsa.h"

typedef struct {
    MPI p;	    /* prime */
    MPI q;	    /* group order */
    MPI g;	    /* group generator */
    MPI y;	    /* g^x mod p */
} DSA_public_key;

typedef struct {
    MPI p;	    /* prime */
    MPI q;	    /* group order */
    MPI g;	    /* group generator */
    MPI y;	    /* g^x mod p */
    MPI x;	    /* secret exponent */
} DSA_secret_key;

static MPI gen_k( MPI q );
static void sign(MPI r, MPI s, MPI input, DSA_secret_key *skey);
static int  verify(MPI r, MPI s, MPI input, DSA_public_key *pkey);

/****************
 * Generate a random secret exponent k less than q
 */
static MPI
gen_k( MPI q )
{
    MPI k = mpi_alloc_secure( mpi_get_nlimbs(q) );
    unsigned int nbits = mpi_get_nbits(q);
    unsigned int nbytes = (nbits+7)/8;
    char *rndbuf = NULL;

    for(;;) {
	if( !rndbuf || nbits < 32 ) {
	    gcry_free(rndbuf);
	    rndbuf = gcry_random_bytes_secure( (nbits+7)/8,
					       GCRY_STRONG_RANDOM );
	}
	else { /* change only some of the higher bits */
	    /* we could imporove this by directly requesting more memory
	     * at the first call to get_random_bytes() and use this the here
	     * maybe it is easier to do this directly in random.c */
	    char *pp = gcry_random_bytes_secure( 4, GCRY_STRONG_RANDOM );
	    memcpy( rndbuf,pp, 4 );
	    gcry_free(pp);
	}
	_gcry_mpi_set_buffer( k, rndbuf, nbytes, 0 );
	if( mpi_test_bit( k, nbits-1 ) )
	    mpi_set_highbit( k, nbits-1 );
	else {
	    mpi_set_highbit( k, nbits-1 );
	    mpi_clear_bit( k, nbits-1 );
	}

	if( !(mpi_cmp( k, q ) < 0) ) {	/* check: k < q */
	    continue; /* no  */
	}
	if( !(mpi_cmp_ui( k, 0 ) > 0) ) { /* check: k > 0 */
	    continue; /* no */
	}
	break;	/* okay */
    }
    gcry_free(rndbuf);

    return k;
}


/****************
 * Make a DSA signature from HASH and put it into r and s.
 */

static void
sign(MPI r, MPI s, MPI hash, DSA_secret_key *skey )
{
    MPI k;
    MPI kinv;
    MPI tmp;

    /* select a random k with 0 < k < q */
    k = gen_k( skey->q );

    /* r = (a^k mod p) mod q */
    gcry_mpi_powm( r, skey->g, k, skey->p );
    mpi_fdiv_r( r, r, skey->q );

    /* kinv = k^(-1) mod q */
    kinv = mpi_alloc( mpi_get_nlimbs(k) );
    mpi_invm(kinv, k, skey->q );

    /* s = (kinv * ( hash + x * r)) mod q */
    tmp = mpi_alloc( mpi_get_nlimbs(skey->p) );
    mpi_mul( tmp, skey->x, r );
    mpi_add( tmp, tmp, hash );
    mpi_mulm( s , kinv, tmp, skey->q );

    mpi_free(k);
    mpi_free(kinv);
    mpi_free(tmp);
}


/****************
 * Returns true if the signature composed from R and S is valid.
 */
static int
verify(MPI r, MPI s, MPI hash, DSA_public_key *pkey )
{
    int rc;
    MPI w, u1, u2, v;
    MPI base[3];
    MPI exp[3];


    if( !(mpi_cmp_ui( r, 0 ) > 0) ) {
	    log_error("assertion 0 < r failed\n");
	    return 0;
    }
    if( !(mpi_cmp( r, pkey->q ) < 0) ) {
	    log_error("assertion r < q  failed\n");
	    return 0; /* assertion	0 < r < q  failed */
    }
    if( !(mpi_cmp_ui( s, 0 ) > 0) ) {
	    log_error("assertion 0 < s failed\n");
	    return 0;
    }
	
    if( !(mpi_cmp( s, pkey->q ) < 0) ) {
	    log_error("assertion s < q  failed\n");
	    return 0;
    }

    w  = mpi_alloc( mpi_get_nlimbs(pkey->q) );
    u1 = mpi_alloc( mpi_get_nlimbs(pkey->q) );
    u2 = mpi_alloc( mpi_get_nlimbs(pkey->q) );
    v  = mpi_alloc( mpi_get_nlimbs(pkey->p) );

    /* w = s^(-1) mod q */
    mpi_invm( w, s, pkey->q );

    /* u1 = (hash * w) mod q */
    mpi_mulm( u1, hash, w, pkey->q );

    /* u2 = r * w mod q  */
    mpi_mulm( u2, r, w, pkey->q );

    /* v =  g^u1 * y^u2 mod p mod q */
    base[0] = pkey->g; exp[0] = u1;
    base[1] = pkey->y; exp[1] = u2;
    base[2] = NULL;    exp[2] = NULL;
    mpi_mulpowm( v, base, exp, pkey->p );
    mpi_fdiv_r( v, v, pkey->q );

    rc = !mpi_cmp( v, r );

    mpi_free(w);
    mpi_free(u1);
    mpi_free(u2);
    mpi_free(v);
    return rc;
}

unsigned int
_gcry_dsa_get_nbits( int algo, MPI *pkey )
{
	algo = 1;
	return mpi_get_nbits( pkey[0] );
}

int hip_dsa_sign(u8 *digest, u8 *private_key, u8 *signature)
{
	DSA_secret_key sk = {0};
	MPI r=NULL,s=NULL,m;
	int pos = 0;
	int err = -EINVAL;
	size_t tmp;
	u8 t;

	t = *(private_key+pos);
	if (t > 8) {
		log_error("Illegal DSA key\n");
		goto cleanup;
	}
	pos++;

	/* XXX: add checking of tmp variable after the scanning to see that
	   the required amount of bytes was actually read. */
	tmp = 20;

	_HIP_HEXDUMP("key-dump",private_key+pos,20);

	if (gcry_mpi_scan(&sk.q,GCRYMPI_FMT_USG,private_key+pos,&tmp) != 0) {
		log_error("Error parsing DSA private_key component Q\n");
		goto cleanup;
	}
	pos += 20;

	tmp = 64+8*t;
	if (gcry_mpi_scan(&sk.p,GCRYMPI_FMT_USG,private_key+pos,&tmp) != 0) {
		log_error("Error parsing DSA private_key component P\n");
		goto cleanup;
	}
	pos += 64+8*t;

	tmp = 64+8*t;
	if (gcry_mpi_scan(&sk.g,GCRYMPI_FMT_USG,private_key+pos,&tmp) != 0) {
		log_error("Error parsing DSA private_key component G\n");
		goto cleanup;
	}
	pos += 64+8*t;

	tmp = 64+8*t;
	if (gcry_mpi_scan(&sk.y,GCRYMPI_FMT_USG,private_key+pos,&tmp) != 0) {
		log_error("Error parsing DSA private_key component Y\n");
		goto cleanup;
	}
	pos += 64+8*t;

	tmp = 20;
	if (gcry_mpi_scan(&sk.x,GCRYMPI_FMT_USG,private_key+pos,&tmp) != 0) {
		log_error("Error parsing DSA private_key component X\n");
		goto cleanup;
	}

	/* p,q,g,x,y retrieved */

	if (gcry_mpi_scan(&m,GCRYMPI_FMT_USG,digest,&tmp) != 0) {
		log_error("Error parsing DSA digest\n");
		goto cleanup;
	}


	r = mpi_alloc(mpi_get_nlimbs(sk.p));
	s = mpi_alloc(mpi_get_nlimbs(sk.p));

	_HIP_DEBUG("Using following numbers for signing:\n");
	_HIP_HEXDUMP("Q", sk.q->d, sk.q->nlimbs*4);
	_HIP_HEXDUMP("P", sk.p->d, sk.p->nlimbs*4);
	_HIP_HEXDUMP("G", sk.g->d, sk.g->nlimbs*4);
	_HIP_HEXDUMP("Y", sk.y->d, sk.y->nlimbs*4);
	_HIP_HEXDUMP("X", sk.x->d, sk.x->nlimbs*4);
	
	sign(r,s,m,&sk);

	_HIP_HEXDUMP("R",r->d,r->nlimbs*4);
	_HIP_HEXDUMP("S",s->d,s->nlimbs*4);

	/* encode now */

	pos = 0;
	*signature = t;
	pos++;
	
	tmp = 20;
	if (gcry_mpi_print(GCRYMPI_FMT_USG, signature+1, 
			   &tmp, r) != 0) {
		log_error("Error encoding DSA signature component R\n");
		goto cleanup;
	}
	pos += tmp;

	tmp = 20;
	if (gcry_mpi_print(GCRYMPI_FMT_USG, signature+21, 
			   &tmp, s) != 0) {
		log_error("Error encoding DSA signature component s\n");
		goto cleanup;
	}

	err = 0;
 cleanup:
	if (s)
		mpi_free(s);
	if (r)
		mpi_free(r);
	if (sk.x)
		mpi_free(sk.x);
	if (sk.y)
		mpi_free(sk.y);
	if (sk.g)
		mpi_free(sk.g);
	if (sk.p)
		mpi_free(sk.p);
	if (sk.q)
		mpi_free(sk.q);

	return err;

}

/* return 0: ok, 1: verify error, -EINVAL: something sucked */
int hip_dsa_verify(u8 *digest, u8 *public_key, u8 *signature)
{
	DSA_public_key sk;
	MPI r=NULL,s=NULL,m;
	int pos = 0;
	int err = -EINVAL;
	size_t tmp;
	u8 t;

	t = *public_key;

	if (t > 8) {
		log_error("DSA public key invalid\n");
		return EINVAL;
	}
	pos++;

	tmp = 20;
	if (gcry_mpi_scan(&sk.q,GCRYMPI_FMT_USG,public_key+pos,&tmp) != 0) {
		log_error("Error parsing DSA public_key component Q\n");
		goto cleanup;
	}
	pos += 20;

	tmp = 64+8*t;
	if (gcry_mpi_scan(&sk.p,GCRYMPI_FMT_USG,public_key+pos,&tmp) != 0) {
		log_error("Error parsing DSA public_key component P\n");
		goto cleanup;
	}
	pos += 64+8*t;

	tmp = 64+8*t;
	if (gcry_mpi_scan(&sk.g,GCRYMPI_FMT_USG,public_key+pos,&tmp) != 0) {
		log_error("Error parsing DSA public_key component G\n");
		goto cleanup;
	}
	pos += 64+8*t;

	tmp = 64+8*t;
	if (gcry_mpi_scan(&sk.y,GCRYMPI_FMT_USG,public_key+pos,&tmp) != 0) {
		log_error("Error parsing DSA public_key component Y\n");
		goto cleanup;
	}

	/* p,q,g,y retrieved */

	tmp = 20;
	if (gcry_mpi_scan(&m,GCRYMPI_FMT_USG,digest,&tmp) != 0) {
		log_error("Error parsing DSA digest\n");
		goto cleanup;
	}
	
	tmp = 20;
	if (gcry_mpi_scan(&r,GCRYMPI_FMT_USG,signature+1,&tmp) != 0) {
		log_error("Error parsing DSA signature component R\n");
		goto cleanup;
	}


	tmp = 20;
	if (gcry_mpi_scan(&s,GCRYMPI_FMT_USG,signature+21,&tmp) != 0) {
		log_error("Error parsing DSA signature component S\n");
		goto cleanup;
	}


	_HIP_DEBUG("Using following numbers for signing:\n");
	_HIP_HEXDUMP("Q", sk.q->d, sk.q->nlimbs*4);
	_HIP_HEXDUMP("P", sk.p->d, sk.p->nlimbs*4);
	_HIP_HEXDUMP("G", sk.g->d, sk.g->nlimbs*4);
	_HIP_HEXDUMP("Y", sk.y->d, sk.y->nlimbs*4);
	_HIP_HEXDUMP("R", r->d, r->nlimbs*4);
	_HIP_HEXDUMP("S", s->d, s->nlimbs*4);

	if (verify(r,s,m,&sk))
		err = 0;
	else
		err = 1;

 cleanup:
	if (s)
		mpi_free(s);
	if (r)
		mpi_free(r);
	if (sk.y)
		mpi_free(sk.y);
	if (sk.g)
		mpi_free(sk.g);
	if (sk.p)
		mpi_free(sk.p);
	if (sk.q)
		mpi_free(sk.q);

	return err;
}




