/*
 * This file contains SHA support and for HIPL.
 *
 * SHA-1 was copied from 2.4.18 (public domain)
 *  
 *  TODO:
 *  - the copy of the SHA-XX algos are not needed, remove them!
 *  - remove SHA-1 and use cryptoapi
 *  - this file is a kludge: update HIPL kernel version or import the
 *    required sha modules
 *  - include copyright information here
 *  - change the running number (1,2,3...) to keymat
 */

/****************************** SHA-1 ********************************/

#define SHA1HANDSOFF /* Copies data before messing with it. */

#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/byteorder.h>

#include <net/keymat.h>
#include <net/hip.h>

#include "debug.h"

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#if defined(__LITTLE_ENDIAN)
# define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#elif defined (__BIG_ENDIAN)
# define blk0(i) block->l[i]
#else
# error fix <asm/bytorder.h>
#endif /* _ENDIAN */

#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

static void SHA1Transform(unsigned long state[5], const unsigned char buffer[64]);
static void SHA1Init(struct SHA1_CTX* context);
static void SHA1Update(struct SHA1_CTX* context, const unsigned char* data, 
		       unsigned int len);
static void SHA1Final(unsigned char digest[20], struct SHA1_CTX* context);



/* Hash a single 512-bit block. This is the core of the algorithm. */

void SHA1Transform(unsigned long state[5], const unsigned char buffer[64])
{
	unsigned long a, b, c, d, e;
	typedef union {
		unsigned char c[64];
		unsigned long l[16];
	} CHAR64LONG16;
	CHAR64LONG16* block;
#ifdef SHA1HANDSOFF
	static unsigned char workspace[64];
	block = (CHAR64LONG16*)workspace;
	memcpy(block, buffer, 64);
#else
	block = (CHAR64LONG16*)buffer;
#endif
	/* Copy context->state[] to working vars */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	/* 4 rounds of 20 operations each. Loop unrolled. */
	R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
	R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
	R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
	/* Add the working vars back into context.state[] */
	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	/* Wipe variables */
	a = b = c = d = e = 0;
}


/* SHA1Init - Initialize new context */

void SHA1Init(struct SHA1_CTX* context)
{
	/* SHA1 initialization constants */
	context->state[0] = 0x67452301;
	context->state[1] = 0xEFCDAB89;
	context->state[2] = 0x98BADCFE;
	context->state[3] = 0x10325476;
	context->state[4] = 0xC3D2E1F0;
	context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */

void SHA1Update(struct SHA1_CTX* context, const unsigned char* data, unsigned int len)
{
	unsigned int i, j;

	j = (context->count[0] >> 3) & 63;
	if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
	context->count[1] += (len >> 29);
	if ((j + len) > 63) {
		memcpy(&context->buffer[j], data, (i = 64-j));
		SHA1Transform(context->state, context->buffer);
		for ( ; i + 63 < len; i += 64) {
			SHA1Transform(context->state, &data[i]);
		}
		j = 0;
	}
	else i = 0;
	memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

void SHA1Final(unsigned char digest[20], struct SHA1_CTX* context)
{
	unsigned long i, j;
	unsigned char finalcount[8];

	for (i = 0; i < 8; i++) {
		finalcount[i] = (unsigned char)((context->count[(i >= 4 ? 0 : 1)]
				 >> ((3-(i & 3)) * 8) ) & 255); 
                                 /* Endian independent */
	}
	SHA1Update(context, (unsigned char *)"\200", 1);
	while ((context->count[0] & 504) != 448) {
		SHA1Update(context, (unsigned char *)"\0", 1);
	}
	SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform() */
	for (i = 0; i < 20; i++) {
		digest[i] = (unsigned char)
			((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
	}
	/* Wipe variables */
	i = j = 0;
	memset(context->buffer, 0, 64);
	memset(context->state, 0, 20);
	memset(context->count, 0, 8);
	memset(&finalcount, 0, 8);
#ifdef SHA1HANDSOFF  /* make SHA1Transform overwrite it's own static vars */
	SHA1Transform(context->state, context->buffer);
#endif
}

/**************************** HIPL ************************************/

void keymat_test(void* buffer)
{
	struct SHA1_CTX context;

	void *teststr = "asdbnsabdmasdnmbasmd,amsnfb,mnbfmndbsfmbdsnfmbmdsnfbnmbdsfm,nsbdnmf,nmb,mnb,";

	SHA1Init(&context);
	SHA1Update(&context, teststr, 50);
	SHA1Final(buffer, &context);

	HIP_INFO("Returning from keymat_test\n");

	return;
}	

/**
 * keymat_hit_is_bigger - compare two HITs
 * @hit1: the first HIT to be compared
 * @hit2: the second HIT to be compared
 *
 * Returns: 1 if @hit1 was bigger than @hit2, or else 0
 */
int keymat_hit_is_bigger(const struct in6_addr *hit1,
			 const struct in6_addr *hit2)
{
	int i;

	for (i=0; i<sizeof(struct in6_addr); i++) {
		if (hit1->s6_addr[i] > hit2->s6_addr[i])
			return 1;
		if (hit1->s6_addr[i] < hit2->s6_addr[i])
			return 0;
	}

	return 0;
}


/**
 * hip_make_keymat - generate HIP keying material
 * @kij:     Diffie-Hellman Kij (as in the HIP drafts)
 * @kij_len: the length of the Kij material
 * @keymat:  pointer to a keymat structure which will be updated according
 *           to the generated keymaterial
 * @dstbuf:  the generated keymaterial will be written here
 * @hit1:    source HIT
 * @hit2:    destination HIT
 *
 * Dstbuflen must be a multiple of 32.
 */
void hip_make_keymat(char *kij, int kij_len, struct keymat_keymat *keymat, 
		     void *dstbuf, int dstbuflen, struct in6_addr *hit1,
		     struct in6_addr *hit2)
{
	// XX FIX: we don't need source data and sourcelen
	struct SHA1_CTX     context;
	uint8_t index_nbr = 1;

	int dstoffset = 0;

	void *seedkey;

	struct in6_addr *smaller_hit, *bigger_hit;
	int hit1_is_bigger;

	/* XX TODO: is this the correct one to test for 32 bit multiplicity? */
	HIP_ASSERT(dstbuflen % 32 == 0);
	HIP_ASSERT(sizeof(index_nbr) == HIP_KEYMAT_INDEX_NBR_SIZE);

	hit1_is_bigger = keymat_hit_is_bigger(hit1, hit2);

	bigger_hit =  hit1_is_bigger ? hit1 : hit2;
	smaller_hit = hit1_is_bigger ? hit2 : hit1;

	HIP_HEXDUMP("bigger hit", bigger_hit, 16);
	HIP_HEXDUMP("smaller hit", smaller_hit, 16);
	HIP_HEXDUMP("index_nbr", (char *) &index_nbr,
		    HIP_KEYMAT_INDEX_NBR_SIZE);

	/* K1 */
	SHA1Init(&context);
	SHA1Update(&context, kij, kij_len);
	SHA1Update(&context, (unsigned char *) smaller_hit,
		   sizeof(struct in6_addr));
	SHA1Update(&context, (unsigned char *) bigger_hit,
		   sizeof(struct in6_addr));
	SHA1Update(&context, (char *) &index_nbr, HIP_KEYMAT_INDEX_NBR_SIZE);
	SHA1Final(dstbuf, &context);

	dstoffset = HIP_AH_SHA_LEN;
	index_nbr++;

	/*
	 * K2 = SHA1(Kij | K1 | 2)
	 * K3 = SHA1(Kij | K2 | 3)
	 * ...
	 */
	seedkey = dstbuf;
	while (dstoffset < dstbuflen) {
		SHA1Init(&context);
		SHA1Update(&context, kij, kij_len);
		SHA1Update(&context, seedkey, HIP_AH_SHA_LEN);
		SHA1Update(&context, &index_nbr, HIP_KEYMAT_INDEX_NBR_SIZE);
		SHA1Final(dstbuf + dstoffset, &context);

		seedkey = dstbuf + dstoffset;

		dstoffset += HIP_AH_SHA_LEN;
		index_nbr++;
	}

	keymat->offset = 0;
	keymat->keymatlen = dstoffset;
	keymat->keymatdst = dstbuf;

	_HIP_HEXDUMP("GENERATED KEYMAT: ", dstbuf, dstbuflen);

	return;
}

/**
 * hip_keymat_draw - draw keying material
 * @keymat: pointer to the keymat structure which contains information
 *          about the actual
 * @data:   currently not used
 * @length: size of keymat structure
 *
 * Returns: pointer the next point where one can draw the next keymaterial
 */
void* hip_keymat_draw(struct keymat_keymat* keymat, void* data, int length)
{
	void *ret = NULL;

	if (length > keymat->keymatlen - keymat->offset) {
		_HIP_INFO("Tried to draw more keys than are available\n");
		goto out_err;
	}

	ret = keymat->keymatdst + keymat->offset;

	keymat->offset += length;

 out_err:
	return ret;
}

