#ifndef HIP_KEYMAT_H
#define HIP_KEYMAT_H

struct keymat_keymat
{
	int offset;      /* Offset into the key material */
	int keymatlen;   /* Length of the key material */
	
	void *keymatdst; /* Pointer to beginning of key material */
};


void* hip_keymat_draw(struct keymat_keymat* keymat, void* data, int length);
void hip_make_keymat(char *kij, int kij_len,   struct keymat_keymat *keymat, 
		     void *dstbuf, int dstbuflen, struct in6_addr *hit1,
		     struct in6_addr *hit2);
  
void hip_keymat_test(void *buffer);

#endif 
