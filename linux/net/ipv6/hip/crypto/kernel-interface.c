/* laitapa defineä kehiin */

#include "kernel-interface.h"

void *gcry_random_bytes (size_t nbytes, enum gcry_random_level level)
{
	u8 *buffer;

	buffer = gcry_malloc(nbytes);
	if (!buffer)
		return NULL;

	get_random_bytes(buffer,nbytes);
	return buffer;
}

void *gcry_random_bytes_secure(size_t nbytes, enum gcry_random_level level)
{
	return gcry_random_bytes(nbytes,level);
}

/*
 * Have to use some magic here. We will record the size of the memory area
 * to first 4 bytes, so that we can later "resize" the area
 *
 * NOTE! ALL memory areas allocated with gcry_malloc _MUST_ be freed
 * with gcry_free!!!
 */

void * gcry_malloc (size_t n)
{
	u8 *ptr;
	u32 *kludge;

	ptr = kmalloc(n+sizeof(u32),GFP_KERNEL);
	if (!ptr) {
		HIP_DEBUG("No memory\n");
	}
	
	kludge = (u32 *)ptr;
	*kludge = n;
	return ptr+sizeof(u32);
}

void * gcry_malloc_secure (size_t n)
{
	/* is this secure? kernel memory should not be swappable
	   at least for now. How about future and with patches?
	 */
	return gcry_malloc(n);
}

int gcry_is_secure( const void *a)
{
	/* eveyrhing is secure for now */
	return 1;
}

void _gcry_check_heap( const void *a)
{
	/* not implemented in user space, and for now,
	   not in kernel space */
	return;
}

void *gcry_realloc(void *a, size_t n)
{
	u32 *kludge;
	u8 *ptr;
	u8 *newptr;

	ptr = (u8 *)a - sizeof(u32);

	kludge = (u32 *)ptr;

	newptr = gcry_malloc(n);
	memcpy(newptr,a,*kludge); 
	return newptr;
}

void gcry_free(void *p)
{
	u8 *ptr;

	if (!p)
		return;

	ptr = (u8 *)p - sizeof(u32);

	kfree(ptr);
}

void *gcry_calloc(size_t n, size_t m)
{
	size_t bytes;
	void *p;

	bytes = n*m;
	p = gcry_malloc(bytes);
	if (p) {
		memset(p,0,bytes);
	}

	return p;
}


void *gcry_calloc_secure (size_t n, size_t m)
{
	return gcry_calloc(n,m);
}


char *
gcry_strdup( const char *string )
{
	int l;
	char *str;

	l = strlen(string);
	str = (char *)gcry_malloc(l);
	if (str) {
		strncpy(str,string,l);
	}

	return str;
}

void *
gcry_xmalloc( size_t n )
{
	/* just a wrapper for malloc.
	   We don't have oomhandler */
	return gcry_malloc(n);
}

void *
gcry_xrealloc( void *a, size_t n )
{
	/* same */
	return gcry_realloc(a,n);
}

void *
gcry_xmalloc_secure( size_t n )
{
	/* and same */
	return gcry_malloc(n);
}

void *
gcry_xcalloc( size_t n, size_t m )
{
	/* puuh */
	return gcry_calloc(n,m);
}

void *
gcry_xcalloc_secure( size_t n, size_t m )
{
	/* pleaseeee */
	return gcry_calloc(n,m);
}

char *
gcry_xstrdup( const char *string )
{
	return gcry_strdup(string);
}
