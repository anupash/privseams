#ifndef KERNEL_INTERFACE_H
#define KERNEL_INTERFACE_H

#ifndef __KERNEL__
#error This file is ment only for kernel compilation
#endif

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>

#ifdef SUBARCH
/* UML in use? */
#  include <asm-um/arch/mpi-defs.h>
#else /* !SUBARCH */
#  include <asm/mpi-defs.h>
#endif

#include "../debug.h"
#include "mpi-internal.h"

#define log_error HIP_ERROR
#define log_bug HIP_ERROR
#define assert(x) do { \
        if (!(x))     \
		BUG(); \
} while(0)

typedef union {
    int a;
    short b;
    char c[1];
    long d;
  #ifdef HAVE_U64_TYPEDEF
    u64 e;
  #endif
    float f;
    double g;
} PROPERLY_ALIGNED_TYPE;

typedef struct string_list {
    struct string_list *next;
    unsigned int flags;
    char d[1];
} *STRLIST;


#define GCRYPT_NO_MPI_MACROS


#endif /* KERNEL_INTERFACE_H */
