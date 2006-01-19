#ifndef MPI_DEFS_H
#define MPI_DEFS_H

#include <linux/types.h>

#define SIZEOF_UNSIGNED_SHORT 2
#define SIZEOF_UNSIGNED_INT 4
#define SIZEOF_UNSIGNED_LONG 4

typedef unsigned char byte;
//typedef unsigned short ushort;
//typedef unsigned long ulong;

#define HAVE_U64_TYPEDEF
#define C_SYMBOL_NAME(name) name
//#define __i386__
#define BYTES_PER_MPI_LIMB (SIZEOF_UNSIGNED_LONG)

#endif
