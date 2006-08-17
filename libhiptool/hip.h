#ifndef _NET_HIP
#define _NET_HIP

/* DON'T PUT ANYTHING TO THIS FILE! IT IS DEPRACATED AND GOING TO BE REMOVED
   SOON. DON'T EVEN INCLUDE IT FROM YOUR OWN FILES. */

#ifdef __KERNEL__
#  include "usercompat.h"
#else
#  include "kerncompat.h"
#endif
#include <sys/un.h> // for sockaddr_un

#include "protodefs.h"
#include "utils.h"
#include "state.h"
#include "icomm.h"
#include "ife.h"

#endif /* _NET_HIP */
