#ifndef HIP_LIB_TOOL_PFKEYSADB_H
#define HIP_LIB_TOOL_PFKEYSADB_H

#include <sys/socket.h>
#include <sys/types.h>

int getsadbpolicy(caddr_t *policy0, int *policylen0, int direction,
                  struct sockaddr *src, struct sockaddr *dst, u_int mode, int cmd);

#endif /* HIP_LIB_TOOL_PFKEYSADB_H */
