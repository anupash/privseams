#include "usercompat.h"

int hip_send_recv_daemon_info(struct hip_common *msg) {return -1;}
int hip_build_digest(const int type, const void *in, int in_len, void *out) {return -1;}
int hip_write_hmac(int type, void *key, void *in, int in_len, void *out) {return -1;}
