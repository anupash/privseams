#ifndef HIPSETUPNEW_H
#define HIPSETUPNEW_H

#include "libhipcore/protodefs.h"

#define DEFAULT_PORT 1111

void usage_f(void);
int install_module(void);
void init_deamon(void);
int add_hi_default(struct hip_common *msg);


#endif /*HIPSETUPNEW_H*/
