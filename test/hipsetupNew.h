#ifndef HIPSETUPNEW_H
#define HIPSETUPNEW_H

#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include "../tools/hipconf.h"
#include "conntest.h"
#include "libinet6/debug.h"
#include "libinet6/crypto.h"

#define DEFAULT_PORT 1111


void usage_f();
int install_module();
void init_deamon();
int add_hi_default(struct hip_common *msg);


#endif /*HIPSETUPNEW_H*/
