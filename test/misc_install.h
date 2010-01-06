#ifndef MISC_INSTALL_H
#define MISC_INSTALL_H

#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include "conntest.h"
#include "libhipcore/debug.h"
#include "libhiptool/crypto.h"

int init_daemon(void);
int install_module(void);
int add_hi_default(struct hip_common *msg);
int main_install(struct hip_common *msg);

#endif /*MISC_INSTALL_H*/
