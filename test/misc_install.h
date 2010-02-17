#ifndef HIP_TEST_MISC_INSTALL_H
#define HIP_TEST_MISC_INSTALL_H

#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include "conntest.h"
#include "lib/core/debug.h"
#include "lib/core/crypto.h"

int init_daemon(void);
int install_module(void);
int add_hi_default(struct hip_common *msg);
int main_install(struct hip_common *msg);

#endif /*HIP_TEST_MISC_INSTALL_H*/
