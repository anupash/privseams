#ifndef MISC_INSTALL_H
#define MISC_INSTALL_H

#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include "../tools/hipconf.h"
#include "conntest.h"
#include "libinet6/debug.h"
#include "libinet6/crypto.h"

void init_daemon();
int install_module();
int add_hi_default(struct hip_common *msg);
int main_install(struct hip_common *msg);

#endif /*MISC_INSTALL_H*/
