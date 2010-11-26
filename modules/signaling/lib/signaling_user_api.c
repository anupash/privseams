/*
 * signaling_user_api.c
 *
 *  Created on: Nov 26, 2010
 *      Author: ziegeldorf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/common.h"

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "signaling_prot_common.h"
#include "signaling_user_api.h"

static int get_user_homedir(uid_t uid) {
    int err = 0;
    struct passwd *pw = NULL;

    HIP_IFEL(!(pw = getpwuid(uid)),
            -1, "Failed to get password entry for given user id.\n");

    HIP_DEBUG("UID %d: Name %s, Homdir: %s\n", uid, pw->pw_name, pw->pw_dir);

out_err:
    return err;
}

int signaling_user_info_by_uid(uid_t uid) {
    get_user_homedir(uid);

    return 0;
}
