/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * This file contains functionality to lower the privileges (or
 * capabilities) of agent, hipd and hipfw. It is important to restrict
 * the damage of a exploit to the software. The code is Linux
 * specific.
 *
 * This code causes problems with valgrind, because of setpwent(3).
 *
 * @brief Functionality to lower the privileges of a daemon
 *
 * @author Miika Komu <miika@iki.fi>
 */

#define _BSD_SOURCE

#include <pwd.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>

#include "config.h"
#include "debug.h"
#include "ife.h"
#include "hip_capability.h"

#include <linux/capability.h>
#include <linux/unistd.h>

#define USER_NOBODY "nobody"
#define USER_HIPD "hipd"

/**
 * map a user name such as "nobody" to the corresponding UID number
 *
 * @param the name to map
 * @return the UID or -1 on error
 */
static int hip_user_to_uid(char *name)
{
    int uid            = -1;
    int i;
    struct passwd *pwp = NULL, pw;
    char buf[4096];

    setpwent();
    while (1) {
        i = getpwent_r(&pw, buf, sizeof(buf), &pwp);
        if (i) {
            break;
        }
        _HIP_DEBUG("%s (%d)\tHOME %s\tSHELL %s\n", pwp->pw_name,
                   pwp->pw_uid, pwp->pw_dir, pwp->pw_shell);
        if (!strcmp(pwp->pw_name, name)) {
            uid = pwp->pw_uid;
            break;
        }
    }
    endpwent();
    return uid;
}

/**
 * Wrapper for the capget system call.
 * @param hdrp  pointer to a __user_cap_header_struct
 * @param datap pointer to a __user_cap_data_struct
 * @return      0 on success, negative otherwise.
 */
static inline int hip_capget(cap_user_header_t hdrp, cap_user_data_t datap)
{
    return syscall(__NR_capget, hdrp, datap);
}

/**
 * Wrapper for the capset system call.
 * @param hdrp  pointer to a __user_cap_header_struct
 * @param datap pointer to a __user_cap_data_struct
 * @retuen      0 on success, negative otherwise.
 */
static inline int hip_capset(cap_user_header_t hdrp, cap_user_data_t datap)
{
    return syscall(__NR_capset, hdrp, datap);
}

/**
 * Lower the privileges of the currently running process.
 *
 * @param run_as_sudo 1 if the process was started with "sudo" or
 *                    0 otherwise
 * @return zero on success and negative on error
 */
int hip_set_lowcapability(int run_as_sudo)
{
    int err   = 0;
    uid_t uid = -1;

    struct __user_cap_header_struct header;
    struct __user_cap_data_struct data;

    header.pid     = 0;
    header.version = _LINUX_CAPABILITY_VERSION_1;
    data.effective = data.permitted = data.inheritable = 0;

    HIP_IFEL(prctl(PR_SET_KEEPCAPS, 1), -1, "prctl err\n");

    HIP_DEBUG("Now PR_SET_KEEPCAPS=%d\n", prctl(PR_GET_KEEPCAPS));

    uid = hip_user_to_uid(USER_NOBODY);

    HIP_IFEL((uid < 0), -1,
             "Error while retrieving USER 'nobody' uid\n");
    HIP_IFEL(hip_capget(&header, &data), -1,
             "error while retrieving capabilities through capget()\n");
    HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
              data.effective, data.permitted, data.inheritable);

    HIP_DEBUG("Before setreuid(,) UID=%d and EFF_UID=%d\n",
              getuid(), geteuid());

    HIP_IFEL(setreuid(uid, uid), -1, "setruid failed\n");

    HIP_DEBUG("After setreuid(,) UID=%d and EFF_UID=%d\n",
              getuid(), geteuid());
    HIP_IFEL(hip_capget(&header, &data), -1,
             "error while retrieving capabilities through 'capget()'\n");

    HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
              data.effective, data.permitted, data.inheritable);
    HIP_DEBUG("Going to clear all capabilities except the ones needed\n");
    data.effective  = data.permitted = data.inheritable = 0;
    /* for CAP_NET_RAW capability */
    data.effective |= (1 << CAP_NET_RAW);
    data.permitted |= (1 << CAP_NET_RAW);
    /* for CAP_NET_ADMIN capability */
    data.effective |= (1 << CAP_NET_ADMIN);
    data.permitted |= (1 << CAP_NET_ADMIN);
    /* kernel module loading and removal capability */
    data.effective |= (1 << CAP_SYS_MODULE);
    data.permitted |= (1 << CAP_SYS_MODULE);

    HIP_IFEL(hip_capset(&header, &data), -1,
             "error in capset (do you have capabilities kernel module?)");
    HIP_DEBUG("UID=%d EFF_UID=%d\n", getuid(), geteuid());
    HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
              data.effective, data.permitted, data.inheritable);

out_err:
    return err;
}
