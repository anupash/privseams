#ifdef CONFIG_HIP_PRIVSEP
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <pwd.h>
#include "debug.h"
#include "ife.h"
#include "sqlitedbapi.h"

#define USER_NOBODY "nobody"
#define USER_HIPD "hipd"

#endif /* CONFIG_HIP_PRIVSEP */

#ifdef CONFIG_HIP_OPENWRT

/*
 * Note: this function does not go well with valgrind
 */
int hip_set_lowcapability(int run_as_nobody) {
  int err = 0;
#ifdef CONFIG_HIP_PRIVSEP
  struct passwd *nobody_pswd;
  uid_t ruid,euid;
  capheader_t header;
  capdata_t data; 

  header.pid=0;
  header.version = _LINUX_CAPABILITY_VERSION_HIPL;
  data.effective = data.permitted = data.inheritable = 0;

  /* openwrt code */

  HIP_IFEL(prctl(PR_SET_KEEPCAPS, 1), -1, "prctl err\n");

  HIP_DEBUG("Now PR_SET_KEEPCAPS=%d\n", prctl(PR_GET_KEEPCAPS));

  HIP_IFEL(!(nobody_pswd = getpwnam(USER_NOBODY)), -1,
	   "Error while retrieving USER 'nobody' uid\n"); 

  HIP_IFEL(capget(&header, &data), -1,
	   "error while retrieving capabilities through capget()\n");

  HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
	    data.effective, data.permitted, data.inheritable);

  ruid=nobody_pswd->pw_uid; 
  euid=nobody_pswd->pw_uid; 
  HIP_DEBUG("Before setreuid(,) UID=%d and EFF_UID=%d\n",
	    getuid(), geteuid());

  /* openwrt code */

  HIP_IFEL(setreuid(ruid,euid), -1, "setruid failed\n");

  HIP_DEBUG("After setreuid(,) UID=%d and EFF_UID=%d\n",
	    getuid(), geteuid());
  HIP_IFEL(capget(&header, &data), -1,
	   "error while retrieving capabilities through 'capget()'\n");

  HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
	    data.effective,data.permitted, data.inheritable);
  HIP_DEBUG ("Going to clear all capabilities except the ones needed\n");
  data.effective = data.permitted = data.inheritable = 0;
  // for CAP_NET_RAW capability 
  data.effective |= (1 <<CAP_NET_RAW );
  data.permitted |= (1 <<CAP_NET_RAW );
  // for CAP_NET_ADMIN capability 
  data.effective |= (1 <<CAP_NET_ADMIN );
  data.permitted |= (1 <<CAP_NET_ADMIN );

  /* openwrt code */

  HIP_IFEL(capset(&header, &data), -1, 
	   "error in capset (do you have capabilities kernel module?)");

  HIP_DEBUG("UID=%d EFF_UID=%d\n", getuid(), geteuid());  
  HIP_DEBUG("effective=%u, permitted = %u, inheritable=%u\n",
	    data.effective, data.permitted, data.inheritable);
#endif /* CONFIG_HIP_PRIVSEP */

 out_err:
  return err;

}

#else /* ! OPENWRT */

/*
 * Note: this function does not go well with valgrind
 */
int hip_set_lowcapability(int run_as_nobody) {
	int err = 0;
#ifdef CONFIG_HIP_PRIVSEP
	cap_value_t cap_list[] = {CAP_NET_RAW, CAP_NET_ADMIN };
	int ncap_list = 2; 
	uid_t ruid,euid;
	cap_t cap_p;
	char *cap_s;
	char *name;
	struct passwd *pswd = NULL;
	struct passwd *hpswd = NULL;

	/* @todo: does this work when you start hipd as root (without sudo) */
         
	if (run_as_nobody) {
		/* Check if user "hipd" exists if it does use it otherwise use "nobody" */
		hpswd = getpwnam(USER_HIPD);
		name = ((hpswd == NULL) ? USER_NOBODY : USER_HIPD);
		/* Chown files that daemon needs to write */
		/*
		if (hpswd != NULL) {
			HIP_IFEL(chown("/etc/hip/test.txt", hpswd->pw_uid, hpswd->pw_gid),
				 -1, "Failed to chown test file\n");
		}
		*/
		if (hpswd != NULL) {
			HIP_IFEL(chown(HIP_CERT_DB_PATH_AND_NAME, hpswd->pw_uid, hpswd->pw_gid),
				 -1, "Failed to chown certdb file\n");
			HIP_IFEL(chown("/etc/hip", hpswd->pw_uid, hpswd->pw_gid),
				 -1, "Failed to chown hip dirctory\n");
		}
	} else
		HIP_IFEL(!(name = getenv("SUDO_USER")), -1,
			 "Failed to determine current username\n");

	HIP_IFEL(prctl(PR_SET_KEEPCAPS, 1), -1, "prctl err\n");

	HIP_DEBUG("Now PR_SET_KEEPCAPS=%d\n", prctl(PR_GET_KEEPCAPS));

        HIP_IFEL(!(pswd = getpwnam(name)), -1,
                 "Error while retrieving USER '%s' uid\n", name);

	HIP_IFEL(!(cap_p = cap_get_proc()), -1, "Error getting capabilities\n");
	HIP_DEBUG("cap_p %s\n", cap_s = cap_to_text(cap_p, NULL));
	cap_free(cap_s);

	ruid=pswd->pw_uid;
	euid=pswd->pw_uid;

	HIP_DEBUG("Before setreuid UID=%d and EFF_UID=%d\n",
		  getuid(), geteuid());

	HIP_IFEL(setreuid(ruid,euid), -1, "setruid failed\n");

	HIP_DEBUG("After setreuid UID=%d and EFF_UID=%d\n",
		  getuid(), geteuid());

	HIP_DEBUG ("Going to clear all capabilities except the ones needed\n");
	HIP_IFEL(cap_clear(cap_p)<0, -1, "Error clearing capabilities\n");

	HIP_IFEL(cap_set_flag(cap_p, CAP_EFFECTIVE, ncap_list, cap_list, CAP_SET)<0, 
		 -1, "Error setting capability flags\n");
	HIP_IFEL(cap_set_flag(cap_p, CAP_PERMITTED, ncap_list, cap_list, CAP_SET)<0, 
		 -1, "Error setting capability flags\n");
	HIP_IFEL(cap_set_proc(cap_p)<0, -1, "Error modifying capabilities\n");
	HIP_DEBUG("UID=%d EFF_UID=%d\n", getuid(), geteuid());	
	HIP_DEBUG("cap_p %s\n", cap_s = cap_to_text(cap_p, NULL));
	cap_free(cap_s);

out_err:
	cap_free(cap_p);

#endif /* CONFIG_HIP_PRIVSEP */

	return err;

}
#endif
