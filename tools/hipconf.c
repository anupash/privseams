/*
 * Command line tool for configuring the HIP kernel module.
 *
 * Authors:
 * - Janne Lundberg <jlu@tcs.hut.fi>
 * - Miika Komu <miika@iki.fi>
 * - Mika Kousa <mkousa@cc.hut.fi>
 *
 * Licence: GNU/GPL
 *
 * TODO:
 * - add/del map
 * - fix the rst kludges
 * - read the output message from send_msg?
 *
 * BUGS:
 * - makefile compiles prefix of debug messages wrong for hipconf in "make all"
 *
 */

#include "hipconf.h"

const char *usage = "new|add|del hi default\n"
                    "new|add|del hi anon|pub|default format filebasename\n"
                    "add|del map hit ipv6\n"
                    "rst all|hit\n";

/*
 * Handler functions.
 */
int (*action_handler[])(struct hip_common *, int action,
			const char *opt[], int optc) = {
  NULL, /* reserved */
  handle_hi,
  handle_map,
  handle_rst
};

/**
 * get_action - map symbolic hipconf action (=add/del) names into numeric
 *              action identifiers
 * @text: the action as a string
 *
 * Returns the numeric action id correspoding to the symbolic @text
 */
int get_action(char *text) {
  int ret = -1;

  if (!strcmp("add", text))
    ret = ACTION_ADD;
  else if (!strcmp("del", text))
    ret = ACTION_DEL;
  else if (!strcmp("rst", text))
    ret = ACTION_RST;
  else if (!strcmp("new", text))
    ret = ACTION_NEW;

  return ret;
}

/**
 * get_type - map symbolic hipconf type (=lhi/map) names to numeric types
 * @text: the type as a string
 *
 * Returns: the numeric type id correspoding to the symbolic @text
 */
int get_type(char *text) {
  int ret = -1;

  if (!strcmp("hi", text))
    ret = TYPE_HI;
  else if (!strcmp("map", text))
    ret = TYPE_MAP;
  else if (!strcmp("rst", text))
    ret = TYPE_RST;

  return ret;
}

/**
 * check_and_create_dir - check and create a directory
 * @dirname: the name of the directory
 * @mode:    creation mode for the directory, if it does not exist
 *
 * Returns: 0 if successful, or negative on error.
 */
int check_and_create_dir(char *dirname, mode_t mode) {
  int err = 0;
  struct stat dir_stat;

  HIP_INFO("dirname=%s mode=%o\n", dirname, mode);
  err = stat(dirname, &dir_stat);
  if (err && errno == ENOENT) { /* no such file or directory */
    err = mkdir(dirname, mode);
    if (err) {
      HIP_ERROR("mkdir %s failed: %s\n", dirname,
		strerror(errno));
    }
  } else if (err) {
      HIP_ERROR("stat %s failed: %s\n", dirname,
		strerror(errno));
  }

  return err;
}

/**
 * handle_hi - handle the hipconf commands where the type is "hi"
 *
 */
int handle_hi(struct hip_common *msg,
	      int action,
	      const char *opt[],
	      int optc) {
  int err, ret;
  hip_hdr_type_t numeric_action = 0;
  int anon = 0;
  int use_default = 0;
  char addrstr[INET6_ADDRSTRLEN];
  char *filebasename = NULL;
  int fmt;
  struct hip_lhi lhi;
  struct hip_host_id *host_id = NULL;
  unsigned char *dsa_key_rr = NULL;
  int dsa_key_rr_len;
  DSA *dsa_key = NULL;
  char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];

  HIP_INFO("action=%d optc=%d\n", action, optc);

  /* Check min/max amount of args */
  if (optc < 1 || optc > 3) {
    HIP_ERROR("Too few arguments\n");
    err = -EINVAL;
    goto out;
  }

  if(!strcmp(opt[OPT_HI_TYPE], "pub")) {
    anon = 0;
  } else if(!strcmp(opt[OPT_HI_TYPE], "anon")) {
    anon = 1;
  } else if(!strcmp(opt[OPT_HI_TYPE], "default")) {
    use_default = 1;
  } else {
    HIP_ERROR("Bad hi type (not public, anon or default)\n");
    err = -EINVAL;
    goto out;
  }  

  if (use_default) {
    if (optc != 1) {
      HIP_ERROR("Wrong number of args for default\n");
      err = -EINVAL;
      goto out;
    }
  } else {
    if (optc != 3) {
      HIP_ERROR("Wrong number of args\n");
      err = -EINVAL;
      goto out;
    }
  }

  memset(hostname, 0, HIP_HOST_ID_HOSTNAME_LEN_MAX);
  err = -gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
  if (err) {
    HIP_ERROR("gethostname failed (%d)\n", err);
    goto out;
  }

  HIP_INFO("Using hostname: %s\n", hostname);

  fmt = HIP_KEYFILE_FMT_HIP_DSA_PEM;
  if (!use_default && strcmp(opt[OPT_HI_FMT], "hip-pem-dsa")) {
    HIP_ERROR("Only PEM encoded HIP DSA keys are supported\n");
    err = -ENOSYS;
    goto out;
  }

  /* Set filebasename (depending on whether the user supplied a filebasename or not) */
  if (use_default == 0) {
    HIP_ERROR("Only default HIs are currently supported\n");
    filebasename = malloc(strlen(opt[OPT_HI_FILE]) + 1);
    memcpy(filebasename, opt[OPT_HI_FILE], strlen(opt[OPT_HI_FILE]));
  } else { /* create dynamically default filebasename */
    int filebasename_len, ret;
    HIP_ERROR("No key file given, use default\n");
    filebasename_len = strlen(DEFAULT_CONFIG_DIR) + 1 +
      strlen(DEFAULT_HOST_DSA_KEY_FILE_BASE) + 1;
    filebasename = malloc(filebasename_len);
    if (!filebasename) {
      HIP_ERROR("Could allocate DSA file name\n");
      err = -ENOMEM;
      goto out;
    }
    ret = snprintf(filebasename, filebasename_len, "%s/%s", DEFAULT_CONFIG_DIR,
		   DEFAULT_HOST_DSA_KEY_FILE_BASE);
    if (ret <= 0) {
      err = -EINVAL;
      goto out;
    }
  }

  lhi.anonymous = htons(anon); // XX FIX: htons() needed?

  HIP_DEBUG("Using filebasename: %s\n", filebasename);
  
  switch(action) {
  case ACTION_NEW:
    numeric_action = 0; /* zero means "do not send any message to kernel */

    /* Default directory is created only in "hipconf new default hi" */
    if (use_default) {
      err = check_and_create_dir(DEFAULT_CONFIG_DIR, DEFAULT_CONFIG_DIR_MODE);
      if (err) {
	HIP_ERROR("Could not create default directory\n", err);
	goto out;
      }
    }

    dsa_key = create_dsa_key(DSA_KEY_DEFAULT_BITS);
    if (!dsa_key) {
      HIP_ERROR("creation of dsa key failed\n");
      err = -EINVAL;
      goto out;  
    }

    err = save_dsa_private_key(filebasename, dsa_key);
    if (err) {
      HIP_ERROR("saving of dsa key failed\n");
      goto out;
    }
    break;
  case ACTION_ADD:
    numeric_action = HIP_USER_ADD_LOCAL_HI;

    err = load_dsa_private_key(filebasename, &dsa_key);
    if (err) {
      HIP_ERROR("Loading of the DSA key failed\n");
      goto out;
    }

    dsa_key_rr_len = dsa_to_dns_key_rr(dsa_key, &dsa_key_rr);
    if (dsa_key_rr_len <= 0) {
      HIP_ERROR("dsa_key_rr_len <= 0\n");
      err = -EFAULT;
      goto out;
    }

    err = dsa_to_hit(dsa_key_rr, HIP_HIT_TYPE_HASH126, &lhi.hit);
    if (err) {
      HIP_ERROR("Conversion from DSA to HIT failed\n");
      goto out;
    }
    HIP_HEXDUMP("Calculated HIT: ", &lhi.hit, sizeof(struct in6_addr));
    break;
  case ACTION_DEL:
    numeric_action = HIP_USER_DEL_LOCAL_HI;
    HIP_ERROR("Deletion of HI not implemented yet\n");
    err = -ENOSYS;
    break;
  }

  if (numeric_action == 0)
    goto skip_msg;

  /* The host id is not used for deletion for two reasons:
     1) The private key is also <hack>included in the dsa_key_rr</hack>.
     2) Lhi should be enough to do the deletion. */
  if (numeric_action == ACTION_DEL)
    goto skip_host_id;

  err = alloc_and_set_host_id_param_hdr(&host_id, dsa_key_rr_len, HIP_HI_DSA,
					hostname);
  if (err) {
    goto out;
  }

  err = hip_build_param_host_id(msg, host_id, dsa_key_rr, hostname);
  if (err) {
    HIP_ERROR("Building of host id failed\n");
    goto out;
  }

 skip_host_id:

  err = hip_build_user_hdr(msg, numeric_action, 0);
  if (err) {
    HIP_ERROR("build hdr error %d\n", err);
    goto out;
  }

 skip_msg:

 out:

  if (host_id)
    free(host_id);
  if (dsa_key)
    DSA_free(dsa_key);
  if (dsa_key_rr)
    free(dsa_key_rr);
  if (filebasename)
    free(filebasename);

  return err;
}

/**
 * handle_map - handle all actions related to "mapping"
 * @msg:    the buffer where the message for kernel will be written
 * @action: the action (add/del) to performed on the given mapping
 * @opt:    an array of pointers to the command line arguments after
 *          the action and type, the HIT and the corresponding IPv6 address
 * @optc:   the number of elements in the array (=2, HIT and IPv6 address)
 *
 * Note: does not support "delete" action.
 *
 * Returns: zero on success, else non-zero.
 */
int handle_map(struct hip_common *msg, int action,
	       const char *opt[], int optc) {
  int err = 0;
  int ret;
  struct in6_addr hit, ip6;

  HIP_INFO("action=%d optc=%d\n", action, optc);

  if (optc != 2) {
    HIP_ERROR("Missing arguments\n");
    err = -EINVAL;
    goto out;
  }

  ret = inet_pton(AF_INET6, opt[0], &hit);
  if (ret < 0 && errno == EAFNOSUPPORT) {
    HIP_PERROR("inet_pton: not a valid address family\n");
    err = -EAFNOSUPPORT;
    goto out;
  } else if (ret == 0) {
    HIP_ERROR("inet_pton: %s: not a valid network address\n", opt[0]);
    err = -EINVAL;
    goto out;
  }

  ret = inet_pton(AF_INET6, opt[1], &ip6);
  if (ret < 0 && errno == EAFNOSUPPORT) {
    HIP_PERROR("inet_pton: not a valid address family\n");
    err = -EAFNOSUPPORT;
    goto out;
  } else if (ret == 0) {
    HIP_ERROR("inet_pton: %s: not a valid network address\n", opt[1]);
    err = -EINVAL;
    goto out;
  }

  err = hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
				 sizeof(struct in6_addr));
  if (err) {
    HIP_ERROR("build param hit failed: %s\n", strerror(err));
    goto out;
  }

  err = hip_build_param_contents(msg, (void *) &ip6, HIP_PARAM_IPV6_ADDR,
				 sizeof(struct in6_addr));
  if (err) {
    HIP_ERROR("build param hit failed: %s\n", strerror(err));
    goto out;
  }

  switch(action) {
  case ACTION_ADD:
    err = hip_build_user_hdr(msg, HIP_USER_ADD_PEER_MAP_HIT_IP, 0);
    if (err) {
      HIP_ERROR("build hdr failed: %s\n", strerror(err));
      goto out;
    }
    break;
  case ACTION_DEL:
	  err = hip_build_user_hdr(msg, HIP_USER_DEL_PEER_MAP_HIT_IP, 0);
	  if (err) {
		  HIP_ERROR("build hdr failed: %s\n", strerror(err));
		  goto out;
	  }
	  break;
  }

 out:
  return err;
}

int handle_rst(struct hip_common *msg, int action,
	       const char *opt[], int optc) 
{
	int err;
	int ret;
	struct in6_addr hit;

	if (optc != 1) {
		HIP_ERROR("Missing arguments\n");
		err = -EINVAL;
		goto out;
	}

	if (!strcmp("all",opt[0])) {
		memset(&hit,0,sizeof(struct in6_addr));
	} else {
		ret = inet_pton(AF_INET6, opt[0], &hit);
		if (ret < 0 && errno == EAFNOSUPPORT) {
			HIP_PERROR("inet_pton: not a valid address family\n");
			err = -EAFNOSUPPORT;
			goto out;
		} else if (ret == 0) {
			HIP_ERROR("inet_pton: %s: not a valid network address\n", opt[0]);
			err = -EINVAL;
			goto out;
		}
	}

	err = hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
				       sizeof(struct in6_addr));
	if (err) {
		HIP_ERROR("build param hit failed: %s\n", strerror(err));
		goto out;
	}

	err = hip_build_user_hdr(msg, HIP_USER_RST, 0);
	if (err) {
		HIP_ERROR("build hdr failed: %s\n", strerror(err));
		goto out;
	}
	
 out:
	return err;
}

/* Parse command line arguments and send the appropiate message to
 * the kernel module
 */
#ifndef HIP_UNITTEST_MODE /* Unit testing code does not compile with main */
int main(int argc, char *argv[]) {
  int err = 0;
  long int action, type;
  struct hip_common *msg;

  if (argc < 2) {
    err = -EINVAL;
    //  display_usage();
    HIP_ERROR("Invalid args.\n%s usage:\n%s\n", argv[0], usage);
    goto out;
  }
  
  set_logtype(LOGTYPE_STDERR); // we don't want log messages via syslog

  action = get_action(argv[1]);
  if (action <= 0 || action >= ACTION_MAX) {
    err = -EINVAL;
    HIP_ERROR("Invalid action argument '%s'\n", argv[1]);
    goto out;
  }
  HIP_INFO("action=%d\n", action);

  if (action != ACTION_RST) {

	  type = get_type(argv[2]);
	  if (type <= 0 || type >= TYPE_MAX) {
		  err = -EINVAL;
		  HIP_ERROR("Invalid type argument '%s'\n", argv[2]);
		  goto out;
	  }
	  HIP_INFO("type=%d\n", type);
  }

  msg = malloc(HIP_MAX_PACKET);
  if (!msg) {
	  HIP_ERROR("malloc failed\n");
	  goto out;
  }
  hip_msg_init(msg);

  if (action != ACTION_RST) {
	  err = (*action_handler[type])(msg, action, (const char **) &argv[3],
					argc - 3);
  } else {
	  err = (*action_handler[TYPE_RST])(msg, ACTION_RST, (const char **) &argv[2],
					    argc - 2);
  }

  if (err) {
     HIP_ERROR("failed to handle msg\n");
     goto out_malloc;
  }

  /* hipconf new hi does not involve any messages to kernel */
  if (hip_get_msg_type(msg) == 0)
    goto skip_msg;

  err = send_msg(msg);
  if (err) {
     HIP_ERROR("sending msg failed\n");
     goto out_malloc;
  }

 skip_msg:

 out_malloc:
  free(msg);
 out:
  return err;
}
#endif /* HIP_UNITTEST_MODE */
