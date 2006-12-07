/** @file
 * This file defines a command line tool for configuring the the Host Identity
 * Protocol daemon (hipd).
 *
 * @author  Janne Lundberg <jlu_tcs.hut.fi>
 * @author  Miika Komu <miika_iki.fi>
 * @author  Mika Kousa <mkousa_cc.hut.fi>
 * @author  Anthony D. Joseph <adj_hiit.fi>
 * @author  Abhinav Pathak <abhinav.pathak_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @author  Anu Markkola
 * @author  Lauri Silvennoinen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>
 * @todo    add/del map
 * @todo    fix the rst kludges
 * @todo    read the output message from send_msg?
 * @bug     makefile compiles prefix of debug messages wrong for hipconf in 
 *          "make all"
 */
#include "hipconftool.h"

/* hip nat on|off|peer_hit is currently specified. For peer_hit we should 'on'
   the nat mapping only when the communication takes place with specified
   peer_hit --Abi */
/** A help string containing the usage of @c hipconf. */
const char *usage =
#ifdef CONFIG_HIP_ESCROW
"add|del escrow  hit\n"
#endif
"add|del map hit ipv6\n"
"add|del service escrow|rvs\n"
"add rvs <hit> <ipv6>\n"
"del hi <hit>\n"
#ifdef CONFIG_HIP_ICOOKIE
"get|set|inc|dec|new puzzle all|hit\n"
#else
"get|set|inc|dec|new puzzle all\n"
#endif
"hip bos\n"
"hip nat on|off|peer_hit\n"
"hip rst all|peer_hit\n"
"new|add hi anon|pub rsa|dsa filebasename\n"
"new|add hi default\n"
"load conf default\n"
"get hi default\n"
"run normal|opp <binary>\n"
#ifdef CONFIG_HIP_OPPORTUNISTIC
"set opp on|off\n"
#endif
;

/** Function pointer array containing pointers to handler functions.
 *  @note Keep the elements in the same order as the @c TYPE values are defined
 *  in hipconf.h because type values are used as @c action_handler array index.
 */
int (*action_handler[])(struct hip_common *, int action,const char *opt[], int optc) = 
{
	NULL, /* reserved */
	hip_conf_handle_hi,
	hip_conf_handle_map,
	hip_conf_handle_rst,
	hip_conf_handle_rvs,
	hip_conf_handle_bos,
	hip_conf_handle_puzzle,
	hip_conf_handle_nat,
	hip_conf_handle_opp,
	hip_conf_handle_escrow,
	hip_conf_handle_service,
	hip_conf_handle_load,
	hip_conf_handle_run_normal, /* run */
	NULL, /* run */
};

/**
 * Maps symbolic hipconf action (=add/del) names into numeric action
 * identifiers.
 * 
 * @param  text the action as a string.
 * @return the numeric action id correspoding to the symbolic text.
 */
int hip_conf_get_action(char *text) {
	int ret = -1;

	if (!strcmp("add", text))
		ret = ACTION_ADD;
	else if (!strcmp("del", text))
		ret = ACTION_DEL;
	else if (!strcmp("new", text))
		ret = ACTION_NEW;
	else if (!strcmp("get", text))
		ret = ACTION_GET;
	else if (!strcmp("set", text))
		ret = ACTION_SET;
	else if (!strcmp("inc", text))
		ret = ACTION_INC;
	else if (!strcmp("dec", text))
		ret = ACTION_DEC;
	else if (!strcmp("hip", text))
		ret = ACTION_HIP;
	else if (!strcmp("run", text))
		ret = ACTION_RUN;
	else if (!strcmp("load",text))
		ret =ACTION_LOAD;

	return ret;
}

/**
 * Gets the minimum amount of arguments needed to be given to the action.
 * 
 * @param  action action type
 * @return how many arguments needs to be given at least
 */
int hip_conf_check_action_argc(int action) {
	int count = -1;

	switch (action) {
	case ACTION_ADD:
		count = 2;
		break;
	case ACTION_DEL:
		count = 2;
		break;
	case ACTION_NEW:
		break;
	case ACTION_HIP:
		break;
	case ACTION_SET:
		count = 2;
		break;
	case ACTION_INC:
		count = 2;
		break;
	case ACTION_DEC:
		break;
	case ACTION_GET:
		count = 2;
		break;
	case ACTION_RUN:
		count = 2;
		break;
	case ACTION_LOAD:
		count=2;
		break;

	}

	return count;
}

/**
 * Maps symbolic hipconf type (=lhi/map) names to numeric types.
 * 
 * @param  text the type as a string.
 * @return the numeric type id correspoding to the symbolic text.
 */
int hip_conf_get_type(char *text) {
	int ret = -1;

	if (!strcmp("hi", text))
		ret = TYPE_HI;
	else if (!strcmp("map", text))
		ret = TYPE_MAP;
	else if (!strcmp("rst", text))
		ret = TYPE_RST;
	else if (!strcmp("rvs", text))
		ret = TYPE_RVS;
	else if (!strcmp("bos", text))
		ret = TYPE_BOS;
	else if (!strcmp("nat", text))
		ret = TYPE_NAT;
	else if (!strcmp("puzzle", text))
		ret = TYPE_PUZZLE;	
	else if (!strcmp("service", text))
		ret = TYPE_SERVICE;	
	else if (!strcmp("normal", text))
		ret = TYPE_RUN;
#ifdef CONFIG_HIP_OPPORTUNISTIC
	else if (!strcmp("opp", text))
		ret = TYPE_OPP; 
#endif
#ifdef CONFIG_HIP_ESCROW
	else if (!strcmp("escrow", text))
		ret = TYPE_ESCROW;
#endif		
	else if (!strcmp("conf", text))
		ret = TYPE_CONFIG;
	return ret;
}

int hip_conf_get_type_arg(int action) {
        int type_arg = -1;

        switch (action) {
        case ACTION_ADD:
        case ACTION_DEL:
        case ACTION_NEW:
        case ACTION_HIP:
        case ACTION_INC:
        case ACTION_DEC:
        case ACTION_SET:
        case ACTION_GET:
        case ACTION_RUN:
	case ACTION_LOAD:
                type_arg = 2;
                break;
        }

        return type_arg;
}

/**
 * Handles the hipconf commands where the type is @c rvs.
 *  
 * Create a message to the kernel module from the function parameters @c msg,
 * @c action and @c opt[].
 * 
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type (should be the HIT and the corresponding
 *               IPv6 address).
 * @param optc   the number of elements in the array (@b 2).
 * @return       zero on success, or negative error value on error.
 * @note         Currently only action @c add is supported.
 * @todo         If the current machine has more than one IP address
 *               there should be a way to choose which of the addresses
 *               to register to the rendezvous server.
 * @todo         There are currently four different HITs at the @c dummy0
 *               interface. There should be a way to choose which of the HITs
 *               to register to the rendezvous server.
 */ 
int hip_conf_handle_rvs(struct hip_common *msg, int action, const char *opt[], 
	       int optc)
{
	struct in6_addr hit, ip6;
	int err=0;
	int ret;
	HIP_DEBUG("handle_rvs() invoked.\n");
	HIP_INFO("action=%d optc=%d\n", action, optc);
	
	HIP_IFEL((action != ACTION_ADD), -1,"Only action \"add\" is supported for \"rvs\".\n");
	HIP_IFEL((optc != 2), -1, "Missing arguments\n");
	
	HIP_IFEL(convert_string_to_address(opt[0], &hit), -1,"string to address conversion failed\n");
	HIP_IFEL(convert_string_to_address(opt[1], &ip6), -1,"string to address conversion failed\n");
	
	HIP_IFEL(hip_build_param_contents(msg, (void *) &hit,
	HIP_PARAM_HIT, sizeof(struct in6_addr)), -1,"build param hit failed\n");
	
	HIP_IFEL(hip_build_param_contents(msg, (void *) &ip6,
					  HIP_PARAM_IPV6_ADDR,
					  sizeof(struct in6_addr)), -1,
		 "build param hit failed\n");

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ADD_RENDEZVOUS, 0), -1,
		 "build hdr failed\n");
out_err:
	return err;

}

/**
 * Handles the hipconf commands where the type is @c hi.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_hi(struct hip_common *msg,
	      int action,
	      const char *opt[],
	      int optc) {
  int err = 0, anon = 0, use_default = 0;

  _HIP_INFO("action=%d optc=%d\n", action, optc);

  if (action == ACTION_DEL)
    return hip_conf_handle_hi_del(msg, action, opt, optc);
  else if (action == ACTION_GET)
    return hip_conf_handle_hi_get(msg, action, opt, optc);

  /* Check min/max amount of args */
  if (optc < 1 || optc > 3) {
    HIP_ERROR("Too few arguments\n");
    err = -EINVAL;
    goto out_err;
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
    goto out_err;
  }  
    
  if (use_default) {
    if (optc != 1) {
      HIP_ERROR("Wrong number of args for default\n");
      err = -EINVAL;
      goto out_err;
    }
  } else {
    if (optc != 3) {
      HIP_ERROR("Wrong number of args\n");
      err = -EINVAL;
      goto out_err;
    }
  }

  err = hip_serialize_host_id_action(msg, action, anon, use_default,
				     opt[OPT_HI_FMT], opt[OPT_HI_FILE]);

 out_err:

  return err;
}

/**
 * Handles the hipconf commands where the type is @c map.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type. (should be the HIT and the corresponding
 *               IPv6 address).
 * @param optc   the number of elements in the array (@b 2).
 * @return       zero on success, or negative error value on error.
 * @note         Does not support @c del action.
 */
int hip_conf_handle_map(struct hip_common *msg, int action,
	       const char *opt[], int optc) {
	int err = 0;
	int ret;
	struct in6_addr hit, ip6;

	HIP_DEBUG("action=%d optc=%d\n", action, optc);

	HIP_IFEL((optc != 2), -1, "Missing arguments\n");
	
	HIP_IFEL(convert_string_to_address(opt[0], &hit), -1,
		 "string to address conversion failed\n");

	HIP_IFEL(convert_string_to_address(opt[1], &ip6), -1,
		 "string to address conversion failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
					  sizeof(struct in6_addr)), -1,
		 "build param hit failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (void *) &ip6,
					  HIP_PARAM_IPV6_ADDR,
					  sizeof(struct in6_addr)), -1,
		 "build param hit failed\n");

	switch(action) {
	case ACTION_ADD:
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ADD_PEER_MAP_HIT_IP,
					    0), -1, "add peer map failed\n");
		break;
	case ACTION_DEL:
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DEL_PEER_MAP_HIT_IP,
					    0), -1, "del peer map failed\n");
		break;
	default:
		err = -1;
		break;
	}
	
out_err:
	return err;
}

/**
 * Handles the hipconf commands where the type is @c del.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_hi_del(struct hip_common *msg, int action,
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
 	
 	HIP_HEXDUMP("HIT to delete: ", &hit,
 		    sizeof(struct in6_addr));
 	
 	err = hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
 				       sizeof(struct in6_addr));
 	if (err) {
 		HIP_ERROR("build param hit failed: %s\n", strerror(err));
 		goto out;
 	}
 	
 	err = hip_build_user_hdr(msg, SO_HIP_DEL_LOCAL_HI, 0);
 	if (err) {
 		HIP_ERROR("build hdr failed: %s\n", strerror(err));
 		goto out;
 	}
 	
out:
	return err;
}

/**
 * Handles the hipconf commands where the type is @c del.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_hi_get(struct hip_common *msg, int action,
		      const char *opt[], int optc) 
{
	struct gaih_addrtuple *at = NULL;
	struct gaih_addrtuple *tmp;
	int err = 0;
 	
 	HIP_IFEL((optc != 1), -1, "Missing arguments\n");

	/* XX FIXME: THIS IS KLUDGE; RESORTING TO DEBUG OUTPUT */
	err = get_local_hits(NULL, &at);
	if (err)
		goto out_err;

	tmp = at;
	while (tmp) {
		/* XX FIXME: THE LIST CONTAINS ONLY A SINGLE HIT */
		_HIP_DEBUG_HIT("HIT", &tmp->addr);
		tmp = tmp->next;
	}

	HIP_DEBUG("*** Do not use the last HIT (see bugzilla 175 ***\n");
 	 	
out_err:
	if (at)
		HIP_FREE(at);
	return err;
}


/**
 * Handles the hipconf commands where the type is @c rst.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_rst(struct hip_common *msg, int action,
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

	err = hip_build_user_hdr(msg, SO_HIP_RST, 0);
	if (err) {
		HIP_ERROR("build hdr failed: %s\n", strerror(err));
		goto out;
	}

 out:
	return err;
}


/**
 * Handles the hipconf commands where the type is @c bos.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_bos(struct hip_common *msg, int action,
		   const char *opt[], int optc) 
{
	int err;

	/* Check that there are no extra args */
	if (optc != 0) {
		HIP_ERROR("Extra arguments\n");
		err = -EINVAL;
		goto out;
	}

	/* Build the message header */
	err = hip_build_user_hdr(msg, SO_HIP_BOS, 0);
	if (err) {
		HIP_ERROR("build hdr failed: %s\n", strerror(err));
		goto out;
	}

 out:
	return err;
}

/**
 * Handles the hipconf commands where the type is @c nat.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_nat(struct hip_common *msg, int action,
		   const char *opt[], int optc)
{
	int err;
	int status = 0;
	int ret;
	struct in6_addr hit;
	
	HIP_DEBUG("nat setting. Options:%s\n", opt[0]);

	if (optc != 1) {
		HIP_ERROR("Missing arguments\n");
		err = -EINVAL;
		goto out;
	}

	if (!strcmp("on",opt[0])) {
		memset(&hit,0,sizeof(struct in6_addr));
		status = SO_HIP_SET_NAT_ON; 
	} else if (!strcmp("off",opt[0])) {
		memset(&hit,0,sizeof(struct in6_addr));
                status = SO_HIP_SET_NAT_OFF;
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
		status = SO_HIP_SET_NAT_ON;
	}

	err = hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
				       sizeof(struct in6_addr));
	if (err) {
		HIP_ERROR("build param hit failed: %s\n", strerror(err));
		goto out;
	}

	err = hip_build_user_hdr(msg, status, 0);
	if (err) {
		HIP_ERROR("build hdr failed: %s\n", strerror(err));
		goto out;
	}

 out:
	return err;

}

/**
 * Handles the hipconf commands where the type is @c puzzle.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_puzzle(struct hip_common *msg, int action,
			   const char *opt[], int optc) 
{
	int err = 0, ret, msg_type, all;
	hip_hit_t hit = {0};

	if (optc != 1) {
		HIP_ERROR("Missing arguments\n");
		err = -EINVAL;
		goto out;
	}

	switch (action) {
	case ACTION_NEW:
		msg_type = SO_HIP_CONF_PUZZLE_NEW;
		break;
	case ACTION_INC:
		msg_type = SO_HIP_CONF_PUZZLE_INC;
		break;
	case ACTION_DEC:
		msg_type = SO_HIP_CONF_PUZZLE_DEC;
		break;
	case ACTION_SET:
		msg_type = SO_HIP_CONF_PUZZLE_SET;
		err = -1; /* Not supported yet */
		break;
	case ACTION_GET:
		msg_type = SO_HIP_CONF_PUZZLE_GET;
		err = -1; /* Not supported yet */
		break;
	default:
		err = -1;
	}

	if (err) {
		HIP_ERROR("Action (%d) not supported yet\n", action);
		goto out;
	}

	all = !strcmp("all", opt[0]);

	if (!all) {
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

	err = hip_build_user_hdr(msg, msg_type, 0);
	if (err) {
		HIP_ERROR("build hdr failed: %s\n", strerror(err));
		goto out;
	}

	if (all) {
		printf("New puzzle difficulty effective immediately\n");
	} else {
		printf("New puzzle difficulty is effective in %d seconds\n",
			 HIP_R1_PRECREATE_INTERVAL);
	}

 out:
	return err;
}

/**
 * Handles the hipconf commands where the type is @c opp.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_opp(struct hip_common *msg, int action,
		   const char *opt[], int optc)
{
	unsigned int oppmode = 0;
	int err = 0;

	if (action == ACTION_RUN)
		return hip_handle_exec_application(0, EXEC_LOADLIB_OPP,
						   (char **) &opt[0],
						   optc);
	if (optc != 1) {
		HIP_ERROR("Incorrect number of arguments\n");
		err = -EINVAL;
		goto out;
	}

	if (!strcmp("on",opt[0])) {
		oppmode = 1;
	} else if (!strcmp("off", opt[0])){
		oppmode = 0;
	} else {
		HIP_ERROR("Invalid argument\n");
		err = -EINVAL;
		goto out;
	}

	err = hip_build_param_contents(msg, (void *) &oppmode, HIP_PARAM_UINT,
				       sizeof(unsigned int));
	if (err) {
		HIP_ERROR("build param oppmode failed: %s\n", strerror(err));
		goto out;
	}

	/* Build the message header */
	err = hip_build_user_hdr(msg, SO_HIP_SET_OPPORTUNISTIC_MODE, 0);
	if (err) {
		HIP_ERROR("build hdr failed: %s\n", strerror(err));
		goto out;
	}

 out:
	return err;
}

/**
 * Handles the hipconf commands where the type is @c escrow.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_escrow(struct hip_common *msg, int action, const char *opt[], 
		      int optc)
{
	struct in6_addr hit;
	struct in6_addr ip;
	int err = 0;

	HIP_DEBUG("hipconf: using escrow");
	HIP_INFO("action=%d optc=%d\n", action, optc);
	
	HIP_IFEL((optc != 2), -1, "Missing arguments\n");
	
	HIP_IFEL(convert_string_to_address(opt[0], &hit), -1,
		 "string to address conversion failed\n");
	HIP_IFEL(convert_string_to_address(opt[1], &ip), -1,
		 "string to address conversion failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
					  sizeof(struct in6_addr)), -1,
		 "build param hit failed\n");
	
	HIP_IFEL(hip_build_param_contents(msg, (void *) &ip,
					  HIP_PARAM_IPV6_ADDR,
					  sizeof(struct in6_addr)), -1,
		 "build param hit failed\n");

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ADD_ESCROW, 0), -1,
		 "build hdr failed\n");
out_err:
	return err;
	
}

/**
 * Handles @c service commands received from @c hipconf.
 *  
 * Create a message to the kernel module from the function parameters @c msg,
 * @c action and @c opt[].
 * 
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed on
 *               the given mapping.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type (pointer to @b "escrow" or @b "rvs").
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_service(struct hip_common *msg, int action, const char *opt[], 
		       int optc)
{
	int err = 0;

	HIP_DEBUG("hipconf: handling service.\n");
	HIP_INFO("action=%d optc=%d\n", action, optc);
	
	HIP_IFEL((action != ACTION_ADD), -1,
		 "Only action \"add\" is supported for \"service\".\n");
	HIP_IFEL((optc < 1), -1, "Missing arguments\n");
	HIP_IFEL((optc > 1), -1, "Too many arguments\n");
	
	if (strcmp(opt[0], "escrow") == 0) {
		HIP_INFO("Adding escrow service.\n");
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OFFER_ESCROW, 0), -1,
			 "build hdr failed\n");
	}
	else if (strcmp(opt[0], "rvs") == 0) {
		HIP_INFO("Adding rvs service.\n");
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OFFER_RENDEZVOUS, 0), -1,
			 "build hdr failed\n");
	}
	else {
		HIP_ERROR("Unknown service %s.\n", opt[0]);
	}

 out_err:
	return err;
	
}

/**
 * Handles the hipconf commands where the type is @c load.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_load(struct hip_common *msg, int action,
		    const char *opt[], int optc)
{
  	int arg_len, err = 0, i, len;
	char c[45], *hip_arg, ch, str[128], *fname, *args[64];
	FILE *hip_config = NULL;  
	List list;

	HIP_IFEL((optc != 1), -1, "Missing arguments\n");

	if (!strcmp(opt[0], "default"))
		fname = HIPD_CONFIG_FILE;
	else
		fname = (char *) opt[0];


	HIP_IFEL(!(hip_config = fopen(fname, "r")), -1, 
		 "Error: can't open config file %s.\n", fname);
        
	while(err == 0 && fgets(c,sizeof(c),hip_config) != NULL) {
		if ((c[0] =='#') || (c[0] =='\n'))
			continue;

		/* prefix the contents of the line with" hipconf"  */
		memset(str, '\0', sizeof(str));
		strcpy(str, "hipconf");
		str[strlen(str)] = ' ';
		hip_arg = strcat(str, c);
		/* replace \n with \0  */
		hip_arg[strlen(hip_arg) - 1] = '\0';

		/* split the line into an array of strings and feed it
		   recursively to hipconf */
		initlist(&list);
		extractsubstrings(hip_arg, &list);
		len = length(&list);
		for(i = 0; i < len; i++) {
			/* the list is backwards ordered */
			args[len - i - 1] = getitem(&list, i);
		}
		err = hip_do_hipconf(len, args);
		destroy(&list);
	}

 out_err:
	if (hip_config)
		fclose(hip_config);

	return err;

}

int hip_conf_handle_run_normal(struct hip_common *msg, int action,
			       const char *opt[], int optc)
{
		return hip_handle_exec_application(0, EXEC_LOADLIB_HIP,
						   (char **) &opt[0],
						   optc);
}

int hip_do_hipconf(int argc, char *argv[]) {
	int err = 0, type_arg;
	long int action, type;
	struct hip_common *msg = NULL;
	char *text;

	/* we don't want log messages via syslog */
	hip_set_logtype(LOGTYPE_STDERR);
	
	/* parse args */

	HIP_IFEL((argc < 2), -1, "Invalid args.\n%s usage:\n%s\n",
		 argv[0], usage);

	action = hip_conf_get_action(argv[1]);
	HIP_IFEL((action <= 0 || action >= ACTION_MAX), -1,
	       "Invalid action argument '%s'\n", argv[1]);

	HIP_IFEL((argc < hip_conf_check_action_argc(action) + 2), -1,
		 "Not enough arguments given for the action '%s'\n",
		 argv[1]);
	
	HIP_IFEL(((type_arg = hip_conf_get_type_arg(action)) < 0), -1,
		 "Could not parse type\n");

	type = hip_conf_get_type(argv[type_arg]);
	HIP_IFEL((type <= 0 || type >= TYPE_MAX), -1,
		 "Invalid type argument '%s'\n", argv[type_arg]);

	/* allocated space for return value and call hipd */

	HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "malloc failed\n");
	hip_msg_init(msg);

	/* Call handler function from the handler function pointer
	   array at index "type" with given commandline arguments. */
        err = (*action_handler[type])(msg, action, (const char **) &argv[3],
                                              argc - 3);
	HIP_IFEL(err, -1, "failed to handle msg\n");

	/* hipconf new hi does not involve any messages to hipd */
	if (hip_get_msg_type(msg) == 0)
		goto out_err;
	
	/* send msg to hipd */
	HIP_IFEL(hip_send_daemon_info(msg), -1,
		 "sending msg failed\n");

	HIP_INFO("hipconf command successfull\n");

out_err:
	if (msg)
		free(msg);
	
	return err;
}

/**
 * Parses command line arguments and send the appropiate message to hipd
 *
 * @param argc   the number of elements in the array.
 * @param argv   an array of pointers to the command line arguments after
 *               the action and type.
 * @return       zero on success, or negative error value on error.
 */
#ifndef HIP_UNITTEST_MODE /* Unit testing code does not compile with main */
int main(int argc, char *argv[]) {
	return hip_do_hipconf(argc, argv);
}

#endif /* HIP_UNITTEST_MODE */
