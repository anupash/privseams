/** @file
 * This file defines functions for configuring the the Host Identity
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
 */
#include "hipconf.h"
#include "libhipopendht.h"

/* hip nat on|off|peer_hit is currently specified. For peer_hit we should 'on'
   the nat mapping only when the communication takes place with specified
   peer_hit --Abi */
/** A help string containing the usage of @c hipconf. */
const char *hipconf_usage =
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
"load config default\n"
"get hi default\n"
"run normal|opp <binary>\n"
#ifdef CONFIG_HIP_OPPORTUNISTIC
"set opp on|off\n"
#endif
#ifdef CONFIG_HIP_OPENDHT
"dht gw <IPv4|hostname> <port> <ttl>\n"
"dht get <fqdn/hit>\n"
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
        hip_conf_handle_ttl,
        hip_conf_handle_gw,
        hip_conf_handle_get,
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
	else if (!strcmp("load", text))
		ret = ACTION_LOAD;
        else if (!strcmp("dht", text))
                ret = ACTION_DHT;
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
        case ACTION_DHT:
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
#ifdef CONFIG_HIP_OPENDHT
        else if (!strcmp("ttl", text))
                ret = TYPE_TTL;
        else if (!strcmp("gw", text))
                ret = TYPE_GW;
        else if (!strcmp("get", text))
                 ret = TYPE_GET;
#endif
	else if (!strcmp("config", text))
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
        case ACTION_DHT:
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
	int err = 0;
	int status = 0;
	struct in6_addr hit;
	
	HIP_DEBUG("nat setting. Options:%s\n", opt[0]);

	HIP_IFEL((optc != 1), -1, "Missing arguments\n");

	if (!strcmp("on",opt[0])) {
		memset(&hit,0,sizeof(struct in6_addr));
		status = SO_HIP_SET_NAT_ON; 
	} else if (!strcmp("off",opt[0])) {
		memset(&hit,0,sizeof(struct in6_addr));
                status = SO_HIP_SET_NAT_OFF;
	} else {
		HIP_IFEL(0, -1, "bad args\n");
	}
#if 0 /* Not used currently */
	else {
		ret = inet_pton(AF_INET6, opt[0], &hit);
		if (ret < 0 && errno == EAFNOSUPPORT) {
			HIP_PERROR("inet_pton: not a valid address family\n");
			err = -EAFNOSUPPORT;
			goto out_err;
		} else if (ret == 0) {
			HIP_ERROR("inet_pton: %s: not a valid network address\n", opt[0]);
			err = -EINVAL;
			goto out_err;
		}
		status = SO_HIP_SET_NAT_ON;
	}

	HIP_IFEL(hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
					  sizeof(struct in6_addr)), -1,
		 "build param hit failed: %s\n", strerror(err));
#endif

	HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1, "build hdr failed: %s\n", strerror(err));

 out_err:
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

/* ================================================================================== */

int hip_conf_handle_ttl(struct hip_common *msg, int action, const char *opt[], int optc)
{
    int ret = 0;
    printf("Got to the DHT ttl handle for hipconf, NO FUNCTIONALITY YET\n");
    return(ret);
}

int hip_conf_handle_gw(struct hip_common *msg, int action, const char *opt[], int optc)
{
	int err;
	int status = 0;
	int ret;
	struct in_addr ip_gw;
        struct in6_addr ip_gw_mapped;
        struct addrinfo new_gateway;
        struct hip_opendht_gw_info *gw_info;

	HIP_DEBUG("Resolving new gateway for openDHT %s\n", opt[0]);
        
	if (optc != 3) {
		HIP_ERROR("Missing arguments\n");
		err = -EINVAL;
		goto out_err;
	}

        memset(&new_gateway, '0', sizeof(new_gateway));
        ret = 0;   
        /* resolve the new gateway */
#ifdef CONFIG_HIP_OPENDHT
        ret = resolve_dht_gateway_info(opt[0], &new_gateway);
#else
	HIP_ERROR("OpenDHT support not compiled in\n");
	goto out_err;
#endif /* CONFIG_HIP_OPENDHT */
        if (ret < 0) goto out_err;
        struct sockaddr_in *sa = (struct sockaddr_in *)new_gateway.ai_addr;
        /*
        HIP_DEBUG("addr %s ", inet_ntoa(sa->sin_addr));       
        HIP_DEBUG("port %s ttl %s\n", opt[1], opt[2]);      
        */  
        ret = 0;
	ret = inet_pton(AF_INET, inet_ntoa(sa->sin_addr), &ip_gw);
        IPV4_TO_IPV6_MAP(&ip_gw, &ip_gw_mapped);
	if (ret < 0 && errno == EAFNOSUPPORT) {
		HIP_PERROR("inet_pton: not a valid address family\n");
		err = -EAFNOSUPPORT;
		goto out_err;
	} else if (ret == 0) {
		HIP_ERROR("inet_pton: %s: not a valid network address\n", opt[0]);
		err = -EINVAL;
		goto out_err;
	}

        err = hip_build_param_opendht_gw_info(msg, &ip_gw_mapped, atoi(opt[2]), atoi(opt[1]));
	if (err) {
		HIP_ERROR("build param hit failed: %s\n", strerror(err));
		goto out_err;
	}

	err = hip_build_user_hdr(msg, SO_HIP_DHT_GW, 0);
	if (err) {
		HIP_ERROR("build hdr failed: %s\n", strerror(err));
		goto out_err;
	}
       
 out_err:
	return err;
}

int hip_conf_handle_get(struct hip_common *msg, int action, const char *opt[], int optc)
{
    int ret = 0;
#ifdef CONFIG_HIP_OPENDHT
    int s, error;
    char dht_response[1024];
    char opendht[] = "planetlab1.diku.dk";
    char host_addr[] = "127.0.0.1"; /* TODO change this to something smarter :) */
    struct addrinfo serving_gateway;
    memset(&serving_gateway, '0', sizeof(struct addrinfo));

    s = init_dht_gateway_socket(s);
    if (s < 0) 
    {
        HIP_DEBUG("Socket creation failed!\n");
        exit(-1);
    }
    error = 0;
    error = resolve_dht_gateway_info (opendht, &serving_gateway);
    if (error < 0) 
    {
        HIP_DEBUG("Resolve error!\n");
        exit(-1);
    }
    error = 0;
    error = connect_dht_gateway(s, &serving_gateway);
    if (error < 0) 
    {
        HIP_DEBUG("Connect error!\n");
        exit(-1);
    }

    memset(dht_response, '\0', sizeof(dht_response));
    ret = opendht_get(s, (unsigned char *)opt[0], (unsigned char *)host_addr);
    ret = opendht_read_response(s, dht_response); 
    close(s);
    if (ret == -1) 
    {
        HIP_DEBUG("Get error!\n");
        exit (-1);
    }
    if (ret == 0)
        HIP_DEBUG("Value received from the DHT %s\n",dht_response);
#endif 
    return(ret);
}

/* ================================================================================== */

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

int hip_conf_handle_run_normal(struct hip_common *msg, int action,
			       const char *opt[], int optc)
{
	return hip_handle_exec_application(0, EXEC_LOADLIB_HIP,
					   (char **) &opt[0], optc);
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
		 argv[0], hipconf_usage);

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
 * Handles the hipconf commands where the type is @c run. Execute new
 * application and set environment variable "LD_PRELOAD" to as type
 * says.
 * @note In order to this function to work properly, "make install"
 * must be executed to install libraries to right paths. Also library
 * paths must be set right.
 *
 * @see
 * exec_app_types\n
 * EXEC_LOADLIB_OPP\n
 * EXEC_LOADLIB_HIP\n
 * EXEC_LOADLIB_NONE\n
 *
 * @param type   the numeric action identifier for the action to be performed.
 * @param argv   an array of pointers to the command line arguments after
 *               the action and type.
 * @param argc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
int hip_handle_exec_application(int do_fork, int type, char *argv[], int argc)
{
	/* Variables. */
	char *libs;
	char *path = "/usr/lib:/lib:/usr/local/lib";
	va_list args;
	int err = 0;

	if (do_fork)
		err = fork();

	if (err < 0) {
		HIP_ERROR("Failed to exec new application.\n");
	} else if (err > 0) {
		err = 0;
	} else if(err == 0) {
		setenv("LD_LIBRARY_PATH", path, 1);
		HIP_DEBUG("Exec new application.\n");
		if (type == EXEC_LOADLIB_HIP) {
#ifdef CONFIG_HIP_OPENDHT
			libs = "libinet6.so:libhiptool.so:libhipopendht.so";
#else
			libs = "libinet6.so:libhiptool.so";
#endif
		} else {
#ifdef CONFIG_HIP_OPENDHT
			libs = "libopphip.so:libinet6.so:libhiptool.so:libhipopendht.so";
#else
			libs = "libopphip.so:libinet6.so:libhiptool.so";
#endif
		}
		setenv("LD_PRELOAD", libs, 1);

		HIP_DEBUG("LD_PRELOADing\n");
		err = execvp(argv[0], argv);
		if (err != 0) {
			HIP_DEBUG("Executing new application failed!\n");
			exit(1);
		}
	}

out_err:
	return (err);
}






