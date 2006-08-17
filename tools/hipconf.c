/*
 * Command line tool for configuring the HIP kernel module.
 *
 * Authors:
 * - Janne Lundberg <jlu@tcs.hut.fi>
 * - Miika Komu <miika@iki.fi>
 * - Mika Kousa <mkousa@cc.hut.fi>
 * - Anthony D. Joseph <adj@hiit.fi>
 * - Abhinav Pathak <abhinav.pathak@hiit.fi>
 * - Bing Zhou <bingzhou@cc.hut.fi>
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

const char *usage =
	"new|add hi default\n"
	"new|add hi anon|pub rsa|dsa filebasename\n"
	"del hi <hit>\n"
	"add|del map hit ipv6\n"
	"hip rst all|peer_hit\n"
	"add rvs hit ipv6\n"
	"hip bos\n"
	"hip nat on|off|peer_hit\n"
	"add|del service service_type\n"
	"run normal|opp <binary>\n"
#ifdef CONFIG_HIP_SPAM
	"get|set|inc|dec|new puzzle all|hit\n"
#else
	"get|set|inc|dec|new puzzle all\n"
#endif

#ifdef CONFIG_HIP_ESCROW
	"add|del escrow hit\n"
#endif
#ifdef CONFIG_HIP_OPPORTUNISTIC
	"set opp on|off\n"
#endif
;
/* hip nat on|off|peer_hit is currently specified. 
 * For peer_hit we should 'on' the nat mapping only when the 
 * communication takes place with specified peer_hit --Abi */


/*
 * Handler functions.
 */
int (*action_handler[])(struct hip_common *, int action,
			const char *opt[], int optc) = {
	NULL, /* reserved */
	handle_hi,
	handle_map,
	handle_rst,
	handle_rvs,
	handle_bos,
	handle_puzzle,
	handle_nat,
	handle_opp,
	handle_escrow,
	handle_service
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
	return ret;
}

/**
 * check_action_argc - get minimum amount of arguments needed to be given to the action
 * @action: action type
 *
 * Returns: how many arguments needs to be given at least
 */
int check_action_argc(int action) {
	int count = -1;

	switch (action) {
	case ACTION_ADD:
	case ACTION_NEW:
	case ACTION_DEL:
		count = 2;
		break;
	case ACTION_GET:
		count = 2;
		break;
	case ACTION_SET:
		count = 2;
		break;
	case ACTION_INC:
		count = 2;
		break;
	case ACTION_RUN:
		count = 2;
		break;
	}

	return count;
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

	return ret;
}

int get_type_arg(int action) {
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
                type_arg = 2;
                break;
        }

        return type_arg;
}

/**
 * handle_rvs - ...
 */

int handle_rvs(struct hip_common *msg, int action, const char *opt[], 
	       int optc)
{
	struct in6_addr hit, ip6;
	int err=0;
	int ret;
	
	HIP_INFO("action=%d optc=%d\n", action, optc);

	HIP_IFEL((optc != 2), -1, "Missing arguments\n");
	
	HIP_IFEL(convert_string_to_address(opt[0], &hit), -1,
		 "string to address conversion failed\n");
	HIP_IFEL(convert_string_to_address(opt[1], &ip6), -1,
		 "string to address conversion failed\n");
	
	/* XX TODO: source HIT selection? */
	HIP_IFEL(hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
					  sizeof(struct in6_addr)), -1,
		 "build param hit failed\n");
	
	HIP_IFEL(hip_build_param_contents(msg, (void *) &ip6,
					  HIP_PARAM_IPV6_ADDR,
					  sizeof(struct in6_addr)), -1,
		 "build param hit failed\n");

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ADD_RVS, 0), -1,
		 "build hdr failed\n");
out_err:
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
  int err = 0, anon = 0, use_default = 0;

  _HIP_INFO("action=%d optc=%d\n", action, optc);

  if (action == ACTION_DEL)
    return handle_del(msg, action, opt, optc);

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

int handle_del(struct hip_common *msg, int action,
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

	err = hip_build_user_hdr(msg, SO_HIP_RST, 0);
	if (err) {
		HIP_ERROR("build hdr failed: %s\n", strerror(err));
		goto out;
	}

 out:
	return err;
}

/**
 * handle_bos - generate a BOS message
 * @msg:    the buffer where the message for kernel will be written
 * @action: the action (add/del) to performed (should be empty)
 * @opt:    an array of pointers to the command line arguments after
 *          the action and type (should be empty)
 * @optc:   the number of elements in the array (=0, no extra arguments)
 *
 * Returns: zero on success, else non-zero.
 */
int handle_bos(struct hip_common *msg, int action,
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
 * handle_nat - Sends a msg to daemon about NAT setting
 * @msg:    the buffer where the message for daemon will be written
 * @action: the action (add/del) to performed (should be empty)
 * @opt:    an array of pointers to the command line arguments after
 *          the action and type (should be empty)
 * @optc:   the number of elements in the array (=0, no extra arguments)
 *
 * Returns: zero on success, else non-zero.
 */

int handle_nat(struct hip_common *msg, int action,
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

int handle_puzzle(struct hip_common *msg, int action,
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

#ifdef CONFIG_HIP_SPAM
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
#else
	if (!all) {
		err = -1;
		HIP_ERROR("Only 'all' is supported\n");
		goto out;
	}
#endif /* CONFIG_HIP_SPAM */

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
int handle_opp(struct hip_common *msg, int action,
		  const char *opt[], int optc)
{
	unsigned int oppmode = 0;
	int err = 0;

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

int handle_escrow(struct hip_common *msg, int action, const char *opt[], 
					int optc)
{
	HIP_DEBUG("hipconf: using escrow");
	
	struct in6_addr hit;
	struct in6_addr ip;
	
	int err = 0;
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


int handle_service(struct hip_common *msg, int action, const char *opt[], 
					int optc)
{
	HIP_DEBUG("hipconf: handling service");
	
	int err = 0;
	HIP_INFO("action=%d optc=%d\n", action, optc);
	
	HIP_IFEL((optc != 1), -1, "Missing arguments\n");
	
	if (strcmp(opt[0], "escrow") == 0) {
		HIP_DEBUG("Adding escrow service");
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OFFER_ESCROW, 0), -1,
		 "build hdr failed\n");
	}
	
out_err:
	return err;
	
}

/* Execute new application.
 */
int exec_application(int type, char *argv[], int argc)
{
	/* Variables. */
	va_list args;
	int err = 0;

	err = fork();

	if (err < 0) HIP_DEBUG("Failed to exec new application.\n");
	else if (err > 0) err = 0;
	else if(err == 0)
	{
		HIP_DEBUG("Exec new application.\n");
		if (type == TYPE_RUN) setenv("LD_PRELOAD", "/usr/local/lib/libinet6.so:/usr/local/lib/libhiptool.so", 1);
		else setenv("LD_PRELOAD", "/usr/local/lib/libopphip.so:/usr/local/lib/libinet6.so:/usr/local/lib/libhiptool.so", 1);

		HIP_DEBUG("Set following libraries to LD_PRELOAD: %s\n", type == TYPE_RUN ? "libinet6.so:libhiptool.so" : "libopphip.so:libinet6.so:libhiptool.so");
		err = execvp(argv[0], argv);
		if (err != 0)
		{
			HIP_DEBUG("Executing new application failed!\n");
			exit(1);
		}
	}

out_err:
	return (err);
}


/* Parse command line arguments and send the appropiate message to
 * the kernel module
 */
#ifndef HIP_UNITTEST_MODE /* Unit testing code does not compile with main */
int main(int argc, char *argv[]) {
	int type_arg, err = 0;
	long int action, type;
	struct hip_common *msg;
	HIP_INFO("Hi, we are testing hipconf\n");
	if (argc < 2) {
		err = -EINVAL;
		//  display_usage();
		HIP_ERROR("Invalid args.\n%s usage:\n%s\n", argv[0], usage);
		goto out;
	}

	hip_set_logtype(LOGTYPE_STDERR); // we don't want log messages via syslog

	action = get_action(argv[1]);
	if (action <= 0 || action >= ACTION_MAX) {
		err = -EINVAL;
		HIP_ERROR("Invalid action argument '%s'\n", argv[1]);
		goto out;
	}
	_HIP_INFO("action=%d\n", action);
	
	if (argc-2 < check_action_argc(action)) {
		err = -EINVAL;
		HIP_ERROR("Not enough arguments given for the action '%s'\n",
			  argv[1]);
		goto out;
	}
	
	type_arg = get_type_arg(action);
	if (type_arg < 0) {
		HIP_ERROR("Could not parse type\n");
		goto out;
	}

	type = get_type(argv[type_arg]);
	if (type <= 0 || type >= TYPE_MAX) {
		err = -EINVAL;
		HIP_ERROR("Invalid type argument '%s'\n", argv[type_arg]);
		goto out;
	}
	_HIP_INFO("type=%d\n", type);

	if (action == ACTION_RUN)
	{
		exec_application(type, (const char **)&argv[3], argc - 3);
		goto out;
	}
	
	msg = malloc(HIP_MAX_PACKET);
	if (!msg) {
		HIP_ERROR("malloc failed\n");
		goto out;
	}
	hip_msg_init(msg);

        err = (*action_handler[type])(msg, action, (const char **) &argv[3],
                                              argc - 3);
	if (err) {
		HIP_ERROR("failed to handle msg\n");
		goto out_malloc;
	}

	/* hipconf new hi does not involve any messages to kernel */
	if (hip_get_msg_type(msg) == 0){
	  HIP_INFO("!!!!  new hi does not involve any messages to kernel\n");
	  goto skip_msg;
	}
	
	/* send msg to hipd */
	err = hip_send_daemon_info(msg);
	if (err) {
		HIP_ERROR("sending msg failed\n");
		goto out_malloc;
	}
	HIP_INFO("!!!! msg to hipd sent\n");

skip_msg:

out_malloc:
	free(msg);
out:
	
	return err;
}
#endif /* HIP_UNITTEST_MODE */
