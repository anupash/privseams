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
 * @author  Teresa Finez <tfinezmo_cc.hut.fi> Modifications
 * @author  Samu Varjonen
 * @author  Tao Wan  <twan_cc.hut.fi>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>
 * @todo    add/del map
 * @todo    fix the rst kludges
 * @todo    read the output message from send_msg?
 */
#include "hipconf.h"
#include "libhipopendht.h"

/** A help string containing the usage of @c hipconf. */
const char *hipconf_usage =
#ifdef CONFIG_HIP_ESCROW
"add|del escrow <hit>\n"
#endif
"add|del map <hit> <ipv6> [lsi]\n"
"Server side:\n\tadd|del service escrow|rvs|hiprelay\n"
"\treinit service rvs|hiprelay\n"
"Client side:\n\tadd rvs|hiprelay <hit> <ipv6> <lifetime in seconds>\n"
"del hi <hit>\n"
"del hi all\n"
"get hi default|all\n"
#ifdef CONFIG_HIP_ICOOKIE
"get|set|inc|dec|new puzzle all|<hit>\n"
#else
"get|set|inc|dec|new puzzle all\n"
#endif
"del hi <hit>\n"
"get hi default\n"
"bos all\n"
//modify by santtu
//"nat on|off|<peer_hit>\n"
"nat none|plain-udp|ice-udp\n"
//end modify
"rst all|<peer_hit>\n"
"new|add hi anon|pub rsa|dsa filebasename\n"
"new hi anon|pub rsa|dsa filebasename keylen\n"
"new|add hi default (HI must be created as root)\n"
"new hi default rsa_keybits dsa_keybits\n"
"load config default\n"
"handoff mode lazy|active\n"
"run normal|opp <binary>\n"
"Server side:\n"
"\tadd|del service escrow|rvs|hiprelay\n"
"\treinit service rvs|hiprelay\n"
"Client side:\n"
"\tadd server rvs|relay|escrow <HIT> <IP address> <lifetime in seconds>\n"
"\tdel server rvs|relay|escrow <HIT> <IP address>\n"
#ifdef CONFIG_HIP_BLIND
"set blind on|off\n"
#endif
#ifdef CONFIG_HIP_OPPORTUNISTIC
"set opp normal|advanced|none\n"
#endif
"get ha all|HIT\n"
"opendht on|off\n"
"dht gw <IPv4|hostname> <port (OpenDHT default = 5851)> <TTL>\n"
"dht get <fqdn/hit>\n"
"dht set <name>\n"
"locator on|off\n"
"debug all|medium|none\n"
"restart daemon\n"
"set tcptimeout on|off\n" /*added by Tao Wan*/
#ifdef CONFIG_HIP_HIPPROXY
"hipproxy on|off\n"
#endif
;

/** Function pointer array containing pointers to handler functions.
 *  @note Keep the elements in the same order as the @c TYPE values are defined
 *        in hipconf.h because type values are used as @c action_handler array
 *        index.
 */
int (*action_handler[])(hip_common_t *, int action,const char *opt[], int optc) = 
{
	NULL, /* reserved */
	hip_conf_handle_hi,
	hip_conf_handle_map,
	hip_conf_handle_rst,
	hip_conf_handle_server,
	hip_conf_handle_bos,
	hip_conf_handle_puzzle,
	hip_conf_handle_nat,
	hip_conf_handle_opp,
	hip_conf_handle_blind,
	hip_conf_handle_service,
	hip_conf_handle_load,
	hip_conf_handle_run_normal, /* run */
	hip_conf_handle_ttl,
	hip_conf_handle_gw,
	hip_conf_handle_get,
	hip_conf_handle_ha,
	hip_conf_handle_handoff,
	hip_conf_handle_debug,
	hip_conf_handle_restart,
        hip_conf_handle_locator,
        hip_conf_handle_set, // relay ????????
        hip_conf_handle_dht_toggle,
	hip_conf_handle_opptcp,
        hip_conf_handle_trans_order,
	hip_conf_handle_tcptimeout, /* added by Tao Wan*/
        hip_conf_handle_hipproxy,
	NULL /* run */
};

/**
 * Maps symbolic hipconf action (=add/del) names into numeric action
 * identifiers.
 * 
 * @param  text the action as a string.
 * @return the numeric action id correspoding to the symbolic text.
 */
int hip_conf_get_action(char *text)
{
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
	else if (!strcmp("nat", text))
		ret = ACTION_NAT;
	else if (!strcmp("bos", text))
		ret = ACTION_BOS;
	else if (!strcmp("rst", text))
		ret = ACTION_RST;
	else if (!strcmp("run", text))
		ret = ACTION_RUN;
	else if (!strcmp("load", text))
		ret = ACTION_LOAD;
	else if (!strcmp("dht", text))
		ret = ACTION_DHT;
	else if (!strcmp("opendht", text))
		ret = ACTION_OPENDHT;
	else if (!strcmp("locator", text))
		ret = ACTION_LOCATOR; 
	else if (!strcmp("debug", text))
		ret = ACTION_DEBUG;
	else if (!strcmp("handoff", text))
		ret = ACTION_HANDOFF;
	else if (!strcmp("transform", text))
		ret = ACTION_TRANSORDER;
	else if (!strcmp("restart", text))
		ret = ACTION_RESTART;
	else if (!strcmp("tcptimeout", text)) /*added by Tao Wan, 08.Jan.2008 */
		ret = ACTION_TCPTIMEOUT;
	else if (!strcmp("reinit", text))
		ret = ACTION_REINIT;
#ifdef CONFIG_HIP_HIPPROXY
	else if (!strcmp("hipproxy", text))
		ret = ACTION_HIPPROXY;
#endif
	
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
	case ACTION_NEW: case ACTION_NAT: case ACTION_DEC: case ACTION_RST:
	case ACTION_BOS: case ACTION_LOCATOR: case ACTION_OPENDHT:
                break;
	case ACTION_DEBUG: case ACTION_RESTART: case ACTION_REINIT:
	case ACTION_TCPTIMEOUT:
		count = 1;
		break;
	case ACTION_ADD: case ACTION_DEL: case ACTION_SET: case ACTION_INC:
	case ACTION_GET: case ACTION_RUN: case ACTION_LOAD: case ACTION_DHT:
	case ACTION_HA: case ACTION_HANDOFF: case ACTION_TRANSORDER:
		count = 2;
		break;
#ifdef CONFIG_HIP_HIPPROXY
    case ACTION_HIPPROXY:
		break;
#endif
	default:
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
int hip_conf_get_type(char *text,char *argv[]) {
	int ret = -1;

	if (!strcmp("hi", text))
		ret = TYPE_HI;
	else if (!strcmp("map", text))
		ret = TYPE_MAP;
	else if (!strcmp("rst", text))
		ret = TYPE_RST;
	else if (!strcmp("server", text))
		ret = TYPE_SERVER;
	else if (!strcmp("puzzle", text))
		ret = TYPE_PUZZLE;	
	else if (!strcmp("service", text))
		ret = TYPE_SERVICE;	
	else if (!strcmp("normal", text))
		ret = TYPE_RUN;
	else if (!strcmp("ha", text))
		ret = TYPE_HA;
	else if ((!strcmp("all", text)) && (strcmp("rst",argv[1])==0))
		ret = TYPE_RST;
	else if ((!strcmp("peer_hit", text)) && (strcmp("rst",argv[1])==0))
		ret = TYPE_RST;
	else if	(strcmp("nat",argv[1])==0) 
		ret = TYPE_NAT;
        else if (strcmp("locator", argv[1])==0)
                ret = TYPE_LOCATOR;
	/* Tao Wan added tcptimeout on 08.Jan.2008 */
	else if (!strcmp("tcptimeout", text))
		ret = TYPE_TCPTIMEOUT;
	else if ((!strcmp("all", text)) && (strcmp("bos",argv[1])==0))
		ret = TYPE_BOS;
	else if (!strcmp("debug", text))
		ret = TYPE_DEBUG;
	else if (!strcmp("mode", text))
		ret = TYPE_MODE;
	else if (!strcmp("daemon", text))
		ret = TYPE_DAEMON;
	else if (!strcmp("mode", text))
		ret = TYPE_MODE;
#ifdef CONFIG_HIP_OPPORTUNISTIC
	else if (!strcmp("opp", text))
		ret = TYPE_OPP; 
#endif
#ifdef CONFIG_HIP_BLIND
	else if (!strcmp("blind", text))
		ret = TYPE_BLIND;
#endif
#ifdef CONFIG_HIP_ESCROW
	else if (!strcmp("escrow", text))
		ret = TYPE_ESCROW;
#endif		
	else if (!strcmp("order", text))
		ret = TYPE_ORDER;
	else if (strcmp("opendht", argv[1])==0)
		ret = TYPE_DHT;
	else if (!strcmp("ttl", text))
		ret = TYPE_TTL;
	else if (!strcmp("gw", text))
		ret = TYPE_GW;
	else if (!strcmp("get", text))
		ret = TYPE_GET;
	else if (!strcmp("set", text))
                ret = TYPE_SET;
	else if (!strcmp("config", text))
		ret = TYPE_CONFIG;
#ifdef CONFIG_HIP_HIPPROXY
	else if (strcmp("hipproxy", argv[1])==0)
		ret = TYPE_HIPPROXY;
#endif
     return ret;
}

/* What does this function do? */
int hip_conf_get_type_arg(int action)
{
	int type_arg = -1;
	
	switch (action) {
	case ACTION_ADD:
	case ACTION_DEL:
	case ACTION_NEW:
	case ACTION_NAT:
	case ACTION_INC:
	case ACTION_DEC:
	case ACTION_SET:
	case ACTION_GET:
	case ACTION_RUN:
	case ACTION_LOAD:
	case ACTION_DHT:
	case ACTION_OPENDHT:
	case ACTION_LOCATOR:
	case ACTION_RST:
	case ACTION_BOS:
	case ACTION_HANDOFF:
	case ACTION_TCPTIMEOUT:
        case ACTION_TRANSORDER:
	case ACTION_REINIT:
#ifdef CONFIG_HIP_HIPPROXY
	case ACTION_HIPPROXY:
#endif
	case ACTION_RESTART:
		type_arg = 2;
		break;
	
	case ACTION_DEBUG:
		type_arg = 1;
		break;
	
	default:
		break;
	}
	
	return type_arg;
}

/**
 * Handles the hipconf commands where the type is @c server. Creates a user
 * message from the function parameters @c msg, @c action and @c opt[]. The
 * command line that this function parses is of type:
 * <code>tools/hipconf <b>add</b> server &lt;SERVICES&gt; &lt;SERVER HIT&gt;
 * &lt;SERVER IP ADDRESS&gt; &lt;LIFETIME&gt;</code> or
 * <code>tools/hipconf <b>del</b> server &lt;SERVICES&gt; &lt;SERVER HIT&gt;
 * &lt;SERVER IP ADDRESS&gt;</code>, where <code>&lt;SERVICES&gt;</code> is a list of
 * the services to which we want to register or cancel or registration. The
 * list can consist of any number of the strings @c rvs, @c relay or @c escrow,
 * or any number of service type numbers between 0 and 255. The list can be a
 * combination of these with repetitions allowed. At least one string or
 * service type number must be provided.
 * 
 * @param msg    a pointer to a target buffer where the message for HIP daemon
 *               is to put
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in array @c opt.
 * @return       zero on success, or negative error value on error.
 * @note         Currently only action @c add is supported.
 * @todo         If the current machine has more than one IP address
 *               there should be a way to choose which of the addresses
 *               to register to the server.
 * @todo         There are currently four different HITs at the @c dummy0
 *               interface. There should be a way to choose which of the HITs
 *               to register to the server.
 */ 
int hip_conf_handle_server(hip_common_t *msg, int action, const char *opt[], 
			   int optc)
{
	hip_hit_t hit;
	in6_addr_t ipv6;
	int err = 0, seconds = 0, i = 0, number_of_regtypes = 0, reg_type = 0;
	int index_of_hit = 0, index_of_ip = 0;
	uint8_t lifetime = 0, *reg_types = NULL;
	time_t seconds_from_lifetime = 0;
	char lowercase[30];
		
	_HIP_DEBUG("hip_conf_handle_server() invoked.\n");

	if(action != ACTION_ADD && action != ACTION_DEL) {
		HIP_ERROR("Only actions \"add\" and \"del\" are supported for "\
			  "\"server\".\n");
		err = -1;
		goto out_err;
	} else if (action == ACTION_ADD) {
		if(optc < 4) {
			HIP_ERROR("Missing arguments.\n");
			err = -1;
			goto out_err;
		}
		number_of_regtypes = optc - 3;
		index_of_hit = optc - 3;
		index_of_ip  = optc - 2;
		
		/* The last commandline argument has the lifetime. */
		HIP_IFEL(hip_string_is_digit(opt[optc - 1]), -1,
			 "Invalid lifetime value \"%s\" given.\n"\
			 "Please give a lifetime value between 1 and "\
			 "15384774 seconds.\n", opt[optc - 1]);

		seconds = atoi(opt[optc - 1]);
		
		if(seconds <= 0 || seconds > 15384774) {
			HIP_ERROR("Invalid lifetime value \"%s\" given.\n"\
				  "Please give a lifetime value between 1 and "\
				  "15384774 seconds.\n", opt[optc - 1]);
			goto out_err;
		}
		
		HIP_IFEL(hip_get_lifetime_value(seconds, &lifetime), -1,
			 "Unable to convert seconds to a lifetime value.\n");
		
		hip_get_lifetime_seconds(lifetime, &seconds_from_lifetime);
		
	} else if (action == ACTION_DEL) {
		if (optc < 3) {
			HIP_ERROR("Missing arguments.\n");
			err = -1;
			goto out_err;
		}
		number_of_regtypes = optc - 2;
		index_of_hit = optc - 2;
		index_of_ip  = optc - 1;
	}
	/* Check the HIT value. */
 	if(inet_pton(AF_INET6, opt[index_of_hit], &hit) <= 0) {
		HIP_ERROR("'%s' is not a valid HIT.\n", opt[index_of_hit]);
		err = -1;
		goto out_err;
	} /* Check the IPv4 or IPV6 value. */
	else if(inet_pton(AF_INET6, opt[index_of_ip], &ipv6) <= 0) {
		struct in_addr ipv4;
		if(inet_pton(AF_INET, opt[index_of_ip], &ipv4) <= 0) {
			HIP_ERROR("'%s' is not a valid IPv4 or IPv6 address.\n",
				  opt[index_of_ip]);
			err = -1;
			goto out_err;
		} else {
			IPV4_TO_IPV6_MAP(&ipv4, &ipv6);
		}
	} 

	reg_types = malloc(number_of_regtypes * sizeof(uint8_t));
	if(reg_types == NULL) {
		err = -1;
		HIP_ERROR("Unable to allocate memory for registration "\
			  "types.\n");
		goto out_err;
	}
	
	/* Every commandline argument in opt[] from '0' to 'optc - 4' should
	   be either one of the predefined strings or a number between
	   0 and 255 (inclusive). */
	for(; i < number_of_regtypes; i++) {
		if(strlen(opt[i]) > 30) {
			HIP_ERROR("'%s' is not a valid service name.\n", opt[i]);
			err = -1;
			goto out_err;
		}
		
		hip_string_to_lowercase(lowercase, opt[i], strlen(opt[i]) + 1);
		if(strcmp("rvs", lowercase) == 0){
			reg_types[i] = HIP_SERVICE_RENDEZVOUS;
		} else if(strcmp("relay", lowercase) == 0) {
			reg_types[i] = HIP_SERVICE_RELAY;
		} else if(strcmp("escrow", lowercase) == 0) {
			reg_types[i] = HIP_SERVICE_ESCROW;
		} /* To cope with the atoi() error value we handle the 'zero'
		     case here. */
		else if(strcmp("0", lowercase) == 0) {
			reg_types[i] = 0;
		} else {
			reg_type = atoi(lowercase);
			if(reg_type <= 0 || reg_type > 255) {
				HIP_ERROR("'%s' is not a valid service name "\
					  "or service number.\n", opt[i]);
				err = -1;
				goto out_err;
			} else {
				reg_types[i] = reg_type;
			}
		}
	}
		
	HIP_IFEL(hip_build_param_contents(msg, &hit, HIP_PARAM_HIT,
					  sizeof(in6_addr_t)), -1, 
		 "Failed to build HIT parameter to hipconf user message.\n");
	
	HIP_IFEL(hip_build_param_contents(msg, &ipv6, HIP_PARAM_IPV6_ADDR,
					  sizeof(in6_addr_t)), -1,
		 "Failed to build IPv6 parameter to hipconf user message.\n");
	
	HIP_IFEL(hip_build_param_reg_request(msg, lifetime, reg_types ,
					     number_of_regtypes), -1,
		 "Failed to build REG_REQUEST parameter to hipconf user "\
		 "message.\n");

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ADD_DEL_SERVER, 0), -1,
		 "Failed to build hipconf user message header.\n");
	
	if(action == ACTION_ADD) {
		HIP_INFO("Requesting %u service%s for %d seconds "
			 "(lifetime 0x%x) from\nHIT %s located at\nIP "\
			 "address %s.\n", number_of_regtypes,
			 (number_of_regtypes > 1) ? "s" : "",
			 seconds_from_lifetime, lifetime, opt[index_of_hit],
			 opt[index_of_ip]);
	} else {
		HIP_INFO("Requesting the cancellation of %u service%s from\n"\
			 "HIT %s located at\nIP address %s.\n",
			 number_of_regtypes,
			 (number_of_regtypes > 1) ? "s" : "", opt[index_of_hit],
			 opt[index_of_ip]);
		
	}
 out_err:
	if(reg_types != NULL)
		free(reg_types);

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
int hip_conf_handle_hi(hip_common_t *msg, int action, const char *opt[],
		       int optc)
{
	int err = 0, anon = 0, use_default = 0, rsa_key_bits = 0, 
	dsa_key_bits = 0;
	char *fmt = NULL, *file = NULL;

     _HIP_DEBUG("action=%d optc=%d\n", action, optc);

     /* @todo: the ACTION_GET is bypassed in hip_do_hipconf() */

     if (action == ACTION_DEL)
	  return hip_conf_handle_hi_del(msg, action, opt, optc);
     if (action == ACTION_GET)
     	  return hip_get_hits(msg, opt, optc);
	  //return hip_conf_handle_hi_get(msg, action, opt, optc);

     /* Check min/max amount of args */
     HIP_IFEL((optc < 1 || optc > 4), -EINVAL, "Invalid number of arguments\n");

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

     if (use_default && action == ACTION_ADD) {
	/* Add default keys in three steps: dsa, rsa anon, rsa pub.
	   Necessary for large keys. */

	if (err = hip_serialize_host_id_action(msg, ACTION_ADD, 0, 1,
							   "dsa", NULL, 0, 0))
	    goto out_err;
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "Sending msg failed.\n");

	hip_msg_init(msg);
	if (err = hip_serialize_host_id_action(msg, ACTION_ADD, 1, 1,
							   "rsa", NULL, 0, 0))
	    goto out_err;
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "Sending msg failed.\n");

	hip_msg_init(msg);
	err = hip_serialize_host_id_action(msg, ACTION_ADD, 0, 1,
							   "rsa", NULL, 0, 0);

	goto out_err;
     }

     if (use_default) {

	  if (optc == 3) {
	       rsa_key_bits = atoi(opt[1]);
	       dsa_key_bits = atoi(opt[2]);
	  } else {
	       HIP_IFEL(optc != 1, -EINVAL, "Invalid number of arguments\n");
	  }

     } else {

	  if (optc == 4)
	       rsa_key_bits = dsa_key_bits = atoi(opt[OPT_HI_KEYLEN]);
	  else
	       HIP_IFEL(optc != 3, -EINVAL, "Invalid number of arguments\n");

	  fmt = opt[OPT_HI_FMT];
	  file = opt[OPT_HI_FILE];
     }

     if (rsa_key_bits < 384 || rsa_key_bits > HIP_MAX_RSA_KEY_LEN ||
							rsa_key_bits % 64 != 0)
	 rsa_key_bits = RSA_KEY_DEFAULT_BITS;
     if (dsa_key_bits < 512 || dsa_key_bits > HIP_MAX_DSA_KEY_LEN ||
							dsa_key_bits % 64 != 0)
	 dsa_key_bits = DSA_KEY_DEFAULT_BITS;

     err = hip_serialize_host_id_action(msg, action, anon, use_default,
					fmt, file, rsa_key_bits, dsa_key_bits);

    //HIP_INFO("\nNew default HI is now created.\nYou must restart hipd to make "\
	      "the changes effective.\n\n");

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
int hip_conf_handle_map(hip_common_t *msg, int action, const char *opt[],
			int optc)
{
     int err = 0;
     int ret;
     struct in_addr lsi, aux;
     in6_addr_t hit, ip6;

     HIP_DEBUG("action=%d optc=%d\n", action, optc);

     HIP_IFEL((optc != 2 && optc != 3), -1, "Missing arguments\n");
	
     HIP_IFEL(convert_string_to_address(opt[0], &hit), -1,
	      "string to address conversion failed\n");

     HIP_IFEL(convert_string_to_address(opt[1], &ip6), -1,
	      "string to address conversion failed\n");
     
     if(!convert_string_to_address_v4(opt[1], &aux)){
	     HIP_IFEL(IS_LSI32(aux.s_addr), -1, "Missing ip address before lsi\n");
     }

     HIP_IFEL(hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
				       sizeof(in6_addr_t)), -1,
	      "build param hit failed\n");

     HIP_IFEL(hip_build_param_contents(msg, (void *) &ip6,
				       HIP_PARAM_IPV6_ADDR,
				       sizeof(in6_addr_t)), -1,
	      "build param hit failed\n");

     if(optc == 3){
	     HIP_IFEL(convert_string_to_address_v4(opt[2], &lsi), -1,
		      "string to address conversion failed\n");	     
	     HIP_IFEL(!IS_LSI32(lsi.s_addr),-1, "Wrong LSI value\n");
	     HIP_IFEL(hip_build_param_contents(msg, (void *) &lsi,
				       HIP_PARAM_LSI,
				       sizeof(struct in_addr)), -1,
	      "build param lsi failed\n");		
     }

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
int hip_conf_handle_hi_del(hip_common_t *msg, int action,
			   const char *opt[], int optc) 
{
     int err = 0;
     int ret;
     in6_addr_t hit;

     HIP_IFEL(optc != 1, -EINVAL, "Invalid number of arguments\n");

     if (!strcmp(opt[0], "all"))
	return hip_conf_handle_hi_del_all(msg);

     ret = inet_pton(AF_INET6, opt[0], &hit);
     HIP_IFEL((ret < 0 && errno == EAFNOSUPPORT), -EAFNOSUPPORT,
				    "inet_pton: not a valid address family\n");
     HIP_IFEL((ret == 0), -EINVAL, 
		       "inet_pton: %s: not a valid network address\n", opt[0]);

     HIP_HEXDUMP("HIT to delete: ", &hit, sizeof(in6_addr_t));

     if (err = hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
				    sizeof(in6_addr_t))) {
	  HIP_ERROR("build param HIT failed: %s\n", strerror(err));
	  goto out_err;
     }

     if (err = hip_build_user_hdr(msg, SO_HIP_DEL_LOCAL_HI, 0)) {
	  HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
	  goto out_err;
     }

 out_err:
     return err;
}

int hip_conf_handle_hi_del_all(hip_common_t *msg)
{
    int err = 0;
    struct hip_tlv_common *param = NULL;
    struct endpoint_hip *endp;
    hip_common_t *msg_tmp = NULL;

    msg_tmp = hip_msg_alloc();
    HIP_IFEL(!msg_tmp, -ENOMEM, "Malloc for msg_tmp failed\n");

    HIP_IFEL(hip_build_user_hdr(msg_tmp, SO_HIP_GET_HITS, 0),
				  -1, "Failed to build user message header\n");
    HIP_IFEL(hip_send_recv_daemon_info(msg_tmp), -1, "Sending msg failed.\n");

    while((param = hip_get_next_param(msg_tmp, param)) != NULL) {

	endp = (struct endpoint_hip *)hip_get_param_contents_direct(param);
	HIP_IFEL(hip_build_param_contents(msg, (void *) &endp->id.hit, 
					    HIP_PARAM_HIT, sizeof(in6_addr_t)),
					    -1, "Failed to build HIT param\n");

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DEL_LOCAL_HI, 0),
-				  -1, "Failed to build user message header\n");
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "Sending msg failed.\n");

	hip_msg_init(msg);

    }

    /*FIXME Deleting HITs from the interface isn't working, so we restart it */
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_RESTART_DUMMY_INTERFACE, 0),
				-1, "Failed to build message header\n");

    HIP_INFO("All HIs deleted.\n");

  out_err:
    if (msg_tmp)
	free(msg_tmp);
    return err;
}

/**
 * Handles the hipconf transform order command.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_trans_order(hip_common_t *msg, int action,
                                const char *opt[], int optc) 
{
     int err, ret, transorder;
     
     if (optc != 1) {
	  HIP_ERROR("Missing arguments\n");
	  err = -EINVAL;
	  goto out;
     }
 	 	
     transorder = atoi(opt[0]);
     if (transorder < 0 || transorder > 5) {
             HIP_ERROR("Invalid argument\n");
             err = -EINVAL;
             goto out;
     } 
     
     /* a bit wastefull but works */
     /* warning: passing argument 2 of 'hip_build_param_opendht_set' discards
	qualifiers from pointer target type. 04.07.2008. */
     err = hip_build_param_opendht_set(msg, opt[0]);
     if (err) {
             HIP_ERROR("build param hit failed: %s\n", strerror(err));
             goto out;
     }
 	
     err = hip_build_user_hdr(msg, SO_HIP_TRANSFORM_ORDER, 0);
     if (err)
     {
	  HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
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
int hip_conf_handle_rst(hip_common_t *msg, int action,
			const char *opt[], int optc) 
{
     int err;
     int ret;
     in6_addr_t hit;

     if (!strcmp("all",opt[0]))
     {
	  memset(&hit,0,sizeof(in6_addr_t));
     } else
     {
	  ret = inet_pton(AF_INET6, opt[0], &hit);
	  if (ret < 0 && errno == EAFNOSUPPORT)
	  {
	       HIP_PERROR("inet_pton: not a valid address family\n");
	       err = -EAFNOSUPPORT;
	       goto out;
	  } else if (ret == 0)
	  {
	       HIP_ERROR("inet_pton: %s: not a valid network address\n", opt[0]);
	       err = -EINVAL;
	       goto out;
	  }
     }

     err = hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
				    sizeof(in6_addr_t));
     if (err)
     {
	  HIP_ERROR("build param hit failed: %s\n", strerror(err));
	  goto out;
     }

     err = hip_build_user_hdr(msg, SO_HIP_RST, 0);
     if (err)
     {
	  HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
	  goto out;
     }

 out:
     return err;
}

/**
 * Handles the hipconf commands where the type is @c debug.
 *
 * @param msg    a pointer to the buffer where the message for kernel will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_debug(hip_common_t *msg, int action,
			  const char *opt[], int optc) 
{

     int err = 0;
     int status = 0;
     in6_addr_t hit;

     if(optc != 0)
	  HIP_IFEL(1, -EINVAL, "Wrong amount of arguments. Usage:\nhipconf debug all|medium|none\n");

     if (!strcmp("all", opt[0]))
     {
	  HIP_INFO("Displaying all debugging messages\n");
	  memset(&hit, 0, sizeof(in6_addr_t));
	  status = SO_HIP_SET_DEBUG_ALL;
     } else if (!strcmp("medium", opt[0]))
     {
	  HIP_INFO("Displaying ERROR and INFO debugging messages\n");
	  memset(&hit, 0, sizeof(in6_addr_t));
	  status = SO_HIP_SET_DEBUG_MEDIUM;
     } else if (!strcmp("none", opt[0]))
     {
	  HIP_INFO("Displaying no debugging messages\n");
	  memset(&hit, 0, sizeof(in6_addr_t));
	  status = SO_HIP_SET_DEBUG_NONE;
     } else
	  HIP_IFEL(1, -EINVAL, "Unknown argument\n");

     HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1, "Failed to build user message header.: %s\n", strerror(err));

 out_err:
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
int hip_conf_handle_bos(hip_common_t *msg, int action,
			const char *opt[], int optc) 
{
     int err;

     /* Check that there are no extra args */
     if (optc != 0)
     {
	  HIP_ERROR("Extra arguments\n");
	  err = -EINVAL;
	  goto out;
     }

     /* Build the message header */
     err = hip_build_user_hdr(msg, SO_HIP_BOS, 0);
     if (err)
     {
	  HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
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
int hip_conf_handle_nat(hip_common_t *msg, int action,
			const char *opt[], int optc)
{
     int err = 0;
     int status = 0;
     in6_addr_t hit;
	
 //    if (!strcmp("on",opt[0]))
     if (!strcmp("plain-udp",opt[0]))
     {
    	 memset(&hit,0,sizeof(in6_addr_t));
	//  status = SO_HIP_SET_NAT_ON; 
    	 status = SO_HIP_SET_NAT_PLAIN_UDP; 
	  } else if (!strcmp("none",opt[0]))
	  {
		  memset(&hit,0,sizeof(struct in6_addr));
	  status = SO_HIP_SET_NAT_NONE;
	  } else if (!strcmp("ice-udp",opt[0]))
	  {
	   	  memset(&hit,0,sizeof(struct in6_addr));
	  	  status = SO_HIP_SET_NAT_ICE_UDP;
	  } else
	  {
		  HIP_IFEL(1, -1, "bad args\n");
	  }
#if 0 /* Not used currently */
     else {
	  ret = inet_pton(AF_INET6, opt[0], &hit);
	  if (ret < 0 && errno == EAFNOSUPPORT)
	  {
	       HIP_PERROR("inet_pton: not a valid address family\n");
	       err = -EAFNOSUPPORT;
	       goto out_err;
	  } else if (ret == 0)
	  {
	       HIP_ERROR("inet_pton: %s: not a valid network address\n", opt[0]);
	       err = -EINVAL;
	       goto out_err;
	  }
	  status = SO_HIP_SET_NAT_ON;
     }

     HIP_IFEL(hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
				       sizeof(in6_addr_t)), -1,
	      "build param hit failed: %s\n", strerror(err));
#endif

     HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1, "Failed to build user message header.: %s\n", strerror(err));

 out_err:
     return err;

}

/**
 * Handles the hipconf commands where the type is @c locator.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *               be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *               the action and type.
 * @param optc   the number of elements in the array (@b 0).
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_locator(hip_common_t *msg, int action,
		   const char *opt[], int optc)
{
    int err = 0, status = 0;
    
    if (!strcmp("on",opt[0])) {
        status = SO_HIP_SET_LOCATOR_ON; 
    } else if (!strcmp("off",opt[0])) {
        status = SO_HIP_SET_LOCATOR_OFF;
    } else {
        HIP_IFEL(1, -1, "bad args\n");
    }
    HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1, "Failed to build user message header.: %s\n", strerror(err));
    
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
int hip_conf_handle_puzzle(hip_common_t *msg, int action,
			   const char *opt[], int optc) 
{
     int err = 0, ret, msg_type, all;
     hip_hit_t hit = {0};

     if (optc != 1)
     {
	  HIP_ERROR("Missing arguments\n");
	  err = -EINVAL;
	  goto out;
     }

     switch (action)
     {
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

     if (err)
     {
	  HIP_ERROR("Action (%d) not supported yet\n", action);
	  goto out;
     }

     all = !strcmp("all", opt[0]);

     if (!all)
     {
	  ret = inet_pton(AF_INET6, opt[0], &hit);
	  if (ret < 0 && errno == EAFNOSUPPORT)
	  {
	       HIP_PERROR("inet_pton: not a valid address family\n");
	       err = -EAFNOSUPPORT;
	       goto out;
	  } else if (ret == 0)
	  {
	       HIP_ERROR("inet_pton: %s: not a valid network address\n", opt[0]);
	       err = -EINVAL;
	       goto out;
	  }
     }

     err = hip_build_param_contents(msg, (void *) &hit, HIP_PARAM_HIT,
				    sizeof(in6_addr_t));
     if (err)
     {
	  HIP_ERROR("build param hit failed: %s\n", strerror(err));
	  goto out;
     }

     err = hip_build_user_hdr(msg, msg_type, 0);
     if (err)
     {
	  HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
	  goto out;
     }

     if (all)
     {
	  HIP_INFO("New puzzle difficulty effective immediately\n");
     } else
     {
	  HIP_INFO("New puzzle difficulty is effective in %d seconds\n",
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
int hip_conf_handle_opp(hip_common_t *msg, int action,
			const char *opt[], int optc)
{
     unsigned int oppmode = 0;
     int err = 0;

	if (action == ACTION_RUN)
		return hip_handle_exec_application(0, EXEC_LOADLIB_OPP, optc, (char **) &opt[0]);
	if (optc != 1) {
		HIP_ERROR("Incorrect number of arguments\n");
		err = -EINVAL;
		goto out;
	}

	if (!strcmp("normal",opt[0])) {
		oppmode = 1;
	} else if (!strcmp("advanced",opt[0])) {
		oppmode = 2;
	} else if (!strcmp("none", opt[0])){
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
		HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
		goto out;
	}

 out:
     return err;
}

int hip_conf_handle_blind(hip_common_t *msg, int action,
			  const char *opt[], int optc)
{
     int err = 0;
     int status = 0;

     HIP_DEBUG("hipconf: using blind\n");

     if (optc != 1)
     {
	  HIP_ERROR("Missing arguments\n");
	  err = -EINVAL;
	  goto out;
     }

     if (!strcmp("on",opt[0]))
     {
	  status = SO_HIP_SET_BLIND_ON; 
     } else if (!strcmp("off",opt[0]))
     {
	  status = SO_HIP_SET_BLIND_OFF;
     } else
     {
	  HIP_PERROR("not a valid blind mode\n");
	  err = -EAFNOSUPPORT;
	  goto out;
     }

     err = hip_build_user_hdr(msg, status, 0);
     if (err)
     {
	  HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
	  goto out;
     }

 out:
     return err;
}

int hip_conf_handle_ttl(hip_common_t *msg, int action, const char *opt[], int optc)
{
	int ret = 0;
	HIP_INFO("Got to the DHT ttl handle for hipconf, NO FUNCTIONALITY YET\n");
	/* useless function remove */
	return(ret);
}


/**
 * Function that is used to set the name sent to DHT in name/fqdn -> HIT -> IP mappings
 *
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_set(hip_common_t *msg, int action, const char *opt[], int optc)
{
    int err = 0;
    int len_name = 0;
    len_name = strlen(opt[0]);
    HIP_DEBUG("Name received from user: %s (len = %d (max 256))\n", opt[0], len_name);
    HIP_IFEL((len_name > 255), -1, "Name too long, max 256\n");
    /* warning: passing argument 2 of 'hip_build_param_opendht_set' discards
       qualifiers from pointer target type. 04.07.2008 */
    err = hip_build_param_opendht_set(msg, opt[0]);
    if (err) {
        HIP_ERROR("build param hit failed: %s\n", strerror(err));
        goto out_err;
    }

    err = hip_build_user_hdr(msg, SO_HIP_DHT_SET, 0);
    if (err) {
        HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
        goto out_err;
    }
 out_err:
    return(err);
}

/**
 * Function that is used to set the used gateway addr port and ttl with DHT
 *
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_gw(hip_common_t *msg, int action, const char *opt[], int optc)
{
        int err,out_err;
        int status = 0;
        int ret;
        struct in_addr ip_gw;
        in6_addr_t ip_gw_mapped;
        struct addrinfo new_gateway;
        struct hip_opendht_gw_info *gw_info;

        HIP_INFO("Resolving new gateway for openDHT %s\n", opt[0]);

        if (optc != 3) {
                HIP_ERROR("Missing arguments\n");
                err = -EINVAL;
                goto out_err;
        }
	
        memset(&new_gateway, '0', sizeof(new_gateway));
        ret = 0;
        /* resolve the new gateway */
        /* warning: passing argument 1 of 'resolve_dht_gateway_info' discards
	   qualifiers from pointer target type. 04.07.2008 */
	/* warning: passing argument 2 of 'resolve_dht_gateway_info' from
	   incompatible pointer type. 04.07.2008 */
        ret = resolve_dht_gateway_info(opt[0], &new_gateway);
        if (ret < 0) goto out_err;
        struct sockaddr_in *sa = (struct sockaddr_in *)new_gateway.ai_addr;

        HIP_INFO("Gateway addr %s, port %s, TTL %s\n",
		 inet_ntoa(sa->sin_addr), opt[1], opt[2]);

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
                HIP_ERROR("Failed to build user message header.: %s\n", strerror(err));
                goto out_err;
        }

 out_err:
        return err;
}


/**
 * Function that gets data from DHT
 *
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_get(hip_common_t *msg, int action, const char *opt[], int optc)
{
        int err = 0;
        char dht_response[1024];
        struct addrinfo * serving_gateway;
        hip_common_t *msgdaemon;
        struct hip_opendht_gw_info *gw_info;
        struct in_addr tmp_v4;
        char tmp_ip_str[21];
        int tmp_ttl, tmp_port;
        int *pret;

        /* ASK THIS INFO FROM DAEMON */
        HIP_INFO("Asking serving gateway info from daemon...\n");
        HIP_IFEL(hip_build_user_hdr(msgdaemon, SO_HIP_DHT_SERVING_GW,0),-1,
                 "Building daemon header failed\n");
        HIP_IFEL(hip_send_recv_daemon_info(msgdaemon), -1, "Send recv daemon info failed\n");
        HIP_IFEL(!(gw_info = hip_get_param(msgdaemon, HIP_PARAM_OPENDHT_GW_INFO)),-1,
                 "No gw struct found\n");

        /* Check if DHT was on */
        if ((gw_info->ttl == 0) && (gw_info->port == 0)) {
                HIP_INFO("DHT is not in use\n");
                goto out_err;
        }
        memset(&tmp_ip_str,'\0',20);
        tmp_ttl = gw_info->ttl;
        tmp_port = htons(gw_info->port);
        IPV6_TO_IPV4_MAP(&gw_info->addr, &tmp_v4);
	/* warning: assignment from incompatible pointer type. 04.07.2008. */
        pret = inet_ntop(AF_INET, &tmp_v4, tmp_ip_str, 20);
        HIP_INFO("Got address %s, port %d, TTL %d from daemon\n",
                  tmp_ip_str, tmp_port, tmp_ttl);

        HIP_IFEL(resolve_dht_gateway_info(tmp_ip_str, &serving_gateway),0,
                 "Resolve error!\n");
        HIP_IFEL(opendht_get_key(serving_gateway, opt[0], dht_response), 0,
                 "Get error!\n");
        HIP_INFO("Value received from the DHT %s\n",dht_response);
 out_err:
        return(err);
}


/**
 * Function that is used to set DHT on or off
 *
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_dht_toggle(hip_common_t *msg, int action, const char *opt[], int optc)
{
        int err = 0, status = 0;
        
        if (!strcmp("on",opt[0])) {
                status = SO_HIP_DHT_ON; 
        } else if (!strcmp("off",opt[0])) {
                status = SO_HIP_DHT_OFF;
        } else {
                HIP_IFEL(1, -1, "bad args\n");
        }
        HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1, 
                 "Failed to build user message header.: %s\n", strerror(err));        
        
 out_err:
        return(err);
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
 *               the action and type (pointer to @b "escrow", @b "rvs" or @b "hiprelay").
 * @param optc   the number of elements in the array.
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_service(hip_common_t *msg, int action, const char *opt[], 
			    int optc)
{
	int err = 0;

	HIP_IFEL((action != ACTION_ADD && action != ACTION_REINIT
		  && action != ACTION_DEL), -1,
		 "Only actions \"add\", \"del\" and \"reinit\" are supported "\
		 "for \"service\".\n");
     
	HIP_IFEL((optc < 1), -1, "Missing arguments.\n");
	HIP_IFEL((optc > 1), -1, "Too many arguments.\n");
	
	if(action == ACTION_ADD){
		if (strcmp(opt[0], "escrow") == 0) {
			HIP_INFO("Adding escrow service.\n");
			HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OFFER_ESCROW, 0), -1,
				 "Failed to build user message header.\n");
		} else if (strcmp(opt[0], "rvs") == 0) {
			HIP_INFO("Adding rendezvous service.\n");
			HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OFFER_RVS, 0), -1,
				 "Failed to build user message header.\n");
		} else if (strcmp(opt[0], "hiprelay") == 0) {
			HIP_INFO("Adding HIP UDP relay service.\n");
			HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OFFER_HIPRELAY, 0), -1,
				 "Failed to build user message header.\n");
		} else {
			HIP_ERROR("Unknown service \"%s\".\n", opt[0]);
		}     
	} else if(action == ACTION_REINIT){
		if (strcmp(opt[0], "rvs") == 0) {
			HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_REINIT_RVS, 0), -1,
				 "Failed to build user message header.\n");
		} else if (strcmp(opt[0], "hiprelay") == 0) {
			HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_REINIT_RELAY, 0), -1,
				 "Failed to build user message header.\n");
		} else if (strcmp(opt[0], "escrow") == 0) {
			HIP_ERROR("Action \"reinit\" is not supported for "\
				  "escrow service.\n");
		} else {
			HIP_ERROR("Unknown service \"%s\".\n", opt[0]);
		}
	} else if(action == ACTION_DEL) {
		if (strcmp(opt[0], "escrow") == 0) {
			HIP_ERROR("Action \"delete\" is not supported for "\
				  "escrow service.\n");
		} else if (strcmp(opt[0], "rvs") == 0) {
			HIP_INFO("Deleting rendezvous service.\n");
			HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_CANCEL_RVS, 0),
				 -1, "Failed to build user message header.\n");
		} else if (strcmp(opt[0], "hiprelay") == 0) {
			HIP_INFO("Deleting HIP UDP relay service.\n");
			HIP_IFEL(hip_build_user_hdr(
					 msg, SO_HIP_CANCEL_HIPRELAY, 0), -1,
				 "Failed to build user message header.\n");
		} else {
			HIP_ERROR("Unknown service \"%s\".\n", opt[0]);
		}
	}
	
 out_err:
	return err;
	
}

int hip_conf_handle_run_normal(hip_common_t *msg, int action,
			       const char *opt[], int optc)
{
	return hip_handle_exec_application(0, EXEC_LOADLIB_HIP, optc,
					   (char **) &opt[0]);
}

int hip_do_hipconf(int argc, char *argv[], int send_only)
{
     int err = 0, type_arg = 0;
     long int action = 0, type = 0;
     hip_common_t *msg = NULL;
     //char *text = NULL;
     
     /* Check that we have at least one command line argument. */
     HIP_IFEL((argc < 2), -1, "Invalid arguments.\n\n%s usage:\n%s\n",
	      argv[0], hipconf_usage);

     /* Get a numeric value representing the action. */
     action = hip_conf_get_action(argv[1]);
     HIP_IFEL((action == -1), -1,
	      "Invalid action argument '%s'\n", argv[1]);

     /* Check that we have at least the minumum number of arguments
	for the given action. */
     HIP_IFEL((argc < hip_conf_check_action_argc(action) + 2), -1,
	      "Not enough arguments given for the action '%s'\n",
	      argv[1]);

     /* Is this redundant? What does it do? -Lauri 19.03.2008 19:46. */
     HIP_IFEL(((type_arg = hip_conf_get_type_arg(action)) < 0), -1,
	      "Could not parse type\n");

     type = hip_conf_get_type(argv[type_arg],argv);
     HIP_IFEL((type <= 0 || type >= TYPE_MAX), -1,
	      "Invalid type argument '%s'\n", argv[type_arg]);

     /* Get the type argument for the given action. */
     HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "malloc failed.\n");
     memset(msg, 0, HIP_MAX_PACKET);

     /* Call handler function from the handler function pointer
	array at index "type" with given commandline arguments. 
	The functions build a hip_common message. */
     if (argc == 3)
	  err = (*action_handler[type])(msg, action, (const char **)&argv[2], argc - 3);
     else
	  err = (*action_handler[type])(msg, action, (const char **)&argv[3], argc - 3);

     if(err != 0) {
	     HIP_ERROR("Failed to build a message to hip daemon.\n");
	     goto out_err;
     }
     /* hipconf new hi does not involve any messages to hipd */
     if (hip_get_msg_type(msg) == 0)
	  goto out_err;
     /* Tell hip daemon that this message is from agent. */
     /* if (from_agent)
	{
	err = hip_build_param_contents(msg, NULL, HIP_PARAM_AGENT_SEND_THIS, 0);
	HIP_IFEL(err, -1, "Failed to add parameter to message!\n");
	}*/

     /* Send message to hipd */
     HIP_IFEL(hip_send_daemon_info_wrapper(msg, send_only), -1,
	      "Failed to send user message to the HIP daemon.\n");
     
     HIP_INFO("User message was sent successfully to the HIP daemon.\n");

 out_err:
     if (msg)
	  free(msg);

     return err;
}

int hip_conf_handle_ha(hip_common_t *msg, int action,const char *opt[], int optc)
{

     struct hip_tlv_common *current_param = NULL;
     int err = 0, state, ret;
     in6_addr_t arg1, hit1;

     HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_HA_INFO, 0), -1,
	      "Building of daemon header failed\n");

     HIP_IFEL(hip_send_recv_daemon_info(msg), -1,
	      "send recv daemon info\n");

     while((current_param = hip_get_next_param(msg, current_param)) != NULL) {
	  struct hip_hadb_user_info_state *ha =
	       hip_get_param_contents_direct(current_param);

	  if (!strcmp("all", opt[0]))
	          hip_conf_print_info_ha(ha);

	 
	  if (((opt[0] !='\0') && (opt[1] == '\0')) &&
	      (strcmp("all",opt[0]) !=0))
	  {

	    HIP_IFEL(convert_string_to_address(opt[0], &hit1), -1, "not a valid address family\n");

	    if ((ipv6_addr_cmp(&hit1, &ha->hit_our) == 0) ||  (ipv6_addr_cmp(&hit1, &ha->hit_peer) == 0))
	            hip_conf_print_info_ha(ha);

	  }
     }

out_err:
        return err;
}

int hip_conf_print_info_ha(struct hip_hadb_user_info_state *ha)
{
        HIP_INFO("HA is %s\n", hip_state_str(ha->state));
        HIP_INFO_HIT(" Local HIT", &ha->hit_our);
	HIP_INFO_HIT(" Peer  HIT", &ha->hit_peer);
	HIP_DEBUG_LSI(" Local LSI", &ha->lsi_our);
        HIP_DEBUG_LSI(" Peer  LSI", &ha->lsi_peer);
        HIP_INFO_IN6ADDR(" Local IP", &ha->ip_our);
        HIP_INFO_IN6ADDR(" Peer  IP", &ha->ip_peer);
	HIP_INFO("\n");

}

int hip_conf_handle_handoff(hip_common_t *msg, int action,const char *opt[], int optc)
{	
     int err=0;
		
     if (strcmp("active",opt[0]) ==0)
     {
	  HIP_IFEL(hip_build_user_hdr(msg,SO_HIP_HANDOFF_ACTIVE, 0), -1,
		   "Building of daemon header failed\n");
	  HIP_INFO("handoff mode set to active successfully\n");
     }else
     {
	  HIP_IFEL(hip_build_user_hdr(msg,SO_HIP_HANDOFF_LAZY, 0), -1,
		   "Building of daemon header failed\n");
	  HIP_INFO("handoff mode set to lazy successfully\n");
     }

     HIP_IFEL(hip_send_recv_daemon_info(msg), -1,"send recv daemon info\n");

 out_err:
     return err;
}

int hip_get_hits(hip_common_t *msg, char *opt[], int optc)
{
    struct hip_tlv_common *current_param = NULL;
    struct endpoint_hip *endp = NULL;
    int err=0;
    //struct sockaddr_in6 addr;
    in6_addr_t *defhit;
    struct in_addr *deflsi;
    //struct hip_hadb_user_info_state *ha;
     hip_tlv_type_t param_type;

 
    HIP_IFEL(optc != 1, -EINVAL, "Invalid number of arguments.\n");

    if (!strcmp(opt[0], "all")) {

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_HITS, 0), -1, "Building header failed\n");
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "Sending msg failed\n");

	while((current_param = hip_get_next_param(msg, current_param)) != NULL) {
	    endp = (struct endpoint_hip *)hip_get_param_contents_direct(current_param);
	    HIP_INFO("hi is %s ", endp->flags == HIP_ENDPOINT_FLAG_HIT ? "anonymous" : "public");
	    HIP_INFO("%s", endp->algo == HIP_HI_DSA ? "dsa" : "rsa");
	    HIP_INFO_HIT("\n", &endp->id.hit);
	}

	HIP_INFO("All HITs printed.\n");

    } else if (!strcmp(opt[0], "default")) {
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DEFAULT_HIT, 0), -1, "Building header failed\n");
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "Sending msg failed\n");

	while((current_param = hip_get_next_param(msg, current_param)) != NULL)
	{
		param_type = hip_get_param_type(current_param);
		
		if (param_type == HIP_PARAM_HIT){
			defhit = (struct in6_addr *)hip_get_param_contents_direct(current_param);
			set_hit_prefix(defhit);
			HIP_INFO_HIT("default hi is ", defhit);
		}
		else if (param_type == HIP_PARAM_LSI){
			deflsi = (struct in_addr *)hip_get_param_contents_direct(current_param);
			HIP_DEBUG_LSI("default lsi is ", deflsi);
		}
	}
    } else {
	HIP_ERROR("Invalid argument. Specify default or all.\n");
        err = -EINVAL;
	goto out_err;
    }

    /* Clear message so do_hipconf() doesn't send it again */
    hip_msg_init(msg);

 out_err:
     return err;
}


/**
 * hip_append_pathtolib: Creates the string intended to set the 
 * environmental variable LD_PRELOAD. The function recibes the required 
 * libraries, and then includes the prefix (path where these libraries 
 * are located) to each one. Finally it appends all of the them to the 
 * same string.
 *
 * @param libs            an array of pointers to the required libraries
 * @param lib_all         a pointer to the string to store the result
 * @param lib_all_length  length of the string lib_all
 * @return                zero on success, or -1 overflow in string lib_all
 */

int hip_append_pathtolib(char **libs, char *lib_all, int lib_all_length)
{

     int c_count = lib_all_length, err = 0;
     char *lib_aux = lib_all;
     char *prefix = HIPL_DEFAULT_PREFIX; /* translates to "/usr/local" etc */

     while(*libs != NULL){

	  // Copying prefix to lib_all
	  HIP_IFEL(c_count<strlen(prefix), -1, "Overflow in string lib_all\n");
	  strncpy(lib_aux, prefix, c_count);
	  while(*lib_aux != '\0')
	  {
	       lib_aux++;
	       c_count--;
	  }

	  // Copying "/lib/" to lib_all
	  HIP_IFEL(c_count<5, -1, "Overflow in string lib_all\n");
	  strncpy(lib_aux, "/lib/", c_count);
	  c_count -= 5;
	  lib_aux += 5;

	  // Copying the library name to lib_all
	  HIP_IFEL(c_count<strlen(*libs), -1, "Overflow in string lib_all\n");
	  strncpy(lib_aux, *libs, c_count);
	  while(*lib_aux != '\0')
	  {
	       lib_aux++;
	       c_count--;
	  }

	  // Adding ':' to separate libraries
	  *lib_aux = ':';
	  c_count--;
	  lib_aux++;

	  // Next library
	  libs++;
     }

     // Delete the last ':'
     *--lib_aux = '\0';

 out_err:
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
 * @param do_fork Whether to fork or not.
 * @param type   the numeric action identifier for the action to be performed.
 * @param argc   the number of elements in the array.
 * @param argv   an array of pointers to the command line arguments after
 *               the action and type.
 * @return       zero on success, or negative error value on error.
 */
int hip_handle_exec_application(int do_fork, int type, int argc, char *argv[])
{
	/* Variables. */
	char *path = "/usr/lib:/lib:/usr/local/lib";
	char lib_all[LIB_LENGTH];
	va_list args;
	int err = 0;
	char *libs[5];


	if (do_fork)
		err = fork();
	if (err < 0)
	{
		HIP_ERROR("Failed to exec new application.\n");
	}
	else if (err > 0)
	{
		err = 0;
	}
	else if(err == 0)
	{
		HIP_DEBUG("Exec new application.\n");
		if (type == EXEC_LOADLIB_HIP)
		{
		      libs[0] = "libinet6.so";
		      libs[1] = "libhiptool.so";
		      libs[3] = NULL;
		      libs[4] = NULL;
		      libs[2] = "libhipopendht.so";
		}
		else if (type == EXEC_LOADLIB_OPP)
		{
		      libs[0] = "libopphip.so";
		      libs[1] = "libinet6.so";
		      libs[2] = "libhiptool.so";
		      libs[4] = NULL;
		      libs[3] = "libhipopendht.so";
		}

#if 0
		if (type != EXEC_LOADLIB_NONE)
		{
			setenv("LD_PRELOAD", libs, 1);
			HIP_DEBUG("LD_PRELOADing\n");
		}
#endif

		hip_append_pathtolib(libs, lib_all, LIB_LENGTH);
		setenv("LD_PRELOAD", lib_all, 1);
		HIP_DEBUG("LD_PRELOADing: %s\n", lib_all);
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


/**
 * Send restart request to HIP daemon.
 */
int hip_conf_handle_restart(hip_common_t *msg, int type, const char *opt[],
			    int optc)
{
	int err = 0;

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_RESTART, 0), -1,
		 "hip_build_user_hdr() failed!");
	
 out_err:
	return err;
}

int hip_conf_handle_opptcp(hip_common_t *msg, int action, const char *opt[],
			   int optc)
{
    int err = 0, status = 0;
    
    if (!strcmp("on",opt[0])) {
        status = SO_HIP_SET_OPPTCP_ON; 
    } else if (!strcmp("off",opt[0])) {
        status = SO_HIP_SET_OPPTCP_OFF;
    } else {
        HIP_IFEL(1, -1, "bad args\n");
    }
    HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1, "Failed to build user message header.: %s\n", strerror(err));
    
 out_err:
    return err;


/*	hip_set_opportunistic_tcp_status(1);*/
/*	hip_set_opportunistic_tcp_status(0);*/
}

/**
 * Handles the hipconf commands where the type is @ tcptimeout.
 *
 * @param msg    a pointer to the buffer where the message for hipd will
 *                be written.
 * @param action the numeric action identifier for the action to be performed.
 * @param opt    an array of pointers to the command line arguments after
 *                the action and type.
 *  @param optc   the number of elements in the array (@b 0).
 *  @return       zero on success, or negative error value on error.
 * */

int hip_conf_handle_tcptimeout(struct hip_common *msg, int action,
                   const char *opt[], int optc)
{
    
   int err = 0, status = 0;

    if (!strcmp("on",opt[0])) {

	HIP_INFO("tcptimeout set on\n");
	status = SO_HIP_SET_TCPTIMEOUT_ON;
    } else if (!strcmp("off",opt[0])) {
       
	HIP_INFO("tcptimeout set off\n");
	status = SO_HIP_SET_TCPTIMEOUT_OFF;
    } else {
        HIP_IFEL(1, -1, "bad args\n");
       // err = -1;
	}
    HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1, "build hdr failed: %s\n", strerror(err));

 out_err:
    return err;
}

/**
 * Function that is used to set HIP PROXY on or off
 *
 * @return       zero on success, or negative error value on error.
 */
int hip_conf_handle_hipproxy(struct hip_common *msg, int action, const char *opt[], int optc)
{
        int err = 0, status = 0;
 
#ifdef CONFIG_HIP_HIPPROXY
        if (!strcmp("on",opt[0])) {
                status = SO_HIP_SET_HIPPROXY_ON; 
        } else if (!strcmp("off",opt[0])) {
                status = SO_HIP_SET_HIPPROXY_OFF;
        } else {
                HIP_IFEL(1, -1, "bad args\n");
        }
        HIP_IFEL(hip_build_user_hdr(msg, status, 0), -1, 
                 "build hdr failed: %s\n", strerror(err));          
#endif
        
 out_err:
        return(err);
}
