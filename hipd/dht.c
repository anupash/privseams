/**
 * @file hipd/dht.c
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 * 
 * Summary on the usage
 *
 * @brief All the necessary functionality for DHT (OpenDHT/OpenLookup) usage. 
 *
 * @author: Samu Varjonen <samu.varjonen@hiit.fi>
 **/
#include "dht.h"
#include "hipd.h"


static void hip_publish_hit(char *, char *);
static int hip_publish_addr(char *);
static int hip_dht_put_hdrr(unsigned char *, unsigned char *, int, int, void *);

/**
 * hip_init_dht_sockets - The function initalized two sockets used for
 *                        connection with lookup service(opendht)
 *
 * @param *socket socket to be initialized
 * @param *socket_status updates the status of the socket after every socket operation
 *
 * @return void
 **/
void 
hip_init_dht_sockets(int *socket, int *socket_status)
{
	if (hip_opendht_inuse == SO_HIP_DHT_ON) 
	{
		if (*socket_status == STATE_OPENDHT_IDLE) 
		{
			HIP_DEBUG("Connecting to the DHT with socket no: %d \n", *socket);
			if (*socket < 1)
				*socket = init_dht_gateway_socket_gw(*socket, 
								     opendht_serving_gateway);
			opendht_error = 0;
			opendht_error = connect_dht_gateway(*socket, 
							    opendht_serving_gateway, 0); 
		}
		if (opendht_error == EINPROGRESS) 
		{
			*socket_status = STATE_OPENDHT_WAITING_CONNECT; 
			/* connect not ready */
			HIP_DEBUG("OpenDHT connect unfinished. Socket No: %d \n",*socket);
		}
		else if (opendht_error > -1 && opendht_error != EINPROGRESS)
		{
			*socket_status = STATE_OPENDHT_START_SEND ;
		}		
	}
}

/**
 * hip_register_to_dht - Insert mapping for local host IP addresses to HITs to the queue.
 *
 * @return void
 **/
void 
hip_register_to_dht(void)
{  
	int pub_addr_ret = 0, err = 0;
	char tmp_hit_str[INET6_ADDRSTRLEN + 2];
	struct in6_addr tmp_hit;
	
	/* Check if OpenDHT is off then out_err*/
	HIP_IFE((hip_opendht_inuse != SO_HIP_DHT_ON), 0);
	
	HIP_IFEL(hip_get_default_hit(&tmp_hit), -1, "No HIT found\n");

	hip_convert_hit_to_str(&tmp_hit, NULL, opendht_current_key);
	hip_convert_hit_to_str(&tmp_hit, NULL, tmp_hit_str);

	hip_publish_hit(opendht_name_mapping, tmp_hit_str);
	pub_addr_ret = hip_publish_addr(tmp_hit_str);

 out_err:
	return;
}

/**
 * hip_publish_hit - This function creates HTTP packet for publish HIT
 *                   and puts it into the queue for sending
 *
 * @param *hostname that will be written to the HTTP option HOST
 * @param *hit_str HIT that will be published
 *
 * @return void
 **/
static void 
hip_publish_hit(char *hostname, char *tmp_hit_str)
{
	int err = 0;
	/* Assuming HIP Max packet length, max for DHT put 
	   while it may be too long for OpenDHT */
	char out_packet[HIP_MAX_PACKET]; 
	
	HIP_IFE((hip_opendht_inuse != SO_HIP_DHT_ON), 0);
	
	memset(out_packet, '\0', HIP_MAX_PACKET);
	opendht_error = opendht_put((unsigned char *)hostname,
				    (unsigned char *)tmp_hit_str, 
				    (unsigned char *)opendht_host_name,
				    opendht_serving_gateway_port,
				    opendht_serving_gateway_ttl,out_packet);
	
        if (opendht_error < 0) {
        	HIP_DEBUG("HTTP packet creation for FDQN->HIT PUT failed.\n");
	} else {
		HIP_DEBUG("Sending FDQN->HIT PUT packet to queue. Packet Length: %d\n",strlen(out_packet)+1);
		opendht_error = hip_write_to_dht_queue(out_packet,strlen(out_packet)+1);
		if (opendht_error < 0) {
        		HIP_DEBUG ("Failed to insert FDQN->HIT PUT data in queue \n");
		}
	}
out_err:
        return;
}

/**
 * hip_publish address - This function creates HTTP packet for publish address
 *                       and writes it in the queue for sending
 *
 * @param *tmp_hit_str 
 *
 * @return 0 on success and -1 on errors
 *
 * @note Keep in mind that id opendht is not enabled this function returns zero
 **/
static int 
hip_publish_addr(char * tmp_hit_str)
{
        char out_packet[HIP_MAX_PACKET];
        /* Assuming HIP Max packet length, max for DHT put
           while OpenDHT max size may be lower */
        int err = 0;
	
        HIP_IFE((hip_opendht_inuse != SO_HIP_DHT_ON), 0);
	
        memset(out_packet, '\0', HIP_MAX_PACKET);
        opendht_error = hip_dht_put_hdrr((unsigned char *)tmp_hit_str, 
					 (unsigned char *)opendht_host_name,
					 opendht_serving_gateway_port,
					 opendht_serving_gateway_ttl,out_packet);
        if (opendht_error < 0) {
                HIP_DEBUG("HTTP packet creation for HIT->IP PUT failed.\n");
                return -1;
        } else {
                HIP_DEBUG("Sending HTTP HIT->IP PUT packet to queue.\n");
                opendht_error = hip_write_to_dht_queue(out_packet,strlen(out_packet)+1);
                if (opendht_error < 0) {
                        HIP_DEBUG ("Failed to insert HIT->IP PUT data in queue \n");
                        return -1;
                }
        }
out_err:
        return 0;
}

/**
 * hip_dht_put_hdrr - Function that will create the hdrr packet for the put operation used with the DHT
 *
 * @param *key Key that is used for the put
 * @param *host Host that will be written to the HTTP header HOST option
 * @param opendht_port Port that will be used in the HTTP hdr
 * @param opendht_ttl TTL for the key-value pair
 * @param[out] *put_packet Buffer for the packet
 *
 * @return int 0 on succes, -1 on error
 **/
static int 
hip_dht_put_hdrr(unsigned char * key,
		 unsigned char * host,
		 int opendht_port,
		 int opendht_ttl,void *put_packet)
{ 
	int err = 0;
	int key_len = 0, value_len = 0;
	struct hip_common *hdrr_msg = NULL;
	char tmp_key[21];
	struct in6_addr addrkey;

	memset(&addrkey, 0, sizeof(&addrkey));
	
	hdrr_msg = hip_msg_alloc();
	hip_build_network_hdr(hdrr_msg, HIP_HDRR, 0, &addrkey, &addrkey);
	value_len = hip_build_locators_old(hdrr_msg, 0);
	
	HIP_IFEL((inet_pton(AF_INET6, (char *)key, &addrkey.s6_addr) == 0), -1,
		 "Lookup for HOST ID structure from HI DB failed as key provided is not a HIT\n");
	
	/* The function below builds and appends Host Id
	 * and signature to the msg */
	/*
	 * Setting two message parameters as stated in RFC for HDRR
	 * First one is sender's HIT
	 * Second one is message type, which is draft is assumed to be 20 but it is already used so using 22
	 * XXTODO check the msg type -Samu
	 */
	ipv6_addr_copy(&hdrr_msg->hits, &addrkey);
	
	err = hip_build_host_id_and_signature(hdrr_msg, &addrkey);
	if( err != 0) {
		HIP_DEBUG("Appending Host ID and Signature to HDRR failed.\n");
		goto out_err;
	}
	
	_HIP_DUMP_MSG(hdrr_msg);
	key_len = opendht_handle_key(key, tmp_key);
	value_len = hip_get_msg_total_len(hdrr_msg);
	_HIP_DEBUG("Value len %d\n",value_len);
	
	/* Debug info can be later removed from cluttering the logs */
	hip_print_locator_addresses(hdrr_msg);
	
	/* store for removals*/
	if (opendht_current_hdrr)
		free(opendht_current_hdrr);
	opendht_current_hdrr = hip_msg_alloc();
	memcpy(opendht_current_hdrr, hdrr_msg, sizeof(hip_common_t));
	
	/* Put operation HIT->IP */
	if (build_packet_put_rm((unsigned char *)tmp_key,
				key_len,
				(unsigned char *)hdrr_msg,
				value_len,
				opendht_hdrr_secret,
				40,
				opendht_port,
				(unsigned char *)host,
				put_packet, opendht_ttl) != 0) {
		HIP_DEBUG("Put packet creation failed.\n");
		err = -1;
	}
	HIP_DEBUG("Host address in OpenDHT put locator : %s\n", host);
	HIP_DEBUG("Actual OpenDHT send starts here\n");
	err = 0;
out_err:
	if (hdrr_msg)
		HIP_FREE(hdrr_msg);
	return(err);
}

/**
 * hip_send_queue_data - This function reads the data from hip_queue
 *                   and sends it to the lookup service for publishing
 * 
 * @param *socket Socket to be initialized
 * @param *socket_status Updates the status of the socket after every socket oepration
 *
 * @return int 0 on success, -1 on errors
 **/
static int 
hip_send_queue_data(int *socket, int *socket_status)
{
	int err = 0;
	
	char packet[2048];
	HIP_IFE((hip_opendht_inuse != SO_HIP_DHT_ON), 0);
	
	if (*socket_status == STATE_OPENDHT_IDLE) {
		HIP_DEBUG("Connecting to the DHT with socket no: %d \n", *socket);
		if (*socket < 1)
			*socket = init_dht_gateway_socket_gw(*socket, opendht_serving_gateway);
		opendht_error = 0;
		opendht_error = connect_dht_gateway(*socket, 
						    opendht_serving_gateway, 0); 
		if (opendht_error == -1) {
			HIP_DEBUG("Error connecting to the DHT. Socket No: %d\n", *socket);
			hip_opendht_error_count++;
		} else if (opendht_error > -1 && opendht_error != EINPROGRESS) {
			/*Get packet from queue, if there then proceed*/
			memset(packet, '\0', sizeof(packet));
			opendht_error = hip_read_from_dht_queue(packet);
			_HIP_DEBUG("Packet: %s\n",packet);
			if (opendht_error < 0 && strlen(packet)>0) {
				HIP_DEBUG("Packet reading from queue failed.\n");
			} else {
				opendht_error = opendht_send(*socket,packet);
				if (opendht_error < 0) {
					HIP_DEBUG("Error sending data to the DHT. Socket No: %d\n",
						  *socket);
					hip_opendht_error_count++;
				} else
					*socket_status = STATE_OPENDHT_WAITING_ANSWER;
			}
		} 
		if (opendht_error == EINPROGRESS) {
			*socket_status = STATE_OPENDHT_WAITING_CONNECT; 
			/* connect not ready */
			HIP_DEBUG("OpenDHT connect unfinished. Socket No: %d \n",*socket);
		}
	} else if (*socket_status == STATE_OPENDHT_START_SEND) {
		/* connect finished send the data */
		/*Get packet from queue, if there then proceed*/
		memset(packet, '\0', sizeof(packet));
		opendht_error = hip_read_from_dht_queue(packet);
		_HIP_DEBUG("Packet: %s\n",packet);
		if (opendht_error < 0  && strlen (packet)>0) {
			HIP_DEBUG("Packet reading from queue failed.\n");
		} else {
			opendht_error = opendht_send(*socket,packet);
			if (opendht_error < 0) {
				HIP_DEBUG("Error sending data to the DHT. Socket No: %d\n", 
					  *socket);
				hip_opendht_error_count++;
			} else
				*socket_status = STATE_OPENDHT_WAITING_ANSWER;
		}
	}
 out_err:
	return err;
}

/**
 * hip_dht_remove_current_hdrr - Reads the daemon database and then publishes certificate 
 *                               after regular interval defined in hipd.h
 *
 * @return void
 **/
void 
hip_dht_remove_current_hdrr(void) 
{
	int err = 0;
	int value_len = 0;
	char remove_packet[2048];
	HIP_DEBUG("Building a remove packet for the current HDRR and queuing it\n");
                           
	value_len = hip_get_msg_total_len(opendht_current_hdrr);
	err = build_packet_rm((unsigned char *)opendht_current_key,
			      strlen(opendht_current_key),
			      (unsigned char *)opendht_current_hdrr,
			      value_len, 
			      opendht_hdrr_secret,
			      40,
			      opendht_serving_gateway_port,
			      (unsigned char *) opendht_host_name,
			      (char *) &remove_packet,
			      opendht_serving_gateway_ttl);
	if (err < 0) {
		HIP_DEBUG("Error creating the remove current HDRR packet\n");
		goto out_err;
	}

        err = hip_write_to_dht_queue(remove_packet, strlen(remove_packet) + 1);
	if (err < 0) 
		HIP_DEBUG ("Failed to insert HDRR remove data in queue \n");
out_err:	
	return;
}

/**
 * hip_verify_hdrr - This function verifies host id in the value (HDRR) against HIT used as a 
 *                   key for DHT and it also verifies the signature in HDRR This works on the 
 *                   hip_common message sent to the daemon modifies the message and sets the 
 *                   required flag if (or not) verified
 * 
 * @param msg HDRR to be verified
 * @param addrkey HIT key used for lookup
 *
 * @return 0 on successful verification (OR of signature and host_id verification)
 **/
int 
hip_verify_hdrr(struct hip_common * msg, struct in6_addr * addrkey)
{
	struct hip_host_id *hostid ; 
	struct in6_addr *hit_from_hostid ;
	struct in6_addr *hit_used_as_key ;
	struct hip_hdrr_info *hdrr_info = NULL;
	int alg = -1;
	int is_hit_verified  = -1;
	int is_sig_verified  = -1;
	int err = 0 ;
	void *key;
		
	hostid = hip_get_param (msg, HIP_PARAM_HOST_ID);
	if ( addrkey == NULL)
	{
		hdrr_info = hip_get_param (msg, HIP_PARAM_HDRR_INFO);
		hit_used_as_key = &hdrr_info->dht_key ; 
	} else {
	  	hit_used_as_key = addrkey;
	}
       
	//Check for algo and call verify signature from pk.c
	alg = hip_get_host_id_algo(hostid);
        
	/* Type of the hip msg in header has been modified to 
	 * user message type SO_HIP_VERIFY_DHT_HDRR_RESP , to
	 * get it here. Revert it back to HDRR to give it
	 * original shape as returned by the DHT and
	 *  then verify signature
	 */

	hip_set_msg_type(msg,HIP_HDRR);
	_HIP_DUMP_MSG (msg);
	HIP_IFEL(!(hit_from_hostid = malloc(sizeof(struct in6_addr))), -1, "Malloc for HIT failed\n");
	switch (alg) {
	case HIP_HI_RSA:
		key = hip_key_rr_to_rsa((struct hip_host_id_priv *)hostid, 0);
		is_sig_verified = hip_rsa_verify(key, msg);
		err = hip_rsa_host_id_to_hit (hostid, hit_from_hostid, HIP_HIT_TYPE_HASH100);
		is_hit_verified = memcmp(hit_from_hostid, hit_used_as_key, sizeof(struct in6_addr)) ;
		if (key)
			RSA_free(key);
		break;
	case HIP_HI_DSA:
		key = hip_key_rr_to_dsa((struct hip_host_id_priv *)hostid, 0);
		is_sig_verified = hip_dsa_verify(key, msg);
		err = hip_dsa_host_id_to_hit (hostid, hit_from_hostid, HIP_HIT_TYPE_HASH100);
		is_hit_verified = memcmp(hit_from_hostid, hit_used_as_key, sizeof(struct in6_addr)) ; 
		if (key)
			DSA_free(key);
		break;
	default:
		HIP_ERROR("Unsupported HI algorithm used cannot verify signature (%d)\n", alg);
		break;
	}
	_HIP_DUMP_MSG (msg);
	if (err != 0) {
		HIP_DEBUG("Unable to convert host id to hit for host id verification \n");
	}
	if(hdrr_info) {
		hdrr_info->hit_verified = is_hit_verified ;
		hdrr_info->sig_verified = is_sig_verified ;
	}
	HIP_DEBUG ("Sig verified (0=true): %d\nHit Verified (0=true): %d \n"
		,is_sig_verified, is_hit_verified);
	return (is_sig_verified | is_hit_verified) ;
out_err:

	return err;
}

/** 
 * hip_send_packet_to_lookup_from_queue - Calls to a function which sends 
 *                                    data from the queue to the dht
 *
 * @return void
 **/
void 
hip_send_packet_to_lookup_from_queue(void)
{
	int err = 0;

	HIP_IFE((hip_opendht_inuse != SO_HIP_DHT_ON), 0);

	HIP_DEBUG("DHT error count now %d/%d.\n", 
			hip_opendht_error_count, OPENDHT_ERROR_COUNT_MAX);
	if (hip_opendht_error_count > OPENDHT_ERROR_COUNT_MAX) {
		HIP_DEBUG("DHT error count reached resolving trying to change gateway\n");
		hip_init_dht();
	}
	hip_send_queue_data (&hip_opendht_sock_fqdn, &hip_opendht_fqdn_sent);
	hip_send_queue_data (&hip_opendht_sock_hit, &hip_opendht_hit_sent);
out_err:
	return;
}
