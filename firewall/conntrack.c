#include "conntrack.h"
#include "dlist.h"
#include "hslist.h"
#include "esp_prot_conntrack.h"

#ifdef CONFIG_HIP_MIDAUTH
#include "pisa.h"
extern int use_midauth;
#endif

#ifdef CONFIG_HIP_PERFORMANCE
#include "performance.h"
#endif

DList * hipList = NULL;
DList * espList = NULL;

int timeoutChecking = 0;
unsigned long timeoutValue = 0;

/*------------print functions-------------*/
void print_data(struct hip_data * data)
{
  char src[INET6_ADDRSTRLEN];
  char dst[INET6_ADDRSTRLEN];
  hip_in6_ntop(&data->src_hit, src);
  hip_in6_ntop(&data->dst_hit, dst);
  HIP_DEBUG("hip data: src %s dst %s\n", src, dst);
  if(data->src_hi == NULL)
    HIP_DEBUG("no hi\n");
  else
    HIP_DEBUG("hi\n");
}

/**
 * prints out the list of addresses of esp_addr_list
 *
 */
void print_esp_addr_list(SList * addr_list)
{
  SList * list = (SList *)addr_list;
  struct esp_address * addr;
  HIP_DEBUG("ESP dst addr list:\n");
  while(list){
    addr = (struct esp_address *) list->data;
    HIP_DEBUG("addr: %s\n", addr_to_numeric(&addr->dst_addr));
    if(addr->update_id != NULL)
      HIP_DEBUG("upd id: %d\n", *addr->update_id);
    list = list->next;
  }
  HIP_DEBUG("\n");
}

void print_tuple(const struct hip_tuple * hiptuple)
{
  HIP_DEBUG("tuple: src:%s dst:%s tuple dir:%d\n",
	    addr_to_numeric(&hiptuple->data->src_hit),
	    addr_to_numeric(&hiptuple->data->dst_hit),
	    hiptuple->tuple->direction);
}

void print_esp_tuple(const struct esp_tuple * esp_tuple)
{
  HIP_DEBUG("esp_tuple: spi:%u new_spi:%u spi_update_id:%d tuple dir:%d\n",
	    esp_tuple->spi, esp_tuple->new_spi, esp_tuple->spi_update_id,
	    esp_tuple->tuple->direction);
  print_esp_addr_list(esp_tuple->dst_addr_list);
  if (esp_tuple->dec_data)
        HIP_DEBUG("Decryption data for esp_tuple exists\n");
}

void print_esp_list()
{
  DList * list = (DList *)espList;
  HIP_DEBUG("ESP LIST: \n");
  while(list){
    print_esp_tuple((struct esp_tuple *) list->data);
    list = list->next;
  }
  HIP_DEBUG("\n");
}

void print_tuple_list()
{
  DList * list = (DList *)hipList;
  HIP_DEBUG("TUPLE LIST: \n");
  if (list) {
  	while(list){
    	print_tuple((struct hip_tuple *) list->data);
    	list = list->next;
  	}
  	HIP_DEBUG("\n");
  }
  else
  	HIP_DEBUG("NULL\n");
}

/*------------tuple handling functions-------------*/

/* forms a data based on the packet, returns a hip_data structure*/
struct hip_data * get_hip_data(const struct hip_common * buf){

  struct hip_data * data = (struct hip_data *)malloc(sizeof(struct hip_data));
  data->src_hit = buf->hits;
  data->dst_hit = buf->hitr;
  data->src_hi = NULL;
  data->verify = NULL;

  _HIP_DEBUG("get_hip_data:\n");

  return data;
}

/* fetches the hip_tuple from connection table.
 * Returns the tuple or NULL, if not found.
 */
struct tuple * get_tuple_by_hip(struct hip_data * data, uint8_t type_hdr,
				struct in6_addr * ip6_from)
{
  DList * list = (DList *) hipList;
  while(list)
    {
      struct hip_tuple * tuple = (struct hip_tuple *)list->data;

      if(IN6_ARE_ADDR_EQUAL(&data->src_hit, &tuple->data->src_hit) &&
	 IN6_ARE_ADDR_EQUAL(&data->dst_hit, &tuple->data->dst_hit))
	{
	  HIP_DEBUG("connection found, \n");
	  //print_data(data);
	  return tuple->tuple;
	}
      list = list->next;
    }

#ifdef CONFIG_HIP_OPPORTUNISTIC
  //if the entry was not found, we check
  //if it was an opportunistic entry and
  //place the real peer hit in the entries
  if(type_hdr == HIP_R1){
    update_peer_opp_info(data, ip6_from);
    return get_tuple_by_hip(data, -1, ip6_from);
  }
#endif

  HIP_DEBUG("get_tuple_by_hip: no connection found\n");
  return NULL;
}

#ifdef CONFIG_HIP_OPPORTUNISTIC
/*
 * replaces the pseudo-hits of the opportunistic entries
 * related to a particular peer with the real hit
*/
void update_peer_opp_info(struct hip_data * data,
			  struct in6_addr * ip6_from){
  struct _DList * list = (struct _DList *) hipList;
  hip_hit_t phit;

  HIP_DEBUG("updating opportunistic entries\n");
  //the pseudo hit is compared with the hit in the entries
  hip_opportunistic_ipv6_to_hit(ip6_from, &phit, HIP_HIT_TYPE_HASH100);

  while(list)
    {
      struct hip_tuple * tuple = (struct hip_tuple *)list->data;

      if(IN6_ARE_ADDR_EQUAL(&data->dst_hit, &tuple->data->src_hit) &&
	 IN6_ARE_ADDR_EQUAL(&phit, &tuple->data->dst_hit))
      {
        ipv6_addr_copy(&tuple->data->dst_hit, &data->src_hit);
      }
      if(IN6_ARE_ADDR_EQUAL(&phit, &tuple->data->src_hit) &&
	 IN6_ARE_ADDR_EQUAL(&data->dst_hit, &tuple->data->dst_hit))
      {
        ipv6_addr_copy(&tuple->data->src_hit, &data->src_hit);
      }
      list = list->next;
    }
  return;
}
#endif

/**
 * Returns the tuple or NULL, if not found.
 * fetches the hip_tuple from connection table.
 */
struct tuple * get_tuple_by_hits(const struct in6_addr * src_hit, const struct in6_addr *dst_hit){
  DList * list = (DList *) hipList;
  while(list)
    {
      struct hip_tuple * tuple = (struct hip_tuple *)list->data;
      if(IN6_ARE_ADDR_EQUAL(src_hit, &tuple->data->src_hit) &&
	 IN6_ARE_ADDR_EQUAL(dst_hit, &tuple->data->dst_hit))
	{
	  HIP_DEBUG("connection found, \n");
	  //print_data(data);
	  return tuple->tuple;
	}
      list = list->next;
    }
  HIP_DEBUG("get_tuple_by_hits: no connection found\n");
  return NULL;
}

/**
 * returns esp_address structure if one is found with address matching
 * the argument, otherwise NULL;
 */
struct esp_address * get_esp_address(SList * addr_list,
				     const struct in6_addr * addr)
{
  SList * list = (SList *) addr_list;
  struct esp_address * esp_addr;
  HIP_DEBUG("get_esp_address\n");

  while(list)
    {
      esp_addr = (struct esp_address *)list->data;
      HIP_DEBUG("addr: %s ", addr_to_numeric(&esp_addr->dst_addr));

	  HIP_DEBUG_HIT("111", &esp_addr->dst_addr);
	  HIP_DEBUG_HIT("222", addr);

      if(IN6_ARE_ADDR_EQUAL(&esp_addr->dst_addr, addr))
	{
	  HIP_DEBUG("addr found\n");
	  return esp_addr;
	}
      list = list->next;
    }
  HIP_DEBUG("get_esp_address: addr %s not found\n", addr_to_numeric(addr));
  return NULL;
}

/**
 * Insert address into list of addresses. If same address exists already
 * the update_id is repplaced with the new value. Returns the address list.
 */
SList * update_esp_address(SList * addr_list,
		     const struct in6_addr * addr,
		     const uint32_t * upd_id)
{
  HIP_DEBUG("update_esp_address: address: %s \n", addr_to_numeric(addr));

  struct esp_address * esp_addr = get_esp_address(addr_list, addr);
  if (!addr_list)
    {
      HIP_DEBUG ("Esp slist is empty\n");
    }
  if(esp_addr != NULL)
    {
      if(upd_id != NULL)
	{
	  if(esp_addr->update_id == NULL)
	    esp_addr->update_id = malloc(sizeof(uint32_t));
	  *esp_addr->update_id = *upd_id;
	}
      HIP_DEBUG("update_esp_address: found and updated\n");
      return addr_list;
    }
  esp_addr = (struct esp_address *) malloc(sizeof(struct esp_address));
  memcpy(&esp_addr->dst_addr, addr, sizeof(struct in6_addr));
  if(upd_id != NULL)
    {
      esp_addr->update_id = malloc(sizeof(uint32_t));
      *esp_addr->update_id = *upd_id;
    }
  else
    esp_addr->update_id = NULL;
  HIP_DEBUG("update_esp_address: addr created and added\n");
  return (SList *)append_to_slist((SList *)addr_list,
					 (void *) esp_addr);
}

/**
 * Finds esp tuple from espList that matches the argument spi and contains the
 * argument ip address
 */
struct tuple * get_tuple_by_esp(const struct in6_addr * dst_addr, uint32_t spi)
{
  SList * list = (SList *) espList;
  if (!list)
    {
      HIP_DEBUG ("Esp tuple list is empty\n");
    }
  while(list)
    {
      struct esp_tuple * tuple = (struct esp_tuple *)list->data;
      if(spi == tuple->spi)
	{
	  if(get_esp_address(tuple->dst_addr_list, dst_addr) != NULL)
	    {
	      HIP_DEBUG("connection found by esp ");
	      return tuple->tuple;
	    }
	}
      list = list->next;
    }
  HIP_DEBUG("get_tuple_by_esp: dst addr %s spi %d no connection found\n",
	     addr_to_numeric(dst_addr), spi);

  HIP_DEBUG_INADDR("DST", dst_addr);

  return NULL;
}

/**
 * find esp_tuple from a list that matches the argument spi value
 * returns NULL is no such esp_tuple is found
 */
struct esp_tuple * find_esp_tuple(const SList * esp_list, uint32_t spi)
{
  SList * list = (SList *) esp_list;
  struct esp_tuple * esp_tuple;
  if (!list)
    {
      HIP_DEBUG ("Esp tuple slist is empty\n");
    }
  while(list)
    {
      esp_tuple = (struct esp_tuple *) list->data;
      if(esp_tuple->spi == spi) {
			HIP_DEBUG("find_esp_tuple: Found esp_tuple with spi %d\n", spi);
			return esp_tuple;
      }
      list = list->next;
    }
  return NULL;
}

/* initialize and insert connection*/
void insert_new_connection(struct hip_data * data){
  HIP_DEBUG("insert_new_connection\n");
  struct connection * connection = NULL;
  DList * list = (DList *) hipList;

  connection = (struct connection *) malloc(sizeof(struct connection));
  memset(connection, 0, sizeof(struct connection));

  connection->state = STATE_ESTABLISHED;
  //set time stamp
  //g_get_current_time(&connection->time_stamp);
  gettimeofday (&connection->time_stamp, NULL);
#ifdef HIP_CONFIG_MIDAUTH
  connection->pisa_state = PISA_STATE_DISALLOW;
#endif

  //original direction tuple
  connection->original.state = HIP_STATE_UNASSOCIATED;
  connection->original.direction = ORIGINAL_DIR;
  connection->original.esp_tuples = NULL;
#ifdef CONFIG_HIP_HIPPROXY
  connection->original.hipproxy = hip_proxy_status;
#endif /* CONFIG_HIP_HIPPROXY */
  //connection->original.esp_tuple->tuple = &connection->original;
  connection->original.connection = connection;
  connection->original.hip_tuple = (struct hip_tuple *) malloc(sizeof(struct hip_tuple));
  memset(connection->original.hip_tuple, 0, sizeof(struct hip_tuple));
  connection->original.hip_tuple->tuple = &connection->original;
  connection->original.hip_tuple->data = (struct hip_data *) malloc(sizeof(struct hip_data));
  memset(connection->original.hip_tuple->data, 0, sizeof(struct hip_data));
  connection->original.hip_tuple->data->src_hit = data->src_hit;
  connection->original.hip_tuple->data->dst_hit = data->dst_hit;
  connection->original.hip_tuple->data->src_hi = NULL;
  connection->original.hip_tuple->data->verify = NULL;

  //reply direction tuple
  connection->reply.state = HIP_STATE_UNASSOCIATED;
  connection->reply.direction = REPLY_DIR;
  connection->reply.esp_tuples = NULL;
#ifdef CONFIG_HIP_HIPPROXY
  connection->reply.hipproxy = hip_proxy_status;
#endif /* CONFIG_HIP_HIPPROXY */
  connection->reply.connection = connection;
  connection->reply.hip_tuple = (struct hip_tuple *) malloc(sizeof(struct hip_tuple));
  memset(connection->reply.hip_tuple, 0, sizeof(struct hip_tuple));
  connection->reply.hip_tuple->tuple = &connection->reply;
  connection->reply.hip_tuple->data = (struct hip_data *) malloc(sizeof(struct hip_data));
  memset(connection->reply.hip_tuple->data, 0, sizeof(struct hip_data));
  connection->reply.hip_tuple->data->src_hit = data->dst_hit;
  connection->reply.hip_tuple->data->dst_hit = data->src_hit;
  connection->reply.hip_tuple->data->src_hi = NULL;
  connection->reply.hip_tuple->data->verify = NULL;

  //add tuples to list
  hipList = (DList *) append_to_list((DList *)hipList,
					   (void *)connection->original.hip_tuple);
  hipList = (DList *) append_to_list((DList *)hipList,
					   (void *)connection->reply.hip_tuple);
  HIP_DEBUG("inserting connection \n");
  //print_data(data);
}

void insert_esp_tuple(const struct esp_tuple * esp_tuple )
{
  DList * list = (DList *) espList;
  espList = (DList *) append_to_list((DList *)espList,
					   (void *)esp_tuple);

  HIP_DEBUG("insert_esp_tuple:\n");
  print_esp_list();
}

/**
 * free hip_tuple structure
 */
void free_hip_tuple(struct hip_tuple * hip_tuple)
{
  HIP_DEBUG("free_hip_tuple:\n");
  if(hip_tuple)
    {
      if(hip_tuple->data)
	{
	  //print_data(hip_tuple->data);
	  if(hip_tuple->data->src_hi)
	    free(hip_tuple->data->src_hi);
	  free(hip_tuple->data);
	}
      free(hip_tuple);
    }
  HIP_DEBUG("free_hip_tuple:\n");
}

/**
 * free esp_tuple structure
 */
void free_esp_tuple(struct esp_tuple * esp_tuple)
{
	HIP_DEBUG("free_esp_tuple:\n");
	//print_esp_tuple(esp_tuple);

	if(esp_tuple)
	{
		SList * list = (SList *) esp_tuple->dst_addr_list;
		struct esp_address * addr = NULL;

		while(list)
		{
			esp_tuple->dst_addr_list = (SList *) remove_link_slist((SList *)esp_tuple->dst_addr_list,
						 list);
			addr = (struct esp_address *) list->data;

			free(addr->update_id);
			free(addr);
			list = (SList *) esp_tuple->dst_addr_list;
		}

		if (esp_tuple->dec_data)
			free(esp_tuple->dec_data);

		free(esp_tuple);
	}

	HIP_DEBUG("free_esp_tuple\n");
}

/**
 * frees dynamically allocated parts and removes hip and esp tuples
 * relating to it
 *
 */
void remove_tuple(struct tuple * tuple)
{
  HIP_DEBUG("remove_tuple\n");
  if(tuple)
    {
      hipList = (DList *) remove_link_dlist((DList *) hipList,
						    find_in_dlist((DList *)
								hipList,
								tuple->hip_tuple));
      free_hip_tuple(tuple->hip_tuple);
      SList * list = (SList *)tuple->esp_tuples;
      while(list)
	{
	  espList = (DList *) remove_link_dlist((DList *)
							espList, (DList *) find_in_dlist((DList *)espList, list->data));
	  tuple->esp_tuples = (SList *) remove_link_slist((SList *)tuple->esp_tuples,
								    list);
	  free_esp_tuple((struct esp_tuple *)list->data);
	  list = (SList *) tuple->esp_tuples;
	}
    }
  HIP_DEBUG("remove_tuple\n");
}

/**
 * removes connection and all hip end esp tuples relating to it
 *
 */
void remove_connection(struct connection * connection)
{
  HIP_DEBUG("remove_connection: tuple list before: \n");
  print_tuple_list();

  HIP_DEBUG("remove_connection: esp list before: \n");
  print_esp_list();

  if(connection)
    {
      remove_tuple(&connection->original);
      remove_tuple(&connection->reply);
      free(connection);
    }

  HIP_DEBUG("remove_connection: tuple list after: \n");
  print_tuple_list();

  HIP_DEBUG("remove_connection: esp list after: \n");
  print_esp_list();
}

/**
 * creates new esp_tuple from parameters.
 * if spis dont match or other failure occurs returns NULL
 */
struct esp_tuple *esp_tuple_from_esp_info_locator(const struct hip_esp_info * esp_info,
					  const struct hip_locator * locator,
					  const struct hip_seq * seq,
					  struct tuple * tuple)
{
  struct esp_tuple * new_esp = NULL;
  struct hip_locator_info_addr_item * locator_addr = NULL;
  int n = 0, i = 0;
  if(esp_info && locator && esp_info->new_spi == esp_info->old_spi) {
      HIP_DEBUG("esp_tuple_from_esp_info_locator: new spi %d\n", esp_info->new_spi);
      //check that old spi is found
      new_esp = (struct esp_tuple *) malloc(sizeof(struct esp_tuple));
      memset(new_esp, 0, sizeof(struct esp_tuple));
      new_esp->spi = ntohl(esp_info->new_spi);
      new_esp->tuple = tuple;

      n = (hip_get_param_total_len(locator) - sizeof(struct hip_locator))/
	sizeof(struct hip_locator_info_addr_item);
      HIP_DEBUG("esp_tuple_from_esp_info_locator: %d addresses in locator\n", n);
      if(n > 0)
	{
	  locator_addr = (void *) locator + sizeof(struct hip_locator);
	  while(n > 0)
	    {
	      struct esp_address * esp_address = malloc(sizeof(struct esp_address));
	      memcpy(&esp_address->dst_addr,
		     &locator_addr->address,
		     sizeof(struct in6_addr));
	      esp_address->update_id = malloc(sizeof(uint32_t));
	      *esp_address->update_id = seq->update_id;
	      new_esp->dst_addr_list = (SList *)
		append_to_slist((SList *)new_esp->dst_addr_list,
			       (void *) esp_address);
	      HIP_DEBUG("esp_tuple_from_esp_info_locator: \n");
	      //print_esp_tuple(new_esp);
	      n--;
	      if(n > 0)
		locator_addr++;
	    }
	}
      else
	{
	  free(new_esp);
	  new_esp = NULL;
	}
    }
  return new_esp;
}

/**
 * creates new esp_tuple from parameters
 * if spis don't match or other failure occurs returns NULL
 */
struct esp_tuple * esp_tuple_from_esp_info(const struct hip_esp_info * esp_info,
				      const struct in6_addr * addr,
				      struct tuple * tuple)
{
  struct esp_tuple * new_esp = NULL;
  if(esp_info)
    {
      new_esp = (struct esp_tuple *) malloc(sizeof(struct esp_tuple));
      memset(new_esp, 0, sizeof(struct esp_tuple));
      new_esp->spi = ntohl(esp_info->new_spi);
      new_esp->tuple = tuple;

      struct esp_address * esp_address = malloc(sizeof(struct esp_address));

      memcpy(&esp_address->dst_addr, addr, sizeof(struct in6_addr));

      esp_address->update_id = NULL;
      new_esp->dst_addr_list = (SList *)append_to_slist((SList *)new_esp->dst_addr_list,
							       (void *) esp_address);
	  HIP_DEBUG("esp_tuple_from_esp_info: \n");
	  //print_esp_tuple(new_esp);
    }
  return new_esp;
}


/**
 * initialize and insert connection based on esp_info and locator
 * returns 1 if succesful 0 otherwise. not used currently
 */
int insert_connection_from_update(struct hip_data * data,
				  struct hip_esp_info * esp_info,
				  struct hip_locator * locator,
				  struct hip_seq * seq)
{
  struct connection * connection = (struct connection *) malloc(sizeof(struct connection));
  DList * list = (DList *) hipList;
  struct esp_tuple * esp_tuple = NULL;

  _HIP_DEBUG("insert_connection_from_update\n");
  if(esp_info)
    _HIP_DEBUG(" esp_info ");
  if(locator)
    _HIP_DEBUG(" locator ");
  if(esp_info)
    _HIP_DEBUG(" esp_info ");
  esp_tuple = esp_tuple_from_esp_info_locator(esp_info, locator, seq, &connection->reply);
  if(esp_tuple == NULL)
    {
      free(connection);
      HIP_DEBUG("insert_connection_from_update: can't create connection\n");
      return 0;
    }
  connection->state = STATE_ESTABLISHING_FROM_UPDATE;
#ifdef HIP_CONFIG_MIDAUTH
  connection->pisa_state = PISA_STATE_DISALLOW;
#endif

  //original direction tuple
  connection->original.state = HIP_STATE_UNASSOCIATED;
  connection->original.direction = ORIGINAL_DIR;
  connection->original.esp_tuples = NULL;
#ifdef CONFIG_HIP_HIPPROXY
  connection->original.hipproxy = hip_proxy_status;
#endif /* CONFIG_HIP_HIPPROXY */
  //connection->original.esp_tuple->tuple = &connection->original;
  connection->original.connection = connection;
  connection->original.hip_tuple = (struct hip_tuple *) malloc(sizeof(struct hip_tuple));
  connection->original.hip_tuple->tuple = &connection->original;
  connection->original.hip_tuple->data = (struct hip_data *) malloc(sizeof(struct hip_data));
  connection->original.hip_tuple->data->src_hit = data->src_hit;
  connection->original.hip_tuple->data->dst_hit = data->dst_hit;
  connection->original.hip_tuple->data->src_hi = NULL;
  connection->original.hip_tuple->data->verify = NULL;


  //reply direction tuple
  connection->reply.state = HIP_STATE_UNASSOCIATED;
  connection->reply.direction = REPLY_DIR;

  connection->reply.esp_tuples = NULL;
#ifdef CONFIG_HIP_HIPPROXY
  connection->reply.hipproxy = hip_proxy_status;
#endif /* CONFIG_HIP_HIPPROXY */
  connection->reply.esp_tuples = (SList *)append_to_slist((SList *)
						connection->reply.esp_tuples,
						(void *) esp_tuple);
  insert_esp_tuple(esp_tuple);

  connection->reply.connection = connection;
  connection->reply.hip_tuple = (struct hip_tuple *) malloc(sizeof(struct hip_tuple));
  connection->reply.hip_tuple->tuple = &connection->reply;
  connection->reply.hip_tuple->data = (struct hip_data *) malloc(sizeof(struct hip_data));
  connection->reply.hip_tuple->data->src_hit = data->dst_hit;
  connection->reply.hip_tuple->data->dst_hit = data->src_hit;
  connection->reply.hip_tuple->data->src_hi = NULL;
  connection->reply.hip_tuple->data->verify = NULL;



  //add tuples to list
  hipList = (DList *) append_to_list((DList *)hipList,
					   (void *)connection->original.hip_tuple);
  hipList = (DList *) append_to_list((DList *)hipList,
					   (void *)connection->reply.hip_tuple);
  HIP_DEBUG("insert_connection_from_update \n");
  //print_data(data);
  return 1;
}


/**
 * returns 0 when signature verification was succesful
 * otherwise error code, also when signature is missing
 */
int verify_packet_signature(struct hip_host_id * hi,
			    struct hip_common * common)
{
#ifdef CONFIG_HIP_PERFORMANCE
  HIP_DEBUG("Start PERF_VERIFY\n");
  hip_perf_start_benchmark(perf_set, PERF_VERIFY);
#endif
  int value = -1;
  if(hi->rdata.algorithm == HIP_HI_RSA)
    return hip_rsa_verify(hi, common);
  else if(hi->rdata.algorithm == HIP_HI_DSA)
    return hip_dsa_verify(hi, common);
  else
    {
      HIP_DEBUG("verify_packet_signature: unknown algorithm\n");
      return -1;
    }
}

/**
 * handles parameters for r1 packet. returns 1 if packet
 * ok. if verify_responder parameter true, store responder HI
 * for verifying signatures
 */

//8.6 at base draft. first check signature then store hi
int handle_r1(struct hip_common * common, const struct tuple * tuple,
		int verify_responder)
{
	struct hip_host_id *hi = NULL, *hi_tuple = NULL;
	struct in6_addr hit;
	int sig_alg = 0;
	// assume correct packet
	int err = 1;

	// R1 should contain the HI
	HIP_IFEL(!(hi = (struct hip_host_id *) hip_get_param(common, HIP_PARAM_HOST_ID)), 0,
			"no hi found\n");

	HIP_DEBUG("verify_responder: %i\n", verify_responder);

	if (verify_responder)
	{
		HIP_DEBUG("verifying hi -> hit mapping...\n");

		/* we have to calculate the hash ourselves to check the
		 * hi -> hit mapping */
		hip_host_id_to_hit(hi, &hit, HIP_HIT_TYPE_HASH100);

		// match received hit and calculated hit
		HIP_IFEL(ipv6_addr_cmp(&hit, &tuple->hip_tuple->data->src_hit), 0,
				"hi -> hit do NOT match\n");
		HIP_DEBUG("hi -> hit match\n");

		HIP_DEBUG("verifying signature...\n");

		// verify the packet's signature
		sig_alg = hip_get_host_id_algo(hi);
		if (sig_alg == HIP_HI_RSA)
		{
			HIP_IFEL(hip_rsa_verify(hi, common), 0, "failed to verify signature\n");

		} else
		{
			HIP_IFEL(hip_dsa_verify(hi, common), 0, "failed to verify signature\n");
		}

		HIP_DEBUG("signature successfully verified\n");

		// store the HI param of the R1 message
		HIP_IFEL(!(hi_tuple = (struct hip_host_id *) malloc(hip_get_param_total_len(hi))),
				0, "failed to allocate memory\n");
		memcpy(hi_tuple, hi, hip_get_param_total_len(hi));
		tuple->hip_tuple->data->src_hi = hi_tuple;

		// also store a function pointer to signature verification function
		sig_alg = hip_get_host_id_algo(tuple->hip_tuple->data->src_hi);
		if (sig_alg == HIP_HI_RSA)
			tuple->hip_tuple->data->verify = hip_rsa_verify;
		else
			tuple->hip_tuple->data->verify = hip_dsa_verify;
	}

	// check if the R1 contains ESP protection transforms
	HIP_IFEL(esp_prot_conntrack_R1_tfms(common, tuple), -1,
			"failed to track esp protection extension transforms\n");

  out_err:
	return err;
}

/**
 * handles parameters for i2 packet. if packet is ok returns 1, otherwise 0;
 */
//if connection already exists and the esp tuple is just added to the existing
//connection. this for example when connection is re-established. the old esp
//tuples are not removed. if attacker spoofs an i2 or r2, the valid peers are
//still able to send data
int handle_i2(const struct in6_addr * ip6_src, const struct in6_addr * ip6_dst,
		const struct hip_common * common, struct tuple * tuple)
{
	struct hip_param *param = NULL;
	struct esp_prot_anchor *prot_anchor = NULL;
	int hash_length = 0;
	struct hip_esp_info * spi = NULL, * spi_tuple = NULL;
	struct tuple * other_dir = NULL;
	struct esp_tuple * esp_tuple = NULL;
	SList * other_dir_esps = NULL;
	// assume correct packet
	int err = 1;

	HIP_DEBUG("\n");

	HIP_IFEL(!(spi = (struct hip_esp_info *) hip_get_param(common,
			HIP_PARAM_ESP_INFO)), 0, "no spi found\n");

	// TODO: clean up
	// TEST
	if(tuple->direction == ORIGINAL_DIR)
	{
		other_dir = &tuple->connection->reply;
		other_dir_esps = tuple->connection->reply.esp_tuples;

	} else
	{
		other_dir = &tuple->connection->original;
		other_dir_esps = tuple->connection->original.esp_tuples;
	}

	// try to look up esp_tuple for this connection
	esp_tuple = find_esp_tuple(other_dir_esps, ntohl(spi->new_spi));

	if (!esp_tuple)
	{
		// esp_tuple does not exist yet
		HIP_IFEL(!(esp_tuple = malloc(sizeof(struct esp_tuple))), 0,
				"failed to allocate memory\n");
		memset(esp_tuple, 0, sizeof(struct esp_tuple));

		esp_tuple->spi = ntohl(spi->new_spi);
		esp_tuple->new_spi = 0;
		esp_tuple->spi_update_id = 0;
		esp_tuple->dst_addr_list = NULL;
		esp_tuple->dst_addr_list = update_esp_address(esp_tuple->dst_addr_list,
					ip6_src, NULL);
		esp_tuple->tuple = other_dir;
		esp_tuple->dec_data = NULL;
		other_dir->esp_tuples = (SList *)
			append_to_slist((SList *)other_dir->esp_tuples, esp_tuple);
		insert_esp_tuple(esp_tuple);

	} else
	{
		_HIP_DEBUG("ESP tuple already exists!\n");
	}

	// TEST_END

	/* check if the I2 contains ESP protection anchor and store state */
	HIP_IFEL(esp_prot_conntrack_I2_anchor(common, tuple), -1,
			"failed to track esp protection extension state\n");

	// store in tuple of other direction that will be using
	// this spi and dst address
	/*if(tuple->direction == ORIGINAL_DIR)
	other_dir = &tuple->connection->reply;
	else
	other_dir = &tuple->connection->original;*/

  out_err:
	return err;
}

/**
 * handles parameters for r2 packet. if packet is ok returns 1, otherwise 0;
 */
//if connection already exists and the esp tuple is just added to the existing
//connection. this for example when connection is re-established. the old esp
//tuples are not removed. if attacker spoofs an i2 or r2, the valid peers are
//still able to send data
int handle_r2(const struct in6_addr * ip6_src, const struct in6_addr * ip6_dst,
		const struct hip_common * common, struct tuple * tuple)
{
	struct hip_esp_info * spi = NULL, * spi_tuple = NULL;
	struct tuple * other_dir = NULL;
	SList * other_dir_esps = NULL;
	struct esp_tuple * esp_tuple = NULL;
	int err = 1;

	HIP_IFEL(!(spi = (struct hip_esp_info *) hip_get_param(common, HIP_PARAM_ESP_INFO)),
			0, "no spi found\n");

	// TODO: clean up
	// TEST
	if(tuple->direction == ORIGINAL_DIR)
	{
		other_dir = &tuple->connection->reply;
		other_dir_esps = tuple->connection->reply.esp_tuples;

	} else
	{
		other_dir = &tuple->connection->original;
		other_dir_esps = tuple->connection->original.esp_tuples;
	}

	// try to look up esp_tuple for this connection
	if (!(esp_tuple = find_esp_tuple(other_dir_esps, ntohl(spi->new_spi))))
	{
		if (!(esp_tuple = esp_prot_conntrack_R2_esp_tuple(other_dir_esps)))
		{
			HIP_IFEL(!(esp_tuple = malloc(sizeof(struct esp_tuple))), 0,
					"failed to allocate memory\n");
			memset(esp_tuple, 0, sizeof(struct esp_tuple));

			//add esp_tuple to list of tuples
			other_dir->esp_tuples = (SList *)
						append_to_slist((SList *)other_dir->esp_tuples,
						esp_tuple);
		}

		// this also has to be set in esp protection extension case
		esp_tuple->spi = ntohl(spi->new_spi);
		esp_tuple->new_spi = 0;
		esp_tuple->spi_update_id = 0;
		esp_tuple->dst_addr_list = NULL;
		esp_tuple->dst_addr_list = update_esp_address(esp_tuple->dst_addr_list,
					ip6_src, NULL);

		esp_tuple->dec_data = NULL;
		esp_tuple->tuple = other_dir;

		insert_esp_tuple(esp_tuple);

		HIP_DEBUG("ESP tuple inserted\n");

	} else
	{
		HIP_DEBUG("ESP tuple already exists!\n");
	}

	/* check if the R2 contains ESP protection anchor and store state */
	HIP_IFEL(esp_prot_conntrack_R2_anchor(common, tuple), -1,
			"failed to track esp protection extension state\n");

	// TEST_END

	/*if(tuple->direction == ORIGINAL_DIR)
	other_dir = &tuple->connection->reply;
	else
	other_dir = &tuple->connection->original;*/

  out_err:
	return err;
}


/**
 * updates esp tuple according to parameters
 * esp_info or locator may be null and spi or ip_addr is
 * not updated in that case
 * returns 1 if successful 0 otherwise
 */
int update_esp_tuple(const struct hip_esp_info * esp_info,
		     const struct hip_locator * locator,
		     const struct hip_seq * seq,
		     struct esp_tuple * esp_tuple)
{
	struct hip_locator_info_addr_item * locator_addr = NULL;
	int err = 1;
	int n = 0;

	HIP_DEBUG("\n");
	//print_esp_tuple(esp_tuple);

	if (esp_info && locator && seq)
	{
		HIP_DEBUG("esp_info, locator and seq, \n");

		if (ntohl(esp_info->old_spi) != esp_tuple->spi
				|| ntohl(esp_info->new_spi) != ntohl(esp_info->old_spi))
		{
			HIP_DEBUG("update_esp_tuple: spi no match esp_info old:%d tuple:%d locator:%d\n",
			ntohl(esp_info->old_spi), esp_tuple->spi, ntohl(esp_info->new_spi));

			err = 0;
			goto out_err;
		}

		esp_tuple->new_spi = ntohl(esp_info->new_spi);
		esp_tuple->spi_update_id = seq->update_id;

		n = (hip_get_param_total_len(locator) - sizeof(struct hip_locator))
				/ sizeof(struct hip_locator_info_addr_item);
		_HIP_DEBUG(" %d locator addresses\n", n);

		if (n < 1)
		{
			HIP_DEBUG("no locator param found\n");

			err = 0; // no param found
			goto out_err;
		}

		locator_addr = (void *) locator + sizeof(struct hip_locator);

		HIP_DEBUG("\n");
		//print_esp_tuple(esp_tuple);

		while (n > 0)
		{
			esp_tuple->dst_addr_list = update_esp_address(esp_tuple->dst_addr_list,
						&locator_addr->address,
						&seq->update_id);
			n--;

			if (n > 0)
				locator_addr++;

		}

		HIP_DEBUG("new tuple:\n");
		//print_esp_tuple(esp_tuple);

	} else if (esp_info && seq)
	{
		HIP_DEBUG("esp_info and seq, ");

		if(ntohl(esp_info->old_spi) != esp_tuple->spi)
		{
			HIP_DEBUG("update_esp_tuple: esp_info spi no match esp_info:%d tuple:%d\n",
						ntohl(esp_info->old_spi), esp_tuple->spi);

			err = 0;
			goto out_err;
		}

		esp_tuple->new_spi = ntohl(esp_info->new_spi);
		esp_tuple->spi_update_id = seq->update_id;

	} else if(locator && seq)
	{
		HIP_DEBUG("locator and seq, ");

		if(ntohl(esp_info->new_spi) != esp_tuple->spi)
		{
			HIP_DEBUG("esp_info spi no match esp_info:%d tuple:%d\n",
			ntohl(esp_info->new_spi), esp_tuple->spi);

			err = 0;
			goto out_err;
		}

		n = (hip_get_param_total_len(locator) - sizeof(struct hip_locator))
				/ sizeof(struct hip_locator_info_addr_item);
		HIP_DEBUG(" %d locator addresses\n", n);

		locator_addr = (void *) locator + sizeof(struct hip_locator);
		_HIP_DEBUG("locator addr: old tuple");
		print_esp_tuple(esp_tuple);

		while(n > 0)
		{
			esp_tuple->dst_addr_list = update_esp_address(esp_tuple->dst_addr_list,
						&locator_addr->address,
						&seq->update_id);
			n--;

			if(n > 0)
				locator_addr++;
		}

		HIP_DEBUG("locator addr: new tuple ");
		print_esp_tuple(esp_tuple);
	}

	_HIP_DEBUG("done, ");
	//print_esp_tuple(esp_tuple);

  out_err:
	return err;
}

/**
 * check parameters for update packet. if packet ok returns 1, otherwise 0
 */
// When announcing new spis/addresses, the other end may still keep sending
// data with old spis and addresses ->
// old values are valid until ack is received
// SPI parameters don't work in current HIPL -> can not be used for creating
// connection state for updates
int handle_update(const struct in6_addr * ip6_src,
                const struct in6_addr * ip6_dst,
		  const struct hip_common * common,
		  struct tuple * tuple)
{
	//Anything that can come out of an update packet
	struct hip_tlv_common * param = NULL;
	struct hip_seq * seq = NULL;
	struct hip_esp_info * esp_info = NULL;
	struct hip_ack * ack = NULL;
	struct hip_locator * locator = NULL;
	struct hip_spi * spi = NULL;
	struct hip_locator_info_addr_item * locator_addr = NULL;
	struct hip_echo_request * echo_req = NULL;
	struct hip_echo_response * echo_res = NULL;
	struct tuple * other_dir_tuple = NULL;
	uint32_t spi_new = 0;
	uint32_t spi_old = 0;
	int err = 0;

	_HIP_DEBUG("handle_update\n");

	// get params from UPDATE message
	seq = (struct hip_seq *) hip_get_param(common, HIP_PARAM_SEQ);
	esp_info = (struct hip_esp_info *) hip_get_param(common, HIP_PARAM_ESP_INFO);
	ack = (struct hip_ack *) hip_get_param(common, HIP_PARAM_ACK);
	locator = (struct hip_locator *) hip_get_param(common, HIP_PARAM_LOCATOR);
	spi = (struct hip_spi *) hip_get_param(common, HIP_PARAM_ESP_INFO);
	echo_req = (struct hip_echo_request *) hip_get_param(common,
			HIP_PARAM_ECHO_REQUEST);
	echo_res = (struct hip_echo_response *) hip_get_param(common,
			HIP_PARAM_ECHO_RESPONSE);

	if(spi)
		_HIP_DEBUG("handle_update: spi param, spi: %d \n", ntohl(spi->spi));

	// connection changed to a path going through this firewall
	if(tuple == NULL)
	{
		_HIP_DEBUG("unknown connection\n");

		// TODO this should only be the case, if (old_spi == 0) != new_spi -> check

		// attempt to create state for new connection
		if(esp_info && locator && seq)
		{
			struct hip_data *data = NULL;

			HIP_DEBUG("setting up a new connection...\n");

			data = get_hip_data(common);

			/* TODO also process anchor here
			 *
			 * active_anchor is set, next_anchor might be NULL
			 */

			if(!insert_connection_from_update(data, esp_info, locator, seq))
			{
				// insertion failed
				HIP_DEBUG("connection insertion failed\n");

				free(data);
				err = 0;
				goto out_err;
			}

			// insertion successful -> go on
			tuple = get_tuple_by_hits(&common->hits, &common->hitr);
			HIP_DEBUG("connection insertion successful\n");
			tuple = get_tuple_by_hits(&common->hits, &common->hitr);

			free(data);

		} else
		{
			// unknown connection, but insufficient parameters to set up state
			HIP_DEBUG("insufficient parameters to create new connection with UPDATE\n");

			err = 0;
			goto out_err;
		}

	} else
	{
		// we already know this connection

		int n = 0;
		SList * other_dir_esps = NULL;
		struct esp_tuple * esp_tuple = NULL;

		if(tuple->direction == ORIGINAL_DIR)
		{
			other_dir_tuple = &tuple->connection->reply;
			other_dir_esps = tuple->connection->reply.esp_tuples;

		} else
		{
			other_dir_tuple = &tuple->connection->original;
			other_dir_esps = tuple->connection->original.esp_tuples;
		}

		if(seq != NULL)
		{
			//announces something new

			_HIP_DEBUG("handle_update: seq found, update id %d\n", seq->update_id);
		}

		/* distinguishing different UPDATE types and type combinations
		 *
		 * TODO check processing of parameter combinations
		 */
		if(esp_info && locator && seq)
		{
			// handling single esp_info and locator parameters
			// Readdress with mobile-initiated rekey

			_HIP_DEBUG("handle_update: esp_info and locator found\n");
			struct esp_tuple * new_esp = NULL;

			/* TODO check processing of SPI
			 *
			 * old_spi == 0, new_spi = x means that host is requesting a new SA
			 * old_spi == new_spi means only location update
			 * old_spi != new_spi means esp_tuple update */
			if(esp_info->old_spi != esp_info->new_spi) //update existing
			{
				esp_tuple = find_esp_tuple(other_dir_esps, ntohl(esp_info->old_spi));

				if(!esp_tuple)
				{
					_HIP_DEBUG("No suitable esp_tuple found for updating\n");

					err = 0;
					goto out_err;
				}

				if(!update_esp_tuple(esp_info, locator, seq, esp_tuple))
				{
					_HIP_DEBUG("failed to update the esp_tuple\n");

					err = 0;
					goto out_err;
				}

			} else //create new esp_tuple
			{
				new_esp = esp_tuple_from_esp_info_locator(esp_info, locator, seq,
						other_dir_tuple);

				if(new_esp == NULL)
				{
					//locator must contain address for this spi
					err = 0;
					goto out_err;
				}

				other_dir_tuple->esp_tuples = (SList *) append_to_slist((SList *)
						other_dir_esps, (void *) new_esp);

				insert_esp_tuple(new_esp);
			}

		} else if(locator && seq)
		{
			// Readdress without rekeying

			_HIP_DEBUG("handle_update: locator found\n");
			esp_tuple = find_esp_tuple(other_dir_esps, ntohl(esp_info->new_spi));

			if(esp_tuple == NULL)
			{
				_HIP_DEBUG("No suitable esp_tuple found for updating\n");

				err = 0;
				goto out_err;
				// if mobile host spi not intercepted, but valid
			}

			if(!update_esp_tuple(NULL, locator, seq, esp_tuple))
			{
				err = 0;
				goto out_err;
			}

		} else if(esp_info && seq)
		{
			//replying to Readdress with mobile-initiated rekey

			_HIP_DEBUG("handle_update: esp_info found old:%d new:%d\n",
					ntohl(esp_info->old_spi), ntohl(esp_info->new_spi));

			if(ntohl(esp_info->old_spi) != ntohl(esp_info->new_spi))
			{
				esp_tuple = find_esp_tuple(other_dir_esps, ntohl(esp_info->old_spi));

				if(esp_tuple == NULL)
				{
					if(tuple->connection->state != STATE_ESTABLISHING_FROM_UPDATE)
					{
						_HIP_DEBUG("No suitable esp_tuple found for updating\n");

						err = 0;
						goto out_err;

					} else//connection state is being established from update
					{
						struct esp_tuple * new_esp = esp_tuple_from_esp_info(
								esp_info, ip6_src, other_dir_tuple);

						other_dir_tuple->esp_tuples = (SList *)
						append_to_slist((SList *) other_dir_esps,
								(void *) new_esp);
						insert_esp_tuple(new_esp);
						tuple->connection->state = STATE_ESTABLISHED;
					}

				} else if(!update_esp_tuple(esp_info, NULL, seq, esp_tuple))
				{
					err = 0;
					goto out_err;
				}

			} else
			{
				struct esp_tuple * new_esp = esp_tuple_from_esp_info(esp_info,
						ip6_src, other_dir_tuple);

				other_dir_tuple->esp_tuples = (SList *) append_to_slist((SList *)
						other_dir_esps, (void *) new_esp);
				insert_esp_tuple(new_esp);
			}
		}

		//multiple update_id values in same ack not tested
		//couldn't get that out of HIPL
		if(ack != NULL)
		{
			SList * esp_tuples = (SList *) tuple->esp_tuples,
				* temp_tuple_list;

			uint32_t * upd_id = &ack->peer_update_id;
			int n = (hip_get_param_total_len(ack) - sizeof(struct hip_ack)) /
					sizeof(uint32_t);

			//Get all update id:s from ack parameter
			//for each update id
			n++; //first one included in hip_ack structure
			while(n > 0)
			{
				//find esp tuple of the connection where
				//addresses have the update id
				temp_tuple_list = esp_tuples;
				struct esp_tuple * esp_tuple;
				SList * original_addr_list, *addr_list,
					* delete_addr_list = NULL, * delete_original_list = NULL;
				int found = 0;

				while(temp_tuple_list)
				{
					esp_tuple = (struct esp_tuple *)temp_tuple_list->data;
					//  original_addr_list = esp_tuple->dst_addr_list;

					//is ack for changing spi?
					if(esp_tuple->spi_update_id == *upd_id)
					{
						esp_tuple->spi = ntohl(esp_tuple->new_spi);
						_HIP_DEBUG("handle_update: ack update id %d, updated spi: %d\n",
								*upd_id, ntohl(esp_tuple->spi));
					}

					addr_list = (SList *)esp_tuple->dst_addr_list;
					struct esp_address * esp_addr;

					while(addr_list)
					{
						esp_addr = (struct esp_address *) addr_list->data;
						//if address has no update id, remove the address

						if(esp_addr->update_id == NULL)
						{
							delete_addr_list = append_to_slist(delete_addr_list,
									(void *)esp_addr);

						} else if(*esp_addr->update_id == *upd_id)
						{
							//if address has the update id, set the update id to null
							free(esp_addr->update_id);
							esp_addr->update_id = NULL;
							found = 1;
						}

						addr_list = addr_list->next;
					}

					//if this was the right tuple,
					//actually remove the deleted addresses
					if(found)
					{
						delete_original_list = delete_addr_list;

						while(delete_addr_list)
						{
							esp_tuple->dst_addr_list = (SList *)
							remove_from_slist((SList *) esp_tuple->dst_addr_list,
							delete_addr_list->data);
							delete_addr_list = delete_addr_list->next;
						}

						free_slist(delete_original_list);
					}

					if(found)
					{
						_HIP_DEBUG("handle_update: ack update id %d,   updated: \n",
								ack->peer_update_id);
						//print_esp_tuple(esp_tuple);
					}

					temp_tuple_list = temp_tuple_list->next;
				}

				n--;
				upd_id++;
			}
		}

		if(echo_req)
		{
			_HIP_DEBUG("handle_update: echo found req\n");
		}

		if(echo_res)
		{
			_HIP_DEBUG("handle_update: echo found res\n");
		}
	}

	// everything should be set now in order to process eventual anchor params
	HIP_IFEL(esp_prot_conntrack_update(common, tuple), -1,
			"failed to process anchor parameter\n");

  out_err:
	return err;
}

/**
 * the sending party wishes to close HIP association.
 * requires new I1.. if any more data is to be sent.
 * so, the spi tuple may be removed
 */
int handle_close(const struct in6_addr * ip6_src,
                const struct in6_addr * ip6_dst,
		 const struct hip_common * common,
		 struct tuple * tuple)
{
	int err = 1;

	// set timeout UAL + MSL ++ (?)
	long int timeout = 20; // TODO: Should this be UAL + MSL?

	HIP_DEBUG("\n");

#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Start PERF_HANDLE_CLOSE\n");
	hip_perf_start_benchmark(perf_set, PERF_HANDLE_CLOSE);
#endif
	HIP_IFEL(!tuple, 0, "tuple is NULL\n");

	tuple->state = STATE_CLOSING;

	//if (!timeoutChecking)
	//	init_timeout_checking(timeout);
	//else
	//	timeoutValue = timeout;

  out_err:
#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Stop and write PERF_HANDLE_CLOSE\n");
	hip_perf_stop_benchmark(perf_set, PERF_HANDLE_CLOSE);
	hip_perf_write_benchmark(perf_set, PERF_HANDLE_CLOSE);
#endif
	return err;
}

/**
 * the sending party agrees to close HIP association.
 * requires new I1.. if any more data is to be sent.
 * so, the spi tuple may be removed
 */
int handle_close_ack(const struct in6_addr * ip6_src,
        const struct in6_addr * ip6_dst,
		 const struct hip_common * common,
		 struct tuple * tuple)
{
	int err = 1;

	// set timeout UAL + 2MSL ++ (?)
	HIP_DEBUG("\n");

#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Start PERF_HANDLE_CLOSE_ACK\n");
	hip_perf_start_benchmark(perf_set, PERF_HANDLE_CLOSE_ACK);
#endif
	HIP_IFEL(!tuple, 0, "tuple is NULL\n");

	tuple->state = STATE_CLOSING;
	remove_connection(tuple->connection);

  out_err:
#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Stop and write PERF_HANDLE_CLOSE_ACK\n");
	hip_perf_stop_benchmark(perf_set, PERF_HANDLE_CLOSE_ACK);
	hip_perf_write_benchmark(perf_set, PERF_HANDLE_CLOSE_ACK);
#endif
	return err; //notify details not specified
}

/**
 * handles hip parameters and returns verdict for packet.
 * tuple parameter is NULL for new connection.
 * returns 1 if packet ok otherwise 0
 *
 */
int check_packet(const struct in6_addr * ip6_src,
                const struct in6_addr * ip6_dst,
		 struct hip_common * common,
		 struct tuple * tuple,
		 int verify_responder,
		 int accept_mobile)
{
	hip_hit_t phit;
	struct in6_addr all_zero_addr;
	int return_value = 1;

	_HIP_DEBUG("check packet: type %d \n", common->type_hdr);

	// new connection can only be started with I1 of from update packets
	// when accept_mobile is true
	if(!(tuple || common->type_hdr == HIP_I1
		|| (common->type_hdr == HIP_UPDATE && accept_mobile)))
    {
     	HIP_DEBUG("hip packet type %d cannot start a new connection\n",
				common->type_hdr);

		return_value = 0;
		goto out_err;
	}

	// verify sender signature when required and available
	// no signature in I1 and handle_r1 does verification
	if (tuple && common->type_hdr != HIP_I1 && common->type_hdr != HIP_R1
			&& tuple->hip_tuple->data->src_hi != NULL)
	{
		if (verify_packet_signature(tuple->hip_tuple->data->src_hi, common) != 0)
		{
			HIP_DEBUG("signature verification failed\n");

			return_value = 0;
			goto out_err;
		}

		HIP_DEBUG_HIT("src hit: ", &tuple->hip_tuple->data->src_hit);
		HIP_DEBUG_HIT("dst hit: ", &tuple->hip_tuple->data->dst_hit);

		HIP_DEBUG("signature verification ok\n");
	}

	// handle different packet types now
	if(common->type_hdr == HIP_I1)
	{
		if(tuple == NULL)
		{
			// create a new tuple
			struct hip_data * data = get_hip_data(common);

#ifdef CONFIG_HIP_OPPORTUNISTIC
			//if peer hit is all-zero in I1 packet, replace it with pseudo hit
			memset(&all_zero_addr, 0, sizeof(struct in6_addr));

			if(IN6_ARE_ADDR_EQUAL(&common->hitr, &all_zero_addr))
			{
				hip_opportunistic_ipv6_to_hit(ip6_dst, &phit,
						HIP_HIT_TYPE_HASH100);
				data->dst_hit = (struct in6_addr)phit;
	  		}
#endif

			insert_new_connection(data);

			// FIXME this does not free all memory -> DEBUG still outputs
			// sth similar to HITs
			// TODO call free for all pointer members of data - comment by René
			free(data);

			HIP_DEBUG_HIT("src hit: ", &data->src_hit);
			HIP_DEBUG_HIT("dst hit: ", &data->dst_hit);

		} else
		{
			HIP_DEBUG("I1 for existing connection\n");

			// TODO shouldn't we drop this?
			return_value = 1;
			goto out_err;
		}
	} else if (common->type_hdr == HIP_R1)
	{
		return_value = handle_r1(common, tuple, verify_responder);

	} else if (common->type_hdr == HIP_I2)
	{
		return_value = handle_i2(ip6_src, ip6_dst, common, tuple);

	} else if (common->type_hdr == HIP_R2)
	{
		return_value = handle_r2(ip6_src, ip6_dst, common, tuple);

	} else if (common->type_hdr == HIP_UPDATE)
	{
		if (tuple == NULL)
		{
			// new connection
			if (!accept_mobile)
				return_value = 0;
			else if (verify_responder)
				return_value = 0; // as responder hi not available
		}

		if (return_value)
			return_value = handle_update(ip6_src, ip6_dst, common, tuple);

	} else if (common->type_hdr == HIP_NOTIFY)
	{
		// don't process and let pass through
		return_value = 1;

	} else if (common->type_hdr == HIP_BOS) //removed from base01
	{
		// don't process and let pass through
		return_value = 1;

	} else if (common->type_hdr == HIP_CLOSE)
	{
		return_value = handle_close(ip6_src, ip6_dst, common, tuple);

	} else if(common->type_hdr == HIP_CLOSE_ACK)
	{
		return_value = handle_close_ack(ip6_src, ip6_dst, common, tuple);

	} else if (common->type_hdr == HIP_LUPDATE)
	{
		return_value = esp_prot_conntrack_lupdate(ip6_src, ip6_dst, common, tuple);
	} else
	{
		HIP_ERROR("unknown packet type\n");
		return_value = 0;
	}

	if(return_value && tuple)
	{
		// update time_stamp only on valid packets
		// for new connections time_stamp is set when creating
		//g_get_current_time(&tuple->connection->time_stamp);
		gettimeofday(&tuple->connection->time_stamp, NULL);
	}

  out_err:
	return return_value;
}

/**
 * Filters esp packet. The entire rule structure is passed as an argument
 * and the HIT options are also filtered here with information from the
 * connection.
 */
int filter_esp_state(const struct in6_addr *dst_addr,
		     struct hip_esp *esp, struct rule * rule, int use_escrow)
{
	struct tuple * tuple = NULL;
	struct hip_tuple * hip_tuple = NULL;
	struct esp_tuple *esp_tuple = NULL;
	int escrow_deny = 0;
	// don't accept packet with this rule by default
	int err = 0;

	// needed to de-multiplex ESP traffic
	uint32_t spi = ntohl(esp->esp_spi);

	// match packet against known connections
	HIP_DEBUG("filtering ESP packet against known connections...\n");

	  //g_mutex_lock(connectionTableMutex);
	//HIP_DEBUG("filter_esp_state: locked mutex\n");

	tuple = get_tuple_by_esp(dst_addr, spi);
	//ESP packet cannot start a connection
	if(!tuple)
	{
		HIP_DEBUG("dst addr %s spi %lx no connection found\n",
				addr_to_numeric(dst_addr), spi);

		err = 0;
		goto out_err;
	} else
	{
		HIP_DEBUG("dst addr %s spi %d connection found\n",
				addr_to_numeric(dst_addr), spi);

		err = 1;
	}

#ifdef CONFIG_HIP_MIDAUTH
	if (use_midauth && tuple->connection->pisa_state == PISA_STATE_DISALLOW) {
		HIP_DEBUG("PISA: ESP unauthorized -> dropped\n");
		err = 0;
	}
#endif

	// move here from escrow processing
	HIP_IFEL(!(esp_tuple = find_esp_tuple(tuple->esp_tuples, spi)), -1,
				"could NOT find corresponding esp_tuple\n");

	// validate hashes of ESP packets if extension is in use
	HIP_IFEL(esp_prot_conntrack_verify(esp_tuple, esp), -1,
			"failed to verify esp hash\n");

	// track ESP SEQ number, if hash token passed verification
	if (ntohl(esp->esp_seq) > esp_tuple->seq_no)
	{
		esp_tuple->seq_no = ntohl(esp->esp_seq);
		//printf("updated esp seq no to: %u\n", esp_tuple->seq_no);
	}

	// do some extra work for key escrow
	if (use_escrow)
	{
		// connection exists and rule is for established connection
		// if rule has options for hits, match them first
		// hits are matched with information of the tuple
		hip_tuple = tuple->hip_tuple;

		if(rule->src_hit)
		{
			HIP_DEBUG("filter_esp_state: src_hit\n ");

			if(!match_hit(rule->src_hit->value,
					hip_tuple->data->src_hit,
					rule->src_hit->boolean))
			{
				// fix this in firewall.c:filter_esp()
				HIP_ERROR("FIXME: wrong rule\n");

				// drop packet to make sure it's noticed that this didn't work
				err = 0;
				goto out_err;
			}
		}

		if(rule->dst_hit)
		{
			HIP_DEBUG("filter_esp_state: dst_hit \n");

			if(!match_hit(rule->dst_hit->value,
					hip_tuple->data->dst_hit,
					rule->dst_hit->boolean))
			{
				// fix this in firewall.c:filter_esp()
				HIP_ERROR("FIXME: wrong rule\n");

				// drop packet to make sure it's noticed that this didn't work
				err = 0;
				goto out_err;
			}
		}

		/* Decrypt contents */
		if (esp_tuple && esp_tuple->dec_data) {
			HIP_DEBUG_HIT("src hit: ", &esp_tuple->tuple->hip_tuple->data->src_hit);
			HIP_DEBUG_HIT("dst hit: ", &esp_tuple->tuple->hip_tuple->data->dst_hit);

			// if there's no error allow the packet
			err = !decrypt_packet(dst_addr, esp_tuple, esp);
		} else
		{
			// If contents cannot be decrypted, drop packet
			// TODO: Is this what we want?
			HIP_DEBUG("Contents cannot be decrypted -> DROP\n");

			err = 0;
		}
	}

  out_err:
	// if we are going to accept the packet, update time stamp of the connection
	if(err > 0)
	{
		gettimeofday(&tuple->connection->time_stamp, NULL);
	}

	//g_mutex_unlock(connectionTableMutex);

	HIP_DEBUG("verdict %d \n", err);

	return err;
}

//check the verdict in rule, so connections can only be created when necessary
int filter_state(const struct in6_addr * ip6_src, const struct in6_addr * ip6_dst,
		 struct hip_common * buf, const struct state_option * option, int accept)
{
	struct hip_data * data = NULL;
	struct tuple * tuple = NULL;
	struct connection * connection = NULL;
	// FIXME results in unsafe use in filter_hip()
	int return_value = -1; //invalid value

	_HIP_DEBUG("\n");
	//g_mutex_lock(connectionTableMutex);
	_HIP_DEBUG("filter_state:locked mutex\n");

	// get data form the buffer and put it in a new data structure
	data = get_hip_data(buf);
	// look up the tuple in the database
	tuple = get_tuple_by_hip(data, buf->type_hdr, ip6_src);

	_HIP_DEBUG("hip_data:\n");
	//print_data(data);
	free(data);

	// cases where packet does not match
	if (!tuple)
	{
		if((option->int_opt.value == CONN_NEW && !option->int_opt.boolean) ||
				(option->int_opt.value == CONN_ESTABLISHED && option->int_opt.boolean))
		{
			return_value = 0;
			goto out_err;
		}
    } else
	{
		if((option->int_opt.value == CONN_ESTABLISHED && !option->int_opt.boolean) ||
				(option->int_opt.value == CONN_NEW && option->int_opt.boolean))

		{
			return_value = 0;
			goto out_err;
		}
	}

	// cases where packet matches, but will be dropped
	// do not create connection or delete existing connection
	// TODO is 'return_value = 1' correct here?
	if (!tuple)
	{
		HIP_DEBUG("filter_state: no tuple found \n");

		if (option->int_opt.value == CONN_NEW && option->int_opt.boolean && !accept)
		{
			return_value = 1;
			goto out_err;

		} else if(option->int_opt.value == CONN_ESTABLISHED &&
				!option->int_opt.boolean && !accept)
		{
			return_value = 1;
			goto out_err;
		}
	} else
	{
		if ((option->int_opt.value == CONN_ESTABLISHED && option->int_opt.boolean
				&& !accept) || (option->int_opt.value == CONN_NEW &&
				!option->int_opt.boolean && !accept))
		{
			remove_connection(tuple->connection);

			return_value = 1;
			goto out_err;
		}
	}

	return_value = check_packet(ip6_src, ip6_dst, buf, tuple, option->verify_responder,
			option->accept_mobile);

  out_err:
	//g_mutex_unlock(connectionTableMutex);
	_HIP_DEBUG("filter state: returning %d \n", return_value);

	return return_value;
}

/**
 * packet is accepted by filtering rules but has not been
 * filtered through any state rules
 * needs to be registered by connection tracking
 */
void conntrack(const struct in6_addr * ip6_src,
        const struct in6_addr * ip6_dst,
	       struct hip_common * buf)
{
	struct hip_data * data;
	struct tuple * tuple;
	struct connection * connection;

	_HIP_DEBUG("\n");
	//g_mutex_lock(connectionTableMutex);
	_HIP_DEBUG("locked mutex\n");

	// convert to new data type
	data = get_hip_data(buf);
	// look up tuple in the db
	tuple = get_tuple_by_hip(data, buf->type_hdr, ip6_src);

	_HIP_DEBUG("checking packet...\n");

	// the accept_mobile parameter is true as packets
	// are not filtered here
	check_packet(ip6_src, ip6_dst, buf, tuple, 0, 1);

	//g_mutex_unlock(connectionTableMutex);
	_HIP_DEBUG("unlocked mutex\n");

	free(data);
}


int add_esp_decryption_data(const struct in6_addr * hit_s,
	const struct in6_addr * hit_r,
	const struct in6_addr * dst_addr,
	uint32_t spi, int dec_alg, int auth_len, int key_len,
	struct hip_crypto_key	* dec_key)
{
	int err = 0;
	struct tuple * tuple = NULL;
	struct esp_tuple * esp_tuple = NULL;
	struct decryption_data * dec_data = NULL;
        struct tuple * other_dir = NULL;

	_HIP_DEBUG("add_esp_decryption_data\n");
//	g_mutex_lock(connectionTableMutex);
	_HIP_DEBUG("add_esp_decryption_data:locked mutex\n");

	HIP_DEBUG("add_esp_decryption_data: dst addr %s spi %d finding connection...\n",
		addr_to_numeric(dst_addr), spi);
        HIP_DEBUG_HIT("src hit: ", hit_s);
        HIP_DEBUG_HIT("dst hit: ", hit_r);
	tuple = get_tuple_by_esp(dst_addr, spi);
	if (!tuple) {
                HIP_DEBUG("Getting tuple by hits\n");
		tuple = get_tuple_by_hits(hit_s, hit_r);
                if (tuple) {
                        esp_tuple = find_esp_tuple(tuple->esp_tuples, spi);
                        if(tuple->direction == ORIGINAL_DIR)
                                other_dir = &tuple->connection->reply;
                        else
                                other_dir = &tuple->connection->original;
                }
        }
        else {
                if(tuple->direction == ORIGINAL_DIR)
                        other_dir = &tuple->connection->original;
                else
                        other_dir = &tuple->connection->reply;
                if (other_dir && other_dir->esp_tuples) {
                        tuple = other_dir;
                        esp_tuple = find_esp_tuple(other_dir->esp_tuples, spi);
                }
                else
                        HIP_DEBUG("No esp-tuples in other direction\n");
        }
	if (!tuple) {
		HIP_DEBUG("Tuple not found!\n");
		err = -1;
		goto out_err;
	}

	if (!esp_tuple) {
		_HIP_DEBUG("ESP tuple not found, creating new\n");
		esp_tuple = malloc(sizeof(struct esp_tuple));

  		// store in tuple of other direction that will be using
  		// this spi and dst address
  		/*if(tuple->direction == ORIGINAL_DIR)
                        other_dir = &tuple->connection->reply;
		else
                        other_dir = &tuple->connection->original;*/
  		esp_tuple->spi = spi;
  		esp_tuple->new_spi = 0;
  		esp_tuple->spi_update_id = 0;
  		esp_tuple->dst_addr_list = NULL;
  		esp_tuple->dec_data = NULL;
  		esp_tuple->dst_addr_list = update_esp_address(esp_tuple->dst_addr_list,
						dst_addr, NULL);
  		esp_tuple->tuple = other_dir;
 		other_dir->esp_tuples = (SList *)append_to_slist((SList *)other_dir->esp_tuples, esp_tuple);
  		insert_esp_tuple(esp_tuple);
		HIP_DEBUG("Created new esp tuple!\n");
	}
	if (esp_tuple != NULL) {
		dec_data = (struct decryption_data *)malloc(sizeof(struct decryption_data));
		if (dec_data) {
			dec_data->auth_len = auth_len;
			dec_data->dec_alg = dec_alg;
			dec_data->key_len = key_len;
			memcpy(&dec_data->dec_key, dec_key, sizeof(struct hip_crypto_key));
			_HIP_DEBUG("Found existing esp_tuple\n");
			_HIP_DEBUG("Key length: %d", key_len);
			_HIP_DEBUG("Key length: %d", dec_data->key_len);
			_HIP_HEXDUMP("Keyhex: ", dec_data->dec_key.key, /*esp_tuple->dec_data->key_len*/ 24);
			esp_tuple->dec_data = dec_data;
			HIP_DEBUG("Added decryption data\n\n");
                        print_esp_list();
		}
	}
	else {
		_HIP_DEBUG("esp_tuple is NULL!");
		err = -1;
		goto out_err;
	}

out_err:
//	g_mutex_unlock(connectionTableMutex);
	return err;
}

int remove_esp_decryption_data(const struct in6_addr * addr, uint32_t spi)
{
	int err = 0;
	struct tuple * tuple = NULL;
	struct esp_tuple * esp_tuple;

	HIP_DEBUG("remove_esp_decryption_data\n");
	//g_mutex_lock(connectionTableMutex);
	HIP_DEBUG("remove_esp_decryption_data:locked mutex\n");

	HIP_DEBUG("remove_esp_decryption_data: dst addr %s spi %d\n",
			addr_to_numeric(addr), spi);

	tuple = get_tuple_by_esp(addr, spi);
	if (!tuple)
	{
		HIP_DEBUG("Tuple not found!\n");

		err = -1;
		goto out_err;
	}

	esp_tuple = find_esp_tuple(tuple->esp_tuples, spi);
	if (!esp_tuple)
	{
		HIP_DEBUG("No ESP-tuple found, state not yet created.\n");

	} else
	{
		free(esp_tuple->dec_data);
		esp_tuple->dec_data = NULL;
	}

  out_err:
	//g_mutex_unlock(connectionTableMutex);
	return err;
}

//Functions for connection timeout checking

void * check_for_timeouts(void * data)
{
  while(timeoutChecking)
    {
      _HIP_DEBUG("check_for_timeouts: waiting for %d seconds \n", 20);
//      g_usleep(20000000);

      _HIP_DEBUG("check_for_timeouts: checking for timed out connections\n");
//      g_mutex_lock(connectionTableMutex);
      _HIP_DEBUG("check_for_timeouts:locked mutex\n");
      DList * list = (DList *)hipList;
      struct hip_tuple * hip_tuple = NULL;
      struct timeval current;
      long difference = 0;
      //g_get_current_time(&current);
      gettimeofday (&current, NULL);
      while(list)
	{
	  hip_tuple = (struct hip_tuple *) list->data;
	  difference = current.tv_sec -
	    hip_tuple->tuple->connection->time_stamp.tv_sec;
	  _HIP_DEBUG("check_for_timeouts: connection idle time: %d\n", difference);
	  if(difference > timeoutValue)
	    {
	      remove_connection(hip_tuple->tuple->connection);
	    }
	  list = list->next;
	}
//      g_mutex_unlock(connectionTableMutex);
      _HIP_DEBUG("check_for_timeouts:unlocked mutex\n");

    }
  return NULL;
}

#if 0
/**
 * initialize checking for connection timeouts. timeout value in seconds is
 * passed in the argument timeout. with negative or 0 value no connection
 * timeout is used
*/
void init_timeout_checking(long int timeout_val)
{
	HIP_DEBUG("initializing timeout checking\n");
	/* Mutex needs to be initialized because thread system is initialized
	 * elsewhere */
// 	connectionTableMutex = g_mutex_new();
  if (timeout_val > 0)
    {
      HIP_DEBUG("Timeout val = %d\n", timeout_val);
      timeoutValue = timeout_val;
      timeoutChecking = 1;
/*      if (!g_thread_supported())
      {
//     		g_thread_init(NULL);
     		_HIP_DEBUG("init_timeout_checking: initialized thread system\n");
  		}
  		else
  		{
     		_HIP_DEBUG("init_timeout_checking: thread system already initialized\n");
  		}
      condition = g_cond_new();

//      connectionChecking = g_thread_create(check_for_timeouts,
//					   NULL,
////					   FALSE,
////					   NULL);
    }
    */
}
#endif
