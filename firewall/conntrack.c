#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <glib.h>
#include <glib/glist.h>

#include "debug.h"
#include "conntrack.h"
#include "firewall.h"
#include "rule_management.h"
#include "hip.h"
#include "misc.h"
#include "hadb.h"
#include "pk.h"

struct GList * hipList = NULL;
struct GList * espList = NULL;

/*------------print functions-------------*/
void print_data(struct hip_data * data)
{
  char src[INET6_ADDRSTRLEN];
  char dst[INET6_ADDRSTRLEN];
  hip_in6_ntop(&data->src_hit, src);
  hip_in6_ntop(&data->dst_hit, dst);
  HIP_DEBUG("hip data: src %s dst %s ", src, dst);
  if(data->src_hi == NULL)
    HIP_DEBUG("no hi\n");
  else
    HIP_DEBUG("hi\n");
}

void print_esp_tuple(struct esp_tuple * esp_tuple)
{
  HIP_DEBUG("esp_tuple: spi:%d addr:%s tuple dir:%d\n", 
	    esp_tuple->spi, 
	    addr_to_numeric(&esp_tuple->dst_addr), 
	    esp_tuple->tuple->direction);
}

void print_esp_list()
{
  struct _GList * list = (struct _GList *)espList;
  HIP_DEBUG("ESP LIST:\n");
  while(list){
    print_esp_tuple((struct esp_tuple *) list->data);
    list = list->next;
  }
}

/*------------tuple handling functions-------------*/

/* forms a data based on the packet, returns the tuple*/
struct hip_data * get_hip_data(const struct hip_common * buf){
  
  struct hip_data * data = (struct hip_data *)malloc(sizeof(struct hip_data));
  data->src_hit = buf->hits;
  data->dst_hit = buf->hitr;
  data->src_hi = NULL;
  data->verify = NULL;
  
  HIP_DEBUG("get_hip_data: ");
  print_data(data);

  return data;
} 

/* fetches the hip_tuple from connection table. 
 * Returns the tuple or NULL, if not found.
 */
struct tuple * get_tuple_by_hip(struct hip_data * data){
  struct _GList * list = (struct _GList *) hipList;
  while(list)
    {
      //      gint * temp = (gint *)list->data;
      struct hip_tuple * tuple = (struct hip_tuple *)list->data;
      if(IN6_ARE_ADDR_EQUAL(&data->src_hit, &tuple->data->src_hit) &&
	 IN6_ARE_ADDR_EQUAL(&data->dst_hit, &tuple->data->dst_hit))
	{
	HIP_DEBUG("connection found ");
	print_data(data);
	return tuple->tuple;
	}
      list = list->next;
    }
  HIP_DEBUG("get_tuple_by_hip: no connection found\n");
  return NULL;
}

struct tuple * get_tuple_by_esp(const struct in6_addr * dst_addr, uint32_t spi)
{
  struct _GList * list = (struct _GList *) espList;
  while(list)
    {
      //      gint * temp = (gint *)list->data;
      struct esp_tuple * tuple = (struct esp_tuple *)list->data;
      if(IN6_ARE_ADDR_EQUAL(dst_addr, &tuple->dst_addr) &&
	 spi == tuple->spi)
	{
	HIP_DEBUG("connection found by esp ");
	HIP_DEBUG("%s, %d \n", addr_to_numeric(&tuple->dst_addr), tuple->spi );
	return tuple->tuple;
	}
      list = list->next;
    }
  HIP_DEBUG("get_tuple_by_esp: dst addr %s spi %d no connection found\n",
	 addr_to_numeric(dst_addr, spi));
  return NULL;
}
/**
 * find esp_tuple from a list that matches the argument spi value
 * returns NULL is no such esp_tuple is found
 */
struct esp_tuple * find_esp_tuple(const struct GSList * esp_list, uint32_t spi)
{
  struct _GSList * list = (struct _GSList *) esp_list;
  struct esp_tuple * esp_tuple;
  while(list)
    {
      esp_tuple = (struct esp_tuple *) list->data;
      if(esp_tuple->spi == spi)
	return esp_tuple;
      list = list->next;
    }
  return NULL;
}

/* initialize and insert connection*/
void insert_new_connection(struct hip_data * data){
  struct connection * connection = (struct connection *) malloc(sizeof(struct connection));
  struct _GList * list = (struct _GList *) hipList;

  //connection TODO state
  connection->state = STATE_ESTABLISHED;

  //TODO opportunistic mode, no original dst_hit, reply src_hit
  //original direction tuple
  connection->original.state = HIP_STATE_UNASSOCIATED;
  connection->original.direction = ORIGINAL_DIR;
  connection->original.esp_tuples = NULL;
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
    //(struct esp_tuple *) malloc(sizeof(struct esp_tuple));
  //  connection->reply.esp_tuple->tuple = &connection->reply;
  connection->reply.connection = connection;
  connection->reply.hip_tuple = (struct hip_tuple *) malloc(sizeof(struct hip_tuple));
  connection->reply.hip_tuple->tuple = &connection->reply;
  connection->reply.hip_tuple->data = (struct hip_data *) malloc(sizeof(struct hip_data));
  connection->reply.hip_tuple->data->src_hit = data->dst_hit;
  connection->reply.hip_tuple->data->dst_hit = data->src_hit;
  connection->reply.hip_tuple->data->src_hi = NULL;
  connection->reply.hip_tuple->data->verify = NULL;

  //add tuples to list
  hipList = (struct GList *) g_list_append((struct _GList *)hipList, 
					   (gpointer)connection->original.hip_tuple);
  hipList = (struct GList *) g_list_append((struct _GList *)hipList, 
					   (gpointer)connection->reply.hip_tuple);
  HIP_DEBUG("inserting connection ");
  print_data(data);
}

void insert_esp_tuple(const struct esp_tuple * esp_tuple )
{
  struct _GList * list = (struct _GList *) espList;
  espList = (struct GList *) g_list_append((struct _GList *)espList, 
					   (gpointer)esp_tuple);
  HIP_DEBUG("insert_esp_tuple:\n");
  print_esp_list();
}


/**
 * creates new esp_tuple from parameters
 * if spis dont match or other failure returns NULL
 */
struct esp_tuple * esp_tuple_from_nes_rea(const struct hip_nes * nes,
					  const struct hip_rea * rea, 
					  const struct tuple * tuple)
{
  struct esp_tuple * new_esp = NULL;
  struct hip_rea_info_addr_item * rea_addr = NULL;
  int n = 0, i = 0;
  if(nes && rea && nes->new_spi == rea->spi)
    {
      HIP_DEBUG("esp_tuple_from_nes_rea: new spi %d\n", nes->new_spi);
      //check that old spi is found
      new_esp = (struct esp_tuple *) malloc(sizeof(struct esp_tuple));
      new_esp->spi = nes->new_spi;
      new_esp->tuple = tuple;
      
      n = (hip_get_param_total_len(rea) - sizeof(struct hip_rea))/
	sizeof(struct hip_rea_info_addr_item);
      HIP_DEBUG("esp_tuple_from_nes_rea: %d parameters\n", n);
      if(n > 0)//TODO unlikely case of multiple addresses under spi
	{
	  rea_addr = (void *) rea + sizeof(struct hip_rea);
	  memcpy(&new_esp->dst_addr, &rea_addr->address, sizeof(struct in6_addr)); 
	  HIP_DEBUG("esp_tuple_from_nes_rea: new address %s\n",  
		    addr_to_numeric(&new_esp->dst_addr));
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
 * if spis dont match or other failure returns NULL
 */
struct esp_tuple * esp_tuple_from_nes(const struct hip_nes * nes,
				      const struct in6_addr * addr, 
				      struct tuple * tuple)
{
  struct esp_tuple * new_esp = NULL;
  if(nes)
    {
      new_esp = (struct esp_tuple *) malloc(sizeof(struct esp_tuple));
      new_esp->spi = nes->new_spi;
      new_esp->tuple = tuple;
      
      memcpy(&new_esp->dst_addr, addr, sizeof(struct in6_addr)); 
      HIP_DEBUG("esp_tuple_from_nes: spi %d address %s\n",  
		nes->new_spi, addr_to_numeric(addr));
    }
  return new_esp;
}


/** 
 * initialize and insert connection based on nes and rea
 * returns 1 if succesful 0 otherwise
 */
int insert_connection_from_update(struct hip_data * data, 
				   struct hip_nes * nes,
				   struct hip_rea * rea)
{
  struct connection * connection = (struct connection *) malloc(sizeof(struct connection));
  struct _GList * list = (struct _GList *) hipList;
  struct esp_tuple * esp_tuple = NULL;

  //TODO more checks for parameter validity?
  esp_tuple = esp_tuple_from_nes_rea(nes, rea, &connection->reply);
  if(esp_tuple == NULL)
    {
      free(connection);
      HIP_DEBUG("insert_connection_from_update: can't create connection\n");
      return 0;
    }
  //connection TODO state
  connection->state = STATE_ESTABLISHING_FROM_UPDATE;

  //TODO opportunistic mode, no original dst_hit, reply src_hit
  //original direction tuple
  connection->original.state = HIP_STATE_UNASSOCIATED;
  connection->original.direction = ORIGINAL_DIR;
  connection->original.esp_tuples = NULL;
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
  connection->reply.esp_tuples = (struct GSList *)g_slist_append((struct _GSList *) 
						connection->reply.esp_tuples,
						(gpointer) esp_tuple);
  insert_esp_tuple(esp_tuple);
  
  //(struct esp_tuple *) malloc(sizeof(struct esp_tuple));
  //  connection->reply.esp_tuple->tuple = &connection->reply;
  connection->reply.connection = connection;
  connection->reply.hip_tuple = (struct hip_tuple *) malloc(sizeof(struct hip_tuple));
  connection->reply.hip_tuple->tuple = &connection->reply;
  connection->reply.hip_tuple->data = (struct hip_data *) malloc(sizeof(struct hip_data));
  connection->reply.hip_tuple->data->src_hit = data->dst_hit;
  connection->reply.hip_tuple->data->dst_hit = data->src_hit;
  connection->reply.hip_tuple->data->src_hi = NULL;
  connection->reply.hip_tuple->data->verify = NULL;

  //add tuples to list
  hipList = (struct GList *) g_list_append((struct _GList *)hipList, 
					   (gpointer)connection->original.hip_tuple);
  hipList = (struct GList *) g_list_append((struct _GList *)hipList, 
					   (gpointer)connection->reply.hip_tuple);
  HIP_DEBUG("insert_connection_from_update ");
  print_data(data);
  return 1;
}

void delete_connection(struct connection * connection){
  HIP_DEBUG("TODO deleting connection\n");
}

/**
 * if packet type causes valid state transition to the connection, 
 * the new state is returned, otherwise -1
 * valid state transitions from hip draft and hipl implementation
 */
int check_state_transition(int type, struct connection * connection)
{
  
}

void check_parameters(struct hip_common * hip_common,
		      struct connection * connection)
{
  //  struct hip_tlv_common * tlv = hip_get_next_param(hip_common, NULL);
   
}

/*
  i1-> rvs?
  r1-> get r hi
  i2-> get spi
  r2-> get spi
*/

/**
 * returns 0 when signature verification was succesful
 * otherwise error code, also when signature is missing
 */
int verify_packet_signature(struct hip_host_id * hi, 
			    struct hip_common * common) 
{
  int value = -1;
  if(hi->rdata.algorithm == HIP_HI_RSA) 
    return hip_rsa_verify(hi, common);
  else if(hi->rdata.algorithm == HIP_HI_DSA) 
    return hip_dsa_verify(hi, common);
  else
    {
      printf("verify_packet_signature: unknown algorithm\n");
      return -1;
    }
}

/**
 * handle parameters for r1 packet return 1 if packet
 * ok. if verify_responder parameter true, store responder HI
 * for verifying signatures
 */

//8.6 at base draft. first check signature then store hi
int handle_r1(struct hip_common * common, 
	      struct tuple * tuple,
	      int verify_responder)
{
  struct hip_host_id * hi = NULL, * hi_tuple = NULL;
  struct in6_addr hit;
  int a = 0, v = 0;
  HIP_DEBUG("handle_r1:\n");

  hi = (struct hip_host_id *) hip_get_param(common, HIP_PARAM_HOST_ID);
  if(hi == NULL)
    {
      HIP_DEBUG("handle_r1: no hi found\n");
      return 0;
    }
  if(verify_responder)
    {
      HIP_DEBUG("handle_r1: verifying responder\n");
      hip_host_id_to_hit(hi, &hit, HIP_HIT_TYPE_HASH126);
      //verify hi -> hit
      if(!ipv6_addr_cmp(&hit, &tuple->hip_tuple->data->src_hit))
	HIP_DEBUG("handle_r1: hi-hit match\n");
      else
	{
	  HIP_DEBUG("handle_r1: hi-hit NO match hash %s hit %s \n", 
		    addr_to_numeric(&hit), 
		    addr_to_numeric(&tuple->hip_tuple->data->src_hit));
	  return 0;
	}
      a = hip_get_host_id_algo(hi);
      if(a == HIP_HI_RSA) 
	v = hip_rsa_verify(hi, common);
      else 
	v = hip_dsa_verify(hi, common);
      HIP_DEBUG("verify returned %d \n", v);
      if(v != 0)
	return 0;
      //store hi
      hi_tuple = (struct hip_host_id *) malloc(hip_get_param_total_len(hi));
      
      memcpy(hi_tuple, hi, hip_get_param_total_len(hi));
      tuple->hip_tuple->data->src_hi = hi_tuple;
      
      //      a = hip_get_host_id_algo(tuple->hip_tuple->data->src_hi);
      if(a == HIP_HI_RSA) 
	tuple->hip_tuple->data->verify = hip_rsa_verify;
      else 
	tuple->hip_tuple->data->verify = hip_dsa_verify;
      HIP_DEBUG("handle_r1: hi algorithm %d\n", v);
      
      //verify signature
      //      v = tuple->hip_tuple->data->verify(hi_tuple, common);
      // HIP_DEBUG("verify returned %d \n", v);
    }
  return 1;
}


//TODO is address tarkistus
//TODO int32 enough for spi or hip_spi
int handle_i2(const struct ip6_hdr * ip6_hdr, 
	      const struct hip_common * common, 
	      struct tuple * tuple)
{
  struct hip_spi * spi = NULL, * spi_tuple = NULL;
  struct tuple * other_dir = NULL;
  struct esp_tuple * esp_tuple = malloc(sizeof(struct esp_tuple));
  HIP_DEBUG("handle_i2: 1");
  spi = (struct hip_spi *) hip_get_param(common, HIP_PARAM_SPI);
  if(spi == NULL){
    HIP_DEBUG("handle_i2: no spi found");
    return 0;
  }
  // store in tuple of other direction that will be using
  // the spi and dst address
  HIP_DEBUG("handle_i2: 2");
  if(tuple->direction == ORIGINAL_DIR)
    other_dir = &tuple->connection->reply;
  else
    other_dir = &tuple->connection->original;
  HIP_DEBUG("handle_i2: 3");
  esp_tuple->spi = spi->spi;
  HIP_DEBUG("handle_i2: 4");
  esp_tuple->dst_addr = ip6_hdr->ip6_src;
  esp_tuple->tuple = other_dir;
  other_dir->esp_tuples = (struct GSList *)g_slist_append((struct _GSList *)other_dir->esp_tuples, esp_tuple);
  insert_esp_tuple(esp_tuple);
}

//TODO int32 enough for spi or hip_spi
int handle_r2(struct ip6_hdr * ip6_hdr,
	      struct hip_common * common, 
	      struct tuple * tuple)
{
  struct hip_spi * spi = NULL, * spi_tuple = NULL;
  struct tuple * other_dir = NULL;
  struct esp_tuple * esp_tuple = malloc(sizeof(struct esp_tuple));
  int v = 1;
  spi = (struct hip_spi *) hip_get_param(common, HIP_PARAM_SPI);
  if(spi == NULL){
    HIP_DEBUG("handle_r2: no spi found");
    return 0;
  }
  if(tuple->direction == ORIGINAL_DIR)
    other_dir = &tuple->connection->reply;
  else
    other_dir = &tuple->connection->original;
  esp_tuple->spi = spi->spi;
  esp_tuple->dst_addr = ip6_hdr->ip6_src;
  esp_tuple->tuple = other_dir;
  //add esp_tuple to list of tuples
  other_dir->esp_tuples = (struct GSList *)g_slist_append((struct _GSList *)other_dir->esp_tuples, esp_tuple);
  HIP_DEBUG("handle_r2: spi found %d\n", esp_tuple->spi);
  insert_esp_tuple(esp_tuple);
  HIP_DEBUG("handle r2, inserted spi\n");
  /*
  if(tuple->hip_tuple->data->src_hi != NULL)
    {
      HIP_DEBUG("handle r2, verifying\n");
      v = tuple->hip_tuple->data->verify(tuple->hip_tuple->data->src_hi,
					 common);
      HIP_DEBUG("verify returned %d \n", v);
    }
  */
  return v;
}


/**
 * updates esp tuple according to parameters
 * nes or rea may be null and spi or ip_addr is 
 * not updated in tha case
 * returns 1 if succesfull 0 otherwise
 */
int update_esp_tuple(struct hip_nes * nes,
		     struct hip_rea * rea,
		     struct esp_tuple * esp_tuple)
{
  struct hip_rea_info_addr_item * rea_addr = NULL;
  int n = 0;
  HIP_DEBUG("update_esp_tuple: esp_tuple spi: %d addr: %s\n", 
	    esp_tuple->spi, 
	    addr_to_numeric(&esp_tuple->dst_addr)); 
  if(nes && rea)
    {
      if(nes->old_spi != esp_tuple->spi || rea->spi != nes->old_spi)
	{
	  HIP_DEBUG("update_esp_tuple: spi no match nes old:%d tuple:%d rea:%d\n",
		    nes->old_spi, esp_tuple->spi, rea->spi);
	  return 0;
	}
      esp_tuple->spi = nes->new_spi;
      n = (hip_get_param_total_len(rea) - sizeof(struct hip_rea))/
	sizeof(struct hip_rea_info_addr_item);
      HIP_DEBUG(" %d parameters\n", n);
      if(n < 1)
	{
	  HIP_DEBUG("update_esp_tuple: no rea param found\n");
	  return 0; // no param found
	}
      rea_addr = (void *) rea + sizeof(struct hip_rea);
      //TODO checking
      HIP_DEBUG("update_esp_tuple: rea addr: old address %s ", 
		addr_to_numeric(&esp_tuple->dst_addr)); 
      memcpy(&esp_tuple->dst_addr, &rea_addr->address, sizeof(struct in6_addr)); 
      HIP_DEBUG("new address %s\n",  
		addr_to_numeric(&esp_tuple->dst_addr));
    }
  else if(nes)
    {
      if(nes->old_spi != esp_tuple->spi)
	{
	  HIP_DEBUG("update_esp_tuple: nes spi no match nes:%d tuple:%d\n",
		    nes->old_spi, esp_tuple->spi);
	  return 0;
	}
      esp_tuple->spi = nes->new_spi;
    }

  else if(rea)
    {
      if(rea->spi != esp_tuple->spi)
	{
	  HIP_DEBUG("update_esp_tuple: nes spi no match nes:%d tuple:%d\n",
		    rea->spi, esp_tuple->spi);
	  return 0;	  
	}
      n = (hip_get_param_total_len(rea) - sizeof(struct hip_rea))/
	sizeof(struct hip_rea_info_addr_item);
      HIP_DEBUG(" %d parameters\n", n);
      if(n < 1)
	{
	  HIP_DEBUG("update_esp_tuple: no rea param found\n");
	  return 0; // no param found
	}
      rea_addr = (void *) rea + sizeof(struct hip_rea);
      //TODO checking
      HIP_DEBUG("update_esp_tuple: rea addr: old address %s ", 
		addr_to_numeric(&esp_tuple->dst_addr)); 
      memcpy(&esp_tuple->dst_addr, &rea_addr->address, sizeof(struct in6_addr)); 
      HIP_DEBUG("new address %s\n",  
		addr_to_numeric(&esp_tuple->dst_addr));
    }
  HIP_DEBUG("update_esp_tuple: esp_tuple spi: %d addr: %s\n", 
	    esp_tuple->spi, 
	    addr_to_numeric(&esp_tuple->dst_addr)); 
  return 1;
}
int handle_update(const struct ip6_hdr * ip6_hdr,
		  const struct hip_common * common, 
		  struct tuple * tuple)
{

  //The other end may still keep sending data with old spis and addresses ->
  // old values must be valid until ack is received
  //Anything that can come out of an update packet
  struct hip_tlv_common * param = NULL;
  struct hip_seq * seq = NULL;
  struct hip_nes * nes = NULL;
  struct hip_ack * ack = NULL;
  struct hip_rea * rea = NULL;
  struct hip_rea_info_addr_item * rea_addr = NULL;
  struct hip_echo_request * echo_req = NULL;
  struct hip_echo_response * echo_res = NULL;
  struct tuple * other_dir_tuple = NULL;
  HIP_DEBUG("handle_update\n");
  seq = (struct hip_seq *) hip_get_param(common, HIP_PARAM_SEQ);
  nes = (struct hip_nes *) hip_get_param(common, HIP_PARAM_NES);
  ack = (struct hip_ack *) hip_get_param(common, HIP_PARAM_ACK);
  rea = (struct hip_rea *) hip_get_param(common, HIP_PARAM_REA);
  echo_req = (struct hip_echo_request *) hip_get_param(common, 
						       HIP_PARAM_ECHO_REQUEST);
  echo_res = (struct hip_echo_response *) hip_get_param(common, HIP_PARAM_ECHO_RESPONSE);

  //TODO remove printing
  HIP_DEBUG("handle_update: all params  ");
  for(param = hip_get_next_param(common, param); 
      param; 
      param = hip_get_next_param(common, param))
    {
      HIP_DEBUG(" %d", param->type);
    }
      HIP_DEBUG("\n");
  if(tuple == NULL)// attempt to create state for new connection
    {
      if(nes && rea && seq)
	{
	  //TODO accept mobile check
	  if(!insert_connection_from_update(get_hip_data(common), nes, rea))
	    return 0;
	}      
      else 
	return 0;
      //      if(seq == NULL)
    }
  else
    {
      int n = 0;
      struct GSList * other_dir_esps = NULL;
      struct esp_tuple * esp_tuple = NULL;
      if(tuple->direction == ORIGINAL_DIR)
	{
	  other_dir_tuple = &tuple->connection->reply;
	  other_dir_esps = tuple->connection->reply.esp_tuples;
	}
      else
	{
	  other_dir_tuple = &tuple->connection->original;
	  other_dir_esps = tuple->connection->original.esp_tuples;
	}
      if(seq != NULL){//announces something new
	//TODO seq talteen
	
	/*  //old spi must match the one in tuple
	    if(nes->old_spi == tuple->esp_tuple->spi){
	    tuple->esp_tuple->spi = nes->new_spi;
	    HIP_DEBUG("handle_update: updated spi to %d\n", tuple->esp_tuple->spi);
	    }
	    else
	    HIP_DEBUG("handle_update: nes old spi %d not matching existing spi %d\n", 
	    nes->old_spi, 
	    tuple->esp_tuple->spi);
	*/
	HIP_DEBUG("handle_update: found seq, update id %d\n", seq->update_id);
      }
      //handling single nes and rea parameters
      //Readdress with mobile-initiated rekey
      if(nes != NULL && rea != NULL && seq != NULL) 
	{
	  HIP_DEBUG("handle_update: nes and rea found\n");
	  struct esp_tuple * new_esp = NULL;
	  if(nes->old_spi != nes->new_spi)//update exiting
	    {
	      esp_tuple = find_esp_tuple(other_dir_esps, nes->old_spi);
	      if(esp_tuple == NULL)
		{
		  HIP_DEBUG("No suitable esp_tuple found for updating\n");
		  return 0; //TODO packet discarded here
		}	
	      if(!update_esp_tuple(nes, rea, esp_tuple))
		return 0;
	    }
	  else//create new
	    {
	      new_esp = esp_tuple_from_nes_rea(nes, rea, other_dir_tuple);
	      if(new_esp == NULL)
		return 0;//rea must contain adress for this spi
	      other_dir_esps = (struct GSList *) g_slist_append((struct _GSList *) other_dir_esps, 
								(gpointer) new_esp);
	      insert_esp_tuple(new_esp);
	      //TODO not getting right spi!!! 

	    }
	}
      //Readdress without rekeying
      else if(rea != NULL && seq != NULL)
	{
	  HIP_DEBUG("handle_update: rea found\n");
	  esp_tuple = find_esp_tuple(other_dir_esps, rea->spi);
	  if(esp_tuple == NULL)
	    {
	      HIP_DEBUG("No suitable esp_tuple found for updating\n");
	      return 1; //TODO should packet be discarded here
	      //if mobile host spi not intercepted, but valid,  
	    }
	  if(!update_esp_tuple(NULL, rea, esp_tuple))
	    {
	      return 0;
	    }
	  /*
	  HIP_DEBUG("handle_update: rea");
	  n = (hip_get_param_total_len(rea) - sizeof(struct hip_rea))/
	    sizeof(struct hip_rea_info_addr_item);
	  HIP_DEBUG(" %d parameters\n", n);
	  if(n < 1)
	    {
	      HIP_DEBUG("handle_update: no rea param found\n");
	      return 0; // no param found
	    }
	  rea_addr = (void *) rea + sizeof(struct hip_rea);
	  //TODO checking
	  HIP_DEBUG("handle_update: rea addr: old address %s ", 
		    addr_to_numeric(&esp_tuple->dst_addr)); 
	  memcpy(&esp_tuple->dst_addr, &rea_addr->address, sizeof(struct in6_addr)); 
	  HIP_DEBUG("new address %s\n",  
		    addr_to_numeric(&esp_tuple->dst_addr));
	  */ 
	}
      //replying to Readdress with mobile-initiated rekey
      else if(nes != NULL)
	{
	  HIP_DEBUG("handle_update: nes found old:%d new:%d\n",
		    nes->old_spi, nes->new_spi);
	  if(nes->old_spi != nes->new_spi)
	    {
	      esp_tuple = find_esp_tuple(other_dir_esps, nes->old_spi);
	      if(esp_tuple == NULL)
		{
		  if(tuple->connection->state != STATE_ESTABLISHING_FROM_UPDATE)
		    {
		      HIP_DEBUG("No suitable esp_tuple found for updating\n");
		      return 1; //TODO should packet be discarded here
		    }
		  else//connection state is being established from update
		    {
		      struct esp_tuple * new_esp = 
			esp_tuple_from_nes(nes,
					   &ip6_hdr->ip6_src, 
					   other_dir_tuple);
		      other_dir_esps = (struct GSList *) 
			g_slist_append((struct _GSList *) other_dir_esps, 
				       (gpointer) new_esp);
		      insert_esp_tuple(new_esp);
		      tuple->connection->state = STATE_ESTABLISHED;
	    }
		}
	      if(!update_esp_tuple(nes, NULL, esp_tuple))
		return 0;
	    }
	  else
	    {
	      
	      struct esp_tuple * new_esp = 
		esp_tuple_from_nes(nes,
				   &ip6_hdr->ip6_src, 
				   other_dir_tuple);
	      other_dir_esps = (struct GSList *) g_slist_append((struct _GSList *) other_dir_esps, 
								(gpointer) new_esp);
	      insert_esp_tuple(new_esp);
	    }
	}
      if(ack != NULL)
	{
	  HIP_DEBUG("handle_update: found ack, peer_upd_id %d\n", 
		    ack->peer_update_id);
	}
      if(echo_req != NULL)
	{
	  HIP_DEBUG("handle_update: found echo req\n");
	}
      if(echo_res != NULL)
	{
	  HIP_DEBUG("handle_update: found echo res\n");
	}
      
    }
  return 1;
}

/**
 * the sending party wishes to close HIP association.
 * requires new I1.. if any more data is to be sent.
 * so, the spi tuple may be removed 
 */
int handle_close(struct ip6_hdr * ip6_hdr, 
		 struct hip_common * common, 
		 struct tuple * tuple)
{
  //set timeout UAL + MSL ++
  return 1; //notify details not specified
}

/**
 * the sending party agrees to close HIP association.
 * requires new I1.. if any more data is to be sent.
 * so, the spi tuple may be removed 
 */
int handle_close_ack()
{
  //set timeout UAL + 2MSL ++
  return 1; //notify details not specified
}

/**
 * handles hip parameters and returns verdict for packet.
 * tuple parameter is NULL for new connection.
 * returns 1 if packet ok otherwise 0
 *  
 */
int check_packet(struct ip6_hdr * ip6_hdr, 
		 struct hip_common * common, 
		 struct tuple * tuple,
		 int verify_responder,
		 int accept_mobile)
{
  HIP_DEBUG("check packet: type %d \n", common->type_hdr);
  
  //verify sender signature when required and available
  //no signature in I1 and handle_r1 does verification
  if(common->type_hdr != HIP_I1 &&
     common->type_hdr != HIP_R1 && 
     tuple->hip_tuple->data->src_hi != NULL)
    {
      if(verify_packet_signature(tuple->hip_tuple->data->src_hi, 
				  common) != 0)
	return 0;
    }
  if(common->type_hdr == HIP_I1) 
    {
      if(tuple == NULL)
	{
	  struct hip_data * data = get_hip_data(common);	  
	  insert_new_connection(data);
	}
      else
	{
	  // multiple I1 packets possible, state could be reestalished between
	  // hosts
	  return 1;
	}
    }
  else if(common->type_hdr == HIP_R1) {
    return handle_r1(common, tuple, verify_responder);
  }
  else if(common->type_hdr == HIP_I2) 
    return handle_i2(ip6_hdr, common, tuple);
  else if(common->type_hdr == HIP_R2)
    return handle_r2(ip6_hdr, common, tuple);
  else if(common->type_hdr == HIP_UPDATE)
    {
      
      if(tuple == NULL)// new connection
	{
	  if(!accept_mobile)
	    return 0;
	  else if(verify_responder)
	    return 0; //responder hi not available
	}
      return handle_update(ip6_hdr, common, tuple);
    }
  else if(common->type_hdr == HIP_NOTIFY)
    return 1;
  else if(common->type_hdr == HIP_BOS) //removed from base01
    return 1;
  else if(common->type_hdr == HIP_CLOSE)//TODO testing
    return handle_close(ip6_hdr, common, tuple);
  else if(common->type_hdr == HIP_CLOSE_ACK) //TODO testing
    return handle_close_ack(ip6_hdr, common, tuple);
  else 
    return 0; 
}


int filter_esp_packet(const struct in6_addr * dst_addr, uint32_t spi)
{
  if(get_tuple_by_esp(dst_addr, spi) != NULL)
    return 1;
  else
    return 0;
}

//check the verdict in rule, so connections can only be created when necessary
int filter_state(struct ip6_hdr * ip6_hdr, 
		 struct hip_common * buf, 
		 struct state_option * option,
		 int accept) 
{
  struct hip_data * data = NULL;
  struct tuple * tuple = NULL;
  struct connection * connection = NULL;

  data = get_hip_data(buf);
  tuple = get_tuple_by_hip(data);
  HIP_DEBUG("filter_state: \n");  
    
  if(!tuple)
    {
      //cases where packet will be dropped
      //do not create connection
      if(option->int_opt.value == CONN_NEW && 
	 option->int_opt.boolean && 
	 !accept)
	return 1;
      else if(option->int_opt.value == CONN_ESTABLISHED && 
	      !option->int_opt.boolean && 
	      !accept)
	return 1;
      //      insert_new_connection(data);      
    }
  else
    {
      //cases where packet will be dropped
      //delete existing connection
      if((option->int_opt.value == CONN_ESTABLISHED && 
	  option->int_opt.boolean && 
	  !accept) ||
	 (option->int_opt.value == CONN_NEW && 
	  !option->int_opt.boolean && 
	  !accept))
	{
	  delete_connection(tuple->connection);
	  return 1;
	}
    }
  if(check_packet(ip6_hdr, buf, tuple, 
		  option->verify_responder, 
		  option->accept_mobile))
    {
	return 1;
    }
  else
    return 0;
}

/**
 *packet is accepted by filteringg rules but has not been 
 * filtered through any state rules 
 * needs to be registered by connection tracking
 */
void conntrack(struct ip6_hdr * ip6_hdr, 
	       struct hip_common * buf) 
{
  struct hip_data * data;
  struct tuple * tuple;
  struct connection * connection;

  HIP_DEBUG("conntrack \n");  
  data = get_hip_data(buf);
  tuple = get_tuple_by_hip(data);
    
  if(!tuple)
    {
      HIP_DEBUG("conntrack:inserting new tuple \n");  
      insert_new_connection(data);      
    }
  else
    {
      HIP_DEBUG("conntrack:checking packet \n");  
      check_packet(ip6_hdr, buf, tuple, 0, 1);
    }
}

/* remove connection*/
