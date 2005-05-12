#include <netinet/in.h>
//#include <arpa/inet.h>
#include <netinet/ip.h>
//#include <linux/ipv6.h>
#include <stdio.h>
#include <glib.h>
#include <glib/glist.h>

#include "debug.h"
#include "conntrack.h"
#include "firewall.h"
#include "hip.h"

//TODO alustus ok?
struct GList * hipList = NULL;
struct GList * espList = NULL;

void print_data(struct hip_data * data)
{
  char src[INET6_ADDRSTRLEN];
  char dst[INET6_ADDRSTRLEN];
  hip_in6_ntop(&data->src_hit, src);
  hip_in6_ntop(&data->dst_hit, dst);
  HIP_DEBUG("src: %s dst %s\n", src, dst);
}

/* forms a data based on the packet, returns the tuple*/
//TODO same thing for esp
//TODO palautetaanko pointteri
struct hip_data * get_hip_tuple(const struct hip_common * buf){
  
  struct hip_data * data = (struct hip_data *)malloc(sizeof(struct hip_data));
  data->src_hit = buf->hits;
  data->dst_hit = buf->hitr;  
  
  HIP_DEBUG("get_hip_tuple ");
  print_data(data);

  return data;
  } 

/* fetches the hip_tuple from connection table. 
 * Returns the tuple or NULL, if not found.
 * TODO esp haku
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
  HIP_DEBUG("get_tuple_by_esp: dst addr %s spi %d no connection found",
	 addr_to_numeric(dst_addr, spi));
  return NULL;
}

/* initialize and insert connection*/
void insert_new_connection(struct hip_data * data){
  struct connection * connection = (struct connection *) malloc(sizeof(struct connection));
  struct _GList * list = (struct _GList *) hipList;

  //connection TODO state
  connection->state = CONN_ESTABLISHED;

  //TODO opportunistic mode, no original dst_hit, reply src_hit
  //original direction tuple
  connection->original.state = HIP_STATE_UNASSOCIATED;
  connection->original.direction = ORIGINAL_DIR;
  connection->original.esp_tuple = (struct esp_tuple *) malloc(sizeof(struct esp_tuple));
  connection->original.esp_tuple->tuple = &connection->original;
  connection->original.connection = connection;
  connection->original.hip_tuple = (struct hip_tuple *) malloc(sizeof(struct hip_tuple));
  connection->original.hip_tuple->tuple = &connection->original;
  connection->original.hip_tuple->data = (struct hip_data *) malloc(sizeof(struct hip_data));
  connection->original.hip_tuple->data->src_hit = data->src_hit;
  connection->original.hip_tuple->data->dst_hit = data->dst_hit;
  

  //reply direction tuple
  connection->reply.state = HIP_STATE_UNASSOCIATED;
  connection->reply.direction = REPLY_DIR;
  connection->reply.esp_tuple = (struct esp_tuple *) malloc(sizeof(struct esp_tuple));
  connection->reply.esp_tuple->tuple = &connection->reply;
  connection->reply.connection = connection;
  connection->reply.hip_tuple = (struct hip_tuple *) malloc(sizeof(struct hip_tuple));
  connection->reply.hip_tuple->tuple = &connection->reply;
  connection->reply.hip_tuple->data = (struct hip_data *) malloc(sizeof(struct hip_data));
  connection->reply.hip_tuple->data->src_hit = data->dst_hit;
  connection->reply.hip_tuple->data->dst_hit = data->src_hit;

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
 * handle parameters for r1 packet return 1 if packet
 * ok 
 *
 */
int handle_r1(const struct hip_common * common, struct tuple * tuple)
{
  struct hip_host_id * hi = NULL, * hi_tuple = NULL;
  hi = (struct hip_host_id *) hip_get_param(common, HIP_PARAM_HOST_ID);
  if(hi == NULL){
    HIP_DEBUG("handle_r1: no hi found\n");
    return 0;
  }
  hi_tuple = (struct hip_host_id *) malloc(sizeof(struct hip_host_id));
  memcpy(hi_tuple, hi, sizeof(struct hip_host_id));
  tuple->hip_tuple->data->src_hi = hi_tuple;
  HIP_DEBUG("hi %s \n", hi_tuple);
  if(tuple->direction == ORIGINAL_DIR)
    tuple->connection->reply.hip_tuple->data->dst_hi = hi_tuple;
  else
    tuple->connection->original.hip_tuple->data->dst_hi = hi_tuple;
  return 0;
}
/*-1208613272 -252704555 233 213*/
//TODO addresses taken only here, earlier?
//TODO is address tarkistus
//TODO int32 enough for spi or hip_spi
int handle_i2(const struct ip6_hdr * ip6_hdr, 
	      const struct hip_common * common, 
	      struct tuple * tuple)
{
  struct hip_spi * spi = NULL, * spi_tuple = NULL;
  struct tuple * other_dir = NULL;
  spi = (struct hip_spi *) hip_get_param(common, HIP_PARAM_SPI);
  if(spi == NULL){
    HIP_DEBUG("handle_i2: no spi found");
    return 0;
  }
  // store in tuple of other direction that will be using
  // the spi and dst address
  if(tuple->direction == ORIGINAL_DIR)
    other_dir = &tuple->connection->reply;
  else
    other_dir = &tuple->connection->original;
  other_dir->esp_tuple->spi = spi->spi;
  other_dir->esp_tuple->dst_addr = ip6_hdr->ip6_src;
  HIP_DEBUG("handle_i2: spi found %d\n", other_dir->esp_tuple->spi);
  insert_esp_tuple(other_dir->esp_tuple);
}

//TODO int32 enough for spi or hip_spi
int handle_r2(const struct ip6_hdr * ip6_hdr,
	      const struct hip_common * common, 
	      struct tuple * tuple)
{
  struct hip_spi * spi = NULL, * spi_tuple = NULL;
  struct tuple * other_dir = NULL;
  spi = (struct hip_spi *) hip_get_param(common, HIP_PARAM_SPI);
  if(spi == NULL){
    HIP_DEBUG("handle_r2: no spi found");
    return 0;
  }
  if(tuple->direction == ORIGINAL_DIR)
    other_dir = &tuple->connection->reply;
  else
    other_dir = &tuple->connection->original;
  other_dir->esp_tuple->spi = spi->spi;
  other_dir->esp_tuple->dst_addr = ip6_hdr->ip6_src;
    
  HIP_DEBUG("handle_r2: spi found %d\n", other_dir->esp_tuple->spi);
  insert_esp_tuple(other_dir->esp_tuple);
}

int handle_update(const struct ip6_hdr * ip6_hdr,
	      const struct hip_common * common, 
	      struct tuple * tuple)
{

  //The other end may still keep sending data with old spis and addresses ->
  // old values must be valid until ack is received
  //Anything that can come out of an update packet
  struct hip_seq * seq = NULL;
  struct hip_nes * nes = NULL;
  struct hip_ack * ack = NULL;
  struct hip_rea * rea = NULL;
  struct hip_rea_info_addr_item * rea_addr = NULL;
  struct hip_echo_request * echo_req = NULL;
  struct hip_echo_response * echo_res = NULL;
  HIP_DEBUG("handle_update\n");
  seq = (struct hip_seq *) hip_get_param(common, HIP_PARAM_SEQ);
  nes = (struct hip_nes *) hip_get_param(common, HIP_PARAM_NES);
  ack = (struct hip_ack *) hip_get_param(common, HIP_PARAM_ACK);
  rea = (struct hip_rea *) hip_get_param(common, HIP_PARAM_REA);
  echo_req = (struct hip_echo_request *) hip_get_param(common, 
						       HIP_PARAM_ECHO_REQUEST);
  echo_res = (struct hip_echo_response *) hip_get_param(common, HIP_PARAM_ECHO_RESPONSE);
  if(seq != NULL){//announces something new
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
    if(nes != NULL)
      {
	HIP_DEBUG("handle_update: found nes, new spi %d\n", nes->new_spi);
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
    
  //spi must be known, possibly from earlier parameters
  if(rea != NULL){
    int n = 0;
    struct esp_tuple * other_dir = NULL;
    if(tuple->direction == ORIGINAL_DIR)
      other_dir = tuple->connection->reply.esp_tuple;
    else
      other_dir = tuple->connection->original.esp_tuple;
    HIP_DEBUG("handle_update: rea");
    n = (hip_get_param_total_len(rea) - sizeof(struct hip_rea))/
      sizeof(struct hip_rea_info_addr_item);
    HIP_DEBUG(" %d parameters\n", n);
    rea_addr = (void *) rea + sizeof(struct hip_rea);
    //TODO checking
    HIP_DEBUG("handle_update: rea addr: old address %s ", 
	   addr_to_numeric(&other_dir->dst_addr)); 
    memcpy(&other_dir->dst_addr, &rea_addr->address, sizeof(struct in6_addr)); 
    HIP_DEBUG("new address %s\n",  
	   addr_to_numeric(&other_dir->dst_addr)); 
  }
  return 1;
}
/**
 * handles hip parameters and returns verdict for packet
 *  
 */
int check_packet(const struct ip6_hdr * ip6_hdr, 
		 const struct hip_common * common, 
		 struct tuple * tuple){
  if(common->type_hdr == HIP_I1) {}
  else if(common->type_hdr == HIP_R1) {
    return handle_r1(common, tuple);
  }
  else if(common->type_hdr == HIP_I2) 
    return handle_i2(ip6_hdr, common, tuple);
  else if(common->type_hdr == HIP_R2)
    return handle_r2(ip6_hdr, common, tuple);
  else if(common->type_hdr == HIP_UPDATE)
    return handle_update(ip6_hdr, common, tuple);
  else 
    return -1; //TODO error handling, uknown header type
  return 1;
}

//TODO rule argumentiksi ja tarkistus!!!
int filter_esp_packet(const struct in6_addr * dst_addr, uint32_t spi)
{
  if(get_tuple_by_esp(dst_addr, spi) != NULL)
    return 1;
  else
    return 0;
}

//accept the verdict in rule, so connections can only be created when necessary
int filter_state(const struct ip6_hdr * ip6_hdr, 
		 const struct hip_common * buf, 
		 const struct int_option * option,
		 int accept) 
{
  struct hip_data * data;
  struct tuple * tuple;
  struct connection * connection;
  
  data = get_hip_tuple(buf);
  tuple = get_tuple_by_hip(data);
    
  if(!tuple)
    {
      //cases where packet will be dropped
      //do not create connection
      if(option->value == CONN_NEW && option->boolean && !accept)
	return 1;
      else if(!option->boolean && !accept)
	return 1;
      insert_new_connection(data);      
    }
  else
    {
      //cases where packet will be dropped
      //delete existing connection
      if((option->value == CONN_ESTABLISHED && option->boolean && !accept) ||
	 (option->value == CONN_NEW && !option->boolean && !accept))
	{
	  delete_connection(tuple->connection);
	  return 1;
	}
    }
  if(check_packet(ip6_hdr, buf, tuple))
    {
      //check, whether hi available done in function
      //      if(verify_signature(buf, tuple))
	return 1;
	//  else 
	//	return 0;
    }
  //TODO returning value
  //  return 1;
  else
    return 0;
}



/* remove connection*/
