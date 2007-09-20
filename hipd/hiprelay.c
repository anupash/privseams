/** @file
 * This file defines a rendezvous extension for the Host Identity Protocol
 * (HIP).
 * 
 * @author  Lauri Silvennoinen
 * @version 1.0
 * @date    10.9.2007
 * @note    Related draft:
 *          <a href="http://www.ietf.org/internet-drafts/draft-ietf-hip-nat-traversal-02.txt">
 *          draft-ietf-hip-nat-traversal-02</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */ 


#include "hiprelay.h"

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_HASH_FN(hip_relht_hash, const hip_relrec_t *)
/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_COMP_FN(hip_relht_compare, const hip_relrec_t *)
/** A callback wrapper of the prototype required by @c lh_doall(). */
static IMPLEMENT_LHASH_DOALL_FN(hip_relht_rec_free, hip_relrec_t *)
/** A callback wrapper of the prototype required by @c lh_doall(). */
static IMPLEMENT_LHASH_DOALL_FN(hip_relht_free_expired, hip_relrec_t *)

/** The hashtable storing the relay records. */
static LHASH *hiprelay_ht = NULL;

LHASH *hip_relht_init()
{
     return hiprelay_ht = lh_new(LHASH_HASH_FN(hip_relht_hash), LHASH_COMP_FN(hip_relht_compare));
}

void hip_relht_uninit()
{
     if(hiprelay_ht == NULL)
	  return;

     lh_doall(hiprelay_ht, LHASH_DOALL_FN(hip_relht_rec_free));
     lh_free(hiprelay_ht);
}

unsigned long hip_relht_hash(const hip_relrec_t *rec)
{
     if(rec == NULL)
	  return 0;

     return hip_hash_hit(&(rec->hit_r));
}

int hip_relht_compare(const hip_relrec_t *rec1, const hip_relrec_t *rec2)
{
     if(rec1 == NULL || rec2 == NULL)
	  return 1;

     return hip_match_hit(&(rec1->hit_r), &(rec2->hit_r));
}

void hip_relht_put(hip_relrec_t *rec)
{
     if(hiprelay_ht == NULL || rec == NULL)
	  return;

     /* lh_insert returns always NULL, we cannot return anything from this function. */
     lh_insert(hiprelay_ht, rec);
}

hip_relrec_t *hip_relht_get(hip_relrec_t *rec)
{
     if(hiprelay_ht == NULL || rec == NULL)
	  return NULL;

     return (hip_relrec_t *)lh_retrieve(hiprelay_ht, rec);
}

void hip_relht_rec_free(hip_relrec_t *rec)
{
     if(hiprelay_ht == NULL || rec == NULL)
	  return;

     /* Check if such element exist, and delete the pointer from the hashtable. */
     hip_relrec_t *deleted_rec = lh_delete(hiprelay_ht, rec);

     /* Free the memory allocated for the element. */
     if(deleted_rec != NULL)
     {
	  memset(deleted_rec, '\0', sizeof(*deleted_rec));
	  free(deleted_rec);
     }
}

void hip_relht_free_expired(hip_relrec_t *rec)
{
     if(rec == NULL)
	  return;

     if(time(NULL) - rec->last_contact > HIP_RELREC_LIFETIME)
     {
	  HIP_INFO("Relay record expired, deleting.\n");
	  lh_delete(hiprelay_ht, rec);
	  memset(rec, '\0', sizeof(*rec));
	  free(rec);
     }
}

unsigned long hip_relht_size()
{
     if(hiprelay_ht == NULL)
	  return 0;

     return hiprelay_ht->num_items;
}

void hip_relht_maintenance()
{
     if(hiprelay_ht == NULL)
	  return;
     
     unsigned int tmp = hiprelay_ht->down_load;
     hiprelay_ht->down_load = 0;
     lh_doall(hiprelay_ht, LHASH_DOALL_FN(hip_relht_free_expired));
     hiprelay_ht->down_load = tmp;
}

hip_relrec_t *hip_relrec_alloc(struct in6_addr *hit_r, struct in6_addr *ip_r,
				 hip_relrec_mode_t mode)
{
     if(hit_r == NULL || ip_r == NULL)
	  return NULL;

     hip_relrec_t *rec = (hip_relrec_t*) malloc(sizeof(hip_relrec_t));
     
     if(rec == NULL)
     {
	  HIP_ERROR("Error allocating memory for HIP relay record.\n");
	  return NULL;
     }

     rec->flags = 0;
     hip_relrec_set_mode(rec, mode);
     memcpy(&(rec->hit_r), hit_r, sizeof(*hit_r));
     memcpy(&(rec->ip_r), ip_r, sizeof(*ip_r));
     rec->lifetime = HIP_RELREC_LIFETIME;
     rec->last_contact = time(NULL);
     
     return rec;
}

void hip_relrec_set_mode(hip_relrec_t *rec, hip_relrec_mode_t mode)
{
     if(rec == NULL)
	  return;
     
     switch (mode){
     case HIP_REL_ON:
	  rec->flags |= 0x10;
	  break;
     case HIP_REL_OFF:
	  rec->flags &= ~0x10;
	  break;
     case HIP_REL_NONE_TO_NONE:
	  rec->flags &= 0xf0;
	  break;
     case HIP_REL_NONE_TO_UDP:
	  rec->flags &= 0xf0;
	  rec->flags |= 0x01;
	  break;
     case HIP_REL_UDP_TO_NONE:
	  rec->flags &= 0xf0;
	  rec->flags |= 0x04;
	  break;
     case HIP_REL_UDP_TO_UDP:
	  rec->flags &= 0xf0;
	  rec->flags |= 0x05;
	  break;
     case HIP_REL_TCP_TO_TCP:
	  rec->flags &= 0xf0;
	  rec->flags |= 0x0a;
	  break;
     }
}

void hip_relrec_info(hip_relrec_t *rec)
{
     if(rec == NULL)
	  return;
     
     char status[1024];
     char *cursor = status;
     cursor += sprintf(cursor, "Relay record info:\n");
     cursor += sprintf(cursor, " HIP Relay status: ");
     cursor += sprintf(cursor, (rec->flags & 0x10) ? "ON\n" : "OFF\n");
     cursor += sprintf(cursor, " I -> Relay: ");
     cursor += sprintf(cursor, (rec->flags & 0x04) ? "UDP\n" :
		       (rec->flags & 0x08) ? "TCP\n" : "None\n");
     cursor += sprintf(cursor, " Relay -> R: ");
     cursor += sprintf(cursor, (rec->flags & 0x01) ? "UDP\n" :
		       (rec->flags & 0x02) ? "TCP\n" : "None\n");
     cursor += sprintf(cursor, " Record lifetime: %lu seconds\n", rec->lifetime);
     cursor += sprintf(cursor, " Last contact: %lu seconds ago\n", time(NULL) - rec->last_contact);
     cursor += sprintf(cursor, " HIT of R: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
		       rec->hit_r.s6_addr16[0], rec->hit_r.s6_addr16[1],
		       rec->hit_r.s6_addr16[2], rec->hit_r.s6_addr16[3],
		       rec->hit_r.s6_addr16[4], rec->hit_r.s6_addr16[5],
		       rec->hit_r.s6_addr16[6], rec->hit_r.s6_addr16[7]);
     cursor += sprintf(cursor, " IP of R:  %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
		       rec->ip_r.s6_addr16[0], rec->ip_r.s6_addr16[1],
		       rec->ip_r.s6_addr16[2], rec->ip_r.s6_addr16[3],
		       rec->ip_r.s6_addr16[4], rec->ip_r.s6_addr16[5],
		       rec->ip_r.s6_addr16[6], rec->ip_r.s6_addr16[7]);

     HIP_INFO("\n%s", status);
}
