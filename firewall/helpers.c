#include <netinet/in.h>
#include <net/hip.h>

//#include "hip.h"
#include "debug.h"
#include "helpers.h"
#include "firewall.h"


/**
 * TODO copied, see if available else where
 * get char* out of in6_addr 
 */
char *
addr_to_numeric(const struct in6_addr *addrp)
{
	/* 0000:0000:0000:0000:0000:000.000.000.000
	 * 0000:0000:0000:0000:0000:0000:0000:0000 */
	static char buf[50+1];
	return (char *)inet_ntop(AF_INET6, addrp, buf, sizeof(buf));
}

/**
 * TODO copied, see if available else where
 * get in6_addr out of char* 
 */
struct in6_addr *
numeric_to_addr(const char *num)
{
	static struct in6_addr ap;
	int err;
	if ((err=inet_pton(AF_INET6, num, &ap)) == 1)
		return &ap;
	//#ifdef DEBUG
	//	fprintf(stderr, "\nnumeric2addr: %d\n", err);
	//#endif
	return (struct in6_addr *)NULL;
}

//TODO make a char * returning version
void print_rule(const struct rule * rule){
  if(rule != NULL)
    {
      HIP_DEBUG("rule: ");
      if(rule->src_hit != NULL)
	{
	  HIP_DEBUG("src_hit ");
	  if (!rule->src_hit->boolean)
	    HIP_DEBUG("! "); 
	  HIP_DEBUG("%s ", addr_to_numeric(&rule->src_hit->value));
	}
      if(rule->dst_hit != NULL)
	{
	  HIP_DEBUG("dst_hit ");
	  if (!rule->dst_hit->boolean)
	    HIP_DEBUG("! "); 
	  HIP_DEBUG("%s ", addr_to_numeric(&rule->dst_hit->value));
	}
      if(rule->type != NULL)
	{
	  HIP_DEBUG("type ");
	  if (!rule->type->boolean)
	    HIP_DEBUG("! "); 
	  HIP_DEBUG("%d ", rule->type->value);
	}
      if(rule->state != NULL)
	{
	  HIP_DEBUG("state ");
	  if (!rule->state->boolean)
	    HIP_DEBUG("! "); 
	  HIP_DEBUG("%d ", rule->state->value);
	}
      if(rule->accept)
	HIP_DEBUG("ACCEPT\n");
      else
	HIP_DEBUG("DROP\n");
    }
}

/**
 * free rule structure and all non NULL members
 */

void free_rule(struct rule * rule){
  if(rule)
    {
      HIP_DEBUG("freeing rule\n");
      if(rule->src_hit != NULL)
	free(rule->src_hit);
      if(rule->dst_hit != NULL)
	free(rule->dst_hit);
      if(rule->type != NULL)
	free(rule->type);
      if(rule->state != NULL)
	free(rule->state);
      free(rule);
    }
}

