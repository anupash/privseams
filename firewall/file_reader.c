#include <netinet/in.h>
#include <glib.h>
#include <glib/glist.h>
#include <stdio.h>

#include "debug.h"
#include "file_reader.h"
#include "firewall.h"
#include "conntrack.h"
#include "helpers.h"

/**
 * parse hit option and return allocated hit_option
 * structure or NULL if parsing fails
 */
struct hit_option * parse_hit(char * token, struct hit_option ** option1){
  //TODO
  struct hit_option * option = (struct hit_option *)malloc(sizeof(struct hit_option));
  struct in6_addr * hit = NULL; 

  //TODO check if tokens found or not
  //  HIP_DEBUG("parse_hit token: %s ", token);

  if(!strcmp(token, "!")){
    HIP_DEBUG("found ! \n");
    option->boolean = 0;
    token = (char *)strtok(NULL, " ");
  }
  else
    option->boolean = 1;
  hit = numeric_to_addr(token);
  if(hit == NULL)
    {
      HIP_DEBUG("parse_hit error\n");
      free(option);
      //    *option1 = NULL;
      return NULL;
    }
  option->value = *hit;
  HIP_DEBUG("hit %d  %s ok\n", option, addr_to_numeric(hit));
  //  *option1 = option;
  return option;
}

/**
 * parse type option and return allocated int_option
 * structure or NULL if parsing fails
 */
struct int_option * parse_type(char * token){
  char * string = NULL;
  struct int_option * option = (struct int_option *) malloc(sizeof(struct int_option));

  //TODO check if tokens found or not
  // HIP_DEBUG("parse_int token: %s ", token);

  if(!strcmp(token, "!")){
    option->boolean = 0;
    token = (char *) strtok(NULL, " ");
  }
  else
    option->boolean = 1;
  HIP_DEBUG("type token %s \n", token);
  if(!strcmp(token, "I1"))
      option->value = HIP_I1;
  else if(!strcmp(token, "R1"))
      option->value = HIP_R1;
  else if(!strcmp(token, "I2"))
      option->value = HIP_I2;
  else if(!strcmp(token, "R2"))
      option->value = HIP_R2;
  else if(!strcmp(token, "CER"))
      option->value = HIP_CER;
  else if(!strcmp(token, "UPDATE"))
      option->value = HIP_UPDATE;
  else if(!strcmp(token, "NOTIFY"))
      option->value = HIP_NOTIFY;
  else if(!strcmp(token, "CLOSE"))
      option->value = HIP_CLOSE;
  else if(!strcmp(token, "CLOSE_ACK"))
      option->value = HIP_CLOSE_ACK;
  else if(!strcmp(token, "PAYLOAD"))
      option->value = HIP_PAYLOAD;
  else
    {
      HIP_DEBUG("parse_type error\n");
      free(option);
      return NULL;
    }
  return option;
}



/**
 * parse state option and return allocated int_option
 * structure or NULL if parsing fails
 */
struct int_option * parse_state(char * token){
  char * string = NULL;
  struct int_option * option = (struct int_option *) malloc(sizeof(struct int_option));

  //TODO check if tokens found or not
  //  HIP_DEBUG("parse_int token: %s ", token);

  if(!strcmp(token, "!")){
    option->boolean = 0;
    token = (char *) strtok(NULL, " ");
  }
  else
    option->boolean = 1;
  if(!strcmp(token, "NEW"))
      option->value = CONN_NEW;
  else if(!strcmp(token, "ESTABLISHED"))
      option->value = CONN_ESTABLISHED;
  else
    {
      HIP_DEBUG("parse_state error\n");
      free(option);
      return NULL;
    }
  return option;
}

/** 
 * parses argument sring into a rule structure,
 * returns pointer to allocated rule structure or NULL if
 * syntax error
 */
struct rule * parse_rule(char * string /*, struct rule ** rule1*/)
{
  struct rule * rule = (struct rule *)malloc(sizeof(struct rule));
  rule->src_hit = NULL; 
  rule->dst_hit = NULL;
  rule->type = NULL;
  rule->state = NULL;
  rule->accept = -1;

  int i = 0;
  char * token;
  int option_found = NO_OPTION;
  
  // NR_OPTIONS + ACCEPT/DROP
  HIP_DEBUG("parse rule string %s\n", string);
  token = (char *) strtok(string, " ");
  while(strlen(string) > 0) //TODO checking nr of options necessary?
    {
      if(token == NULL)
	{
	  //empty string
	  if(i = 0){
	    HIP_DEBUG("parse_rule error 1\n");
	    free_rule(rule);
	    //*rule1 = NULL;
	    //return;
	    return NULL;
	  }
	  break;
	}
      else if(option_found == NO_OPTION)
	{
	  if(!strcmp(token, "src_hit"))
	    {
	      //option already defined
	      if(rule->src_hit != NULL)
		{
		  HIP_DEBUG("parse_rule error 2\n");
		  free_rule(rule);
		  //rule1 = NULL;
		  //return;
		  return NULL;
		}
	      option_found = SRC_HIT_OPTION;
	      HIP_DEBUG("src_hit found\n");
	    }
	  else if(!strcmp(token, "dst_hit"))
	    {  
	      //option already defined
	      if(rule->dst_hit != NULL)
		{
		  HIP_DEBUG("parse_rule error 3\n");
		  free_rule(rule);
		  //rule1 = NULL;
		  //return;
		  return NULL;
		}
	      option_found = DST_HIT_OPTION;
	      HIP_DEBUG("dst_hit found\n");
	    }
	  else if(!strcmp(token, "type"))
	    {
	      //option already defined
	      if(rule->type != NULL)
		{
		  HIP_DEBUG("parse_rule error 4\n");
		  free_rule(rule);
		  //rule1 = NULL;
		  //return;
		  return NULL;
		}
	      option_found = TYPE_OPTION;
	      HIP_DEBUG("type found\n");
	    }
	  else if(!strcmp(token, "state"))
	    {
	      //option already defined
	      if(rule->state != NULL)
		{
		  HIP_DEBUG("parse_rule error 5\n");
		  free_rule(rule);
		  //rule1 = NULL;
		  //return;
		  return NULL;
		}
	      option_found = STATE_OPTION;	
	      HIP_DEBUG("state found\n");
	    }
	  else if(!strcmp(token, "ACCEPT"))
	    {
	      //target already defined
	      if(rule->accept > -1)
		{
		  HIP_DEBUG("parse_rule error 6\n");
		  free_rule(rule);
		  //rule1 = NULL;
		  //return;
		  return NULL;
		}
	      rule->accept = 1;
	      HIP_DEBUG("accept found \n");
	    }
	  else if(!strcmp(token, "DROP"))
	    {
	      //target already defined
	      if(rule->accept > -1)
		{
		  HIP_DEBUG("parse_rule error 7\n");
		  free_rule(rule);
		  //rule1 = NULL;
		  //return;
		  return NULL;
		}
	      rule->accept = 0;
	      HIP_DEBUG("drop found \n");
	    }
	  else 
	    {
	      //invalid option
	      HIP_DEBUG("invalid option \n");
	      free_rule(rule);
		  //rule1 = NULL;
		  //return;
	      return NULL;
	    }
	}
      else
	{
	  if(option_found == SRC_HIT_OPTION)
	    {
	      //HIP_DEBUG("parse_rule: src hit \n");
	      rule->src_hit = 
	      parse_hit(token, &rule->src_hit);
	      HIP_DEBUG("parse_rule : src hit %d %s \n", rule->src_hit, addr_to_numeric(&rule->src_hit->value));
	      if(rule->src_hit == NULL)
		{
		  //  HIP_DEBUG("parse_rule src hit NULL\n");
		  HIP_DEBUG("parse_rule error 8\n");
		  free_rule(rule);
		  //rule1 = NULL;
		  //return;
		  return NULL;
		}
	      option_found = NO_OPTION;
	      //  HIP_DEBUG("parse_rule 3: option %d src opt %d\n", option_found, SRC_HIT_OPTION);
	    }
	  else if(option_found == DST_HIT_OPTION)
	    {
	      //      HIP_DEBUG("parse_rule: dst hit \n");
	      // parse_hit(token, &rule->dst_hit);
	   
	      rule->dst_hit = parse_hit(token, &rule->dst_hit);
	      if(rule->dst_hit == NULL)
		{
		  HIP_DEBUG("parse_rule error 9\n");
		  free_rule(rule);
		  //rule1 = NULL;
		  //return;
		  return NULL;
		}
	      option_found = NO_OPTION;
	    }
	  else if(option_found == TYPE_OPTION)
	    {
	      rule->type = parse_type(token);
	      if(rule->type == NULL)
		{
	    HIP_DEBUG("parse_rule error 10\n");
		  free_rule(rule);
		  //rule1 = NULL;
		  //return;
		  return NULL;
		}
	      option_found = NO_OPTION;
	    }
	  else if(option_found == STATE_OPTION)
	    {
	      rule->state = parse_state(token);
	      if(rule->state == NULL)
		{
		  HIP_DEBUG("parse_rule error 11\n");
		  free_rule(rule);
		  //rule1 = NULL;
		  //return;
		  return NULL;
		}
	      option_found = NO_OPTION;
	    }
	}
      HIP_DEBUG("getting token");
      token = (char *) strtok(NULL, " ");
      HIP_DEBUG(" %sopt %d \n", token, option_found);
      i++; 
    }
  HIP_DEBUG("done with parsing rule ");
  print_rule(rule);
  //  *rule1 = rule;
  return rule;
}


/**
 * Reads rules from file specified and parses them into rule
 * structures. Returns GList structure with pointers to allocated rules  
 *
 */
void get_rules(char * file_name, struct GList ** list)
{
  FILE *file = fopen(file_name, "r");
  struct rule * rule;
  char * line = NULL;
  char temp[100] = "src_hit 55b6:9f23:894b:3064:d297:e5d1:e772:934 ACCEPT";
  char * original_line = NULL;
  size_t s = 0;
  if(file != NULL)
    {
      //HIP_DEBUG("get_rules going to while\n");
      while(getline(&line, &s, file ) > 0)	  {
	original_line = (char *) malloc(strlen(line) * + sizeof(char) );
	original_line = strcpy(original_line, line);
	HIP_DEBUG("line read: %s", line);
	//remove trailing new line
	line = (char *) strtok(line, "\n");
	//if(line)
	//  {
	rule = parse_rule(line/*, &rule*/);
	if(rule)
	  {
	    *list = (struct GList *)g_list_append((struct _GList *) *list, (gpointer) rule);
	    HIP_DEBUG("get_rules 1, list->data %d, src_hit %d \n", 
		   (struct rule *)((struct _GList *) *list)->data, 
		   ((struct rule *)((struct _GList *)*list)->data)->src_hit);
	    print_rule((struct rule *)((struct _GList *) *list)->data);
	    HIP_DEBUG("get_rules 2\n");
	    rule = NULL;
	    HIP_DEBUG("get_rules 3\n");
	  }
	else //TODO error print?
	  HIP_DEBUG("unable to parse rule: %s\n", original_line);
	free(line);
	line = NULL;
      }
      fclose(file);
    }
  else
    { //TODO error print?
      HIP_DEBUG("Can't open file %s \n", file_name );
    }
}

