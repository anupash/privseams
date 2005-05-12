#ifndef HIP_FIREWALL_H
#define HIP_FIREWALL_H

#include <netinet/in.h>
//#include "builder.h"
//#include <linux/ipv6.h>
//#include "debug.h"

/*-------------- RULES ------------*/

#define NR_OPTIONS 4;
#define OPTION_MAX_LEN 100; //TODO akateemisempi arvaus
#define DROP 0;
#define ACCEPT 1;


//states for the connection, hip state machine states from hip.h
enum {
  CONN_NEW,
  CONN_ESTABLISHED
};

enum {
  NO_OPTION,
  SRC_HIT_OPTION,
  DST_HIT_OPTION,
  TYPE_OPTION,
  STATE_OPTION,
    };

struct hit_option{
  struct in6_addr value; //hit value
  int boolean; //0 if negation, else 1
};

struct int_option{
  int value; //int value
  int boolean; // 0 if negation, else 1
};

//pointers are NULL if option is not specified
struct rule{
  struct hit_option * src_hit;
  struct hit_option * dst_hit;
  struct int_option * type;
  struct int_option * state; 
  int accept;
};

/*-------------- RULES ------------*/




#endif

