/*
    HIP Agent
*/

#ifndef HIT_DB_H
#define HIT_DB_H


/******************************************************************************/
/* INCLUDES */
#include <fcntl.h>
#include <socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "hip.h"


/******************************************************************************/
/* DEFINES */
#define HIT_DB_TYPE_ACCEPT				0
#define HIT_DB_TYPE_DENY				1


/******************************************************************************/
/* STRUCT DEFINITIONS */
/** This structure stores one HIT and information needed for it. */
typedef struct
{
	/**
		Stores HIT item 'human' identifier, it's name.
		Maximum length for this is 48 + null.
	*/
	char name[48 + 1];
	/** Stores local HIT of this item. */
	struct in6_addr lhit;
	/** Stores remote HIT of this item. */
	struct in6_addr rhit;
	/**
		Stores url of this item.
		Used for accepting connections for this HIT.
	*/
	char *url;
	/**
		Stores port of this item.
		Used for accepting connections for this HIT.
	*/
	uint16_t port;
	/** Is this hit accept or deny type. */
	int type;
} HIT_Item;


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int hit_db_init(void);
void hit_db_quit(void);
int hit_db_add(char *, struct in6_addr *, struct in6_addr *,
               char *, uint16_t, int);
int hit_db_del(int);

HIT_Item *hit_db_find(int *, char *, struct in6_addr *, struct in6_addr *,
                      char *, uint16_t, int);


#endif /* END OF HEADER FILE */
/******************************************************************************/

