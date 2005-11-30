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

#ifndef __cplusplus
#include "hip.h"
#else
#include <linux/in6.h>
#endif


/******************************************************************************/
/* DEFINES */
#define HIT_DB_TYPE_ACCEPT				0
#define HIT_DB_TYPE_DENY				1


/******************************************************************************/
/* STRUCT DEFINITIONS */
/** This structure stores one HIT and information needed for it. */
typedef struct
{
	/** Index of this item. Stored for GUI usage. */
	int index;
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
	char url[1024];
	/**
		Stores port of this item.
		Used for accepting connections for this HIT.
	*/
	int port;
	/** Is this hit accept or deny type. */
	int type;
} HIT_Item;


/******************************************************************************/
/* Set up for C function definitions, even when using C++ */
#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************/


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int hit_db_init(void);
void hit_db_quit(void);
int hit_db_add_hit(HIT_Item *);
int hit_db_add(char *, struct in6_addr *, struct in6_addr *,
               char *, int, int);
int hit_db_del(int);

HIT_Item *hit_db_find(int *, char *, struct in6_addr *, struct in6_addr *,
                      char *, int, int);


/******************************************************************************/
/* Ends C function definitions when using C++ */
#ifdef __cplusplus
}
#endif
/******************************************************************************/


#endif /* END OF HEADER FILE */
/******************************************************************************/

