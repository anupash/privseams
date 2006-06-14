/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef HIT_DB_H
#define HIT_DB_H


/******************************************************************************/
/* INCLUDES */
#include <fcntl.h>
//#include <socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"

#ifndef __cplusplus
#include "hip.h"
#else
//#include <netinet/in6.h>
#endif


/******************************************************************************/
/* DEFINES */
#define HIT_DB_TYPE_NONE				0
#define HIT_DB_TYPE_ACCEPT				1
#define HIT_DB_TYPE_DENY				2
#define HIT_DB_TYPE_LOCAL				4
#define HIT_DB_TYPE_ALL					0xffffffff


/******************************************************************************/
/* STRUCT DEFINITIONS */
/** This structure stores one HIT and information needed for it. */
typedef struct
{
	/** Index of this item. Stored for GUI usage. */
	int index;
	/**
		Stores HIT item 'human' identifier, it's name.
		Maximum length for this is 64 + null.
	*/
	char name[64 + 1];
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
	/** What is the type of the HIT. */
	int type;
	/** Remote HIT group. */
	char group[64 + 1];
	/** Is HIT lightweight or not. */
	int lightweight;
} HIT_Item;

/** This structure stores one group information. */
typedef struct
{
	/* Group name. */
	char name[64 + 1];
	/* Next group item. */
	void *next;
} HIT_Group;


/******************************************************************************/
/* Set up for C function definitions, even when using C++ */
#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************/


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int hit_db_init(char *);
void hit_db_quit(char *);
int hit_db_clear(void);

int hit_db_add_hit(HIT_Item *, int);
int hit_db_add(char *, struct in6_addr *, struct in6_addr *,
               char *, int, int, char *, int, int);
int hit_db_del(struct in6_addr *, struct in6_addr *, int);

HIT_Item *hit_db_search(int *, char *, struct in6_addr *, struct in6_addr *,
			            char *, int, int, int, int);

int hit_db_save_to_file(char *);
int hit_db_save_rgroup_to_file(HIT_Group *, void *);
int hit_db_load_from_file(char *);

int hit_db_parse_hit(char *);
int hit_db_parse_rgroup(char *);

HIT_Group *hit_db_add_rgroup(char *);
int hit_db_del_rgroup(char *);
HIT_Group *hit_db_find_rgroup(char *);
int hit_db_enum_rgroups(int (*)(HIT_Group *, void *), void *);
int hit_db_enum_locals(int (*)(HIT_Item *, void *), void *);


/******************************************************************************/
/* Ends C function definitions when using C++ */
#ifdef __cplusplus
}
#endif
/******************************************************************************/


#endif /* END OF HEADER FILE */
/******************************************************************************/

