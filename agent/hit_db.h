/*
    HIP Agent
*/

#ifndef HIT_DB_H
#define HIT_DB_H

/******************************************************************************/
/* INCLUDES */
#include <sys/types.h>

#include "hip.h"


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
	/** Stores HIT of this item. */
	struct hip_lhi hit;
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
} HIT_Item;


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int hit_db_init(void);
void hit_db_quit(void);
int hit_db_add(char *, void *, char *, uint16_t);
void hit_db_del(int);

HIT_Item *hit_db_find(int *, char *, void *, char *, uint16_t);


#endif /* END OF HEADER FILE */
/******************************************************************************/

