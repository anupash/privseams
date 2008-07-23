#ifndef ESP_PROT_ANCHORDB_H_
#define ESP_PROT_ANCHORDB_H_

#include "builder.h"

typedef struct anchor_db
{
	int num_anchors[NUM_TRANSFORMS];
	unsigned char *anchors[NUM_TRANSFORMS][MAX_HCHAINS_PER_ITEM];
} anchor_db_t;

void init_anchor_db(void);
int update_anchor_db(struct hip_common *msg);
int has_more_anchors(void);
unsigned char * get_next_anchor(void);

#endif /*ESP_PROT_ANCHORDB_H_*/
