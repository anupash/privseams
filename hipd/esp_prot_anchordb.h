#ifndef ESP_PROT_ANCHORDB_H_
#define ESP_PROT_ANCHORDB_H_

#include "esp_prot_common.h"
#include "hashchain_store.h"
#include "builder.h"

typedef struct anchor_db
{
	// amount of anchors for each transform
	int num_anchors[NUM_TRANSFORMS];
	// length of the anchors for each transform
	int anchor_lengths[NUM_TRANSFORMS];
	// set to support max amount of anchors possible
	unsigned char *anchors[NUM_TRANSFORMS][MAX_HCHAINS_PER_ITEM];
} anchor_db_t;

void anchor_db_init(void);
void anchor_db_uninit(void);
int anchor_db_update(struct hip_common *msg);
int anchor_db_has_more_anchors(uint8_t transform);
unsigned char * anchor_db_get_anchor(uint8_t transform);
int anchor_db_get_anchor_length(uint8_t transform);

#endif /*ESP_PROT_ANCHORDB_H_*/
