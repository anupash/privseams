#ifndef ANCHORDB_H_
#define ANCHORDB_H_

#include "builder.h"
#include "hashchain.h"

void init_anchor_db(void);
int update_anchor_db(struct hip_common *msg);
int has_more_anchors(void);
int get_next_anchor(hash_item_t *anchor_item);

#endif /*ANCHORDB_H_*/
