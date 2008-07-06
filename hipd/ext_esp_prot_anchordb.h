#ifndef EXT_ESP_PROT_ANCHORDB_H_
#define EXT_ESP_PROT_ANCHORDB_H_

#include "builder.h"

void init_anchor_db(void);
int update_anchor_db(struct hip_common *msg);
int has_more_anchors(void);
int get_next_anchor(unsigned char *anchor);

#endif /*ANCHORDB_H_*/
