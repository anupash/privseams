#ifndef ANCHORDB_H_
#define ANCHORDB_H_

#include "builder.h"

int update_anchor_db(struct hip_common *msg);
int has_more_anchors(void);
int get_next_anchor(unsigned char *anchor_element);

#endif /*ANCHORDB_H_*/
