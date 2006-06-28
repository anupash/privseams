#ifndef BLIND_H
#define BLIND_H 

#include "hip.h"
#include "debug.h"

extern int hip_blind_status;

int hip_blind_on(struct hip_common *msg);
int hip_blind_off(struct hip_common *msg);

int hip_set_blind_off_sa(hip_ha_t *entry, void *not_used);
int hip_set_blind_on_sa(hip_ha_t *entry, void *not_used);

#endif
