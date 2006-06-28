#include "blind.h"

int hip_set_blind_on_sa(hip_ha_t *entry, void *not_used)
{
        int err = 0;

        if(entry)
        {
                entry->blind = 1;
        }
 out_err:
        return err;
}
int hip_set_blind_off_sa(hip_ha_t *entry, void *not_used)
{
        int err = 0;

        if(entry)
        {
                entry->blind = 0;
                HIP_DEBUG("*******Setting blind off blind: %d\n", entry->blind);
        }
 out_err:
        return err;
}


int hip_blind_on(struct hip_common *msg)
{
        int err = 0;

        hip_blind_status = 1;
        HIP_IFEL(hip_for_each_ha(hip_set_blind_on_sa, NULL), 0,
                         "for_each_ha err.\n");

 out_err:
        return err;
}

int hip_blind_off(struct hip_common *msg)
{
        int err = 0;

        hip_blind_status = 0;
        HIP_IFEL(hip_for_each_ha(hip_set_blind_off_sa, NULL), 0,
                         "for_each_ha err.\n");

 out_err:
        return err;
}

int hip_get_blind(void)
{
	return hip_blind_on;
}
