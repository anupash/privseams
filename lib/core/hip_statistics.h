#ifndef HIP_STATISTICS_H_
#define HIP_STATISTICS_H_

#include <stdlib.h>
#include <inttypes.h>
#include <sys/time.h>

#define STATS_IN_MSECS  1000
#define STATS_IN_USECS  1000000

typedef struct statistics_data {
    uint32_t num_items;
    uint64_t added_values;
    uint64_t added_squared_values;
    uint64_t min_value;
    uint64_t max_value;
} statistics_data_t;

uint64_t calc_timeval_diff(const struct timeval *timeval_start,
                           const struct timeval *timeval_end);
int add_statistics_item(statistics_data_t *statistics_data,
                        const uint64_t item_value);
void calc_statistics(const statistics_data_t *statistics_data,
                     uint32_t *num_items,
                     double *min,
                     double *max,
                     double *avg,
                     double *std_dev,
                     double scaling_factor);

#endif /* HIP_STATISTICS_H_ */
