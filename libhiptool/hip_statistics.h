#ifndef HIP_STATISTICS_H_
#define HIP_STATISTICS_H_

#include <stdlib.h>
#include <inttypes.h>
#include <math.h>
#include "debug.h"

#define STATS_IN_MSECS	1000.0
#define SEC_TO_USEC		1000000

typedef struct statistics_data
{
	uint32_t num_items;
	uint32_t added_values;
	uint32_t added_squared_values;
	uint32_t min_value;
	uint32_t max_value;
} statistics_data_t;

#ifdef CONFIG_HIP_MEASUREMENTS
typedef struct hcupdate_track
{
	unsigned char update_anchor[MAX_HASH_LENGTH];
	struct timeval time_start;
} hcupdate_track_t;
#endif

uint32_t timeval_to_uint32(struct timeval *timeval);
uint32_t calc_timeval_diff(struct timeval *timeval_start, struct timeval *timeval_end);
float calc_avg(statistics_data_t *statistics_data, float scaling_factor);
double calc_std_dev(statistics_data_t *statistics_data, float scaling_factor);
void add_statistics_item(statistics_data_t *statistics_data, uint32_t item_value);
void calc_statistics(statistics_data_t *statistics_data, uint32_t *num_items,
		float *min, float *max, float *avg, double *std_dev, float scaling_factor);
//static long llsqrt(long long a);

#endif /* HIP_STATISTICS_H_ */
