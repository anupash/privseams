#ifndef HIP_STATISTICS_H_
#define HIP_STATISTICS_H_

#include <stdlib.h>
#include <inttypes.h>
#include "debug.h"

typedef struct statistics_data
{
	uint32_t num_items;
	uint32_t added_values;
	uint32_t added_squared_values;
	uint32_t min_value;
	uint32_t max_value;
} statistics_data_t;

uint32_t timeval_to_uint32(struct timeval *timeval);
uint32_t calc_timeval_diff(struct timeval *timeval_start, struct timeval *timeval_end);
uint32_t calc_avg(statistics_data_t *statistics_data);
uint32_t calc_std_dev(statistics_data_t *statistics_data);
void add_statistics_item(statistics_data_t *statistics_data, uint32_t item_value);
void calc_statistics(statistics_data_t *statistics_data, uint32_t *num_items,
		uint32_t *min, uint32_t *max, uint32_t *avg, uint32_t *std_dev);
void print_statistics(statistics_data_t *statistics_data, const char *output_string);
static long llsqrt(long long a);

#endif /* HIP_STATISTICS_H_ */
