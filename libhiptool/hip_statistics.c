#include "hip_statistics.h"

uint32_t timeval_to_uint32(struct timeval *timeval)
{
	HIP_ASSERT(timeval != NULL);

	// convert seconds to microseconds and add
	return (timeval->tv_sec * 1000000) + timeval->tv_usec;
}

uint32_t calc_timeval_diff(struct timeval *timeval_start, struct timeval *timeval_end)
{
	struct timeval rel_timeval;

	HIP_ASSERT(timeval_start != NULL);
	HIP_ASSERT(timeval_end != NULL);

	// XX TODO test that timeval_high really is higher

	rel_timeval.tv_sec = timeval_end->tv_sec - timeval_start->tv_sec;
	rel_timeval.tv_usec = timeval_end->tv_usec - timeval_start->tv_usec;

	return timeval_to_uint32(&rel_timeval);
}

uint32_t calc_avg(statistics_data_t *statistics_data)
{
	uint32_t avg = 0;

	HIP_ASSERT(statistics_data != NULL);

	if (statistics_data->num_items >= 1)
	{
		avg = statistics_data->added_values / statistics_data->num_items;
	}

	return avg;
}

uint32_t calc_std_dev(statistics_data_t *statistics_data)
{
	uint32_t std_dev = 0;
	uint32_t sum1 = 0, sum2 = 0;

	HIP_ASSERT(statistics_data != NULL);

	if (statistics_data->num_items >= 1)
	{
		sum1 = statistics_data->added_values;
		sum2 = statistics_data->added_squared_values;
		sum1 /= statistics_data->num_items;
		sum2 /= statistics_data->num_items;
		std_dev = llsqrt(sum2 - sum1 * sum1);
	}

	return std_dev;
}

void add_item(statistics_data_t *statistics_data, uint32_t item_value)
{
	HIP_ASSERT(statistics_data != NULL);

	statistics_data->num_items++;
	statistics_data->added_values += item_value;
	statistics_data->added_squared_values += item_value * item_value;
}

void calc_statistics(statistics_data_t *statistics_data, uint32_t *num_items,
		uint32_t *avg, uint32_t *std_dev)
{
	HIP_ASSERT(statistics_data != NULL);
	HIP_ASSERT(num_items != NULL);
	HIP_ASSERT(avg != NULL);
	HIP_ASSERT(std_dev != NULL);

	*num_items = statistics_data->num_items;
	*avg = calc_avg(statistics_data);
	*std_dev = calc_std_dev(statistics_data);
}

static long llsqrt(long long a)
{
	long long prev = ~((long long)1 << 63);
	long long x = a;

	if (x > 0)
	{
		while (x < prev) {
				prev = x;
				x = (x+(a/x))/2;
		}
	}

	return (long)x;
}
