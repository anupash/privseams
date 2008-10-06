#include "hip_statistics.h"

uint32_t timeval_to_uint32(struct timeval *timeval)
{
	HIP_ASSERT(timeval != NULL);

	// convert seconds to microseconds and add
	return (timeval->tv_sec * SEC_TO_USEC) + timeval->tv_usec;
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

float calc_avg(statistics_data_t *statistics_data, float scaling_factor)
{
	float avg = 0.0;

	HIP_ASSERT(statistics_data != NULL);
	HIP_ASSERT(scaling_factor > 0.0);

	if (statistics_data->num_items >= 1)
	{
		avg = (statistics_data->added_values / scaling_factor)
					/ statistics_data->num_items;
	}

	return avg;
}

double calc_std_dev(statistics_data_t *statistics_data, float scaling_factor)
{
	double std_dev = 0.0;
	double sum1 = 0.0, sum2 = 0.0;

	HIP_ASSERT(statistics_data != NULL);

	if (statistics_data->num_items >= 1)
	{
		sum1 = (double)statistics_data->added_values / statistics_data->num_items;
		sum2 = (double)statistics_data->added_squared_values
					/ statistics_data->num_items;

		printf("sum2 - (sum1 * sum1) = %.3f\n", sum2 - (sum1 * sum1));

		std_dev = sqrt(sum2 - (sum1 * sum1));
	}

	return std_dev / scaling_factor;
}

void add_statistics_item(statistics_data_t *statistics_data, uint32_t item_value)
{
	HIP_ASSERT(statistics_data != NULL);

	statistics_data->num_items++;
	statistics_data->added_values += item_value;
	statistics_data->added_squared_values += item_value * item_value;

	if (item_value > statistics_data->max_value)
		statistics_data->max_value = item_value;

	if (item_value < statistics_data->min_value ||
			statistics_data->min_value == 0)
		statistics_data->min_value = item_value;
}

/* only returns values for non-NULL pointers */
void calc_statistics(statistics_data_t *statistics_data, uint32_t *num_items,
		float *min, float *max, float *avg, double *std_dev, float scaling_factor)
{
	HIP_ASSERT(statistics_data != NULL);

	if (num_items)
		*num_items = statistics_data->num_items;
	if (min)
		*min = statistics_data->min_value / scaling_factor;
	if (max)
		*max = statistics_data->max_value / scaling_factor;
	if (avg)
		*avg = calc_avg(statistics_data, scaling_factor);
	if (std_dev)
		*std_dev = calc_std_dev(statistics_data, scaling_factor);
}

#if 0
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
#endif
