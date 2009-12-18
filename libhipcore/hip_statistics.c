#include <math.h>

#include "hip_statistics.h"
#include "debug.h"

static uint64_t timeval_to_uint64(const struct timeval *timeval)
{
	HIP_ASSERT(timeval != NULL);

	/* convert values to microseconds and add */
	return ((timeval->tv_sec * STATS_IN_USECS) + timeval->tv_usec);
}

static double calc_avg(const statistics_data_t *statistics_data, const double scaling_factor)
{
	double avg = 0.0;

	HIP_ASSERT(statistics_data != NULL);
	HIP_ASSERT(scaling_factor > 0);

	if (statistics_data->num_items >= 1)
	{
		avg = (statistics_data->added_values / scaling_factor)
					/ statistics_data->num_items;
	}

	return avg;
}

static double calc_std_dev(const statistics_data_t *statistics_data, const double scaling_factor)
{
	double std_dev = 0.0;
	double sum1 = 0.0, sum2 = 0.0;

	HIP_ASSERT(statistics_data != NULL);

	if (statistics_data->num_items >= 1)
	{
		sum1 = (double)statistics_data->added_values / statistics_data->num_items;
		sum2 = (double)statistics_data->added_squared_values
					/ statistics_data->num_items;

		std_dev = sqrt(sum2 - (sum1 * sum1));
	}

	return std_dev / scaling_factor;
}

uint64_t calc_timeval_diff(const struct timeval *timeval_start,
		const struct timeval *timeval_end)
{
	struct timeval rel_timeval;

	HIP_ASSERT(timeval_start != NULL);
	HIP_ASSERT(timeval_end != NULL);

	// check that timeval_high really is higher
	if ((timeval_end->tv_sec > timeval_start->tv_sec) && (timeval_end->tv_usec > timeval_start->tv_usec)) {
		rel_timeval.tv_sec = timeval_end->tv_sec - timeval_start->tv_sec;
		rel_timeval.tv_usec = timeval_end->tv_usec - timeval_start->tv_usec;
	}
	else {
		rel_timeval.tv_sec = 0;
		rel_timeval.tv_usec = 0;
	}

	return timeval_to_uint64(&rel_timeval);
}

int add_statistics_item(statistics_data_t *statistics_data, const uint64_t item_value)
{
	int err = 0;

	HIP_ASSERT(statistics_data != NULL);

	HIP_IFEL(!(statistics_data->num_items < statistics_data->num_items + 1), -1,
			"value exceeds data type range\n");
	statistics_data->num_items++;

	HIP_IFEL(!(statistics_data->added_values < statistics_data->added_values + item_value), -1,
			"value exceeds data type range\n")
	statistics_data->added_values += item_value;


	HIP_IFEL(!(statistics_data->added_squared_values < statistics_data->added_squared_values + item_value * item_value), -1,
			"value exceeds data type range\n");
	statistics_data->added_squared_values += item_value * item_value;

	if (item_value > statistics_data->max_value) {
		statistics_data->max_value = item_value;
	}

	if (item_value < statistics_data->min_value ||
			statistics_data->min_value == 0.0) {
		statistics_data->min_value = item_value;
	}

  out_err:
	if (err) {
		HIP_DEBUG("resetting statistics\n");

		statistics_data->num_items = 0;
		statistics_data->added_values = 0;
		statistics_data->added_squared_values = 0;
	}

	return err;
}

/* only returns values for non-NULL pointers */
void calc_statistics(const statistics_data_t *statistics_data, uint32_t *num_items,
		double *min, double *max, double *avg, double *std_dev,
		double scaling_factor)
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
