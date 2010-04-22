/** @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * Header file for hip_statistics.c
 *
 * @author Rene Hummen
 */

#ifndef HIP_LIB_CORE_HIP_STATISTICS_H
#define HIP_LIB_CORE_HIP_STATISTICS_H

#include <stdlib.h>
#include <inttypes.h>
#include <sys/time.h>

#define STATS_IN_MSECS  1000
#define STATS_IN_USECS  1000000

/**
 * Data set that contains the the collected values
 */
typedef struct statistics_data {
    uint32_t num_items;             /* number of items that have been added to the set */
    uint64_t added_values;          /* total amount of added values */
    uint64_t added_squared_values;  /* squared values for standard deviation calculation */
    uint64_t min_value;             /* minimal of all values added to the set */
    uint64_t max_value;             /* maximum of all values added to the set */
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

#endif /* HIP_LIB_CORE_HIP_STATISTICS_H */
