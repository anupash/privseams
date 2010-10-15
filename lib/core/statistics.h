/** @file
 *
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * @author Rene Hummen
 */

#ifndef HIP_LIB_CORE_STATISTICS_H
#define HIP_LIB_CORE_STATISTICS_H

#include <stdint.h>
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

#endif /* HIP_LIB_CORE_STATISTICS_H */
