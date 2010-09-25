/*!
 * \file dh_performance.c
 *
 * \brief Primitive performance measurement library.
 * \author Tobias Heer
 *
 * This file provides a set of functions to measure execution time.
 * The measurement unit is second.
 *
 * \note Distributed under
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "debug.h"
#include "ife.h"
#include "performance.h"

/*!
 * \brief Create a set of performance slots. Each performance measurement type
 * needs a slot.
 *
 * Create a set of performance slots. Each performance measurement type needs
 * a slot. This is the first step when starting measurements.
 *
 * \author      Tobias Heer
 *
 * \param num Number of distinct sets to create.
 * \return A pointer to the performance set.
 *
 * \note The performance set memory must be freed after finishing the tests.
 */
perf_set_t *hip_perf_create(int num)
{
    /* create the perf set struct*/
    perf_set_t *set;
    set            = malloc(sizeof(perf_set_t));
    memset(set, 0, sizeof(perf_set_t));

    set->num_files = num;

    /* allocate memory for filenames and file pointers*/
    set->files     = malloc(sizeof(FILE *) * num);
    memset(set->files, 0, sizeof(FILE *) * num);

    set->names     = malloc(sizeof(char *) * num);
    memset(set->names, 0, sizeof(char *) * num);

    set->linecount = malloc(sizeof(int) * num);
    memset(set->linecount, 0, sizeof(int) * num);

    set->times     = malloc(sizeof(struct timeval) * num);
    memset(set->times, 0, sizeof(struct timeval) * num);

    set->result    = malloc(sizeof(double) * num);
    memset(set->result, 0, sizeof(double) * num);

    set->running   = malloc(sizeof(int) * num);
    memset(set->running, 0, sizeof(int) * num);

    set->writable  = malloc(sizeof(int) * num);
    memset(set->writable, 0, sizeof(int) * num);

    return perf_set;
}

/*!
 * \brief Set the filename for an performance slot..
 *
 * Assigns a filename to each performance measurement slot.
 * \author      Tobias Heer
 *
 * \param set The respective performance measurement created by hip_perf_create.
 * \see hip_perf_create
 * \param slot The slot number beginning with 0.
 * \param name The filename.
 * \return Returns error code. 0 = Success, 1 = Error.
 */
int hip_perf_set_name(perf_set_t *set,  int slot, const char *name)
{
    int err = 0, len = 0;
    HIP_IFEL(set == NULL,       -1, "Performance set is empty\n");
    HIP_IFEL(set->files_open,   -1, "Files have already been opened\n");
    HIP_IFEL(set->names[slot],  -1, "Slot is already named\n");
    HIP_IFEL(slot >= set->num_files, -1, "Slot %d does not exist\n", slot);

    len                   = strlen(name);
    set->names[slot] = malloc(len + 1);
    memcpy(set->names[slot], name, len + 1);
out_err:
    return err;
}

/*!
 * \brief Open the files for result output.
 *
 * Open the files for a specific perf set.
 * \author      Tobias Heer
 *
 * \see hip_perf_create
 * \note Filenames must have been set by hip_perf_set_name before calling this function.
 * \param set The respective performance measurement created by hip_perf_create.
 * \return Returns error code. 0 = Success, 1 = Error.
 */
int hip_perf_open(perf_set_t *set)
{
    int err = 0, i = 0;
    HIP_IFEL(!set,              -1, "Performance set is empty\n");
    HIP_IFEL(set->files_open,   -1, "Files already open\n");

    for (i = 0; i < set->num_files; i++) {
        if (set->names[i]) {
            set->files[i] =  fopen(set->names[i], "a");
            if (!set->files[i]) {
                HIP_ERROR("Error opening file for slot %d\n", i);
            }
        } else {
            HIP_ERROR("Name for slot %d not set \n", i);
            err = 1;
        }
    }
out_err:
    return err;
}

/*!
 * \brief Start benchmarking for a perf set slot.
 *
 * Start taking the time for a perf set slot. Slots can overlap but should not
 * write to disk while another slot is active.
 * \author      Tobias Heer
 *
 * \see hip_perf_create
 * \param set The respective performance measurement created by hip_perf_create.
 * \param slot The slot number beginning with 0.
 * \return void
 */
void hip_perf_start_benchmark(perf_set_t *set, int slot)
{
    if (set->num_files > slot) {
        gettimeofday(&set->times[slot], NULL);
        set->running[slot] = 1;
    }
}

/*!
 * \brief Stop benchmarking for a perf set slot and memorize the result.
 *
 * Stop taking the time for a perf set slot. Slots can overlap but should not
 * write to disk while another slot is active.
 * \author      Tobias Heer
 *
 * \note This function only writes results to the memory. For disk writes you
 * need to run hip_perf_write_benchmark.
 *
 * \see hip_perf_write_benchmark
 * \see hip_perf_create
 *
 * \param set The respective performance measurement created by hip_perf_create.
 * \param slot The slot number beginning with 0.
 * \return void
 */
void hip_perf_stop_benchmark(perf_set_t *set, int slot)
{
    struct timeval now;
    if (set->num_files > slot && set->running[slot] == 1) {
        gettimeofday(&now, NULL);
        set->result[slot]   = ((now.tv_sec - set->times[slot].tv_sec) * 1000000 +
                                    (now.tv_usec - set->times[slot].tv_usec)) / 1000000.0;
        set->running[slot]  = 0;
        set->writable[slot] = 1;
    }
}

/*!
 * \brief Write the benchmark results to the files.
 *
 * Save the benchmark results to the respective files.
 * \author      Tobias Heer
 *
 * \note Do not use this functions while other benchmarks are in progress. It may disturb the measurements.
 *
 * \see hip_perf_write_benchmark
 * \see hip_perf_create
 *
 * \param set The respective performance measurement created by hip_perf_create.
 * \param slot The slot number beginning with 0.
 * \return Returns error code. 0 = Success, 1 = Error.
 */
int hip_perf_write_benchmark(perf_set_t *set, int slot)
{
    int err = 0;
    HIP_IFEL(!set, -1, "Performance set is empty\n");
    char buffer[30];
    memset(buffer, 0, 30);
    if (set->num_files > slot && set->writable[slot] == 1) {
        if (set->files[slot]) {
            sprintf(buffer, "%4d\t%8.8lf\n", set->linecount[slot]++,
                    set->result[slot]);
            fputs(buffer, set->files[slot]);
            set->result[slot]   = 0;
            set->writable[slot] = 0;
        } else {
            HIP_ERROR("Name for slot %d not set \n", slot);
            err = 1;
        }
    }
out_err:
    return err;
}

/*!
 * \brief Deallocate memory of a performance set
 *
 * Deallocate memory of the given performance set, including each member of
 * the perf_set_t data structure.
 * \author      Dongsu Park
 *
 * \param set The respective performance measurement created by hip_perf_create.
 * \return Nothing.
 */
void hip_perf_destroy(perf_set_t *set)
{
    int slot = 0;

    if (set->files) {
        free(set->files);
        set->files = NULL;
    }

    /* Deallocate every slot in set->names.
     * You need to do it because every slot memory is allocated
     * in hip_perf_set_name().
     */
    if (set->names) {
        for (slot = 0; slot < PERF_MAX; slot++) {
            if (set->names[slot]) {
                free(set->names[slot]);
                set->names[slot] = NULL;
            }
        }
        free(set->names);
        set->names = NULL;
    }

    if (set->linecount) {
        free(set->linecount);
        set->linecount = NULL;
    }
    if (set->times) {
        free(set->times);
        set->times = NULL;
    }
    if (set->result) {
        free(set->result);
        set->result = NULL;
    }
    if (set->running) {
        free(set->running);
        set->running = NULL;
    }
    if (set->writable) {
        free(set->writable);
        set->writable = NULL;
    }

    if (set) {
        free(set);
        set = NULL;
    }

    return;
}
