#ifndef performance_h
#define performance_h

/*
 * Primitive performance measurement
 *
 * Authors:
 * - Tobias Heer <heer@tobibox.de>
 */




#include<stdio.h>

/*! This performace set holds all measurements */
struct perf_set{
	/*! \brief A pointer to names of output files */
	FILE 		**files; 
	
	/*! \brief A list of names of the perf sets. */
	char 		**names; 
	
	/*! \brief A list timeval time structs. */
	struct timeval 	*times;
	
	/*! \brief A list of measured results. */
	double 		*result;
	
	/*! \brief The number of perf sets. */
	int 		num_files;
	
	/*! \brief A linecount.. */
	int 		*linecount;
	
	/*! \brief Are the necessary files opened? 1=TRUE, 0=FALSE. */
	int 		files_open;
	
	/*! \brief Are measurements running? This is an integer field of the length num_files. */
	int		*running;
	
	/*! \brief Are the measurements writable (completed)? This is an integer field of the length num_files. */
	int		*writable;
};

typedef struct perf_set perf_set_t;

int hip_perf_enabled();

perf_set_t * hip_perf_create(int num);

int hip_perf_set_name(perf_set_t * perf_set,  int slot, const char* name);

int hip_perf_open(perf_set_t *perf_set);

void hip_perf_start_benchmark(perf_set_t * perf_set, int slot);

void hip_perf_stop_benchmark(perf_set_t * perf_set, int slot);

int hip_perf_write_benchmark(perf_set_t * perf_set, int slot);

int hip_perf_close(perf_set_t *perf_set);

#endif
