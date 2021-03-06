/*
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
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE O
 */

/**
 * @file
 *
 * This is a general purpose configurationfilereader. The configurationfile
 * consists of stanzas of the following form:
 * <pre>
 * parametername = "value1", "value2", "value3", ..., "valueN"
 * </pre>
 * where there can be as many values as needed per line with the exception that
 * the total line length may not exceed @c HIP_RELAY_MAX_LINE_LEN characters.
 * <code>parametername</code> is at most @c HIP_RELAY_MAX_PAR_LEN characters
 * long and <code>value</code> is at most @c HIP_RELAY_MAX_VAL_LEN characters
 * long. A value itself may not contain a @c HIP_RELAY_VAL_SEP character.
 *
 * There is no need to use any other function from this file than
 * hip_cf_get_line_data().
 *
 * Usage:
 * <ol>
 * <li>Declare integers <code>lineerr</code> and <code>parseerr</code> and set
 * them zero</li>
 * <li>Declare a char array for the parameter's name
 * <code>parameter[HIP_RELAY_MAX_PAR_LEN + 1]</code></li>
 * <li>Declare a linked list <code>struct hip_config_value_list values</code> for values</li>
 * <li>Open the configfile using <code>fopen()</code></li>
 * <li>Go through the configuration file using hip_cf_get_line_data()
 * inside a <code>do { } while ()</code> -loop:
 * <pre>
 * do {
 *     parseerr = 0;
 *     memset(parameter, '\\0', sizeof(parameter));
 *     hip_cvl_init(&values);
 *     lineerr = hip_cf_get_line_data(fp, parameter, &values, &parseerr);
 *
 *     if (parseerr == 0) {
 *
 *       ... parameter has now the parameter name ...
 *
 *         struct hip_configfile_value *current = NULL;
 *         while ((current = hip_cvl_get_next(&values, current)) != NULL) {
 *
 *           ... do stuff with the current value ...
 *
 *         }
 *     }
 *     hip_cvl_uninit(&values);
 * } while (lineerr != EOF);
 * </pre>
 * </li>
 * <li>Close the configfile using <code>close()</code></li>
 * </ol>
 */

#ifndef HIP_HIPD_CONFIGFILEREADER_H
#define HIP_HIPD_CONFIGFILEREADER_H

#include <stdio.h>

/* For debuging macros. */

/** Maximum number of characters per line in HIP relay config file. */
#define HIP_RELAY_MAX_LINE_LEN 2048
/** Maximum number of characters in a HIP relay config file parameter. */
#define HIP_RELAY_MAX_PAR_LEN  32
/** Maximum number of characters in a HIP relay config file value. */
#define HIP_RELAY_MAX_VAL_LEN  64
/** HIP relay config file commented line mark as a char. */
#define HIP_RELAY_COMMENT      '#'
/** HIP relay config file value separator as a char. */
#define HIP_RELAY_VAL_SEP      ','

/** Linked list node. */
struct hip_configfile_value {
    char                         data[HIP_RELAY_MAX_VAL_LEN + 1]; /**< Node data. */
    struct hip_configfile_value *next;     /**< A pointer to next item. */
};

/** Linked list. */
struct hip_config_value_list {
    struct hip_configfile_value *head;     /**< A pointer to the first item of the list. */
};

int hip_cf_get_line_data(FILE *fp, char *parameter,
                         struct hip_config_value_list *values,
                         int *parseerr);
void hip_cvl_init(struct hip_config_value_list *linkedlist);
void hip_cvl_uninit(struct hip_config_value_list *linkedlist);
struct hip_configfile_value *hip_cvl_get_next(struct hip_config_value_list *linkedlist,
                                              struct hip_configfile_value *current);
void print_node(struct hip_configfile_value *node);

#endif /* HIP_HIPD_CONFIGFILEREADER_H */
