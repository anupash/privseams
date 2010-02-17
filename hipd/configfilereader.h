/** @file
 * A header file for configfilereader.c
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
 * <li>Declare a linked list <code>hip_configvaluelist_t values</code> for values</li>
 * <li>Open the configfile using <code>fopen()</code></li>
 * <li>Go through the configuration file using hip_cf_get_line_data()
 * inside a <code>do{ }while()</code> -loop:
 * <pre>
 * do {
 *     parseerr = 0;
 *     memset(parameter, '\0', sizeof(parameter));
 *     hip_cvl_init(&values);
 *     lineerr = hip_cf_get_line_data(fp, parameter, &values, &parseerr);
 *
 *     if(parseerr == 0){
 *
 *       ... parameter has now the parameter name ...
 *
 *        hip_configfilevalue_t *current = NULL;
 *    while((current = hip_cvl_get_next(&values, current)) != NULL) {
 *
 *           ... do stuff with the current value ...
 *
 *        }
 *    }
 *    hip_cvl_uninit(&values);
 * } while(lineerr != EOF);
 * </pre>
 * </li>
 * <li>Close the configfile using <code>close()</code></li>
 * </ol>
 *
 * @author  Lauri Silvennoinen
 * @version 1.0
 * @date    14.02.2008
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_HIPD_CONFIGFILEREADER_H
#define HIP_HIPD_CONFIGFILEREADER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "lib/core/misc.h" /* For debuging macros. */

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
typedef struct hip_cvl_node {
    char                 data[HIP_RELAY_MAX_VAL_LEN + 1]; /**< Node data. */
    struct hip_cvl_node *next;     /**< A pointer to next item. */
} hip_configfilevalue_t;

/** Linked list. */
typedef struct {
    hip_configfilevalue_t *head;     /**< A pointer to the first item of the list. */
} hip_configvaluelist_t;

int hip_cf_get_line_data(FILE *fp, char *parameter, hip_configvaluelist_t *values,
                         int *parseerr);
void hip_cvl_init(hip_configvaluelist_t *linkedlist);
void hip_cvl_uninit(hip_configvaluelist_t *linkedlist);
hip_configfilevalue_t *hip_cvl_get_next(hip_configvaluelist_t *linkedlist,
                                        hip_configfilevalue_t *current);
void print_node(hip_configfilevalue_t *node);

#endif /* HIP_HIPD_CONFIGFILEREADER_H */
