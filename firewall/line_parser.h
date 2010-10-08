/**
 * @file
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
 * @author Stefan Goetz <stefan.goetz@cs.rwth-aachen.de>
 */
#ifndef HIP_FIREWALL_LINE_PARSER_H
#define HIP_FIREWALL_LINE_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hip_line_parser hip_line_parser_t;

hip_line_parser_t *hip_lp_new(const char *file_name);
void hip_lp_delete(hip_line_parser_t *lp);
char *hip_lp_first(hip_line_parser_t *lp);
char *hip_lp_next(hip_line_parser_t *lp);
int hip_lp_reload(hip_line_parser_t *lp);

#ifdef __cplusplus
}
#endif

#endif
