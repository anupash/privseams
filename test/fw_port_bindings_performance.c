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
#include <time.h>
#include <stdio.h>
#include <assert.h>
#include "firewall/file_buffer.h"
#include "firewall/line_parser.h"
#include "firewall/port_bindings.h"

static double time_hip_fb_create_delete(const unsigned long iterations,
                                        const char *file_name)
{
    clock_t start, end;
    unsigned long i;

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        struct hip_file_buffer *fb = hip_fb_create(file_name);
        if (fb != NULL) {
            hip_fb_delete(fb);
        }
    }
    end = clock();

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_fb_reload(const unsigned long iterations,
                                 const char *file_name)
{
    clock_t start, end;
    unsigned long i;
    struct hip_file_buffer *fb;
    int err;

    fb = hip_fb_create(file_name);
    assert(fb != NULL);

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        err = hip_fb_reload(fb);
        assert(err == 0);
    }
    end = clock();

    if (fb != NULL) {
        hip_fb_delete(fb);
    }

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_lp_create_delete(const unsigned long iterations,
                                        const char *file_name)
{
    clock_t start, end;
    unsigned long i;

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        struct hip_line_parser *lp = hip_lp_create(file_name);
        if (lp != NULL) {
            hip_lp_delete(lp);
        }
    }
    end = clock();

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_lp_first(const unsigned long iterations,
                                const char *file_name)
{
    clock_t start, end;
    unsigned long i;
    struct hip_line_parser *lp;
    char *line;

    lp = hip_lp_create(file_name);
    assert(lp != NULL);

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        line = hip_lp_first(lp);
    }
    end = clock();

    if (lp != NULL) {
        hip_lp_delete(lp);
    }

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_lp_next(const unsigned long iterations,
                               const char *file_name)
{
    clock_t start, end;
    unsigned long i;
    struct hip_line_parser *lp;
    char *line;

    lp = hip_lp_create(file_name);
    assert(lp != NULL);
    line = hip_lp_first(lp);
    assert(line != NULL);

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        line = hip_lp_next(lp);
    }
    end = clock();

    if (lp != NULL) {
        hip_lp_delete(lp);
    }

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_lp_parse_file(const unsigned long iterations,
                                     const char *file_name)
{
    clock_t start, end;
    unsigned long i;
    struct hip_line_parser *lp;
    char *line;

    lp = hip_lp_create(file_name);
    assert(lp != NULL);

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        line = hip_lp_first(lp);
        while (line != NULL) {
            line = hip_lp_next(lp);
        }
    }
    end = clock();

    if (lp != NULL) {
        hip_lp_delete(lp);
    }

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_lp_reload(const unsigned long iterations,
                                 const char *file_name)
{
    clock_t start, end;
    unsigned long i;
    struct hip_line_parser *lp;

    lp = hip_lp_create(file_name);
    assert(lp != NULL);

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        hip_lp_reload(lp);
    }
    end = clock();

    if (lp != NULL) {
        hip_lp_delete(lp);
    }

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_port_binding_create_delete(const unsigned long iterations)
{
    clock_t start, end;
    unsigned long i;

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        hip_port_bindings_init();
        hip_port_bindings_uninit();
    }
    end = clock();

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_port_bindings_get(const unsigned long iterations,
                                     const uint8_t proto,
                                     const in_port_t port)
{
    clock_t start, end;
    unsigned long i;
    enum hip_port_binding pi;

    hip_port_bindings_init();

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        pi = hip_port_bindings_get(proto, port);
    }
    end = clock();

    hip_port_bindings_uninit();

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}




int main(void)
{
    unsigned long iterations = 10000;
    const char *file_name = "/proc/net/tcp6";
    const uint8_t proto = 6;
    const in_port_t port = 0xFFFF;

    printf("Testing file buffer allocation and de-allocation:\n"
           "  - call hip_fb_create() to\n"
           "    - allocate the file buffer object\n"
           "    - open the file\n"
           "    - call hip_fb_reload() to\n"
           "      - allocate a memory buffer for the file data (if new fb object)\n"
           "      - read the file data into the memory buffer\n"
           "  - call hip_fb_delete() to\n"
           "    - de-allocate the file buffer object\n"
           "  ==> time_hip_fb_create_delete(%ld, %s): %fs\n\n", iterations,
           file_name, time_hip_fb_create_delete(iterations, file_name));

    printf("Testing file buffer file access:\n"
           "  - call hip_fb_reload() to\n"
           "    - allocate a memory buffer for the file data (if new fb object)\n"
           "    - read the file data into the memory buffer\n"
           "  ==> time_hip_fb_reload(%ld, %s): %fs\n\n", iterations, file_name,
           time_hip_fb_reload(iterations, file_name));

    printf("Testing line parser allocation and de-allocation:\n"
           "  - call hip_lp_create() to\n"
           "    - allocate a line parser object\n"
           "    - call hip_fb_create() (s.a.)\n"
           "  - call hip_lp_delete() to\n"
           "    - de-allocate the line parser object\n"
           "  ==> time_hip_lp_create_delete(%ld, %s): %fs\n\n", iterations,
           file_name, time_hip_lp_create_delete(iterations, file_name));

    printf("Testing line parser parsing function:\n"
           "  - call hip_lp_first() to\n"
           "    - retrieve a pointer to the beginning of the file\n"
           "  ==> time_hip_lp_first(%ld, %s): %fs\n\n", iterations, file_name,
           time_hip_lp_first(iterations, file_name));

    printf("Testing line parser parsing function:\n"
           "  - call hip_lp_next() to\n"
           "    - search for the next line\n"
           "    - retrieve a pointer to the beginning of the line\n"
           "  ==> time_hip_lp_next(%ld, %s): %fs\n\n", iterations, file_name,
           time_hip_lp_next(iterations, file_name));

    printf("Testing line parser whole file parsing:\n"
           "  - call hip_lp_first() (s.a.)\n"
           "  - call hip_lp_next() (s.a.) until the end of the file\n"
           "  ==> time_hip_lp_parse_file(%ld, %s): %fs\n\n", iterations, file_name,
           time_hip_lp_parse_file(iterations, file_name));

    printf("Testing line parser reloading:\n"
           "  - call hip_lp_reload() to\n"
           "    - call hip_fb_reload() (s.a.)\n"
           "  ==> time_hip_lp_reload(%ld, %s): %fs\n\n", iterations, file_name,
           time_hip_lp_reload(iterations, file_name));

    printf("Testing port binding allocation and de-allocation:\n"
           "  - call hip_port_bindings_init() to\n"
           "    - allocate and zero cache\n"
           "    - create tcp6 and udp6 line parser objects\n"
           "  - call hip_port_bindings_uninit() to\n"
           "    - delete tcp6 and udp6 line parser objects\n"
           "    - de-allocate cache\n"
           "  ==> time_hip_port_binding_create_delete(%ld): %fs\n\n", iterations,
           time_hip_port_binding_create_delete(iterations));

    printf("Testing port binding parsing:\n"
           "  - call hip_port_bindings_get() to\n"
           "    - check cache for port binding\n"
           "    - parse proc file if no cache entry\n"
           "  ==> time_hip_port_bindings_get(%ld, %d, 0x%X): %fs\n\n", iterations,
           proto, port, time_hip_port_bindings_get(iterations, proto, port));

    return 0;
}
