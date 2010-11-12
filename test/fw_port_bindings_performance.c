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
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file
 * @author Stefan Goetz <stefan.goetz@cs.rwth-aachen.de>
 */

#include <assert.h>
#include <stdio.h>
#include <time.h>

#include "firewall/file_buffer.h"
#include "firewall/line_parser.h"
#include "firewall/port_bindings.h"

static double time_clock(const unsigned int iterations)
{
    clock_t start, end, tmp;
    unsigned int i;

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        tmp = clock();
    }
    end = clock();

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_fb_create_delete(const unsigned int iterations,
                                        const char *file_name)
{
    clock_t start, end;
    unsigned int i;
    struct hip_file_buffer fb;

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        if (hip_fb_create(&fb, file_name) == 0) {
            hip_fb_delete(&fb);
        }
    }
    end = clock();

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_fb_reload(const unsigned int iterations,
                                 const char *file_name)
{
    clock_t start, end;
    unsigned int i;
    struct hip_file_buffer fb;
    int err;

    err = hip_fb_create(&fb, file_name);
    assert(0 == err);

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        err = hip_fb_reload(&fb);
        assert(err == 0);
    }
    end = clock();

    hip_fb_delete(&fb);

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_lp_create_delete(const unsigned int iterations)
{
    clock_t start, end;
    unsigned int i;
    struct hip_mem_area ma = { 0, 0 };
    struct hip_line_parser lp;

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        if (hip_lp_create(&lp, &ma) == 0) {
            hip_lp_delete(&lp);
        }
    }
    end = clock();

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_lp_first(const unsigned int iterations)
{
    clock_t start, end;
    unsigned int i;
    struct hip_line_parser lp;
    char *line;
    struct hip_mem_area ma = { 0, 0 };
    int err;

    err = hip_lp_create(&lp, &ma);
    assert(0 == err);

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        line = hip_lp_first(&lp);
    }
    end = clock();

    hip_lp_delete(&lp);

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_lp_next(const unsigned int iterations,
                               const char *file_name)
{
    clock_t start, end;
    unsigned int i;
    struct hip_file_buffer fb;
    struct hip_line_parser lp;
    char *line;
    int err;

    err = hip_fb_create(&fb, file_name);
    assert(0 == err);
    err = hip_lp_create(&lp, hip_fb_get_mem_area(&fb));
    assert(0 == err);
    line = hip_lp_first(&lp);
    assert(line != NULL);

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        line = hip_lp_next(&lp);
    }
    end = clock();

    hip_lp_delete(&lp);
    hip_fb_delete(&fb);

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_lp_parse_file(const unsigned int iterations,
                                     const char *file_name)
{
    clock_t start, end;
    unsigned int i;
    struct hip_file_buffer fb;
    struct hip_line_parser lp;
    char *line;
    int err;

    err = hip_fb_create(&fb, file_name);
    assert(0 == err);
    err = hip_lp_create(&lp, hip_fb_get_mem_area(&fb));
    assert(0 == err);

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        line = hip_lp_first(&lp);
        while (line != NULL) {
            line = hip_lp_next(&lp);
        }
    }
    end = clock();

    hip_lp_delete(&lp);
    hip_fb_delete(&fb);

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_port_binding_create_delete(const unsigned int iterations,
                                                  const bool enable_cache)
{
    clock_t start, end;
    unsigned int i;

    start = clock();
    for (i = 0; i < iterations; i += 1) {
        hip_port_bindings_init(enable_cache);
        hip_port_bindings_uninit();
    }
    end = clock();

    return (((double) (end - start)) / CLOCKS_PER_SEC) / iterations;
}

static double time_hip_port_bindings_get(const unsigned int iterations,
                                         const uint8_t proto,
                                         const in_port_t port,
                                         const bool enable_cache)
{
    clock_t start, end;
    unsigned int i;
    enum hip_port_binding pi;

    hip_port_bindings_init(enable_cache);

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
    const unsigned int iterations = 10000;
    const char *file_name = "/proc/net/tcp6";
    const uint8_t proto = 6;
    const in_port_t port = 0xFFFF;
    bool enable_cache = false;

    printf("Testing clock reading used for benchmarks:\n"
           "  - call clock()\n"
           "  ==> time_clock(%d): %fs\n\n", iterations,
           time_clock(iterations));

    printf("Testing file buffer allocation and de-allocation:\n"
           "  - call hip_fb_create() to\n"
           "    - zero the file buffer object\n"
           "    - open the file\n"
           "    - call hip_fb_reload() to\n"
           "      - allocate a memory buffer for the file data (if new fb object)\n"
           "      - read the file data into the memory buffer\n"
           "  - call hip_fb_delete() to\n"
           "    - de-allocate the file buffer object\n"
           "  ==> time_hip_fb_create_delete(%d, %s): %fs\n\n", iterations,
           file_name, time_hip_fb_create_delete(iterations, file_name));

    printf("Testing file buffer file access:\n"
           "  - call hip_fb_reload() to\n"
           "    - allocate a memory buffer for the file data (if new fb object)\n"
           "    - read the file data into the memory buffer\n"
           "  ==> time_hip_fb_reload(%d, %s): %fs\n\n", iterations, file_name,
           time_hip_fb_reload(iterations, file_name));

    printf("Testing line parser allocation and de-allocation:\n"
           "  - call hip_lp_create() to\n"
           "    - allocate a line parser object\n"
           "    - call hip_fb_create() (s.a.)\n"
           "  - call hip_lp_delete() to\n"
           "    - de-allocate the line parser object\n"
           "  ==> time_hip_lp_create_delete(%d): %fs\n\n", iterations,
           time_hip_lp_create_delete(iterations));

    printf("Testing line parser parsing function:\n"
           "  - call hip_lp_first() to\n"
           "    - retrieve a pointer to the beginning of the file\n"
           "  ==> time_hip_lp_first(%d): %fs\n\n", iterations,
           time_hip_lp_first(iterations));

    printf("Testing line parser parsing function:\n"
           "  - call hip_lp_next() to\n"
           "    - search for the next line\n"
           "    - retrieve a pointer to the beginning of the line\n"
           "  ==> time_hip_lp_next(%d, %s): %fs\n\n", iterations, file_name,
           time_hip_lp_next(iterations, file_name));

    printf("Testing line parser whole file parsing:\n"
           "  - call hip_lp_first() (s.a.)\n"
           "  - call hip_lp_next() (s.a.) until the end of the file\n"
           "  ==> time_hip_lp_parse_file(%d, %s): %fs\n\n", iterations, file_name,
           time_hip_lp_parse_file(iterations, file_name));

    printf("Testing port binding allocation and de-allocation without cache:\n"
           "  - call hip_port_bindings_init() to\n"
           "    - create tcp6 and udp6 line parser objects\n"
           "  - call hip_port_bindings_uninit() to\n"
           "    - delete tcp6 and udp6 line parser objects\n"
           "  ==> time_hip_port_binding_create_delete(%d, %d): %fs\n\n",
           iterations, enable_cache,
           time_hip_port_binding_create_delete(iterations, enable_cache));

    printf("Testing port binding parsing without cache:\n"
           "  - call hip_port_bindings_get() to\n"
           "    - parse proc file\n"
           "  ==> time_hip_port_bindings_get(%d, %d, 0x%X, %d): %fs\n\n",
           iterations, proto, port, enable_cache,
           time_hip_port_bindings_get(iterations, proto, port, enable_cache));

    enable_cache = true;
    printf("Testing port binding allocation and de-allocation with cache:\n"
           "  - call hip_port_bindings_init() to\n"
           "    - allocate and zero cache\n"
           "    - create tcp6 and udp6 line parser objects\n"
           "  - call hip_port_bindings_uninit() to\n"
           "    - delete tcp6 and udp6 line parser objects\n"
           "    - de-allocate cache\n"
            "  ==> time_hip_port_binding_create_delete(%d, %d): %fs\n\n",
            iterations, enable_cache,
            time_hip_port_binding_create_delete(iterations, enable_cache));

    printf("Testing port binding parsing with cache:\n"
           "  - call hip_port_bindings_get() to\n"
           "    - check cache for port binding\n"
           "    - parse proc file if no cache entry\n"
            "  ==> time_hip_port_bindings_get(%d, %d, 0x%X, %d): %fs\n\n",
            iterations, proto, port, enable_cache,
            time_hip_port_bindings_get(iterations, proto, port, enable_cache));

    return 0;
}
