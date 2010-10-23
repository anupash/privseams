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
#include <check.h>
#include <fcntl.h>  // open()
#include <stdio.h>  // mkstemp()
#include <unistd.h> // write()
#include <string.h> // strncpy(), memcmp()
#include <assert.h> // assert()
#include "firewall/file_buffer.h"
#include "firewall/file_buffer.c"

// these tests do not clean up after themselves because they assume that
// check runs them in dedicated processes so the OS does the cleanup

START_TEST(test_hip_fb_create_valid)
{
    struct hip_file_buffer fb;

    fail_unless(hip_fb_create(&fb, "/etc/fstab") == 0, "Opening the file '/etc/fstab' failed - does it exist?");
}
END_TEST

START_TEST(test_hip_fb_create_null_buffer)
{
    fail_unless(hip_fb_create(NULL, "/etc/fstab") == -1, NULL);
}
END_TEST

START_TEST(test_hip_fb_create_null_file_name)
{
    struct hip_file_buffer fb;

    fail_unless(hip_fb_create(&fb, NULL) == -1, NULL);
}
END_TEST

START_TEST(test_hip_fb_create_missing_file)
{
    struct hip_file_buffer fb;

    fail_unless(hip_fb_create(&fb, "XhUp8vH5sbye3izn25XbY3EVu9VcAsNC42WOCVYxAkMXiFo7cuh4Zsp2jHgfJ2OsBUTamYDuSyB9oSuAYEfBJA6EaEXBpNCp2l88Zo2yaWaLw6pB5mh61dlBDQZjaqlS") == -2, NULL);
}
END_TEST

START_TEST(test_hip_fb_create_check_file_integrity)
{
    struct hip_file_buffer fb;
    const struct hip_mem_area *ma = NULL;
    int fd = -1;
    const char FILE_NAME_PATTERN[] = "XXXXXX";
    char file_name[sizeof(FILE_NAME_PATTERN)];
    const char file_contents[] = "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";
    size_t bytes_written = 0;

    strncpy(file_name, FILE_NAME_PATTERN, sizeof(file_name));

    // create a file and write well-known data into it
    fd = mkstemp(file_name);
    assert(fd != -1);
    bytes_written = write(fd, file_contents, sizeof(file_contents));
    assert(sizeof(file_contents) == bytes_written);
    close(fd);

    fail_unless(hip_fb_create(&fb, file_name) == 0, NULL);
    fail_unless((ma = hip_fb_get_mem_area(&fb)) != NULL, NULL);
    fail_unless((ma->end - ma->start) == sizeof(file_contents));
    fail_unless(memcmp(ma->start, file_contents, sizeof(file_contents)) == 0, NULL);

    fd = open(file_name, O_RDWR | O_APPEND);
    assert(fd != -1);
    bytes_written = write(fd, file_contents, sizeof(file_contents));
    assert(sizeof(file_contents) == bytes_written);
    close(fd);

    fail_unless(hip_fb_reload(&fb) == 0, NULL);
    fail_unless(ma == hip_fb_get_mem_area(&fb), NULL);
    fail_unless((ma->end - ma->start) == sizeof(file_contents) * 2);
    fail_unless(memcmp(ma->start, file_contents, sizeof(file_contents)) == 0, NULL);
    fail_unless(memcmp(ma->start + sizeof(file_contents), file_contents, sizeof(file_contents)) == 0, NULL);

    remove(file_name);
}
END_TEST

START_TEST(test_hip_fb_delete_valid)
{
    struct hip_file_buffer fb;
    int err = 0;

    err = hip_fb_create(&fb, "/etc/fstab");
    assert(0 == err);
    hip_fb_delete(&fb);
}
END_TEST

START_TEST(test_hip_fb_delete_null_fb)
{
    hip_fb_delete(NULL);
}
END_TEST

START_TEST(test_hip_fb_reload_null_fb)
{
    fail_unless(hip_fb_reload(NULL) == -1, NULL);
}
END_TEST

// For unknown reasons, this file does not compile with the following,
// seemingly useless forward declaration
Suite *firewall_file_buffer(void);

Suite *firewall_file_buffer(void)
{
    Suite *s = suite_create("firewall/file_buffer");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_hip_fb_create_valid);
    tcase_add_test(tc_core, test_hip_fb_create_null_buffer);
    tcase_add_test(tc_core, test_hip_fb_create_null_file_name);
    tcase_add_test(tc_core, test_hip_fb_create_missing_file);
    tcase_add_test(tc_core, test_hip_fb_create_check_file_integrity);
    tcase_add_test(tc_core, test_hip_fb_delete_valid);
    tcase_add_test(tc_core, test_hip_fb_delete_null_fb);
    tcase_add_test(tc_core, test_hip_fb_reload_null_fb);
    suite_add_tcase(s, tc_core);

    return s;
}
