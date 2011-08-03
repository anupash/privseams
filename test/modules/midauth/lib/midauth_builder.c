/*
 * Copyright (c) 2011 Aalto University and RWTH Aachen University.
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
#include <stdint.h>

#include "lib/core/protodefs.h"
#include "modules/midauth/lib/midauth_builder.h"
#include "../test_suites.h"

#define MIDAUTH_DEFAULT_NONCE_LENGTH 18

#ifdef HAVE_TCASE_ADD_EXIT_TEST
START_TEST(test_midauth_builder_puzzle_seed_opaque_NULL)
{
    const uint8_t *const opaque = NULL;
    uint8_t puzzle_value[PUZZLE_LENGTH];

    hip_midauth_puzzle_seed(opaque, MIDAUTH_DEFAULT_NONCE_LENGTH, puzzle_value);
}
END_TEST
#endif /* HAVE_TCASE_ADD_EXIT_TEST */

START_TEST(test_midauth_builder_puzzle_seed_opaque_len_0)
{
    const uint8_t opaque[] = "\x01\x41\x00\x14\x05\x00\x48\x49\x0b";
    uint8_t puzzle_value[PUZZLE_LENGTH];

    fail_unless(hip_midauth_puzzle_seed(opaque,
                                        0,
                                        puzzle_value) == -1, NULL);
}
END_TEST

START_TEST(test_midauth_builder_puzzle_seed_correct)
{
    const uint8_t opaque[] = "\x01\x41\x01\x14\x05\x00\x48\x49\x0b"
                             "\x02\x42\x02\x15\x06\x08\x49\x50\x0c";
    uint8_t puzzle_value[PUZZLE_LENGTH];
    uint8_t correct_puzzle_value[] = "\x43\x03\x8F\xD7\x2F\xC7\xD2\xF3";

    fail_unless(hip_midauth_puzzle_seed(opaque,
                                        MIDAUTH_DEFAULT_NONCE_LENGTH,
                                        puzzle_value) == 0, NULL);
    fail_unless(memcmp(correct_puzzle_value, puzzle_value, PUZZLE_LENGTH) == 0,
                NULL);
}
END_TEST

Suite *modules_midauth_lib_builder(void)
{
    Suite *s = suite_create("modules/midauth/lib/midauth_builder");
    TCase *tc_midauth_builder = tcase_create("Midauth_builder");

// the tcase_add_exit_test macro is only available in check 0.9.8 or later but
// scratchbox uses an older version of checkc so we try to avoid this macro
#ifdef HAVE_TCASE_ADD_EXIT_TEST
    tcase_add_exit_test(tc_midauth_builder,
                        test_midauth_builder_puzzle_seed_opaque_NULL, 1);
#endif
    tcase_add_test(tc_midauth_builder, test_midauth_builder_puzzle_seed_opaque_len_0);
    tcase_add_test(tc_midauth_builder, test_midauth_builder_puzzle_seed_correct);

    suite_add_tcase(s, tc_midauth_builder);

    return s;
}
