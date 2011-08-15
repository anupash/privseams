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
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/rand.h>

#include "lib/core/solve.h"
#include "config.h"
#include "test_suites.h"


START_TEST(test_hip_solve_puzzle_0_K)
{
    struct puzzle_hash_input puzzle_input = { { 0 } };
    uint8_t                  difficulty   = 0;

    RAND_bytes(puzzle_input.puzzle, sizeof(PUZZLE_LENGTH));

    fail_unless(hip_solve_puzzle(&puzzle_input, difficulty) == 0, NULL);
}
END_TEST

START_TEST(test_hip_solve_puzzle_5_K)
{
    struct puzzle_hash_input puzzle_input = { { 0 } };
    uint8_t                  difficulty   = 5;

    RAND_bytes(puzzle_input.puzzle, sizeof(PUZZLE_LENGTH));

    fail_unless(hip_solve_puzzle(&puzzle_input, difficulty) == 0, NULL);
}
END_TEST

START_TEST(test_hip_solve_puzzle_exceeding_K)
{
    struct puzzle_hash_input puzzle_input = { { 0 } };
    uint8_t                  difficulty   = MAX_PUZZLE_DIFFICULTY + 1;

    RAND_bytes(puzzle_input.puzzle, sizeof(PUZZLE_LENGTH));

    fail_unless(hip_solve_puzzle(&puzzle_input, difficulty) == -1, NULL);
}
END_TEST

START_TEST(test_hip_verify_puzzle_solution_invalid)
{
    struct puzzle_hash_input puzzle_input = { { 0 } };
    uint8_t                  difficulty   = 5;

    memset(puzzle_input.puzzle, 1, PUZZLE_LENGTH);

    fail_unless(hip_verify_puzzle_solution(&puzzle_input, difficulty) == -1, NULL);
}
END_TEST

START_TEST(test_hip_verify_puzzle_solution_against_ourselves)
{
    struct puzzle_hash_input puzzle_input = { { 0 } };
    uint8_t                  difficulty   = 5;

    RAND_bytes(puzzle_input.puzzle, sizeof(PUZZLE_LENGTH));

    fail_unless(hip_solve_puzzle(&puzzle_input, difficulty) == 0, NULL);
    fail_unless(hip_verify_puzzle_solution(&puzzle_input, difficulty) == 0, NULL);
}
END_TEST

START_TEST(test_hip_test_hip_verify_puzzle_solution_against_real_solution)
{
    char solution_dump[] = "\x01\x41\x00\x14\x05\x00\x48\x49\x0b\xbd\xd0\xb4"
                           "\x92\xbb\xea\xe3\xa9\x71\x97\xdf\x12\xe1\x2c\x9f";
    struct hip_solution     *solution          = (struct hip_solution *) solution_dump;
    const char              *initiator_hit_str = "2001:1b:d8b0:77f0:c617:7170:ded7:f320";
    const char              *responder_hit_str = "2001:17:5df8:c426:98e5:5fa2:286d:2847";
    struct in6_addr          initiator_hit;
    struct in6_addr          responder_hit;
    struct puzzle_hash_input puzzle_input;

    inet_pton(AF_INET6, initiator_hit_str, &initiator_hit);
    inet_pton(AF_INET6, responder_hit_str, &responder_hit);

    memcpy(puzzle_input.puzzle, solution->I, PUZZLE_LENGTH);
    puzzle_input.initiator_hit = initiator_hit;
    puzzle_input.responder_hit = responder_hit;
    memcpy(puzzle_input.solution, solution->J, PUZZLE_LENGTH);

    fail_unless(hip_verify_puzzle_solution(&puzzle_input, solution->K) == 0, NULL);
}
END_TEST

Suite *lib_core_solve(void)
{
    Suite *s = suite_create("lib/core/solve");

    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_hip_solve_puzzle_0_K);
    tcase_add_test(tc_core, test_hip_solve_puzzle_5_K);
    tcase_add_test(tc_core, test_hip_solve_puzzle_exceeding_K);
    tcase_add_test(tc_core, test_hip_verify_puzzle_solution_invalid);
    tcase_add_test(tc_core, test_hip_verify_puzzle_solution_against_ourselves);
    tcase_add_test(tc_core, test_hip_test_hip_verify_puzzle_solution_against_real_solution);
    suite_add_tcase(s, tc_core);

    return s;
}
