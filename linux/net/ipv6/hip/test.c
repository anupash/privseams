/*
 * Unit tests for HIPL kernel module.
 *
 * USAGE:
 *
 * - How to add a new test suite in the kernelspace:
 *   - Add a new struct unit_test_suite.
 *   - Insert the name of the struct into unit_test_suite_list
 *     in this file.
 *   - Increase the counter in unit_test_suite_list by one.
 * - How to add a new test case in the kernelspace:
 *   - Insert a new HIP_UNIT_TEST_CASE(name) macro before the test suite in
 *     which the test case belongs to.
 *   - Insert the name of the macro the test suite.
 *   - Increase the counter in the test suite by one. An empty test suite has
 *     0 as the counter value.
 * - How to add a new test into a test case:
 *   - Insert a HIP_UNIT_ASSERT(value) macro call into the test case.
 *
 * Author:
 * - Miika Komu <miika@iki.fi>
 *
 * TODO:
 * - xx
 *
 */

#include "unit.h"
#include "debug.h"

/*************** internal test cases ************************************/

HIP_UNIT_TEST_CASE(hip_test_internal) {
  int i = 1;
  HIP_UNIT_ASSERT(i);
  HIP_DEBUG("Unit test environment is working in the kernel\n");
}

static struct hip_unit_test_suite hip_unit_test_suite_internal = {
  1,
  {
    hip_test_internal
  }
};

/**************** collection of all test suites *************************/

static struct hip_unit_test_suite_list hip_unit_test_suite_list = {
  1,
  {
    &hip_unit_test_suite_internal
  }
};
