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

#define _BSD_SOURCE

#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <check.h>
#include <signal.h>
#include <time.h>

#include "firewall/conntrack.h"
#include "firewall/conntrack.c"
#include "test_suites.h"

static time_t fake_time = 0;

time_t time(time_t *t)
{
    if (t) {
        *t = fake_time;
    }

    return fake_time;
}

static struct connection *setup_connection(void)
{
    struct hip_data data = {};

    inet_pton(AF_INET6, "2001:12:bd2d:d23e:4a09:b2ab:6414:e110", &data.src_hit);
    inet_pton(AF_INET6, "2001:10:f039:6bc5:cab3:0727:7fbc:9dcb", &data.dst_hit);

    insert_new_connection(&data);

    fail_if(conn_list       == NULL, "No connection inserted.");
    fail_if(conn_list->next != NULL, "More than one connection inserted.");
    fail_if(conn_list->data == NULL, "No connection allocated.");
    return conn_list->data;
}

START_TEST(test_hip_fw_conntrack_periodic_cleanup_timeout)
{
    struct connection *conn;

    cleanup_interval   = 0;
    connection_timeout = 2;

    conn            = setup_connection();
    conn->timestamp = 1;

    fake_time = 2;
    hip_fw_conntrack_periodic_cleanup(); // don't time out yet
    fail_if(conn_list == NULL, "Connection was removed too early.");

    fake_time = 3;
    hip_fw_conntrack_periodic_cleanup(); // time out this time
    fail_unless(conn_list == NULL, "Idle connection was not removed.");
}
END_TEST

START_TEST(test_hip_fw_conntrack_periodic_cleanup_glitched_system_time)
{
    cleanup_interval = 0;

    fake_time = 2;
    hip_fw_conntrack_periodic_cleanup(); // OK

    fake_time = 1;
    hip_fw_conntrack_periodic_cleanup(); // throws assertion
}
END_TEST

START_TEST(test_hip_fw_conntrack_periodic_cleanup_glitched_packet_time)
{
    struct connection *conn;

    cleanup_interval   = 0;
    connection_timeout = 2;

    fake_time = 1;

    conn            = setup_connection();
    conn->timestamp = 1;
    hip_fw_conntrack_periodic_cleanup(); // OK
    conn->timestamp = 2;
    hip_fw_conntrack_periodic_cleanup(); // throws assertion
}
END_TEST

Suite *firewall_conntrack(void)
{
    Suite *s = suite_create("firewall/conntrack");

    TCase *tc_conntrack = tcase_create("Conntrack");
    tcase_add_test(tc_conntrack, test_hip_fw_conntrack_periodic_cleanup_timeout);
    tcase_add_exit_test(tc_conntrack, test_hip_fw_conntrack_periodic_cleanup_glitched_system_time, 1);
    tcase_add_exit_test(tc_conntrack, test_hip_fw_conntrack_periodic_cleanup_glitched_packet_time, 1);
    suite_add_tcase(s, tc_conntrack);

    return s;
}
