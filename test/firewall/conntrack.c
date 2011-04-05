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
#include "test/mocks.h"
#include "test_suites.h"


static struct connection *setup_connection(void)
{
    struct hip_data data = { { { { 0 } } } };

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

    mock_time = true;

    cleanup_interval   = 0;
    connection_timeout = 2;
    conn               = setup_connection();
    conn->timestamp    = 1;

    mock_time_next = 2;
    hip_fw_conntrack_periodic_cleanup(); // don't time out yet
    fail_if(conn_list == NULL, "Connection was removed too early.");

    mock_time_next = 3;
    hip_fw_conntrack_periodic_cleanup(); // time out this time
    fail_unless(conn_list == NULL, "Idle connection was not removed.");
}
END_TEST

START_TEST(test_hip_fw_conntrack_periodic_cleanup_glitched_system_time)
{
    struct connection *conn;

    mock_time = true;

    cleanup_interval   = 0;
    connection_timeout = 2;
    conn               = setup_connection();
    conn->timestamp    = 1;

    mock_time_next = 2;
    hip_fw_conntrack_periodic_cleanup();
    fail_if(conn_list == NULL, "Connection was removed too early.");

    mock_time_next = 1; // travel back in time
    hip_fw_conntrack_periodic_cleanup();
    fail_if(conn_list == NULL,
            "Connection was removed despite system time glitch.");

    mock_time_next = 3;
    hip_fw_conntrack_periodic_cleanup();
    fail_if(conn_list != NULL, "Connection was not removed.");
}
END_TEST

START_TEST(test_hip_fw_conntrack_periodic_cleanup_glitched_packet_time)
{
    struct connection *conn;

    mock_time = true;

    cleanup_interval   = 0;
    connection_timeout = 2;
    conn               = setup_connection();

    mock_time_next  = 1;
    conn->timestamp = 1;
    hip_fw_conntrack_periodic_cleanup();
    fail_if(conn_list == NULL, "Connection was removed too early.");

    conn->timestamp = 0xC0FFEE; // timestamp in the future
    hip_fw_conntrack_periodic_cleanup();
    fail_if(conn_list == NULL,
            "Connection was removed despite packet time glitch.");
    fail_if(conn->timestamp != 1, "Packet timestamp was not reset.");

    mock_time_next = 3;
    hip_fw_conntrack_periodic_cleanup();
    fail_if(conn_list != NULL, "Connection was not removed.");
}
END_TEST

Suite *firewall_conntrack(void)
{
    Suite *s = suite_create("firewall/conntrack");

    TCase *tc_conntrack = tcase_create("Conntrack");
    tcase_add_test(tc_conntrack, test_hip_fw_conntrack_periodic_cleanup_timeout);
    tcase_add_test(tc_conntrack, test_hip_fw_conntrack_periodic_cleanup_glitched_system_time);
    tcase_add_test(tc_conntrack, test_hip_fw_conntrack_periodic_cleanup_glitched_packet_time);
    suite_add_tcase(s, tc_conntrack);

    return s;
}
