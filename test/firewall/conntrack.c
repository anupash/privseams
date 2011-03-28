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
#include <assert.h>

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
    struct hip_fw_context ctx  = { };   // only ctx.udp_encap_hdr is examined
    struct hip_data       data = { };

    inet_pton(AF_INET6, "2001:12:bd2d:d23e:4a09:b2ab:6414:e110", &data.src_hit);
    inet_pton(AF_INET6, "2001:10:f039:6bc5:cab3:0727:7fbc:9dcb", &data.dst_hit);

    insert_new_connection(&data, &ctx);

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
    fake_time          = 1;

    conn            = setup_connection();
    conn->timestamp = 1;
    hip_fw_conntrack_periodic_cleanup(); // OK
    conn->timestamp = 2;
    hip_fw_conntrack_periodic_cleanup(); // throws assertion
}
END_TEST

START_TEST(test_parse_iptables_esp_rule)
{
    struct {
        const char  *input;
        bool         valid;
        unsigned int pkts;
        const char  *ip;
        uint32_t     spi;
    } test_cases[] = {
        { "Chain HIPFW-FORWARD (1 references)",                                                                        .valid = false },
        { " pkts bytes target     prot opt in     out     source               destination         ",                  .valid = false },
        { "    2   312 ACCEPT     esp      *      *       ::/0                 3ffe:2::1/128       esp spi:469913213", .valid = true, .pkts = 2, .ip = "3ffe:2::1", .spi = 0x1c024e7d },
        { "    0     0 QUEUE      udp      *      *       ::/0                 ::/0                udp spt:10500",     .valid = false },
        { "    0     0 QUEUE      esp      *      *       ::/0                 ::/0                ",                  .valid = false },
        { "    4  2264 QUEUE      139      *      *       ::/0                 ::/0                ",                  .valid = false },
        { "    3   336 ACCEPT     udp  --  *      *       0.0.0.0/0            192.168.2.1         udp spt:10500 dpt:10500 u32 0x4&0x1fff=0x0&&0x0>>0x16&0x3c@0x8=0xab772758", .valid = true, .pkts = 3, .ip = "::ffff:192.168.2.1", .spi = 0xab772758 }
    };

    const int num_tests = sizeof(test_cases) / sizeof(*test_cases);
    int       i;

    for (i = 0; i < num_tests; ++i) {
        struct in6_addr dest, reference;
        unsigned int    pkts;
        uint32_t        spi;

        if (parse_iptables_esp_rule(test_cases[i].input, &pkts, &spi, &dest)) {
            fail_unless(test_cases[i].valid,        "Invalid rule was considered valid");
            fail_unless(pkts == test_cases[i].pkts, "Packet count not parsed correctly");
            fail_unless(spi  == test_cases[i].spi,  "SPI not parsed correctly");

            assert(inet_pton(AF_INET6, test_cases[i].ip, &reference) == 1);
            fail_unless(IN6_ARE_ADDR_EQUAL(&dest, &reference),
                        "Destination IP not parsed correctly.");
        } else {
            fail_unless(test_cases[i].valid == false, "Valid rule was considered invalid");
        }
    }
}
END_TEST

Suite *firewall_conntrack(void)
{
    Suite *s = suite_create("firewall/conntrack");

    TCase *tc_conntrack = tcase_create("Conntrack");
    tcase_add_test(tc_conntrack, test_hip_fw_conntrack_periodic_cleanup_timeout);
    tcase_add_test(tc_conntrack, test_parse_iptables_esp_rule);
    tcase_add_exit_test(tc_conntrack, test_hip_fw_conntrack_periodic_cleanup_glitched_system_time, 1);
    tcase_add_exit_test(tc_conntrack, test_hip_fw_conntrack_periodic_cleanup_glitched_packet_time, 1);
    suite_add_tcase(s, tc_conntrack);

    return s;
}
