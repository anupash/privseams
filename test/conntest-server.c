/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * An echo server that receives data from network and echoes it back. Use this with
 * with conntest-client
 *
 * @todo rewrite/refactor for better modularity
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>

#include "lib/core/debug.h"
#include "conntest.h"

/**
 * handle signals
 *
 * @param signo the signal number
 */
static void sig_handler(int signo)
{
    if (signo == SIGTERM) {
        // close socket
        HIP_DIE("Sigterm\n");
    } else {
        HIP_DIE("Signal %d\n", signo);
    }
}

/**
 * Main function.
 *
 * @param argc command line argument count.
 * @param argv command line arguments.
 * @return zero on success or non-zero on failure
 */
int main(int argc, char *argv[])
{
    int port;
    int type;

    if (signal(SIGTERM, sig_handler) == SIG_ERR) {
        exit(1);
    }

    if (argc != 3) {
        fprintf(stderr, "Usage: %s tcp|udp port\n", argv[0]);
        exit(1);
    }

    if (strcmp(argv[1], "tcp") == 0) {
        type = SOCK_STREAM;
    } else if (strcmp(argv[1], "udp") == 0) {
        type = SOCK_DGRAM;
    } else {
        fprintf(stderr, "error: protonum != tcp|udp\n");
        exit(1);
    }

    port = atoi(argv[2]);
    if (port <= 0 || port >= 65535) {
        fprintf(stderr, "error: port < 0 || port > 65535\n");
        exit(1);
    }

    main_server(type, port);

    return 0;
}
