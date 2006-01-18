/*
 * Echo STDIN to a selected machine via tcp or udp using ipv6. Use this
 * with conntest-server.
 *
 * $Id: conntest-client-gai.c,v 1.16 2003/10/14 15:50:30 krisu Exp $
 */

/*
 * Notes:
 * - assumes that udp packets arrive in order (high probability within same
 *   network)
 * Bugs:
 * - none
 * Todo:
 * - rewrite/refactor for better modularity
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif

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
#include <sys/time.h>
#include <time.h>
#include "debug.h"

#include "conntest.h"


// usage: ./conntest-client host tcp|udp port
// reads stdin

int main(int argc,char *argv[]) {
	
	int proto, socktype;
	char *proto_name, *peer_port_name, *peer_name;

	hip_set_logtype(LOGTYPE_STDERR);
	hip_set_logfmt(LOGFMT_SHORT);

	if (argc != 4) {
		fprintf(stderr, "Usage: %s host tcp|udp port\n", argv[0]);
		exit(1);
	}

	peer_name = argv[1];
	proto_name = argv[2];
	peer_port_name = argv[3];

	if (strcmp(proto_name, "tcp") == 0) {
		proto = IPPROTO_TCP;
		socktype = SOCK_STREAM;
	} else if (strcmp(proto_name, "udp") == 0) {
		proto = IPPROTO_UDP;
		socktype = SOCK_DGRAM;
	} else {
		fprintf(stderr, "error: proto != tcp|udp\n");
		exit(1);
	}
	
	main_client_gai(proto, socktype, peer_name, peer_port_name);

}
