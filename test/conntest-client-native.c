/*
 * Echo STDIN to a selected server which should echo it back.
 * Use this application with conntest-server-xx.
 *
 * usage: ./conntest-client-native host tcp|udp port
 *        (reads stdin)
 *
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
#include <arpa/inet.h>
#include <net/if.h>
#include "libinet6/debug.h"

#include "conntest.h"

int main(int argc,char *argv[]) {
	char *proto_name, *peer_port_name, *peer_name;
	int proto, socktype;

	hip_set_logtype(LOGTYPE_STDERR);
	hip_set_logfmt(LOGFMT_SHORT);

	if (argc != 4) {
		HIP_ERROR("Usage: %s host tcp|udp port\n", argv[0]);
		return(1);
	}
  
	peer_name = argv[1];
	proto_name = argv[2];
	peer_port_name = argv[3];
  
	/* Set transport protocol */
	if (strcmp(proto_name, "tcp") == 0) {
		proto = IPPROTO_TCP;
		socktype = SOCK_STREAM;
	} else if (strcmp(proto_name, "udp") == 0) {
		proto = IPPROTO_UDP;
		socktype = SOCK_DGRAM;
	} else {
		HIP_ERROR("Error: only TCP and UDP supported.\n");
		return(1);
	}

	return(main_client_native(proto, socktype, peer_name, peer_port_name));
}
