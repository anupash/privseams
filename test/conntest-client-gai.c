/** @file
 * A test client for testing HIP connection between hosts. Use this in context
 * with conntest-server. "gai" stands for "give all information" :D
 *
 * @author  Lauri Silvennoinen
 * @version 1.1
 * @date    30.01.2008
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
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
#include "ife.h"
#include "conntest.h"

#define MINPORTNUM 1
#define MAXPORTNUM 65535

/**
 * Main function.
 * 
 * @param argc command line argument count.
 * @param argv command line arguments.
 * @return     EXIT_FAILURE on failure, EXIT_SUCCESS on success.
 */
int main(int argc, char *argv[]) {
	
	int socktype = -1, err = 0;
	const char *cfile = "default";
	char usage[100];
	in_port_t port = 0;

	sprintf(usage, "Usage: %s <host> tcp|udp <port>", argv[0]);

	hip_set_logtype(LOGTYPE_STDERR);
	hip_set_logfmt(LOGFMT_SHORT);
	HIP_IFEL(hip_set_auto_logdebug(cfile), -1,
		 "Error: Cannot set the debugging parameter.\n");
	
	if(argc < 4) {
		HIP_INFO("Not enough arguments.\n%s\n", usage);
		return EXIT_FAILURE;
	}else if(argc > 4) {
		HIP_INFO("Too many arguments.\n%s\n", usage);
		return EXIT_FAILURE;
	}
	
	if (strcmp(argv[2], "tcp") == 0) {
		socktype = SOCK_STREAM;
	} else if (strcmp(argv[2], "udp") == 0) {
		socktype = SOCK_DGRAM;
	} else {
		HIP_INFO("Invalid protocol: '%s'\n%s\n", argv[2], usage);
		return EXIT_FAILURE;
	}
	
	port = atoi(argv[3]);

	if(port < MINPORTNUM || port > MAXPORTNUM){
		HIP_INFO("Invalid port number, allowed port numbers are "\
			 "from %d to %d.\n%s\n", MINPORTNUM, MAXPORTNUM,
			 usage);
		return EXIT_FAILURE;
	}
	
	HIP_INFO("=== Testing %s connection to '%s' on port %s ===\n",
		 (socktype == SOCK_STREAM ? "TCP" : "UDP"), argv[1],
		 argv[3]);

	/* Call the main function to do the actual logic. */
	err = main_client_gai(socktype, argv[1], argv[3], 0);

 out_err:
	if(err == 0) {
		HIP_INFO("=== Connection test result: \e[92mSUCCESS\e[00m ===\n");
		return EXIT_SUCCESS;
	} else {
		HIP_INFO("=== Connection test result: \e[91mFAILURE\e[00m ===\n");
		return EXIT_FAILURE;
	}
}
