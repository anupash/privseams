#include "first_test.h"

/**
 * send_bos(): it allows to send a BOS packet
 */
int send_bos()
{
	struct hip_common *msg;
	int err = 0;
	
	msg = malloc(HIP_MAX_PACKET);
	if (!msg) {
		HIP_ERROR("malloc failed\n");
		goto out;
	}
	hip_msg_init(msg);

	printf("Sending BOS...\n");
	err = handle_bos(msg, 0, (const char **) NULL, 0);
	if (err) {
		HIP_ERROR("failed to handle msg\n");
		goto out_err;
	}
	
	if (hip_get_msg_type(msg) == 0) {
		err = -1;
		goto out_err;
	}
	
	err = hip_set_global_option(msg);
	if (err) {
		HIP_ERROR("sending msg failed\n");
		goto out_err;
	}
out_err:
	free(msg);
out:
	return err;
}

int main(int argc, char *argv[])
{
	int err = 0, port = DEFAULT_PORT;

	struct timeval stats_before, stats_after;
	unsigned long stats_diff_sec, stats_diff_usec;

	struct in6_addr my_hit, any = IN6ADDR_ANY_INIT;
	struct addrinfo hints, *res = NULL, *ai;
	char buf[20];

	/* Retrieving out HIT */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_HIP | AI_PASSIVE;
	hints.ai_family = AF_INET6; /* Legacy API supports only HIT-in-IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	sprintf(buf, "%d",DEFAULT_PORT);
	err = getaddrinfo(NULL, buf, &hints, &res);

	if (err) {
		printf("GAI ERROR %d: %s\n", err, gai_strerror(err));
		return(1);
	}
	if (res) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) res->ai_addr;
		ipv6_addr_copy(&my_hit, &sin6->sin6_addr);
		/* Now that I have the HIT I can free the memory allocated for res */
		freeaddrinfo(res);
		res = NULL;
	} else {
		HIP_ERROR("Cannot find my HIT\n");
		goto out_err;
	}
	
	/* By calling getaddrinfo with the flags set to AI_HIP | AI_KERNEL_LIST, the beet database
	 * is scrolled and if any entry is found, then it means that the BOS packets has been received
	 */
	hints.ai_flags = AI_HIP | AI_KERNEL_LIST;
	
	while (!res) {
		/* BOS */
		if (send_bos())
			goto out_err;
		
		err = getaddrinfo(NULL, buf, &hints, &res);
		if (err < 0) {
			printf("GAI ERROR %d: %s\n", err, gai_strerror(err));
			return(1);
		}


		HIP_HEXDUMP("my_hit is: ", &my_hit, 16);
		
		if (err > 0) {
			/*The BOS packet has been received because at least one entry has been found*/
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) res->ai_addr;
			if (ipv6_addr_cmp(&my_hit, &sin6->sin6_addr) > 0) {
				/* my_hit is greater ---> I am the initiator */
				printf("----> Initiator mode\n");
				hip_set_logtype(LOGTYPE_STDERR);
				hip_set_logfmt(LOGFMT_SHORT);

				gettimeofday(&stats_before, NULL);

				hip_connect_func(IPPROTO_TCP, res);
				
				gettimeofday(&stats_after, NULL);
				stats_diff_sec  = (stats_after.tv_sec - stats_before.tv_sec) * 1000000;
				stats_diff_usec = stats_after.tv_usec - stats_before.tv_usec;
				
				printf("connect took %.3f sec\n",
				       (stats_diff_sec+stats_diff_usec) / 1000000.0);
				
			} else {
				int peer, serversock;
				unsigned int peerlen = sizeof(struct sockaddr_in6);
				struct sockaddr_in6 peeraddr;
                                /* my_hit is smaller ---> I am the responder */
				serversock = create_serversocket(IPPROTO_TCP, DEFAULT_PORT);
				printf("----> Responder mode\n");
				/* Base Exchange Responder */
				peer = accept(serversock, (struct sockaddr *)&peeraddr, &peerlen);
				if (peer < 0) {
					perror("accept");
					exit(2);
				}
				//main_server(IPPROTO_TCP, DEFAULT_PORT);
			}
			goto out_mem;
		}

		freeaddrinfo(res);
		res = NULL;
		sleep(3);
	}
out_mem:
	if (res)
		freeaddrinfo(res);
out_err:
	return err;
}
