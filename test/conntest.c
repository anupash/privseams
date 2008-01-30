#include "conntest.h"

/**
 * create_serversocket - given the port and the protocol
 * it binds the socket and listen to it
 * @param proto type of protocol
 * @param port the kind of protocol
 *
 * @return the socket id,
 * exits on error.
 */
int create_serversocket(int type, int port) {
	int fd, on = 1;
	struct sockaddr_in6 addr;
	
	fd = socket(AF_INET6, type, 0);
	if (fd < 0) {
		perror("socket");
		exit(1);
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	bzero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	addr.sin6_addr = in6addr_any;
	addr.sin6_flowinfo = 0;
	// the following gives error "structure has no member named `sin6_scope_id'"
	// on gaijin:
	// addr.sin6_scope_id = 0 ;

	if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in6)) < 0) {
		perror("bind");
		close(fd);
		exit(1);
	}

	if (type == SOCK_STREAM) {
		if (listen(fd, 1) < 0) {
			perror("listen");
			close(fd);
			exit(1);
		}
	}

	return(fd);
}

int main_server_tcp(int serversock) {
	int peerfd = 0, err = 0;
	socklen_t locallen;
	unsigned int peerlen;
	struct sockaddr_in6 localaddr, peeraddr;
	char mylovemostdata[IP_MAXPACKET];
	int recvnum, sendnum;
	char addrstr[INET6_ADDRSTRLEN];

	peerlen = sizeof(struct sockaddr_in6);
  
	peerfd = accept(serversock, (struct sockaddr *)&peeraddr, &peerlen);
	if (peerfd < 0) {
		perror("accept");
		err = -1;
		goto out_err;
	}
	
	locallen = sizeof(localaddr);
	if (!getsockname(serversock,
			 (struct sockaddr *)&localaddr,
			 &locallen))
		HIP_DEBUG_HIT("local addr", &localaddr.sin6_addr);
	HIP_DEBUG_HIT("peer addr", &peeraddr.sin6_addr);
	
	while((recvnum = recv(peerfd, mylovemostdata,
			      sizeof(mylovemostdata), 0)) > 0 ) {
		mylovemostdata[recvnum] = '\0';
		printf("Client sends: %s", mylovemostdata);
		fflush(stdout);
		if (recvnum == 0) {
			close(peerfd);
			err = -1;
			break;
		}
		
		/* send reply */
		sendnum = send(peerfd, mylovemostdata, recvnum, 0);
		if (sendnum < 0) {
			perror("send");
			err = -1;
			break;
		}
		printf("Client has been replied.\n");
	}

	if (peerfd)
		close(peerfd);

out_err:
	return err;
}

int main_server_udp(int serversock) {
	/* Use recvmsg/sendmsg instead of recvfrom/sendto because
	   the latter combination may choose a different source
	   HIT for the server */
	struct sockaddr_in6 peeraddr;
	char control[CMSG_SPACE(256)];
	char mylovemostdata[IP_MAXPACKET];
	struct iovec iov = { mylovemostdata,
			     sizeof(mylovemostdata) - 1 };
        struct cmsghdr *cmsg;
	struct in6_pktinfo *pktinfo_in6;
	struct msghdr msg = {
		&peeraddr, sizeof(peeraddr),
		&iov, 1,
		control, sizeof(control), 0
	};
	int err = 0, on = 1, recvnum, sendnum;
	
        err = setsockopt(serversock, IPPROTO_IPV6,
			 IPV6_2292PKTINFO, &on, sizeof(on));
	if (err != 0) {
		perror("setsockopt IPV6_RECVPKTINFO");
		goto out_err;
	}

	memset(mylovemostdata, 0, sizeof(mylovemostdata));
	memset(&peeraddr, 0, sizeof(peeraddr));

	printf("=== Server listening IN6ADDR_ANY ===\n");

	while((recvnum = recvmsg(serversock, &msg, 0)) > 0) {
		fprintf(stderr,"=== received string: %s ===\n",
			mylovemostdata);
		fflush(stdout);
		
		/* Local address comes from ancillary data passed
		 * with msg due to IPV6_PKTINFO socket option */
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
		     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			_HIP_DEBUG("level=%d type=%d\n",
				   cmsg->cmsg_level, cmsg->cmsg_type);
			if ((cmsg->cmsg_level == IPPROTO_IPV6) && 
			    (cmsg->cmsg_type == IPV6_2292PKTINFO)) {
				pktinfo_in6 =
					(struct in6_pktinfo *) CMSG_DATA(cmsg);
				HIP_DEBUG_HIT("localaddr",
					      &pktinfo_in6->ipi6_addr);
				break;
			}
		}

		HIP_DEBUG_HIT("peeraddr", hip_cast_sa_addr(&peeraddr));

		/* send only the data we received (notice that there is
		   always a \0 in the end of the string) */
		iov.iov_len = strlen(mylovemostdata);
		
		/* send reply using the ORIGINAL src/dst address pair
		 (preserved in the control field) */
		sendnum = sendmsg(serversock, &msg, 0);
		if (sendnum < 0) {
			perror("send");
			err = -1;
			break;
		}

		/* reset all fields for the next round */
		memset(mylovemostdata, 0, sizeof(mylovemostdata));
		memset(&peeraddr, 0, sizeof(peeraddr));
		msg.msg_namelen = sizeof(peeraddr);
		memset(control, 0, sizeof(control));
		iov.iov_len = sizeof(mylovemostdata);

		printf("=== Sent string successfully back ===\n");
		printf("=== Server listening IN6ADDR_ANY ===\n");
	}

out_err:

	return err;
}

/**
 * main_server - given the port and the protocol
 * it handles the functionality of the responder
 * @param proto type of protocol
 * @param port the kind of protocol
 *
 * @return the socket id,
 * exits on error.
 */
int main_server(int type, int port)
{
	int serversock = 0, err = 0;
	
	serversock = create_serversocket(type, port);
	if (serversock < 0)
		err = -1;
  
	while(err == 0) {
		if (type == SOCK_STREAM) {
			err = main_server_tcp(serversock);
		} else {
			err = main_server_udp(serversock);
		}
	}

	if (serversock)
		close(serversock);
	return err;
}

 /**
  * Connects to the addresses specified by res
  *
  * @param res list containing the peers addresses
  * @param filename ?
  *
  * @return 0 on error, the sockid on success
  */
 int hip_connect_func(struct addrinfo *res, const char* filename)
 {
	 struct addrinfo *ai, hints;
	 int sock = 0;
	 struct timeval stats_before, stats_after;
	 unsigned long stats_diff_sec, stats_diff_usec;
	 FILE *fp = NULL;

	 HIP_DEBUG("FILENAME IS: %s.\n", filename);

	 if (filename)
		 if ((fp = fopen(filename, "a")) == NULL) {
			 HIP_ERROR("Error opening file\n");
			 goto out_err;
		 }
	 /* connect */

	 for(ai = res; ai != NULL; ai = ai->ai_next) {
		 struct sockaddr_in6 *sin6 =
			 (struct sockaddr_in6 *) ai->ai_addr;
		 struct sockaddr_in *sin =
			 (struct sockaddr_in *) ai->ai_addr;
		 struct sockaddr_in6 localaddr;
		 char addr_str[INET6_ADDRSTRLEN];
		 socklen_t locallen;
		 int e;
		
		 /* Currently only IPv6 socket structures are supported */
		 sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		 if (sock < 0) {
			 sock = 0;
			 printf("socket creation failed\n");
			 goto out_err;
		 }
		 
		 HIP_DEBUG("ai_flags %d\n",ai->ai_flags );
		 HIP_DEBUG("ai_family %d\n",ai->ai_family); 
		 HIP_DEBUG("ai_socktype %d\n",ai->ai_socktype); 
		 HIP_DEBUG("ai_protocol%d\n",ai->ai_protocol); 
		 HIP_DEBUG("ai_addrlen %d\n",ai->ai_addrlen); 
		 HIP_DEBUG("ai_canonname %s\n",ai->ai_canonname); 
		 
		 
		 if (!inet_ntop(AF_INET6, (char *) &sin6->sin6_addr, addr_str,
				sizeof(addr_str))) {
			 if (!inet_ntop(AF_INET, (char *) &sin->sin_addr,
					addr_str, sizeof(addr_str))) {
				 perror("inet_ntop\n");
				 goto out_err;
			 }
		 }
		 
		 locallen = sizeof(localaddr);
		 if (!getsockname(sock,
				  (struct sockaddr *)&localaddr,
				  &locallen))
			 HIP_DEBUG_HIT("local addr", &localaddr.sin6_addr);
		 
		 if (ai->ai_family == AF_INET6)
			 HIP_DEBUG_IN6ADDR("Trying to connect to IPv6", hip_cast_sa_addr(sin6));
		 else
			 HIP_DEBUG_INADDR("Trying to connect to IPv4", hip_cast_sa_addr(sin6));
		 
		 gettimeofday(&stats_before, NULL);
		 e = connect(sock, ai->ai_addr, ai->ai_addrlen);
		 printf("After call conntest.c: connect to %s\n", addr_str);
		 
		 gettimeofday(&stats_after, NULL);
		 stats_diff_sec  = (stats_after.tv_sec - stats_before.tv_sec) * 1000000;
		 stats_diff_usec = stats_after.tv_usec - stats_before.tv_usec;

		 locallen = sizeof(localaddr);
		 printf("connect ret=%d errno=%d\n", e, errno);
		 if (e < 0) {
			 strerror(errno);
			 close(sock);
			 sock = 0;
			 printf("trying next\n");
			 continue; /* Try next address */
		 }

		 printf("connect took %.3f sec\n",
			(stats_diff_sec+stats_diff_usec) / 1000000.0);

		 if (filename)
		   fprintf(fp, "%.3f\n",
			   (stats_diff_sec+stats_diff_usec) / 1000000.0);
		 else
		   printf("connect took %.3f sec\n",
			  (stats_diff_sec+stats_diff_usec) / 1000000.0);
		 break; /* Connect succeeded and data can be sent/received. */
		 
	 }
	 if (sock == 0) {
		 printf("failed to connect\n");
		 goto out_err;
	 }
	
out_err:
	 if (filename && fp)
		 fclose(fp);
	 return sock;
}

/**
 * main_client_gai - it handles the functionality of the client-gai
 * @param proto type of protocol
 * @param socktype the type of socket
 * @param peer_name the peer name
 * @param peer_port_name the prot number
 *
 * @return 1 with success, 0 otherwise.
 */
int main_client_gai(int socktype, char *peer_name, char *peer_port_name, int flags)
{
	struct timeval stats_before, stats_after;
	unsigned long stats_diff_sec, stats_diff_usec;
	char mylovemostdata[IP_MAXPACKET], receiveddata[IP_MAXPACKET];
	int recvnum, sendnum, datalen = 0, port = 0, datasent = 0;
	int datareceived = 0, ch, gai_err, sock = 0;
	struct addrinfo hints, *res = NULL, *ai;
	
	/* lookup host */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = flags;
	/* If peer_name is not specified the destination is looked in the hadb */
	if (!peer_name)
		hints.ai_flags |= AI_KERNEL_LIST;
	hints.ai_family = AF_UNSPEC; /* Legacy API supports only HIT-in-IPv6 */
	hints.ai_socktype = socktype;
	
	gai_err = getaddrinfo(peer_name, peer_port_name, &hints, &res);
	
	if (gai_err < 0) {
		printf("GAI ERROR %d: %s\n", gai_err, gai_strerror(gai_err));
		return(1);
	}

	/* data from stdin to buffer */
	bzero(receiveddata, IP_MAXPACKET);
	bzero(mylovemostdata, IP_MAXPACKET);

	printf("Input some text, press enter and ctrl+d\n");

	/* horrible code */
	while ((ch = fgetc(stdin)) != EOF && (datalen < IP_MAXPACKET)) {
		mylovemostdata[datalen] = (unsigned char) ch;
		datalen++;
	}
	/*
	HIP_HEXDUMP("addr: ", res, sizeof(*res));
        */
        if (res->ai_family == AF_INET)
            {
                struct sockaddr_in * ad;
                ad = (struct sockaddr_in *)res->ai_addr;
                hip_print_lsi("Addr given to connect", &ad->sin_addr);
            }
        if (res->ai_family == AF_INET6)
            {
                struct sockaddr_in6 * ad6;
                ad6 = (struct sockaddr_in6 *)res->ai_addr;
                hip_print_hit("Addr given to connect", &ad6->sin6_addr);
            }

	gettimeofday(&stats_before, NULL);
	/* Connecting... */
	HIP_INFO("!!!! conntest.c Connecting...\n");
	sock = hip_connect_func(res, NULL);
	if (!sock)
		goto out_err;
	HIP_INFO("!!!! conntest.c got sock %d\n", sock);
	gettimeofday(&stats_after, NULL);
	stats_diff_sec  = (stats_after.tv_sec - stats_before.tv_sec) * 1000000;
	stats_diff_usec = stats_after.tv_usec - stats_before.tv_usec;
#if 0
	printf("connect took %.3f sec\n",
	       (stats_diff_sec+stats_diff_usec) / 1000000.0);
#endif

	/* send and receive data */

	while((datasent < datalen) || (datareceived < datalen)) {

		if (datasent < datalen) {
			sendnum = send(sock, mylovemostdata+datasent, datalen-datasent, 0);

			if (sendnum < 0) {
				perror("send");
				printf("FAIL\n");
				goto out_err;
			}
			datasent += sendnum;
		}

		if (datareceived < datalen) {
			recvnum = recv(sock, receiveddata+datareceived, datalen-datareceived, 0);
			if (recvnum <= 0) {
				perror("recv");
				goto out_err;
			}
			datareceived += recvnum;
		}
	}

	printf("=== connection test result: ");
	if (!memcmp(mylovemostdata, receiveddata, IP_MAXPACKET)) {
		printf("OK ===\n");
	} else {
		printf("FAIL ===\n");
		return(1);
	}

out_err:

	if (res)
		freeaddrinfo(res);
	if (sock)
		close(sock);
	return 0;
}

/**
 * main_client_native - it handles the functionality of the client-native
 * @param proto type of protocol
 * @param socktype the type of socket
 * @param peer_name the peer name
 * @param peer_port_name the prot number
 *
 * @return 1 with success, 0 otherwise.
 */
int main_client_native(int socktype, char *peer_name, char *peer_port_name)
{
	struct endpointinfo hints, *epinfo, *res = NULL;
	struct timeval stats_before, stats_after;
	unsigned long stats_diff_sec, stats_diff_usec;
	char mylovemostdata[IP_MAXPACKET];
	char receiveddata[IP_MAXPACKET];
	int recvnum, sendnum;
	int datalen = 0;
	int datasent = 0;
	int datareceived = 0;
	int ch;
	int err = 0;
	int sockfd = -1;
	se_family_t endpoint_family;

	endpoint_family = PF_HIP;

	sockfd = socket(endpoint_family, socktype, 0);
	if (sockfd == -1) {
		HIP_ERROR("creation of socket failed\n");
		err = 1;
		goto out;
	}
	
	/* set up host lookup information  */
	memset(&hints, 0, sizeof(hints));
	hints.ei_socktype = socktype;
	hints.ei_family = endpoint_family;
	/* Use the following flags to use only the kernel list for name resolution
	 * hints.ei_flags = AI_HIP | AI_KERNEL_LIST;
	 */

	/* lookup host */
	err = getendpointinfo(peer_name, peer_port_name, &hints, &res);
	if (err) {
		HIP_ERROR("getaddrinfo failed (%d): %s\n", err, gepi_strerror(err));
		goto out;
	}
	if (!res) {
		HIP_ERROR("NULL result, TODO\n");
		goto out;
	}

	HIP_DEBUG("family=%d value=%d\n", res->ei_family,
		  ntohs(((struct sockaddr_eid *) res->ei_endpoint)->eid_val));

	// data from stdin to buffer
	bzero(receiveddata, IP_MAXPACKET);
	bzero(mylovemostdata, IP_MAXPACKET);

	printf("Input some text, press enter and ctrl+d\n");

	// horrible code
	while ((ch = fgetc(stdin)) != EOF && (datalen < IP_MAXPACKET)) {
		mylovemostdata[datalen] = (unsigned char) ch;
		datalen++;
	}

	gettimeofday(&stats_before, NULL);

	epinfo = res;
	while(epinfo) {
		err = connect(sockfd, (struct sockaddr *) epinfo->ei_endpoint,
			      epinfo->ei_endpointlen);
		if (err) {
			HIP_PERROR("connect");
			goto out;
		}
		epinfo = epinfo->ei_next;
	}

	
	gettimeofday(&stats_after, NULL);
	stats_diff_sec  = (stats_after.tv_sec - stats_before.tv_sec) * 1000000;
	stats_diff_usec = stats_after.tv_usec - stats_before.tv_usec;
  
	HIP_DEBUG("connect took %.10f sec\n",
		  (stats_diff_sec + stats_diff_usec) / 1000000.0);
	
	/* Send the data read from stdin to the server and read the response.
	   The server should echo all the data received back to here. */
	while((datasent < datalen) || (datareceived < datalen)) {
    
		if (datasent < datalen) {
			sendnum = send(sockfd, mylovemostdata + datasent, datalen - datasent, 0);
      
			if (sendnum < 0) {
				HIP_PERROR("send");
				err = 1;
				goto out;
			}
			datasent += sendnum;
		}
    
		if (datareceived < datalen) {
			recvnum = recv(sockfd, receiveddata + datareceived,
				       datalen-datareceived, 0);
			if (recvnum <= 0) {
				HIP_PERROR("recv");
				err = 1;
				goto out;
			}
			datareceived += recvnum;
		}
	}

	if (memcmp(mylovemostdata, receiveddata, IP_MAXPACKET)) {
		HIP_ERROR("Sent and received data did not match\n");
		err = 1;
		goto out;
	}

out:
	if (res)
		free_endpointinfo(res);
	if (sockfd != -1)
		close(sockfd); // discard errors

	HIP_INFO("Result of data transfer: %s.\n", (err ? "FAIL" : "OK"));

	return err;
}

/**
 * main_server_native - it handles the functionality of the client-native
 * @param socktype the type of socket
 * @param port_name the prot number
 *
 * @return 1 with success, 0 otherwise.
 */
int main_server_native(int socktype, char *port_name)
{
	struct endpointinfo hints, *res = NULL;
	struct sockaddr_eid peer_eid;
	char mylovemostdata[IP_MAXPACKET];
	int recvnum, sendnum, serversock = 0, sockfd = 0, err = 0, on = 1;
	int endpoint_family = PF_HIP;
	socklen_t peer_eid_len;
	
	serversock = socket(endpoint_family, socktype, 0);
	if (serversock < 0) {
		HIP_PERROR("socket");
		err = 1;
		goto out;
	}

	setsockopt(serversock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&hints, 0, sizeof(struct endpointinfo));
	hints.ei_family = endpoint_family;
	hints.ei_socktype = socktype;

	HIP_DEBUG("Native server calls getendpointinfo\n");
	
	err = getendpointinfo(NULL, port_name, &hints, &res);
	if (err) {
		HIP_ERROR("Resolving of peer identifiers failed (%d)\n", err);
		goto out;
	}

	HIP_DEBUG("Native server calls bind\n");

	if (bind(serversock, res->ei_endpoint, res->ei_endpointlen) < 0) {
		HIP_PERROR("bind");
		err = 1;
		goto out;
	}
	
	HIP_DEBUG("Native server calls listen\n");

	if (socktype == SOCK_STREAM && listen(serversock, 1) < 0) {
		HIP_PERROR("listen");
		err = 1;
		goto out;
	}

	HIP_DEBUG("Native server waits connection request\n");

	while(1) {
		if (socktype == SOCK_STREAM) {
			sockfd = accept(serversock, (struct sockaddr *) &peer_eid,
					&peer_eid_len);
			if (sockfd < 0) {
				HIP_PERROR("accept failed");
				err = 1;
				goto out;
			}

			while((recvnum = recv(sockfd, mylovemostdata,
					      sizeof(mylovemostdata), 0)) > 0 ) {
				mylovemostdata[recvnum] = '\0';
				printf("%s", mylovemostdata);
				fflush(stdout);
				if (recvnum == 0) {
					break;
				}
	
				/* send reply */
				sendnum = send(sockfd, mylovemostdata, recvnum, 0);
				if (sendnum < 0) {
					HIP_PERROR("send");
					err = 1;
					goto out;
				}
			}
		} else { /* UDP */
			sockfd = serversock;
			while(recvnum = recvfrom(sockfd, mylovemostdata,
						 sizeof(mylovemostdata), 0,
						 (struct sockaddr *)& peer_eid,
						 &peer_eid_len) > 0) {
				mylovemostdata[recvnum] = '\0';
				printf("%s", mylovemostdata);
				fflush(stdout);
				if (recvnum == 0) {
					break;
				}
	
				/* send reply */
				sendnum = sendto(sockfd, mylovemostdata, recvnum, 0,
						 (struct sockaddr *) &peer_eid, peer_eid_len);
				if (sendnum < 0) {
					HIP_PERROR("send");
					err = 1;
					goto out;
				}
			}
		}
	}

out:

	if (res)
		free_endpointinfo(res);

	if (sockfd)
		close(sockfd); // discard errors
	if (serversock)
		close(serversock); // discard errors

	return err;
}
