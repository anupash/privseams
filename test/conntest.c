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
	/* the following gives error "structure has no member named 
	   sin6_scope_id'" on gaijin:
	   addr.sin6_scope_id = 0; */
	
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
		printf("Client sends:\n%s", mylovemostdata);
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
 * Creates a socket and connects it a remote socket address. The connection is
 * tried using addresses in the @c peer_ai in the order specified by the linked
 * list of the structure. If a connection is successful, the rest of the
 * addresses are omitted. The socket is bound to the peer HIT, not to the peer
 * IP addresses.
 *
 * @param peer_ai a pointer to peer address info.
 * @param sock    a target buffer where the socket file descriptor is to be
 *                stored.
 * @return        zero on success, negative on failure. Possible error values
 *                are the @c errno values of socket(), connect() and close()
 *                with a minus sign.
 */
int hip_connect_func(struct addrinfo *peer_ai, int *sock)
{
	int err = 0, connect_err = 0;
	unsigned long microseconds = 0;
	struct timeval stats_before, stats_after;
	char ip_str[INET6_ADDRSTRLEN];
	struct addrinfo *ai = NULL;
	struct in_addr *ipv4 = NULL;
	struct in6_addr *ipv6 = NULL;

	/* Reset the global error value since at out_err we set err as
	   -errno. */
	errno = 0;

	/* Set the memory allocated from the stack to zeros. */
	memset(&stats_before, 0, sizeof(stats_before));
	memset(&stats_after, 0, sizeof(stats_after));
	memset(ip_str, 0, sizeof(ip_str));
	
	/* Loop through every address in the address info. */
	for(ai = peer_ai; ai != NULL; ai = ai->ai_next) {
		
		ipv4 = &((struct sockaddr_in *)ai->ai_addr)->sin_addr;
		ipv6 = &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr;

		/* Check the type of address we are connecting to and print
		   information about the address to the user. If address is
		   not supported the move to next address in peer_ai. */
		if (ai->ai_family == AF_INET) {
			inet_ntop(AF_INET, ipv4, ip_str, sizeof(ip_str));
			
			if(IS_LSI32(ipv4->s_addr)) {
				HIP_INFO("Connecting to LSI %s.\n", ip_str);
			} else {
				HIP_INFO("Connecting to IPv4 address %s.\n",
					 ip_str);
			}
		} else if(ai->ai_family == AF_INET6) {
			inet_ntop(AF_INET6, ipv6, ip_str, sizeof(ip_str));
			
			if(ipv6_addr_is_hit(ipv6)){
				HIP_INFO("Connecting to HIT %s.\n", ip_str);
			} else if (IN6_IS_ADDR_V4MAPPED(ipv6)) {
				HIP_INFO("Connecting to IPv6-mapped IPv4 "\
					 "address %s.\n", ip_str);
			} else {
				HIP_INFO("Connecting to IPv6 address %s.\n",
					 ip_str);
			}
		} else {
			HIP_INFO("Trying to connect to a non-inet address "\
				 "family address. Skipping.\n");
			continue;
		}

		/* Get a socket for sending. */
		*sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

		if(*sock < 3) {
			HIP_ERROR("Unable to get a socket for sending.\n");
			err = -errno;
			goto out_err;
		}
		
		gettimeofday(&stats_before, NULL);
		connect_err = connect(*sock, ai->ai_addr, ai->ai_addrlen);
		
		/* If we're unable to connect to the remote address we try next
		   address in peer_ai. We back off if the closing of the socket
		   fails. */
		if(connect_err != 0){
			HIP_ERROR("Unable to connect to the remote address.\n");
			if(close(*sock) != 0) {
				HIP_ERROR("Unable to close a socket.\n");
				err = -errno;
				break;
			}
			*sock = 0;
			err = -errno;
			continue;
		}
	
		gettimeofday(&stats_after, NULL);
		
		microseconds  =
			((stats_after.tv_sec - stats_before.tv_sec) * 1000000)
			+ (stats_after.tv_usec - stats_before.tv_usec);
		
		HIP_INFO("Connecting socket to remote socket address took "\
			 "%.5f seconds.\n", microseconds / 1000000.0 );
		
		if (connect_err != 0) {
			if(close(*sock) != 0) {
				HIP_ERROR("Unable to close a socket.\n");
				err = -errno;
				break;
			}
			*sock = 0;
			/* Try the next address in peer_ai. */
			continue;
		} else {
			/* Connect succeeded and data can be sent/received. */
			break;
		}
	}
		
 out_err:
	return err;
}

/**
 * Does the logic of the "conntest-client-gai" command line utility. 
 *
 * @param socktype  the type of socket (SOCK_STREAM or SOCK_DGRAM)
 * @param peer_name the host name of the peer as read from the command lien
 * @param port_name the port number as a string as read from the command line
 * @param flags     flags that are set to addrinfo flags.
 *
 * @return          zero on success, non-zero otherwise.
 */
int main_client_gai(int socktype, char *peer_name, char *port_name, int flags)
{
	int recvnum = 0, sendnum = 0, datalen = 0, port = 0, bytes_sent = 0;
	int bytes_received = 0, c = 0, sock = 0, err = 0;
	char sendbuffer[IP_MAXPACKET], receivebuffer[IP_MAXPACKET];
	unsigned long microseconds = 0;
	struct addrinfo search_key, *peer_ai = NULL;
	struct timeval stats_before, stats_after;
	
	/* Set the memory allocated from the stack to zeros. */
	memset(&search_key, 0, sizeof(search_key));
	memset(&stats_before, 0, sizeof(stats_before));
	memset(&stats_after, 0, sizeof(stats_after));
	memset(sendbuffer, 0, sizeof(sendbuffer));
	memset(receivebuffer, 0, sizeof(receivebuffer));
	
	/* Fill in the socket address structure to host and service name. */
	search_key.ai_flags = flags;
	/* If peer_name is not specified the destination is looked in the
	   hadb. (?) */
	if (peer_name == NULL)
		search_key.ai_flags |= AI_KERNEL_LIST;

	/* Legacy API supports only HIT-in-IPv6 */
	search_key.ai_family = AF_UNSPEC;
	search_key.ai_socktype = socktype;
	
	/* Get the peer's address info. If we get an error, getaddrinfo
	   returns a negative error value, but does not neccesarily set the
	   global errno accordingly. Also, since getaddrinfo error values
	   overlap negative errno values, we just set the errno as a generic
	   -1000 in an error case.*/
	HIP_IFEL(getaddrinfo(peer_name, port_name, &search_key, &peer_ai),
		 -1000, "Name '%s' or service '%s' is unknown.\n",
		 peer_name, port_name);
	
	HIP_INFO("Please input some text to be sent to '%s'.\n"\
		 "Empty row or \"CTRL+d\" sends data.\n", peer_name);
	
	/* Read user input from the standard input. */
	while((c = getc(stdin)) != EOF && (datalen < IP_MAXPACKET))
	{
		datalen++;
		if((sendbuffer[datalen-1] = c) == '\n'){
			/* First character is a newlinefeed. */
			if(datalen == 1){
				break;
			}
			c = getc(stdin);
			if(c == '\n' || c == EOF){
				break;
			} else {
				ungetc(c, stdin);
			}
		}
	}
	
	if(datalen == 0) {
		HIP_INFO("No input data given.\nRunning plain connection test "\
			 "with no payload data exchange.\n");
	}
	
	/* Get a socket for sending and receiving data. */
	HIP_IFE(err = (hip_connect_func(peer_ai, &sock)), err);

	gettimeofday(&stats_before, NULL);
	
	if(datalen > 0) {
		/* Send and receive data from the socket. */
		while((bytes_sent < datalen) || (bytes_received < datalen)) {
			/* send() returns the number of bytes sent or negative
			   on error. */
			if (bytes_sent < datalen) {
				HIP_IFEL(((sendnum =
					   send(sock, sendbuffer + bytes_sent,
						datalen - bytes_sent, 0)) < 0),
					 err = -errno,
					 "Communication error on send.\n");
				bytes_sent += sendnum;
			}
		
			/* recv() returns the number of bytes sent, negative
			   on error or zero when the peer has performed an
			   orderly shutdown. */
			if (bytes_received < datalen) {
				recvnum = recv(sock,
					       receivebuffer + bytes_received,
					       datalen - bytes_received, 0);
			
				if (recvnum == 0) {
					HIP_INFO("The peer has performed an "\
						 "orderly shutdown.\n");
					goto out_err;
				} else if(recvnum < 0) {
					err = -errno;
					HIP_ERROR("Communication error on "\
						  "receive.\n");
				}
				
				bytes_received += recvnum;
			}
		}
	}

	gettimeofday(&stats_after, NULL);
	
	microseconds  =
		((stats_after.tv_sec - stats_before.tv_sec) * 1000000)
		+ (stats_after.tv_usec - stats_before.tv_usec);
	
	HIP_INFO("Data exchange took %.5f seconds.\n",
		 microseconds / 1000000.0 );

	HIP_INFO("Sent/received %d/%d bytes payload data to/from '%s'.\n",
		 bytes_sent, bytes_received, peer_name);
	
	if (memcmp(sendbuffer, receivebuffer, IP_MAXPACKET) != 0) {
		err = -1001;
	}

 out_err:
	if (peer_ai != NULL) {
		freeaddrinfo(peer_ai);
	}
	if (sock > 0) {
		close(sock);
	}

	return err;
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
