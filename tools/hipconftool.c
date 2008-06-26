/** @file
 * This file defines a command line tool for configuring the the Host Identity
 * Protocol daemon (hipd).
 *
 * @author  Janne Lundberg <jlu_tcs.hut.fi>
 * @author  Miika Komu <miika_iki.fi>
 * @author  Mika Kousa <mkousa_cc.hut.fi>
 * @author  Anthony D. Joseph <adj_hiit.fi>
 * @author  Abhinav Pathak <abhinav.pathak_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @author  Anu Markkola
 * @author  Lauri Silvennoinen
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>
 * @todo    add/del map
 * @todo    fix the rst kludges
 * @todo    read the output message from send_msg?
 * @bug     makefile compiles prefix of debug messages wrong for hipconf in 
 *          "make all"
 */
#include "hipconftool.h"
#include "ife.h"


/**
 * Parses command line arguments and send the appropiate message to hipd
 *
 * @param argc   the number of elements in the array.
 * @param argv   an array of pointers to the command line arguments after
 *               the action and type.
 * @return       zero on success, or negative error value on error.
 */
#ifndef HIP_UNITTEST_MODE /* Unit testing code does not compile with main */

/**
 * Does something?
 *
 * @param  socket         a file descriptor.
 * @param  encap_hdr_size ?
 * @return Number of bytes received on success or a negative error value on
 *         error.
 */ 
int hip_peek_total_len(int socket, int encap_hdr_size)
{
	int bytes = 0, err = 0;
	
	int hdr_size = encap_hdr_size + sizeof(struct hip_common);
	
	char *msg = NULL;
	
	hip_common_t *hip_hdr = NULL;
	
    /* We're using system call here add thus reseting errno. */
	errno = 0;
	
	msg = (char *)malloc(hdr_size);
	
	if(msg == NULL) {
		HIP_ERROR("Error allocating memory.\n");
		err = -ENOMEM;
		goto out_err;
	}
	

	bytes = recvfrom(socket, msg, hdr_size, MSG_PEEK, NULL, NULL);
	
	if(bytes != hdr_size) {
		err = bytes;
		goto out_err;
	}

	hip_hdr = (struct hip_common *) (msg + encap_hdr_size);
	bytes = hip_get_msg_total_len(hip_hdr);
	
	if(bytes == 0) {
		err = -EBADMSG;
		errno = EBADMSG;
		HIP_ERROR("HIP message is of zero length.\n");
		goto out_err;
	} else if(bytes > HIP_MAX_PACKET) {
		err = -EMSGSIZE;
		errno = EMSGSIZE;
		HIP_ERROR("HIP message max length exceeded.\n");
		goto out_err;
	}

	bytes += encap_hdr_size;
	
 out_err:
	if (msg != NULL) {
		free(msg);
	}
	if (err != 0) {
		return err;
	}

	return bytes;
}


int 
callback_sendto_hipd(int * sock, void *msg, size_t len)
{
	struct sockaddr_in6 sock_addr;
	int n, alen;
	
	bzero(&sock_addr, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = htons(970);
	sock_addr.sin6_addr = in6addr_loopback;
    
	alen = sizeof(sock_addr);
	
	int hip_user_sock = 0, err = 0;
	
	struct sockaddr_in6 addr;

	*sock = socket(AF_INET6, SOCK_DGRAM, 0);

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_loopback;
	addr.sin6_port = htons(1023);
	 
	err = bind(*sock,(struct sockaddr *)&addr,
			   sizeof(struct sockaddr_in6));
	
	n = sendto(*sock, msg, len, 0,
		   (struct sockaddr *)&sock_addr, alen);
	
	if (n < len) {
		HIP_DEBUG("Could not send message to daemon.\n");
		goto out_err;
	} else {
		HIP_DEBUG("Message of size %d was sent\n", n);
	}
	
 out_err:

	return err;
}

int 
callback_recvfrom_hipd(int sock, void *msg, size_t len) {
	int err = 0;
	if((len = hip_peek_total_len(sock, 0)) < 0) {
		err = len;
		goto out_err;
	}
	
	int n = recvfrom(socket, msg, len, MSG_WAITALL, NULL, NULL);
out_err:
	return n;
}


int main(int argc, char *argv[]) {

	int err = 0;
	
	const char *cfile = "default";
	
	/* we don't want log messages via syslog */
	(LOGTYPE_STDERR);
	hip_set_logfmt(LOGFMT_SHORT);
	HIP_IFEL(hip_set_auto_logdebug(cfile), -1,
	  "Error: Cannot set the debugging parameter.\n");

	
	HIP_IFEL(hip_do_hipconf(argc, argv, 1, 
							&callback_sendto_hipd,
							&callback_recvfrom_hipd), -2,
	  "Error: Cannot configure hip daemon.\n");

 out_err:
	return err;

}

#endif /* HIP_UNITTEST_MODE */
