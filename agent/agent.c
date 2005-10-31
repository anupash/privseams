/*
    HIP Agent
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */
#include "agent.h"


/******************************************************************************/
/* VARIABLES */
int hip_user_sock = 0;


/******************************************************************************/
/**
	main().
*/
int main(int argc, char *argv[])
{
	/* Variables. */
	int err = 0, n, len;
	struct sockaddr_un user_addr;
	struct hip_common *msg = NULL;
	socklen_t alen;

	/* Initialize database. */
//	HIP_IFE(hit_db_init(), -1);
	
	/* Allocate message. */
	HIP_IFE(((msg = hip_msg_alloc()) == NULL), -1);

	/* Create and bind daemon socket. */
	hip_user_sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (hip_user_sock < 0)
	{
		HIP_ERROR("Failed to create socket.\n");
		err = -1;
		goto out_err;
	}
	
	bzero(&user_addr, sizeof(user_addr));
	user_addr.sun_family = AF_LOCAL;
	strcpy(user_addr.sun_path, tmpnam(NULL));
	HIP_IFEL(bind(hip_user_sock, (struct sockaddr *)&user_addr,
		      sizeof(user_addr)),
		 -1, "Bind failed.\n");

	/* Test connection. */
	hip_build_user_hdr(msg, SO_HIP_DAEMON_PING, 0);
	bzero(&user_addr, sizeof(user_addr));
	user_addr.sun_family = AF_LOCAL;
	strcpy(user_addr.sun_path, HIP_DAEMONADDR_PATH);
	alen = sizeof(user_addr);
	n = sendto(hip_user_sock, msg, sizeof(struct hip_common), 0,
		   (struct sockaddr *)&user_addr, alen);
	if (n < 0)
	{
		HIP_ERROR("Could not send ping to daemon.\n");
		err = -1;
		goto out_err;
	}
	bzero(&user_addr, sizeof(user_addr));
	alen = sizeof(user_addr);
	n = recvfrom(hip_user_sock, msg, sizeof(struct hip_common), 0,
		     (struct sockaddr *)&user_addr, &alen);
	if (n < 0)
	{
		HIP_ERROR("Did not receive ping reply from daemon.\n");
		err = -1;
		goto out_err;
	}
	
	HIP_DEBUG("Received %d bytes of ping reply message from daemon.\n", n);

	/* Start handling. */
	for (;;)
	{
		HIP_DEBUG("Receiving msg\n");

		bzero(&user_addr, sizeof(user_addr));
		alen = sizeof(user_addr);
		n = recvfrom(hip_user_sock, msg, sizeof(struct hip_common),
			     MSG_PEEK,
			     (struct sockaddr *)&user_addr, &alen);
		if (n < 0)
		{
			HIP_ERROR("Error receiving message header from daemon.\n");
			err = -1;
			goto out_err;
		}

		HIP_DEBUG("Header received successfully\n");
		alen = sizeof(user_addr);
		len = hip_get_msg_total_len(msg);

		HIP_DEBUG("Receiving message (%d bytes)\n", len);
		n = recvfrom(hip_user_sock, msg, len, 0,
			     (struct sockaddr *)&user_addr, &alen);

		if (n < 0)
		{
			HIP_ERROR("Error receiving message parameters from daemon.\n");
			err = -1;
			goto out_err;
		}

		HIP_ASSERT(n == len);
		HIP_DEBUG("Whole message received successfully\n");

		/* TODO XX: Modify message and check message type. */
		HIP_DEBUG("Message modified, sending back to daemon.\n");

		alen = sizeof(user_addr);
		n = sendto(hip_user_sock, msg, sizeof(struct hip_common), 0,
			   (struct sockaddr *)&user_addr, alen);
		if (n < 0)
		{
			HIP_ERROR("Could not send message back to daemon.\n");
			err = -1;
			goto out_err;
		}		

		HIP_DEBUG("Reply sent successfully\n");
	}

 out_err:
	if (hip_user_sock) close(hip_user_sock);
	if (msg != NULL) HIP_FREE(msg);

	return err;

}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

