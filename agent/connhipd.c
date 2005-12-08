/*
    HIP Agent
*/

/******************************************************************************/
/* INCLUDES */
#include "connhipd.h"


/******************************************************************************/
/* VARIABLES */
/** This socket is used for communication between agent and HIP daemon. */
int hip_user_sock = 0;
/** This is just for waiting the connection thread to start properly. */
int hip_agent_thread_started = 0;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Initialize connection to hip daemon.

	@return 0 on success, -1 on errors.
*/
int connhipd_init(void)
{
	/* Variables. */
	int err = 0, n, len;
	struct sockaddr_un user_addr;
	struct hip_common *msg = NULL;
	socklen_t alen;
	pthread_t pt;

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
	         sizeof(user_addr)), -1, "Bind failed.\n");

	/* Test connection. */
	hip_build_user_hdr(msg, SO_HIP_AGENT_PING, 0);
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
	
	/* Start thread for connection handling. */
	HIP_DEBUG("Received %d bytes of ping reply message from daemon.\n"
	          "Starting thread for HIP daemon connection handling\n", n);

	pthread_create(&pt, NULL, connhipd_thread, msg);

	hip_agent_thread_started = 0;
	while (hip_agent_thread_started == 0) usleep(100 * 1000);
	usleep(100 * 1000);

	return (0);

out_err:
	if (hip_user_sock) close(hip_user_sock);
	if (msg != NULL) HIP_FREE(msg);

	return err;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	This thread keeps the HIP daemon connection alive.
*/
int connhipd_thread(void *data)
{
	/* Variables. */
	int err = 0, n, len, ret;
	struct sockaddr_un user_addr;
	struct hip_common *msg = (struct hip_common *)data;
	socklen_t alen;
	HIT_Item hit;

	/* Start handling. */
	hip_agent_thread_started = 1;
	while (agent_exec())
	{
		HIP_DEBUG("Waiting msg...\n");

		bzero(&user_addr, sizeof(user_addr));
		alen = sizeof(user_addr);
		n = recvfrom(hip_user_sock, msg, sizeof(struct hip_common), MSG_PEEK,
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
		HIP_DEBUG("Whole message received successfully, asking for accept...\n");

		/* TODO XX: Modify message and check message type. */
		strcpy(hit.name, "New HIT");
		strcpy(hit.url, "<not set>");
		hit.port = 0;
		memcpy(&hit.lhit, &msg->hits, sizeof(struct in6_addr));
		memcpy(&hit.rhit, &msg->hitr, sizeof(struct in6_addr));
		ret = gui_check_hit(&hit);
		
		if (ret == 0)
		{
			HIP_DEBUG("Message accepted, sending back to daemon.\n");

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
		else
		{
			HIP_DEBUG("Message rejected, sending reply to daemon.\n");

			alen = sizeof(user_addr);
			n = sendto(hip_user_sock, "no", 2, 0,
			           (struct sockaddr *)&user_addr, alen);
			if (n < 0)
			{
				HIP_ERROR("Could not send reply to daemon.\n");
				err = -1;
				goto out_err;
			}		
	
			HIP_DEBUG("Rejection sent successfully\n");
		}
	}


 out_err:
	if (hip_user_sock) close(hip_user_sock);
	if (msg != NULL) HIP_FREE(msg);
	
	agent_exit();
	
	return err;
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

