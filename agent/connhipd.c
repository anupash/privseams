/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "connhipd.h"


/******************************************************************************/
/* VARIABLES */
/** This socket is used for communication between agent and HIP daemon. */
int hip_agent_sock = 0;
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
	struct sockaddr_un agent_addr;
	struct hip_common *msg = NULL;
	socklen_t alen;
	pthread_t pt;

	/* Allocate message. */
	HIP_IFE(((msg = hip_msg_alloc()) == NULL), -1);

	/* Create and bind daemon socket. */
	hip_agent_sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (hip_agent_sock < 0)
	{
		HIP_ERROR("Failed to create socket.\n");
		err = -1;
		goto out_err;
	}
	
	bzero(&agent_addr, sizeof(agent_addr));
	agent_addr.sun_family = AF_LOCAL;
	strcpy(agent_addr.sun_path, tmpnam(NULL));
	HIP_IFEL(bind(hip_agent_sock, (struct sockaddr *)&agent_addr,
	         sizeof(agent_addr)), -1, "Bind failed.\n");

	/* Test connection. */
	hip_build_user_hdr(msg, SO_HIP_AGENT_PING, 0);
	bzero(&agent_addr, sizeof(agent_addr));
	agent_addr.sun_family = AF_LOCAL;
	strcpy(agent_addr.sun_path, HIP_AGENTADDR_PATH);
	alen = sizeof(agent_addr);
	n = sendto(hip_agent_sock, msg, sizeof(struct hip_common), 0,
	           (struct sockaddr *)&agent_addr, alen);
	if (n < 0)
	{
		HIP_ERROR("Could not send ping to daemon.\n");
		err = -1;
		goto out_err;
	}
	bzero(&agent_addr, sizeof(agent_addr));
	alen = sizeof(agent_addr);
	n = recvfrom(hip_agent_sock, msg, sizeof(struct hip_common), 0,
	             (struct sockaddr *)&agent_addr, &alen);
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
	if (hip_agent_sock) close(hip_agent_sock);
	if (msg != NULL) HIP_FREE(msg);

	return err;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
*/
int connhipd_handle_msg(struct hip_common *msg, struct sockaddr_un *addr)
{
	/* Variables. */
	struct hip_tlv_common *param = NULL;
	hip_hdr_type_t type;
	HIT_Item hit;
	socklen_t alen;
	struct in6_addr *lhit;
	int err = 0, ret, n;
	char chit[128];

	type = hip_get_msg_type(msg);
	HIP_DEBUG("Message received successfully from daemon with type %d.\n", type);

	if (type == SO_HIP_ADD_LOCAL_HI)
	{
		n = 0;

		while((param = hip_get_next_param(msg, param)))
		{
			if (hip_get_param_type(param) == HIP_PARAM_HIT)
			{
				lhit = hip_get_param_contents_direct(param);
				HIP_HEXDUMP("Adding local HIT:", lhit, 16);
				print_hit_to_buffer(chit, lhit);
				gui_add_hit(chit);
				n++;
			}
		}
	}
	else
	{
		strcpy(hit.name, "NewHIT");
		strcpy(hit.url, "<notset>");
		hit.port = 0;
		memcpy(&hit.lhit, &msg->hits, sizeof(struct in6_addr));
		memcpy(&hit.rhit, &msg->hitr, sizeof(struct in6_addr));
		ret = check_hit(&hit);
		
		if (ret == 0)
		{
			HIP_DEBUG("Message accepted, sending back to daemon.\n");

			alen = sizeof(addr);
			n = sendto(hip_agent_sock, msg,
			           hip_get_msg_total_len(msg), 0,
			           (struct sockaddr *)&addr, alen);
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

			alen = sizeof(addr);
			n = sendto(hip_agent_sock, "no", 2, 0,
			           (struct sockaddr *)&addr, alen);
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
	return (err);
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
	struct sockaddr_un agent_addr;
	struct hip_common *msg = (struct hip_common *)data;
	socklen_t alen;

	/* Start handling. */
	hip_agent_thread_started = 1;
	while (agent_exec())
	{
		HIP_DEBUG("Waiting msg...\n");

		bzero(&agent_addr, sizeof(agent_addr));
		alen = sizeof(agent_addr);
		n = recvfrom(hip_agent_sock, msg, sizeof(struct hip_common), MSG_PEEK,
		             (struct sockaddr *)&agent_addr, &alen);
		if (n < 0)
		{
			HIP_ERROR("Error receiving message header from daemon.\n");
			err = -1;
			goto out_err;
		}

		HIP_DEBUG("Header received successfully\n");
		alen = sizeof(agent_addr);
		len = hip_get_msg_total_len(msg);

		HIP_DEBUG("Receiving message (%d bytes)\n", len);
		n = recvfrom(hip_agent_sock, msg, len, 0,
		             (struct sockaddr *)&agent_addr, &alen);

		if (n < 0)
		{
			HIP_ERROR("Error receiving message parameters from daemon.\n");
			err = -1;
			goto out_err;
		}

		HIP_ASSERT(n == len);
		
		connhipd_handle_msg(msg, &agent_addr);
	}


out_err:
	/* Send quit message to daemon. */
	hip_build_user_hdr(msg, SO_HIP_AGENT_QUIT, 0);
	bzero(&agent_addr, sizeof(agent_addr));
	agent_addr.sun_family = AF_LOCAL;
	strcpy(agent_addr.sun_path, HIP_AGENTADDR_PATH);
	alen = sizeof(agent_addr);
	n = sendto(hip_agent_sock, msg, sizeof(struct hip_common), 0,
	           (struct sockaddr *)&agent_addr, alen);
	if (n < 0) HIP_ERROR("Could not send quit message to daemon.\n");
	
	if (hip_agent_sock) close(hip_agent_sock);
	if (msg != NULL) HIP_FREE(msg);

	hip_agent_thread_started = 0;
	agent_exit();
	
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Quits connection thread. Function agent_exit() should be called before
	calling this.
*/
void connhipd_quit(void)
{
	/* Wait connection thread to exit. */
	//while (hip_agent_thread_started);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

