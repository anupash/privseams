/*
    HIP Agent
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */
#include <fcntl.h>

#include "hip.h"
#include "linux/netlink.h"
#include "linux/rtnetlink.h"
#include "workqueue.h"


/******************************************************************************/
/* VARIABLES */
struct hip_nl_handle nl_khipd;


/******************************************************************************/
/**
	main().
*/
int main(int argc, char *argv[])
{
	/* Variables. */
	fd_set read_fdset;
	int err = 0;
	int highest_descriptor;

	/* Initialize database. */
	if (hit_db_init() < 0) goto out_err;

	struct hip_work_order ping;

	/*
		Send a NETLINK ping so that we can communicate the pid of
		the agent and we know that netlink works.
	*/

	/* We may need a separate NETLINK_HIP_AGENT ?!? */
	HIP_IFEL((hip_netlink_open(&nl_khipd, 0, NETLINK_HIP) < 0), -1,
	         "Netlink address and IF events socket error: %s\n");

	/* Ping kernel and announce our PID. */
	HIP_INIT_WORK_ORDER_HDR(ping.hdr, HIP_WO_TYPE_OUTGOING,
	                        HIP_WO_SUBTYPE_AGENT_PID, NULL, NULL, NULL,
	                        getpid(), 0, 0);
	ping.msg = hip_msg_alloc();
	if (hip_netlink_talk(&nl_khipd, &ping, &ping))
	{
		HIP_ERROR("Unable to connect to the kernel HIP daemon over netlink.\n");
		goto out;
	}
	
	/* Add a similar select loop as in hipd.c */

	/* Enter to the select-loop */
	for (;;)
	{
		struct hip_work_order *hwo;
		
		/* prepare file descriptor sets */
		FD_ZERO(&read_fdset);
		FD_SET(nl_khipd.fd, &read_fdset);
		FD_SET(nl_ifaddr.fd, &read_fdset);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		
		_HIP_DEBUG("select\n");

		/* wait for socket activity */
#ifndef CONFIG_HIP_HI3
		err = select((highest_descriptor + 1), &read_fdset, 
		             NULL, NULL, &timeout);
		if (err < 0)
		{
#else
		err = cl_select((highest_descriptor + 1), &read_fdset, 
		                NULL, NULL, &timeout);
        if (err < 0)
		{
				
#endif
			HIP_INFO("select() error: %s.\n", strerror(errno));
		}
		else if (err == 0)
		{ 
				/* idle cycle - select() timeout */               
		}
		else if (FD_ISSET(nl_khipd.fd, &read_fdset))
		{
			/*
				Something on kernel daemon netlink socket,
				fetch it to the queue.
			*/
/*			hip_netlink_receive(&nl_khipd,
					    hip_netlink_receive_workorder,
					    NULL);*/
		}
		else if (FD_ISSET(nl_ifaddr.fd, &read_fdset))
		{
			/*
				Something on IF and address event netlink socket,
				fetch it.
			*/
			hip_netlink_receive(&nl_ifaddr, hip_netdev_event, NULL);
		}
		else
		{
			HIP_INFO("Unknown socket activity.");
		}
			
		while (hwo = hip_get_work_order())
		{
			HIP_DEBUG("Processing work order\n");
			hip_do_work(hwo);
		}
		
	}
	
	/*
		handle messages in the loop and if packets are ok, send them
		back using netlink messages to the hipd.
	*/
	
	/* Return OK. */
	return (0);
	
	/* Return failure. */
out_err:
	hip_msg_free(ping.msg);

	return (-1);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

