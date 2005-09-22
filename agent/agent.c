int main(int argc, char *argv[])
{
	int err = 0;
	struct hip_work_order ping;

	/* Send a NETLINK ping so that we can communicate the pid of the agent
	   and we know that netlink works. */

	/* we may need a separate NETLINK_HIP_AGENT ?!? */
	HIP_IFEL((hip_netlink_open(&nl_khipd, 0, NETLINK_HIP) < 0), -1,
		 "Netlink address and IF events socket error: %s\n");

        /* Ping kernel and announce our PID */
        HIP_INIT_WORK_ORDER_HDR(ping.hdr, HIP_WO_TYPE_OUTGOING,
                                HIP_WO_SUBTYPE_AGENT_PID, NULL, NULL, NULL,
                                getpid(), 0, 0);
        ping.msg = hip_msg_alloc();
        if (hip_netlink_talk(&nl_khipd, &ping, &ping)) {
                HIP_ERROR("Unable to connect to the kernel HIP daemon over netli
nk.\n");
                ret = 1;
                goto out;
        }

	/* add a similar select loop as in hipd.c */

	/* handle messages in the loop and if packets are ok, send them
	   back using netlink messages to the hipd */

 out_err:
	hip_msg_free(ping.msg);

	return err;
}
