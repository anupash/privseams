/*
 * The lower level implementation of userspace messaging system. All the
 * messages between userspace and kernel are passed as ioctl calls.
 *
 * Authors:
 * - Janne Lundberg <jlu@tcs.hut.fi>
 * - Miika Komu <miika@iki.fi>
 * - Mika Kousa <mkousa@cc.hut.fi>
 *
 * TODO:
 * - Write the communication mechnism again with netlink? Netlink may not be
 *   suitable for the job (Kristian).
 * - ioctl is depracated in 2.6.x
 * - Asynchronous message should have more strict checks because any userspace
 *   application can send them at will. An evil application might send any
 *   kind of corrupted data.
 *
 * BUGS:
 * - does the kernel halt (on client side) if hipd is not running
 *   (and no LHIs added...) and a HIP connection is tried?
 * - hipd_running counts also hipconf!
 */

#include "ioctl.h"

/**
 * hipd_output_copy - copy data from the userspace to the kernelspace 
 * @data_from_userspace: address of the userspace data
 * @output_msg:          data from the userspace data will be copied here
 *
 * Copy a synchronous/asynchronous message from the userspace to the
 * kernelspace. Some checking is also done on the integrity of
 * the message.
 *
 * Returns: zero on success, or negative error value on failure
 */
int hipd_output_copy(unsigned long data_from_userspace,
		     struct hip_common *output_msg) {
          int err = 0;

	  _HIP_DEBUG("copying msg header\n");

	  /* copy msg header */
	  if (copy_from_user(output_msg,
			     (void *) data_from_userspace,
			     sizeof(struct hip_common)) != 0) {
	    err = -EFAULT;
	    goto out_err;
	  }

	  if (!hip_check_userspace_msg_type(output_msg)) {
		  HIP_ERROR("output msg type invalid (%d)\n",
			    hip_get_msg_type(output_msg));
		  err = -EINVAL;
		  goto out_err;
	  }

	  if (!hip_check_msg_len(output_msg)) {
		  HIP_ERROR("msg size invalid (%d)\n",
			    hip_get_msg_total_len(output_msg));
		  err = -EMSGSIZE;
		  goto out_err;
	  }

	  if (hip_get_msg_contents_len(output_msg) == 0) {
		  HIP_DEBUG("skipping copying of rest\n");
		  goto skip_copy_rest;
	  }

	  _HIP_DEBUG("copying rest hipd msg from us %d bytes\n",
		     hip_get_msg_contents_len(output_msg));

	  /* copy rest of the msg from userspace: the header is copied
	     redundantly because otherwise this just would not work */
	  if (copy_from_user(output_msg,
			     ((void *) data_from_userspace),
			     hip_get_msg_total_len(output_msg)) != 0) {
	    err = -EFAULT;
	    goto out_err;
	  }

 skip_copy_rest:
 out_err:
	  return err;
}

/**
 * hip_ioctl_handle_async_msg - handle an async message from the userspace
 * @data_from_userspace: address of the async message from the userspace
 *
 * The asynchronous message is copied from the userspace to the kernelspace
 * and it is send to the appropiate asynchronous message handler function.
 * 
 * Returns: zero on success, or negative error value on failure
 */
int hip_ioctl_handle_async_msg(unsigned long data_from_userspace)
{
	int err = 0;

	spin_lock(&hipd_async_msg.lock);
	
	/* pass the async msg pointer */
	err = hipd_output_copy(data_from_userspace, hipd_async_msg.msg);
	if (err) {
		HIP_ERROR("out copying failed (%d)\n", err);
		goto out_err;
	}
	
	if (!hip_check_userspace_msg_type(hipd_async_msg.msg) ||
	    !*hipd_async_msg_handlers[hip_get_msg_type(hipd_async_msg.msg) - HIP_USER_BASE_MIN - 1]) {
		HIP_ERROR("msg handler not implemented (%d)\n",
			  hip_get_msg_type(hipd_async_msg.msg));
		err = -ENOSYS;
		goto out_err;
	}
	
	_HIP_DUMP_MSG(hipd_async_msg.msg);

	err = (*hipd_async_msg_handlers[hip_get_msg_type(hipd_async_msg.msg) - HIP_USER_BASE_MIN - 1])(hipd_async_msg.msg);

	if (err) {
		HIP_ERROR("hipd async handler failed\n");
		goto out_err;
	}
	
	_HIP_DEBUG("hipd async message was successful\n");
	
 out_err:
	spin_unlock(&hipd_async_msg.lock);
	return err;
}

/**
 * hip_ioctl - handle HIP ioctl calls
 * @in:   unused, but required by the ioctl interface
 * @file: unused, but required by the ioctl interface
 * @cmd:  the type of the HIP ioctl call (async, sync input, sync output, etc)
 * @arg:  pointer to userspace input or output HIP message
 *
 * This function is a multiplexer for any type of HIP ioctl call. The
 * appropiate subhandler function is determined using @cmd and called
 * with the parameters required for the subhandler function.
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_ioctl(struct inode *in, struct file *file, unsigned int cmd,
	      unsigned long arg)
{
	/*
	 * TODO: special situations like when hipd dies are not handled.
	 * Open() and close() methods should be used for these? Also the
	 * locking mechanism will go berserk if something fails
	 * (err = -EFAULT).
	 */
	int err = 0;

	_HIP_DEBUG("hip_ioctl(): cmd=%u arg=0x%lx/%lu\n", cmd, arg, arg);

	if (_IOC_TYPE(cmd) != HIP_IOC_MAGIC || _IOC_NR(cmd) > HIP_IOC_MAX) {
		err = -ENOTTY;
		goto out;
	}

	if ((_IOC_DIR(cmd) & _IOC_READ) &&
	    !access_ok(VERIFY_WRITE, (void *)arg, _IOC_SIZE(cmd))) {
		err = -EFAULT;
		goto out;
	}

	if ((_IOC_DIR(cmd) & _IOC_WRITE) &&
	    !access_ok(VERIFY_READ, (void *)arg, _IOC_SIZE(cmd))) {
		err = -EFAULT;
		goto out;
	}

	switch(cmd) {
	case HIP_IOCSHIPDASYNCMSG:
		err = hip_ioctl_handle_async_msg(arg);
		if (err) {
			HIP_ERROR("handling of async msg failed\n");
			goto out;
		}
	  break;
	case HIP_IOCSTEST:
		HIP_DEBUG("hip_ioctl: Called HIP ioctl test\n");
		break;

	default:
		HIP_ERROR("hip_ioctl: cmd %d not supported\n", cmd);
		err = -ENOTTY;
		break;
	}

 out:
	HIP_DEBUG("hip_ioctl return(%d)\n", err);

	return err;
}

/**
 * hip_open - handle file open calls on HIP device
 * @inode: unused, but required by the kernel interface
 * @filp:  unused, but required by the kernel interface
 *
 * Returns: zero on success, or negative error value on failure 
 */
int hip_open(struct inode *inode, struct file *filp) {
	_HIP_DEBUG("\n");
	return 0;
}

/**
 * hip_release - handle file close calls on HIP device
 * @inode: unused, but required by the kernel interface
 * @filp:  unused, but required by the kernel interface
 *
 * Returns: zero on success, or negative error value on failure 
 */
int hip_release(struct inode *inode, struct file *filp) {
	_HIP_DEBUG("\n");
	return(0);
}

static struct file_operations hip_fops = 
{
  ioctl:     hip_ioctl,
  open:      hip_open,
  release:   hip_release
};

/**
 * hip_init_ioctl - register HIP device
 *
 * Register HIP device using the kernel interface so that userspace processes
 * can communicate with the kernel module.
 *
 * Returns: zero for success, or negative error value on error
 */
int hip_init_ioctl(void)
{
	int err = 0;

	SET_MODULE_OWNER(&hip_fops);

	err = register_chrdev(HIP_CHAR_MAJOR, HIP_CHAR_NAME, &hip_fops);
	if (err < 0) {
		HIP_ERROR("failed to register char driver\n");
		goto out;
	}

 out:
	return err;
}

/**
 * hip_uninit_ioctl - unregister the HIP device
 *
 * Unregister the HIP device when the HIP module is unloaded
 */
void hip_uninit_ioctl(void)
{
	int err = 0;

	err = unregister_chrdev(HIP_CHAR_MAJOR, HIP_CHAR_NAME);
	if(err < 0) {
		HIP_ERROR("failed to unregister char driver\n");
		goto out;
	}

 out:
	return;
}
