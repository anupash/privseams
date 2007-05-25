/** @file
 * This file defines building and parsing functions for Host Identity Protocol
 * (HIP) kernel module and user messages <span style="color:#f00">(Update the
 * comments of this file)</span>.
 * 
 * These functions work both in the userspace and in the kernel.
 * 
 * Keep in mind the following things when using the builder:
 * <ul>
 * <li>Never access members of @c hip_common and @c hip_tlv_common directly. Use
 * the accessor functions to hide byte ordering and length manipulation.</li>
 * <li>Remember always to use <code>__attribute__ ((packed))</code> (see hip.h)
 * with builder because compiler adds padding into the structures.</li>
 * <li>This file is shared between userspace and kernel: do not put any memory
 * allocations or other kernel/userspace specific stuff into here.</li>
 * <li>If you build more functions like build_signature2_contents(), remember
 * to use hip_build_generic_param() in them.</li>
 * </ul>
 * 
 * Usage examples:
 * <ul>
 * <li>sender of "add mapping", i.e. the hip module in kernel</li>
 * <ul>
 * <li>struct hip_common *msg = k/malloc(HIP_MAX_PACKET);</li>
 * <li>hip_msg_init(msg);</li>
 * <li>err = hip_build_user_hdr(msg, SO_HIP_ADD_MAP_HIT_IP, 0);</li>
 * <li>err = hip_build_param_contents(msg, &hit, HIP_PARAM_HIT,
 * sizeof(struct in6_addr));</li>
 * <li>err = hip_build_param_contents(msg, &ip, HIP_PARAM_IPV6_ADDR,
 * sizeof(struct in6_addr));</li>
 * <li>send the message to user space.</li>
 * </ul>
 * <li>receiver of "add mapping", i.e. the daemon</li>
 * <ul>
 * <li>struct hip_common *msg = k/malloc(HIP_MAX_PACKET);</li>
 * <li>receive the message from kernel.</li>
 * <li>if (msg->err) goto_error_handler;</li>
 * <li>hit = (struct in6addr *) hip_get_param_contents(msg, HIP_PARAM_HIT);</li>
 * <li>note: hit can be null, if the param was not found.</li>
 * <li>ip = (struct in6addr *) hip_get_param_object(msg, HIP_PARAM_IPV6ADDR);
 * </li>
 * <li>note: hit can be null.</li>
 * </ul>
 * </ul>
 * @author Miika Komu
 * @author Mika Kousa
 * @author Tobias Heer
 * @note   In network packets @c hip_build_network_hdr() should be used instead
 *         of @c hip_build_user_hdr().
 * @todo Macros for doing @c ntohs() and @c htons() conversion? Currently they are
 * used in a platform dependent way.
 * @todo Why does build network header return void whereas build daemon does
 *       not?
 * @todo There is a small TODO list in @c hip_build_network_hdr()
 * @todo <span style="color:#f00">Update the comments of this file.</span>
 */
#include "builder.h"

/**
 * hip_msg_init - initialize a network/daemon message
 * @param msg the message to be initialized
 *
 * Initialize a message to be sent to the daemon or into the network.
 * Initialization must be done before any parameters are build into
 * the message. Otherwise the writing of the parameters will result in bizarre
 * behaviour.
 *
 */
void hip_msg_init(struct hip_common *msg) {
	/* note: this is used both for daemon and network messages */
	memset(msg, 0, HIP_MAX_PACKET);
}

/**
 * hip_msg_alloc - allocate and initialize a HIP packet
 *
 * Return: initialized HIP packet if successful, NULL on error.
 */
struct hip_common *hip_msg_alloc(void)
{
        struct hip_common *ptr;

	ptr = HIP_MALLOC(HIP_MAX_PACKET, GFP_ATOMIC);
        if (ptr)
		hip_msg_init(ptr);
        return ptr;
}

/**
 * hip_msg_free - deallocate a HIP packet
 * @param msg the packet to be deallocated
 */
void hip_msg_free(struct hip_common *msg)
{
	HIP_FREE(msg);
}

/**
 * hip_convert_msg_total_len_to_bytes - convert message total length to bytes
 * @param len the length of the HIP header as it is in the header
 *       (in host byte order) 
 *
 * @return the real size of HIP header in bytes (host byte order)
 */
uint16_t hip_convert_msg_total_len_to_bytes(hip_hdr_len_t len) {
	return (len == 0) ? 0 : ((len + 1) << 3);
}

/**
 * hip_get_msg_total_len - get the real, total size of the header in bytes
 * @param msg pointer to the beginning of the message header
 *
 * @return the real, total size of the message in bytes (host byte order).
 */
uint16_t hip_get_msg_total_len(const struct hip_common *msg) {
	return hip_convert_msg_total_len_to_bytes(msg->payload_len);
}

/**
 * hip_get_msg_contents_len - get message size excluding type and length
 * @param msg pointer to the beginning of the message header
 *
 * @return the real, total size of the message in bytes (host byte order)
 *          excluding the the length of the type and length fields
 */
uint16_t hip_get_msg_contents_len(const struct hip_common *msg) {
	HIP_ASSERT(hip_get_msg_total_len(msg) >=
		   sizeof(struct hip_common));
	return hip_get_msg_total_len(msg) - sizeof(struct hip_common);
}

/**
 * hip_set_msg_total_len - set the total message length in bytes
 * @param msg pointer to the beginning of the message header
 * @param len the total size of the message in bytes (host byte order)
 */
void hip_set_msg_total_len(struct hip_common *msg, uint16_t len) {
	/* assert len % 8 == 0 ? */
	msg->payload_len = (len < 8) ? 0 : ((len >> 3) - 1);
}

/**
 * hip_get_msg_type - get the type of the message in host byte order
 * @param msg pointer to the beginning of the message header
 *
 * @return the type of the message (in host byte order)
 *
 */
hip_hdr_type_t hip_get_msg_type(const struct hip_common *msg) {
	return msg->type_hdr;
}

/**
 * hip_set_msg_type - set the type of the message
 * @param msg pointer to the beginning of the message header
 * @param type the type of the message (in host byte order)
 *
 */
void hip_set_msg_type(struct hip_common *msg, hip_hdr_type_t type) {
	msg->type_hdr = type;
}

/**
 * hip_get_msg_err - get the error values from daemon message header
 * @param msg pointer to the beginning of the message header
 *
 * @return the error value from the message (in host byte order)
 *
 */
hip_hdr_err_t hip_get_msg_err(const struct hip_common *msg) {
	/* Note: error value is stored in checksum field for daemon messages.
	   This should be fixed later on by defining an own header for
	   daemon messages. This function should then input void* as
	   the message argument and cast it to the daemon message header
	   structure. */
	return msg->checksum; /* 1 byte, no ntohs() */
}

/**
 * hip_set_msg_err - set the error value of the daemon message
 * @param msg pointer to the beginning of the message header
 * @param err the error value
 */
void hip_set_msg_err(struct hip_common *msg, hip_hdr_err_t err) {
	/* note: error value is stored in checksum field for daemon messages */
	msg->checksum = err;
}

uint16_t hip_get_msg_checksum(struct hip_common *msg) {
	return msg->checksum; /* one byte, no ntohs() */
}

/**
 * hip_zero_msg_checksum - zero message checksum
 */
void hip_zero_msg_checksum(struct hip_common *msg) {
	msg->checksum = 0; /* one byte, no ntohs() */
}

void hip_set_msg_checksum(struct hip_common *msg, u8 checksum) {
	msg->checksum = checksum; /* one byte, no ntohs() */
}

/**
 * hip_get_param_total_len - get total size of message parameter
 * @param tlv_common pointer to the parameter
 *
 * @return the total length of the parameter in bytes (host byte
 * order), including the padding.
 */
hip_tlv_len_t hip_get_param_total_len(const void *tlv_common) {
	return HIP_LEN_PAD(sizeof(struct hip_tlv_common) +
			   ntohs(((const struct hip_tlv_common *)
				  tlv_common)->length));
}

/**
 * hip_get_param_contents_len - get the size of the parameter contents
 * @param tlv_common pointer to the parameter
 *
 * @return the length of the parameter in bytes (in host byte order),
 *          excluding padding and the length of "type" and "length" fields
 */
hip_tlv_len_t hip_get_param_contents_len(const void *tlv_common) {
	return ntohs(((const struct hip_tlv_common *)tlv_common)->length);
}

/**
 * hip_set_param_contents_len - set parameter length
 * @param tlv_common pointer to the parameter
 * @param len the length of the parameter in bytes (in host byte order),
 *              excluding padding and the length of "type" and "length" fields
 */
void hip_set_param_contents_len(void *tlv_common,
				hip_tlv_len_t len) {
	((struct hip_tlv_common *)tlv_common)->length = htons(len);
}

/**
 * hip_get_param_type - get type of parameter
 * @param tlv_common pointer to the parameter
 *
 * @return The type of the parameter (in host byte order).
 */
hip_tlv_type_t hip_get_param_type(const void *tlv_common) {
	return ntohs(((const struct hip_tlv_common *)tlv_common)->type);
}

/**
 * hip_set_param_type - set parameter type
 * @param tlv_common pointer to the parameter
 * @param type type of the parameter (in host byte order)
 */
void hip_set_param_type(void *tlv_common, hip_tlv_type_t type) {
	((struct hip_tlv_common *)tlv_common)->type = htons(type);
}

/**
 * hip_get_diffie_hellman_param_public_value_contents - get dh public value contents
 * @param tlv_common pointer to the dh parameter
 *
 * @return pointer to the public value of Diffie-Hellman parameter
 */
void *hip_get_diffie_hellman_param_public_value_contents(const void *tlv_common) {
	return (void *) tlv_common + sizeof(struct hip_diffie_hellman);
}

/**
 * hip_get_diffie_hellman_param_public_value_len - get dh public value real length
 * @param dh pointer to the Diffie-Hellman parameter
 *
 * @return the length of the public value Diffie-Hellman parameter in bytes
 *          (in host byte order).
 */
hip_tlv_len_t hip_get_diffie_hellman_param_public_value_len(const struct hip_diffie_hellman *dh)
{
	return hip_get_param_contents_len(dh) - sizeof(uint8_t) - sizeof(uint16_t);
}


#if 0
/**
 * hip_set_param_spi_value - set the spi value in spi_lsi parameter
 * @param spi_lsi the spi_lsi parameter
 * @param spi the value of the spi in the spi_lsi value in host byte order
 *
 */
void hip_set_param_spi_value(struct hip_esp_info *esp_info, uint32_t spi)
{
	esp_info->spi = htonl(spi);
}

/**
 * hip_get_param_spi_value - get the spi value from spi_lsi parameter
 * @param spi_lsi the spi_lsi parameter
 *
 * @return the spi value in host byte order
 */
uint32_t hip_get_param_spi_value(const struct hip_esp_info *esp_info)
{
	return ntohl(esp_info->spi);
}
#endif

/**
 * hip_get_unit_test_suite_param_id - get suite id from unit test parameter
 * @param test pointer to the unit test parameter
 *
 * @return the id of the test suite (in host byte order) of the unit test
 *          parameter
 */
uint16_t hip_get_unit_test_suite_param_id(const struct hip_unit_test *test)
{
	return ntohs(test->suiteid);
}

/**
 * hip_get_unit_test_case_param_id - get test case id from unit test parameter
 * @param test pointer to the unit test parameter
 *
 * @return the id of the test case (in host byte order) of the unit test
 *          parameter
 */
uint16_t hip_get_unit_test_case_param_id(const struct hip_unit_test *test)
{
	return ntohs(test->caseid);
}

uint8_t hip_get_host_id_algo(const struct hip_host_id *host_id) {
	return host_id->rdata.algorithm; /* 8 bits, no ntons() */
}

struct hip_locator_info_addr_item *hip_get_locator_first_addr_item(struct hip_locator *locator) {
	return (struct hip_locator_info_addr_item *) (locator + 1);
}

int hip_get_locator_addr_item_count(struct hip_locator *locator) {
	return (hip_get_param_contents_len(locator) -
		(sizeof(struct hip_locator) -
		 sizeof(struct hip_tlv_common))) /
		sizeof(struct hip_locator_info_addr_item);
}

/**
 * hip_check_msg_len - check validity of message length
 * @param msg pointer to the message
 *
 * @return 1 if the message length is valid, or 0 if the message length is
 *          invalid
 */
int hip_check_msg_len(const struct hip_common *msg) {
	uint16_t len;

	HIP_ASSERT(msg);
	len = hip_get_msg_total_len(msg);

	if (len < sizeof(struct hip_common) || len > HIP_MAX_PACKET) {
		return 0;
	} else {
		return 1;
	}
}

/**
 * hip_check_network_msg_type - check the type of the network message
 * @param msg pointer to the message
 *
 * @return 1 if the message type is valid, or 0 if the message type is
 *          invalid
 */
int hip_check_network_msg_type(const struct hip_common *msg) {
	int ok = 0;
	hip_hdr_type_t supported[] =
		{
			HIP_I1,
			HIP_R1,
			HIP_I2,
			HIP_R2,
			HIP_UPDATE,
			HIP_NOTIFY,
			HIP_BOS,
			HIP_CLOSE,
			HIP_CLOSE_ACK
		};
	hip_hdr_type_t i;
	hip_hdr_type_t type = hip_get_msg_type(msg);

	for (i = 0; i < sizeof(supported) / sizeof(hip_hdr_type_t); i++) {
		if (type == supported[i]) {
			ok = 1;
			break;
		}
	}

	return ok;
}

/**
 * hip_check_userspace_param_type - check the userspace parameter type
 * @param param pointer to the parameter
 *
 * @return 1 if parameter type is valid, or 0 if parameter type is invalid
 */
int hip_check_userspace_param_type(const struct hip_tlv_common *param)
{
	return 1;
}

/**
 * Checks the network parameter type.
 * 
 * Optional parameters are not checked, because the code just does not
 * use them if they are not supported.
 *
 * @param param the network parameter
 * @return 1 if parameter type is valid, or 0 if parameter type
 * is not valid. "Valid" means all optional and non-optional parameters
 * in the HIP draft.
 * @todo Clarify the functionality and explanation of this function. Should
 *       new parameters be added to the checked parameters list as they are
 *       introduced in extensions drafts (RVS, NAT, Registration...), or should
 *       here only be the parameters listed in Sections 5.2.3 through Section
 *       5.2.18 of the draft-ietf-hip-base-06?
 */
int hip_check_network_param_type(const struct hip_tlv_common *param)
{
	int ok = 0;
	hip_tlv_type_t i;
	hip_tlv_type_t valid[] =
		{
			HIP_PARAM_ACK,
			HIP_PARAM_BLIND_NONCE,
                        HIP_PARAM_CERT,
                        HIP_PARAM_DIFFIE_HELLMAN,
                        HIP_PARAM_ECHO_REQUEST,
                        HIP_PARAM_ECHO_REQUEST_SIGN,
                        HIP_PARAM_ECHO_RESPONSE,
                        HIP_PARAM_ECHO_RESPONSE_SIGN,
                        HIP_PARAM_ENCRYPTED,
                        HIP_PARAM_ESP_INFO,
                        HIP_PARAM_ESP_INFO,
                        HIP_PARAM_ESP_TRANSFORM,
                        HIP_PARAM_FROM,
			HIP_PARAM_FROM_NAT,
                        HIP_PARAM_HIP_SIGNATURE,
                        HIP_PARAM_HIP_SIGNATURE2,
                        HIP_PARAM_HIP_TRANSFORM,
                        HIP_PARAM_HMAC,
                        HIP_PARAM_HMAC,
                        HIP_PARAM_HMAC2,
			HIP_PARAM_RVS_HMAC,
                        HIP_PARAM_HOST_ID,
                        HIP_PARAM_LOCATOR,
                        HIP_PARAM_NOTIFICATION,
                        HIP_PARAM_PUZZLE,
                        HIP_PARAM_R1_COUNTER,
                        HIP_PARAM_REG_FAILED,
                        HIP_PARAM_REG_INFO,
                        HIP_PARAM_REG_REQUEST,
                        HIP_PARAM_REG_RESPONSE,
                        HIP_PARAM_SEQ,
                        HIP_PARAM_SOLUTION,
                        HIP_PARAM_VIA_RVS,
			HIP_PARAM_VIA_RVS_NAT
		};
	hip_tlv_type_t type = hip_get_param_type(param);

	/** @todo check the lengths of the parameters */

	for (i = 0; i < ARRAY_SIZE(valid); i++) {
		if (type == valid[i]) {
			ok = 1;
			break;
		}
	}

	return ok;
}

/**
 * Checks the validity of parameter contents length.
 * 
 * The msg is passed also in to check to the parameter will not cause buffer
 * overflows.
 * 
 * @param msg   a pointer to the beginning of the message
 * @param param a pointer to the parameter to be checked for contents length
 * @return      1 if the length of the parameter contents length was valid
 *              (the length was not too small or too large to fit into the
 *              message). Zero is returned on invalid contents length.
 */
int hip_check_param_contents_len(const struct hip_common *msg,
				 const struct hip_tlv_common *param) {
	int ok = 0;
	int param_len = hip_get_param_total_len(param);
	void *pos = (void *) param;

	/* Note: the lower limit is not checked, because there really is no
	   lower limit. */

	if (pos == ((void *)msg)) {
		HIP_ERROR("use hip_check_msg_len()\n");
	} else if (pos + param_len > ((void *) msg) + HIP_MAX_PACKET) {
		_HIP_DEBUG("param far too long (%d)\n", param_len);
	} else if (param_len > hip_get_msg_total_len(msg)) {
		_HIP_DEBUG("param too long (%d)\n", param_len);
	} else {
		_HIP_DEBUG("param ok\n");
		ok = 1;
	}
	return ok;
}

/**
 * Iterates to the next parameter.
 * 
 * @param msg           a pointer to the beginning of the message header
 * @param current_param a pointer to the current parameter, or NULL if the msg
 *                      is to be searched from the beginning.
 * @return              the next parameter after the current_param in msg, or
 *                      NULL if no parameters were found.
 */
struct hip_tlv_common *hip_get_next_param(const struct hip_common *msg,
					  const struct hip_tlv_common *current_param)
{
	struct hip_tlv_common *next_param = NULL;
	void *pos = (void *) current_param;

	if (!msg) {
		HIP_ERROR("msg null\n");
		goto out;
	}

	if (current_param == NULL) {
		pos = (void *) msg;
	}

	if (pos == msg)
		pos += sizeof(struct hip_common);
	else
		pos += hip_get_param_total_len(current_param);

	next_param = (struct hip_tlv_common *) pos;

	/* check that the next parameter does not point
	   a) outside of the message
	   b) out of the buffer with check_param_contents_len()
	   c) to an empty slot in the message */
	if (((char *) next_param) - ((char *) msg) >=
	    hip_get_msg_total_len(msg) || /* a */
	    !hip_check_param_contents_len(msg, next_param) || /* b */
	    hip_get_param_contents_len(next_param) == 0) {    /* c */
		_HIP_DEBUG("no more parameters found\n");
		next_param = NULL;
	} else {
		/* next parameter successfully found  */
		_HIP_DEBUG("next param: type=%d, len=%d\n",
			  hip_get_param_type(next_param),
			  hip_get_param_contents_len(next_param));
	}

 out:
	return next_param;


}

/**
 * Gets  the first parameter of the given type.
  *
 * If there are multiple parameters of the same type, one should use
 * hip_get_next_param() after calling this function to iterate through
 * them all.
 
 * @param msg        a pointer to the beginning of the message header.
 * @param param_type the type of the parameter to be searched from msg
 *                   (in host byte order)
 * @return           a pointer to the first parameter of the type param_type,
 *                   or NULL if no parameters of the type param_type were not
 *                   found. 
 */
void *hip_get_param(const struct hip_common *msg,
		    hip_tlv_type_t param_type)
{
	void *matched = NULL;
	struct hip_tlv_common *current_param = NULL;

	_HIP_DEBUG("searching for type %d\n", param_type);

       /** @todo Optimize: stop when next parameter's type is greater than the
	   searched one. */

	while((current_param = hip_get_next_param(msg, current_param))
	      != NULL) {
		_HIP_DEBUG("current param %d\n",
			   hip_get_param_type(current_param));
		if (hip_get_param_type(current_param) == param_type) {
			matched = current_param;
			break;
		}
	}

	return matched;
}

/**
 * hip_get_param_contents - get the first parameter contents of the given type
 * @param msg pointer to the beginning of the message header
 * @param param_type the type of the parameter to be searched from msg
 *              (in host byte order)
 *
 * If there are multiple parameters of the same type, one should use
 * hip_get_next_param after calling this function to iterate through
 * them all.
 *
 * @return a pointer to the contents of the first parameter of the type
 *          param_type, or NULL if no parameters of the type param_type
 *          were not found. 
 */
void *hip_get_param_contents(const struct hip_common *msg,
			     hip_tlv_type_t param_type)
{
	void *contents = hip_get_param(msg,param_type);
	if (contents)
		contents += sizeof(struct hip_tlv_common);
	return contents;
}

/**
 * hip_get_param_contents_direct - get parameter contents direct from TLV
 * @param tlv_common pointer to a parameter
 *
 * @return pointer to the contents of the tlv_common (just after the
 *          the type and length fields)
 */
void *hip_get_param_contents_direct(const void *tlv_common)
{
	return ((void *)tlv_common) + sizeof(struct hip_tlv_common);
}


/* hip_get_nth_param - get nth parameter of given type from the message
 * @param msg pointer to the beginning of the message header
 * @param param_type the type of the parameter to be searched from msg
 *              (in host byte order)
 * @param n index number to be get
 *
 * @return the nth parameter from the message if found, else %NULL.
 */
void *hip_get_nth_param(const struct hip_common *msg,
			hip_tlv_type_t param_type, int n)
{
	struct hip_tlv_common *param = NULL;
	int i = 0;

	if (n < 1) {
		HIP_ERROR("n < 1 (n=%d)\n", n);
		return NULL;
	}

	while((param = hip_get_next_param(msg, param))) {
		if (hip_get_param_type(param) == param_type) {
			i++;
			if (i == n)
				return param;
		}
	}
	return NULL;
}

/**
 * hip_find_free_param - find the first free position in message
 * @param msg pointer to the beginning of the message header
 *
 * This function does not check whether the new parameter to be appended
 * would overflow the msg buffer. It is the responsibilty of the caller
 * to check such circumstances because this function does not know
 * the length of the object to be appended in the message. Still, this
 * function checks the special situation where the buffer is completely
 * full and returns a null value in such a case.
 *
 * @return pointer to the first free (padded) position, or NULL if
 *          the message was completely full
 */
void *hip_find_free_param(const struct hip_common *msg)
{
	/*! \todo this function should return hip_tlv_common ? */
        struct hip_tlv_common *current_param = NULL;
	struct hip_tlv_common *last_used_pos = NULL;
	void *free_pos = NULL;
	void *first_pos = ((void *) msg) + sizeof(struct hip_common);

	/* Check for no parameters: this has to be checked separately because
	   we cannot tell from the return value of get_next_param() whether
	   the message was completely full or there just were no parameters.
	   The length is used for checking the existance of parameter, because
	   type field may be zero (SPI_LSI = 0) and therefore it cannot be
	   used for checking the existance. */
	if (hip_get_param_contents_len((struct hip_tlv_common *) first_pos)
	    == 0) {
		_HIP_DEBUG("no parameters\n");
		free_pos = first_pos;
		goto out;
	}

	while((current_param = hip_get_next_param(msg, current_param))
	      != NULL) {
		last_used_pos = current_param;
		_HIP_DEBUG("not free: type=%d, contents_len=%d\n",
			  hip_get_param_type(current_param),
			  hip_get_param_contents_len(current_param));
	}

	if (last_used_pos == NULL) {
		free_pos = NULL; /* the message was full */
	} else {
		free_pos = ((void *) last_used_pos) +
			hip_get_param_total_len(last_used_pos);
	}

 out:
	return free_pos;
}


/**
 * hip_calc_hdr_len - update messsage header length
 * @param msg pointer to the beginning of the message header
 *
 * This function is called always when a parameter has been added or the
 * daemon/network header was written. This functions writes the new
 * header length directly into the message.
 */
void hip_calc_hdr_len(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	void *pos = (void *) msg;

	/* We cannot call get_next() or get_free() because they need a valid
	   header length which is to be (possibly) calculated now. So, the
	   header length must be calculated manually here. */

	if (hip_get_msg_total_len(msg) == 0) {
		/* msg len is zero when
		   1) calling build_param() for the first time
		   2) calling just the build_hdr() without building
		      any parameters, e.g. in plain error messages */
		_HIP_DEBUG("case 1,2\n");
		hip_set_msg_total_len(msg, sizeof(struct hip_common));
	} else {
		/* 3) do nothing, build_param()+ */
		/* 4) do nothing, build_param()+ and build_hdr() */
		_HIP_DEBUG("case 3,4\n");
	}

	pos += hip_get_msg_total_len(msg);
	param = (struct hip_tlv_common *) pos;
	if (hip_get_param_contents_len(param) != 0) {
		/* Case 1 and 3: a new parameter (with a valid length) has
		   been added and the message length has not been updated. */
		_HIP_DEBUG("case 1,3\n");
		hip_set_msg_total_len(msg, hip_get_msg_total_len(msg) +
				      hip_get_param_total_len(param));
		/* XX assert: new pos must be of type 0 (assume only one
		   header has been added) */
	} else {
		/* case 2 and 4: the message length does not need to be
		   updated */
		_HIP_DEBUG("case 2,4\n");
	}

	_HIP_DEBUG("msg len %d\n", hip_get_msg_total_len(msg));	
}

/**
 * hip_calc_generic_param_len - calculate and write the length of any parameter
 * @param tlv_common pointer to the beginning of the parameter
 * @param tlv_size size of the TLV header  (in host byte order)
 * @param contents_size size of the contents after the TLV header
 *                 (in host byte order)
 *
 * This function can be used for semi-automatic calculation of parameter
 * length field. This function should always be used instead of manual
 * calculation of parameter lengths. The tlv_size is usually just
 * sizeof(struct hip_tlv_common), but it can include other fields than
 * just the type and length. For example, DIFFIE_HELLMAN parameter includes
 * the group field as in hip_build_param_diffie_hellman_contents().
 */
void hip_calc_generic_param_len(void *tlv_common,
			      hip_tlv_len_t tlv_size,
			      hip_tlv_len_t contents_size)
{
	hip_set_param_contents_len(tlv_common,
				   tlv_size + contents_size -
				   sizeof(struct hip_tlv_common));
}

/**
 * hip_calc_param_len - calculate the length of a "normal" TLV structure
 * @param tlv_common pointer to the beginning of the TLV structure
 * @param contents_size size of the contents after type and length fields
 *                 (in host byte order)
 *
 * This function calculates and writes the length of TLV structure field.
 * This function is different from hip_calc_generic_param_len() because
 * it assumes that the length of the header of the TLV is just
 * sizeof(struct hip_tlv_common).
 */
void hip_calc_param_len(void *tlv_common, hip_tlv_len_t contents_size)
{
	hip_calc_generic_param_len(tlv_common, sizeof(struct hip_tlv_common),
				   contents_size);
}

/**
 * hip_dump_msg - dump the message contents using HIP debug interface
 * @param msg the message to be dumped using the HIP debug interface
 *
 * Do not call this function directly, use the HIP_DUMP_MSG macro instead.
 */
void hip_dump_msg(const struct hip_common *msg)
{
	struct hip_tlv_common *current_param = NULL;
	void *contents = NULL;
	/* The value of the "Length"-field in current parameter. */
	hip_tlv_len_t len = 0;
	/* Total length of the parameter (type+length+value+padding), and the
	   length of padding. */
	size_t total_len = 0, pad_len = 0;
	HIP_DEBUG("--------------- MSG START ------------------\n");
	HIP_DEBUG("Msg type : %s (%d)\n",
		  hip_message_type_name(hip_get_msg_type(msg)),
		  hip_get_msg_type(msg));
	HIP_DEBUG("Msg length: %d\n", hip_get_msg_total_len(msg));
	HIP_DEBUG("Msg err  : %d\n", hip_get_msg_err(msg));
	
	while((current_param = hip_get_next_param(msg, current_param))
	      != NULL) {
		len = hip_get_param_contents_len(current_param);
		/* Formula from base draft section 5.2.1. */
		total_len = 11 + len - (len +3) % 8;
		pad_len = total_len - len - sizeof(hip_tlv_type_t)
			- sizeof(hip_tlv_len_t);
		contents = hip_get_param_contents_direct(current_param);
		HIP_DEBUG("Parameter type:%s (%d). Total length: %d (4 type+"\
			  "length, %d content, %d padding).\n",
			  hip_param_type_name(hip_get_param_type(current_param)),
			  hip_get_param_type(current_param),
			  total_len,
			  len,
			  pad_len);
		HIP_HEXDUMP("Contents:", contents, len);
		HIP_HEXDUMP("Padding:", contents + len , pad_len);
	}
	HIP_DEBUG("---------------- MSG END --------------------\n");
}

/**
 * Returns a string for a given parameter type number.
 * 
 * @param msg_type message type number
 * @return         name of the message type
 **/
char* hip_message_type_name(const uint8_t msg_type){
	switch (msg_type) {
	case HIP_I1:        return "HIP_I1";
	case HIP_R1:        return "HIP_R1";
	case HIP_I2:        return "HIP_I2";
	case HIP_R2:        return "HIP_R2";
	case HIP_CER:       return "HIP_CER";
	case HIP_UPDATE:    return "HIP_UPDATE";
	case HIP_NOTIFY:    return "HIP_NOTIFY";
	case HIP_CLOSE:     return "HIP_CLOSE";
	case HIP_CLOSE_ACK: return "HIP_CLOSE_ACK";
	case HIP_BOS:       return "HIP_BOS";
	case HIP_PSIG:      return "HIP_PSIG";
	case HIP_TRIG:      return "HIP_TRIG";
	default:            return "UNDEFINED";
	}
}

/**
 * hip_message_type_name - returns a string for a given parameter type number
 * @param param_type parameter type number
 * @return name of the message type
 **/
char* hip_param_type_name(const hip_tlv_type_t param_type){
	switch (param_type) {
	case HIP_PARAM_ACK: return "HIP_PARAM_ACK";
	case HIP_PARAM_BLIND_NONCE: return "HIP_PARAM_BLIND_NONCE";
	case HIP_PARAM_CERT: return "HIP_PARAM_CERT";
	case HIP_PARAM_DH_SHARED_KEY: return "HIP_PARAM_DH_SHARED_KEY";
	case HIP_PARAM_DIFFIE_HELLMAN: return "HIP_PARAM_DIFFIE_HELLMAN";
	case HIP_PARAM_ECHO_REQUEST: return "HIP_PARAM_ECHO_REQUEST";
	case HIP_PARAM_ECHO_REQUEST_SIGN: return "HIP_PARAM_ECHO_REQUEST_SIGN";
	case HIP_PARAM_ECHO_RESPONSE: return "HIP_PARAM_ECHO_RESPONSE";
	case HIP_PARAM_ECHO_RESPONSE_SIGN: return "HIP_PARAM_ECHO_RESPONSE_SIGN";
	case HIP_PARAM_EID_ADDR: return "HIP_PARAM_EID_ADDR";
	case HIP_PARAM_EID_ENDPOINT: return "HIP_PARAM_EID_ENDPOINT";
	case HIP_PARAM_EID_IFACE: return "HIP_PARAM_EID_IFACE";
	case HIP_PARAM_EID_SOCKADDR: return "HIP_PARAM_EID_SOCKADDR";
	case HIP_PARAM_ENCRYPTED: return "HIP_PARAM_ENCRYPTED";
	case HIP_PARAM_ESP_INFO: return "HIP_PARAM_ESP_INFO";
	case HIP_PARAM_ESP_TRANSFORM: return "HIP_PARAM_ESP_TRANSFORM";
	case HIP_PARAM_FROM: return "HIP_PARAM_FROM";
	case HIP_PARAM_FROM_NAT: return "HIP_PARAM_FROM_NAT";
	case HIP_PARAM_HASH_CHAIN_ANCHORS: return "HIP_PARAM_HASH_CHAIN_ANCHORS";
	case HIP_PARAM_HASH_CHAIN_PSIG: return "HIP_PARAM_HASH_CHAIN_PSIG";
	case HIP_PARAM_HASH_CHAIN_VALUE: return "HIP_PARAM_HASH_CHAIN_VALUE";
	case HIP_PARAM_HIP_SIGNATURE2: return "HIP_PARAM_HIP_SIGNATURE2";
	case HIP_PARAM_HIP_SIGNATURE: return "HIP_PARAM_HIP_SIGNATURE";
	case HIP_PARAM_HIP_TRANSFORM: return "HIP_PARAM_HIP_TRANSFORM";
	case HIP_PARAM_HI: return "HIP_PARAM_HI";
	case HIP_PARAM_HMAC2: return "HIP_PARAM_HMAC2";
	case HIP_PARAM_HMAC: return "HIP_PARAM_HMAC";
	case HIP_PARAM_HOST_ID: return "HIP_PARAM_HOST_ID";
	case HIP_PARAM_IPV6_ADDR: return "HIP_PARAM_HIT";
	case HIP_PARAM_KEYS: return "HIP_PARAM_KEYS";
	case HIP_PARAM_LOCATOR: return "HIP_PARAM_LOCATOR";
	case HIP_PARAM_NOTIFICATION: return "HIP_PARAM_NOTIFICATION";
	case HIP_PARAM_PUZZLE: return "HIP_PARAM_PUZZLE";
	case HIP_PARAM_R1_COUNTER: return "HIP_PARAM_R1_COUNTER";
	case HIP_PARAM_REG_FAILED: return "HIP_PARAM_REG_FAILED";
	case HIP_PARAM_REG_INFO: return "HIP_PARAM_REG_INFO";
	case HIP_PARAM_REG_REQUEST: return "HIP_PARAM_REG_REQUEST";
	case HIP_PARAM_REG_RESPONSE: return "HIP_PARAM_REG_RESPONSE";
	case HIP_PARAM_RVS_HMAC: return "HIP_PARAM_RVS_HMAC";
	case HIP_PARAM_SEQ: return "HIP_PARAM_SEQ";
	case HIP_PARAM_SOLUTION: return "HIP_PARAM_SOLUTION";
	case HIP_PARAM_UINT: return "HIP_PARAM_UINT";
	case HIP_PARAM_UNIT_TEST: return "HIP_PARAM_UNIT_TEST";
	case HIP_PARAM_VIA_RVS: return "HIP_PARAM_VIA_RVS";
	case HIP_PARAM_VIA_RVS_NAT: return "HIP_PARAM_VIA_RVS_NAT";
	}
	return "UNDEFINED";
}

/**
 * hip_check_userspace msg - check userspace message for integrity
 * @param msg the message to be verified for integrity
 *
 * @return zero if the message was ok, or negative error value on error.
 */
int hip_check_userspace_msg(const struct hip_common *msg) {
	struct hip_tlv_common *current_param = NULL;
	int err = 0;

	if (!hip_check_msg_len(msg)) {
		err = -EMSGSIZE;
		HIP_ERROR("bad msg len %d\n", hip_get_msg_total_len(msg));
		goto out;
	}

	while((current_param = hip_get_next_param(msg, current_param))
	      != NULL) {
		if(!hip_check_param_contents_len(msg, current_param)) {
			err = -EMSGSIZE;
			HIP_ERROR("bad param len\n");
			break;
		} else if (!hip_check_userspace_param_type(current_param)) {
			err = -EINVAL;
			HIP_ERROR("bad param type\n");
			break;
		}
	}

 out:
	return err;
}

/**
 * hip_check_network_param_attributes - check parameter attributes
 * @param param the parameter to checked
 *
 * This is the function where one can test special attributes such as algo,
 * groupid, suiteid, etc of a HIP parameter. If the parameter does not require
 * other than just the validation of length and type fields, one should not
 * add any checks for that parameter here.
 *
 * @return zero if the message was ok, or negative error value on error.
 *
 * XX TODO: this function may be unneccessary because the input handlers
 * already do some checking. Currently they are double checked..
 */
int hip_check_network_param_attributes(const struct hip_tlv_common *param)
{
	hip_tlv_type_t type = hip_get_param_type(param);
	int err = 0;

	_HIP_DEBUG("type=%u\n", type);

	switch(type) {
	case HIP_PARAM_HIP_TRANSFORM:
	case HIP_PARAM_ESP_TRANSFORM:
	{
		/* Search for one supported transform */
		hip_transform_suite_t suite;

 		_HIP_DEBUG("Checking %s transform\n",
			   type == HIP_PARAM_HIP_TRANSFORM ? "HIP" : "ESP");
		suite = hip_get_param_transform_suite_id(param, 0);
		if (suite == 0) {
			HIP_ERROR("Could not find suitable %s transform\n",
				  type == HIP_PARAM_HIP_TRANSFORM ? "HIP" : "ESP");
			err = -EPROTONOSUPPORT;
		}
		break;
	}
	case HIP_PARAM_HOST_ID:
	{
		uint8_t algo = 
			hip_get_host_id_algo((struct hip_host_id *) param);
		if (algo != HIP_HI_DSA && algo != HIP_HI_RSA) {
			err = -EPROTONOSUPPORT;
			HIP_ERROR("Host id algo %d not supported\n", algo);
		}
		break;
	}
	}
	_HIP_DEBUG("err=%d\n", err);
	return err;
}

/**
 * hip_check_network_msg - check network message for integrity
 * @param msg the message to be verified for integrity
 *
 * @return zero if the message was ok, or negative error value on error.
 */
int hip_check_network_msg(const struct hip_common *msg)
{
	struct hip_tlv_common *current_param = NULL;
	hip_tlv_type_t current_param_type = 0, prev_param_type = 0;
	int err = 0;

	/* Checksum of the message header is verified in input.c */

	if (!hip_check_network_msg_type(msg)) {
		err = -EINVAL;
		HIP_ERROR("bad msg type (%d)\n", hip_get_msg_type(msg));
		goto out;
	}

	if (!hip_check_msg_len(msg)) {
		err = -EMSGSIZE;
		HIP_ERROR("bad msg len %d\n", hip_get_msg_total_len(msg));
		goto out;
	}

	/* Checking of param types, lengths and ordering. */
	while((current_param = hip_get_next_param(msg, current_param))
	      != NULL) {
		current_param_type = hip_get_param_type(current_param);
		if(!hip_check_param_contents_len(msg, current_param)) {
			err = -EMSGSIZE;
			HIP_ERROR("bad param len\n");
			break;
		} else if (!hip_check_network_param_type(current_param)) {
			err = -EINVAL;
			HIP_ERROR("bad param type, current param=%u\n",
				  hip_get_param_type(current_param));
			break;
		} else if (current_param_type < prev_param_type &&
			   ((current_param_type < HIP_LOWER_TRANSFORM_TYPE ||
			    current_param_type > HIP_UPPER_TRANSFORM_TYPE) &&
			    (prev_param_type < HIP_LOWER_TRANSFORM_TYPE ||
			     prev_param_type > HIP_UPPER_TRANSFORM_TYPE))) {
			/* According to draft-ietf-hip-base-03 parameter type order 
			 * strictly enforced, except for 
			 * HIP_LOWER_TRANSFORM_TYPE - HIP_UPPER_TRANSFORM_TYPE
			 */
			err = -ENOMSG;
			HIP_ERROR("Wrong order of parameters (%d, %d)\n",
				  prev_param_type, current_param_type);
			break;
		} else if (hip_check_network_param_attributes(current_param)) {
			HIP_ERROR("bad param attributes\n");
			err = -EINVAL;
			break;
		}
		prev_param_type = current_param_type;
	}

 out:
	return err;
}

/**
 * Builds and inserts a parameter into the message.
 *
 * This is the root function of all parameter building functions.
 * hip_build_param() and hip_build_param_contents() both  use this function to
 * actually append the parameter into the HIP message. This function updates the
 * message header length to keep the next free parameter slot quickly accessible
 * for faster writing of the parameters. This function also automagically adds
 * zero filled paddign to the parameter, to keep its total length in multiple of
 * 8 bytes.
 * 
 * @param msg            the message where the parameter is to be appended
 * @param parameter_hdr  pointer to the header of the parameter
 * @param param_hdr_size size of parameter_hdr structure (in host byte order)
 * @param contents       the contents of the parameter; the data to be inserted
 *                       after the parameter_hdr (in host byte order)
 * @return               zero on success, or negative on error
 * @see                  hip_build_param().
 * @see                  hip_build_param_contents().
 */
int hip_build_generic_param(struct hip_common *msg,
			    const void *parameter_hdr,
			    hip_tlv_len_t param_hdr_size,
			    const void *contents)
{
	const struct hip_tlv_common *param =
		(struct hip_tlv_common *) parameter_hdr;
	void *src = NULL;
	void *dst = NULL;
	int err = 0;
	int size = 0;
	void *max_dst = ((void *) msg) + HIP_MAX_PACKET;

	_HIP_DEBUG("\n");

	if (!msg) {
		HIP_ERROR("message is null\n");
		err = -EFAULT;
		goto out;
	}

	if (!contents) {
		HIP_ERROR("object is null\n");
		err = -EFAULT;
		goto out;
	}

	if (param_hdr_size < sizeof(struct hip_tlv_common)) {
		HIP_ERROR("parameter size too small\n");
		err = -EMSGSIZE;
		goto out;
	}

	dst = hip_find_free_param(msg);
	if (!dst) {
		err = -EMSGSIZE;
		HIP_ERROR("msg full\n");
		goto out;
	}

	_HIP_DEBUG("found free: %d\n", dst - ((void *)msg));

	if (dst + hip_get_param_total_len(param) > max_dst) {
		err = -EMSGSIZE;
		HIP_ERROR("hipd build param: contents size (%d) too long\n",
			  hip_get_param_contents_len(param));
		goto out;
	}

	/* copy header */
	src = (void *) param;
	size = param_hdr_size;
	memcpy(dst, src, size);

	/* copy contents  */
	dst += param_hdr_size;
	src = (void *) contents;
	/* Copy the right amount of contents, see jokela draft for TLV
	   format. For example, this skips the algo in struct hip_sig2
           (which is included in the length), see the
	   build_param_signature2_contents() function below. */
	size = hip_get_param_contents_len(param) -
		(param_hdr_size - sizeof(struct hip_tlv_common));
	memcpy(dst, src, size);

	_HIP_DEBUG("contents copied %d bytes\n", size);

	/* we have to update header length or otherwise hip_find_free_param
	   will fail when it checks the header length */
	hip_calc_hdr_len(msg);
	if (hip_get_msg_total_len(msg) == 0) {
		HIP_ERROR("could not calculate temporary header length\n");
		err = -EFAULT;
	}

	_HIP_DEBUG("dumping msg, len = %d\n", hip_get_msg_total_len(msg));
	_HIP_HEXDUMP("build msg: ", (void *) msg,
		     hip_get_msg_total_len(msg));
 out:

	return err;
}

/**
 * Builds and appends parameter contents into message
 * 
 * This function differs from hip_build_generic_param only because it
 * assumes that the parameter header is just sizeof(struct hip_tlv_common).
 * This function updates the message header length to keep the next free
 * parameter slot quickly accessible for faster writing of the parameters.
 * This function automagically adds zero filled paddign to the parameter,
 * to keep its total length in multiple of 8 bytes.
 *
 * @param msg           the message where the parameter will be appended.
 * @param contents      the data after the type and length fields.
 * @param param_type    the type of the parameter (in host byte order).
 * @param contents_size the size of contents (in host byte order).
 * @return              zero on success, or negative on error.
 * @see                 hip_build_generic_param().
 * @see                 hip_build_param().
 */
int hip_build_param_contents(struct hip_common *msg,
			     const void *contents,
			     hip_tlv_type_t param_type,
			     hip_tlv_len_t contents_size)
{
	struct hip_tlv_common param;

	hip_set_param_type(&param, param_type);
	hip_set_param_contents_len(&param, contents_size);

	return hip_build_generic_param(msg, &param,
				       sizeof(struct hip_tlv_common),
				       contents);
}


/**
 * Appends a complete parameter into a HIP message.
 * 
 * Appends a complete network byte ordered parameter @c tlv_common into a HIP
 * message @c msg. This function differs from hip_build_param_contents() and
 * hip_build_generic_param() because it takes a complete network byte ordered
 * parameter as its input. It means that this function can be used for e.g.
 * copying a parameter from a message to another.
 *
 * This function updates the message header length to keep the next free
 * parameter slot quickly accessible for faster writing of the parameters. This
 * function automagically adds zero filled paddign to the parameter, to keep its
 * total length in multiple of 8 bytes.
 *
 * @param msg        a pointer to a message where the parameter will be
 *                   appended.
 * @param tlv_common a pointer to the network byte ordered parameter that will
 *                   be appended into the message.
 * @return           zero on success, or negative error value on error.
 * @see              hip_build_generic_param().
 * @see              hip_build_param_contents().
 */
int hip_build_param(struct hip_common *msg, const void *tlv_common)
{
	int err = 0;
	void *contents = ((void *) tlv_common) + sizeof(struct hip_tlv_common);

	if (tlv_common == NULL) {
		err = -EFAULT;
		HIP_ERROR("param null\n");
		goto out;
	}

	err = hip_build_param_contents(msg, contents,
		       hip_get_param_type(tlv_common),
				       hip_get_param_contents_len(tlv_common));
	if (err) {
		HIP_ERROR("could not build contents (%d)\n", err);
	}

 out:
	return err;
}

/**
 * Builds a header for userspace-kernel communication.
 * 
 * This function builds the header that can be used for HIP kernel-userspace
 * communication. It is commonly used by the daemon, hipconf, resolver or
 * the kernel module itself. This function can be called before or after
 * building the parameters for the message.
 *
 * This function does not write the header length into the message. It should
 * be written by the build_param_functions. 
 *
 * @param msg       the message where the userspace header is to be written.
 * @param base_type the type of the message.
 * @param err_val   a positive error value to be communicated for the receiver
 *                  (usually just zero for no errors).
 * @return          zero on success, or negative on error.
 */
int hip_build_user_hdr(struct hip_common *msg,
			 hip_hdr_type_t base_type,
			 hip_hdr_err_t err_val)
{
	int err = 0;

	_HIP_DEBUG("\n");

	hip_set_msg_type(msg, base_type);
	hip_set_msg_err(msg, err_val);
	/* Note: final header length is usually calculated by the
	   last call to build_param() but it is possible to build a
	   msg with just the header, so we have to calculate the
	   header length anyway. */
	hip_calc_hdr_len(msg);
	if (hip_get_msg_total_len(msg) == 0) {
		err = -EMSGSIZE;
		goto out;
	}

	/* some error checking on types and for null values */

	if (!msg) {
		err = -EINVAL;
		HIP_ERROR("msg null\n");
		goto out;
	}

	if (hip_get_msg_total_len(msg) == 0) {
		HIP_ERROR("hipd build hdr: could not calc size\n");
		err = -EMSGSIZE;
		goto out;
	}

	if (!hip_check_msg_len(msg)) {
		HIP_ERROR("hipd build hdr: msg len (%d) invalid\n",
			  hip_get_msg_total_len(msg));
		err = -EMSGSIZE;
		goto out;
	}

 out:
	return err;
}

/**
 * Writes a network header into a message.
 * 
 * This function does not write the header length into the message. It should
 * be written by the build_param_functions. The checksum field is not written
 * either because it is done in hip_send_raw() and hip_send_udp().
 * 
 * @param msg          the message where the HIP network should be written
 * @param type_hdr     the type of the HIP header as specified in the drafts
 * @param control      HIP control bits in host byte order
 * @param hit_sender   source HIT in network byte order
 * @param hit_receiver destination HIT in network byte order
 * @todo build HIP network header in the same fashion as in build_daemon_hdr().
 * <ul>
 * <li>Write missing headers in the header using accessor functions
 * (see hip_get/set_XXX() functions in the beginning of this file). You have to
 * create couple of new ones, but daemon and network messages use the same
 * locations for storing len and type (hip_common->err is stored in the
 * hip_common->checksum) and they can be used as they are.</li>
 * <li>payload_proto.</li>
 * <li>payload_len: see how build_daemon_hdr() works.</li>
 * <li>ver_res.</li>
 * <li>checksum (move the checksum function from hip.c to this file
 *     because this file is shared by kernel and userspace).</li>
 * <li>write the parameters of this function into the message.</li>
 * </ul>
 * @note Use @b only accessors to hide byte order and size conversion issues!
 */
void hip_build_network_hdr(struct hip_common *msg, uint8_t type_hdr,
			   uint16_t control, const struct in6_addr *hit_sender,
			   const struct in6_addr *hit_receiver)
{
	msg->payload_proto = IPPROTO_NONE; /* 1 byte, no htons()    */
	/* Do not touch the length; it is written by param builders */
	msg->type_hdr = type_hdr;              /* 1 byte, no htons()    */
	/* version includes the SHIM6 bit */
	msg->ver_res = (HIP_VER_RES << 4) | 1;   /* 1 byte, no htons() */

	msg->control = htons(control);
	msg->checksum = htons(0); /* this will be written by xmit */

	ipv6_addr_copy(&msg->hits, hit_sender ? hit_sender : &in6addr_any);
	ipv6_addr_copy(&msg->hitr, hit_receiver ? hit_receiver : &in6addr_any);
}

#ifndef __KERNEL__
/**
 * Builds a @c HMAC parameter.
 *
 * Builds a @c HMAC parameter to the HIP packet @c msg. This function calculates
 * also the hmac value from the whole message as specified in the drafts.
 *
 * @param msg a pointer to the message where the @c HMAC parameter will be
 *            appended.
 * @param key a pointer to a key used for hmac.
 * @return    zero on success, or negative error value on error.
 * @see       hip_build_param_hmac2_contents()
 * @see       hip_build_param_rvs_hmac_contents().
 * @see       hip_write_hmac().
 */
int hip_build_param_hmac_contents(struct hip_common *msg,
				  struct hip_crypto_key *key)
{
	int err = 0;
	struct hip_hmac hmac;

	hip_set_param_type(&hmac, HIP_PARAM_HMAC);
	hip_calc_generic_param_len(&hmac, sizeof(struct hip_hmac), 0);

	HIP_IFEL(!hip_write_hmac(HIP_DIGEST_SHA1_HMAC, key->key, msg,
				 hip_get_msg_total_len(msg),
				 hmac.hmac_data), -EFAULT,
		 "Error while building HMAC\n");

	err = hip_build_param(msg, &hmac);
 out_err:
	return err;
}

/**
 * Builds a @c RVS_HMAC parameter.
 *
 * Builds a @c RVS_HMAC parameter to the HIP packet @c msg. This function
 * calculates also the hmac value from the whole message as specified in the drafts.
 *
 * @param msg a pointer to the message where the @c RVS_HMAC parameter will be
 *            appended.
 * @param key a pointer to a key used for hmac.
 * @return    zero on success, or negative error value on error.
 * @see       hip_build_param_hmac_contents().
 * @see       hip_build_param_hmac2_contents().
 * @see       hip_write_hmac().
 * @note      Except the TLV type value, the functionality of this function is
 *            identical to the functionality of hip_build_param_hmac_contents().
 *            If something is changed there, it is most likely that it should
 *            be changed here also.
 */
int hip_build_param_rvs_hmac_contents(struct hip_common *msg,
				  struct hip_crypto_key *key)
{
	int err = 0;
	struct hip_hmac hmac;

	hip_set_param_type(&hmac, HIP_PARAM_RVS_HMAC);
	hip_calc_generic_param_len(&hmac, sizeof(struct hip_hmac), 0);
	HIP_IFEL(!hip_write_hmac(HIP_DIGEST_SHA1_HMAC, key->key, msg,
				 hip_get_msg_total_len(msg),
				 hmac.hmac_data), -EFAULT,
		 "Error while building HMAC\n");
	err = hip_build_param(msg, &hmac);
 out_err:
	return err;
}

/**
 * Builds a @c HMAC2 parameter.
 *
 * Builds a @c HMAC2 parameter to the HIP packet @c msg. This function 
 * calculates also the hmac value from the whole message as specified in the
 * drafts. Assumes that the hmac includes only the header and host id.
 *
 * @param msg      a pointer to the message where the @c HMAC2 parameter will be
 *                 appended.
 * @param key      a pointer to a key used for hmac.
 * @param host_id  a pointer to a host id.
 * @return         zero on success, or negative error value on error.
 * @see            hip_build_param_hmac_contents().
 * @see            hip_build_param_rvs_hmac_contents().
 * @see            hip_write_hmac().
 */
int hip_build_param_hmac2_contents(struct hip_common *msg,
				   struct hip_crypto_key *key,
				   struct hip_host_id *host_id)
{
	int err = 0;
	struct hip_hmac hmac2;
	struct hip_common *tmp = NULL;
	struct hip_esp_info *esp_info;

	tmp = hip_msg_alloc();
	if (!tmp) {
		err = -ENOMEM;
		goto out_err;
	}

	memcpy(tmp, msg, sizeof(struct hip_common));
	hip_set_msg_total_len(tmp, 0);
	/* assume no checksum yet */

	esp_info = hip_get_param(msg, HIP_PARAM_ESP_INFO);
	HIP_ASSERT(esp_info);
	err = hip_build_param(tmp, esp_info);
	if (err) {
		err = -EFAULT;
		goto out_err;
	}

	hip_set_param_type(&hmac2, HIP_PARAM_HMAC2);
	hip_calc_generic_param_len(&hmac2, sizeof(struct hip_hmac), 0);

	err = hip_build_param(tmp, host_id);
	if (err) {
		HIP_ERROR("Failed to append pseudo host id to R2\n");
		goto out_err;
	}

	HIP_HEXDUMP("HMAC data", tmp, hip_get_msg_total_len(tmp));
	HIP_HEXDUMP("HMAC key\n", key->key, 20);

	if (!hip_write_hmac(HIP_DIGEST_SHA1_HMAC, key->key, tmp,
			    hip_get_msg_total_len(tmp),
			    hmac2.hmac_data)) {
		HIP_ERROR("Error while building HMAC\n");
		err = -EFAULT;
		goto out_err;
	}

	err = hip_build_param(msg, &hmac2);
 out_err:
	if (tmp)
		HIP_FREE(tmp);

	return err;
}

/**
 * Calculates the checksum of a HIP packet with pseudo-header.
 * 
 * @c src and @c dst are IPv4 or IPv6 addresses in network byte order.
 *
 * @param data a pointer to...
 * @param src  a pointer to...
 * @param dst  a pointer to...
 * @note       Checksumming is from Boeing's HIPD.
 * @return     ...
 */
u16 hip_checksum_packet(char *data, struct sockaddr *src, struct sockaddr *dst)
{
	u16 checksum = 0;
	unsigned long sum = 0;
	int count = 0, length = 0;
	unsigned short *p = NULL; /* 16-bit */
	struct pseudo_header pseudoh;
	struct pseudo_header6 pseudoh6;
	u32 src_network, dst_network;
	struct in6_addr *src6, *dst6;
	struct hip_common *hiph = (struct hip_common *) data;
	
	if (src->sa_family == AF_INET) {
		/* IPv4 checksum based on UDP-- Section 6.1.2 */
		src_network = ((struct sockaddr_in*)src)->sin_addr.s_addr;
		dst_network = ((struct sockaddr_in*)dst)->sin_addr.s_addr;
		
		memset(&pseudoh, 0, sizeof(struct pseudo_header));
		memcpy(&pseudoh.src_addr, &src_network, 4);
		memcpy(&pseudoh.dst_addr, &dst_network, 4);
		pseudoh.protocol = IPPROTO_HIP;
		length = (hiph->payload_len + 1) * 8;
		pseudoh.packet_length = htons(length);
		
		count = sizeof(struct pseudo_header); /* count always even number */
		p = (unsigned short*) &pseudoh;
	} else {
		/* IPv6 checksum based on IPv6 pseudo-header */
		src6 = &((struct sockaddr_in6*)src)->sin6_addr;
		dst6 = &((struct sockaddr_in6*)dst)->sin6_addr;
		
		memset(&pseudoh6, 0, sizeof(struct pseudo_header6));
		memcpy(&pseudoh6.src_addr[0], src6, 16);
		memcpy(&pseudoh6.dst_addr[0], dst6, 16);
		length = (hiph->payload_len + 1) * 8;
		pseudoh6.packet_length = htonl(length);
		pseudoh6.next_hdr = IPPROTO_HIP;
                
		count = sizeof(struct pseudo_header6); /* count always even number */
		p = (unsigned short*) &pseudoh6;
	}
	/* 
	 * this checksum algorithm can be found 
	 * in RFC 1071 section 4.1
	 */
	
	/* sum the psuedo-header */
	/* count and p are initialized above per protocol */
	while (count > 1) {
		sum += *p++;
		count -= 2;
	}

	/* one's complement sum 16-bit words of data */
	HIP_DEBUG("Checksumming %d bytes of data.\n", length);
	count = length;
	p = (unsigned short*) data;
	while (count > 1) {
		sum += *p++;
		count -= 2;
	}
	/* add left-over byte, if any */
	if (count > 0)
		sum += (unsigned char)*p;
	
	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	/* take the one's complement of the sum */ 
	checksum = ~sum;
	
	return(checksum);
}

int hip_verify_network_header(struct hip_common *hip_common,
			      struct sockaddr *src, struct sockaddr *dst,
			      int len)
{
	int err = 0, plen;

	plen = hip_get_msg_total_len(hip_common);

        /* Currently no support for piggybacking */
        HIP_IFEL(len != hip_get_msg_total_len(hip_common), -EINVAL, 
		 "Invalid HIP packet length (%d,%d). Dropping\n",
		 len, plen);
        HIP_IFEL(hip_common->payload_proto != IPPROTO_NONE, -EOPNOTSUPP,
		 "Protocol in packet (%u) was not IPPROTO_NONE. Dropping\n",
		 hip_common->payload_proto);
	HIP_IFEL(hip_common->ver_res != ((HIP_VER_RES << 4) | 1), -EPROTOTYPE,
		 "Invalid version in received packet. Dropping\n");
	HIP_IFEL(!ipv6_addr_is_hit(&hip_common->hits), -EAFNOSUPPORT,
		 "Received a non-HIT in HIT-source. Dropping\n");
	HIP_IFEL(!ipv6_addr_is_hit(&hip_common->hitr) &&
		 !ipv6_addr_any(&hip_common->hitr),
		 -EAFNOSUPPORT,
		 "Received a non-HIT or non NULL in HIT-receiver. Dropping\n");
	HIP_IFEL(ipv6_addr_any(&hip_common->hits), -EAFNOSUPPORT,
		 "Received a NULL in HIT-sender. Dropping\n");

        /** @todo handle the RVS case better. */
        if (ipv6_addr_any(&hip_common->hitr)) {
                /* Required for e.g. BOS */
                HIP_DEBUG("Received opportunistic HIT\n");
	} else {
#ifdef CONFIG_HIP_RVS
                HIP_DEBUG("Received HIT is ours or we are RVS\n");
#else
		HIP_IFEL(!hip_hidb_hit_is_our(&hip_common->hitr), -EFAULT,
			 "Receiver HIT is not ours\n");
#endif
	}

#if 0
        HIP_IFEL(!ipv6_addr_cmp(&hip_common->hits, &hip_common->hitr), -ENOSYS,
		 "Dropping HIP packet. Loopback not supported.\n");
#endif

        /* Check checksum. */
	if (dst->sa_family == AF_INET && ((struct sockaddr_in *)dst)->sin_port) {
		HIP_DEBUG("HIP IPv4 UDP packet: ignoring HIP checksum\n");
	} else {
		HIP_IFEL(hip_checksum_packet((char*)hip_common, src, dst),
			 -EBADMSG, "HIP checksum failed.\n");
	}
	
out_err:
        return err;
}

#endif /* __KERNEL__ */

/**
 * hip_build_param_encrypted_aes_sha1 - build the hip_encrypted parameter
 * @param msg the message where the parameter will be appended
 * @param param the parameter that will contained in the hip_encrypted
 *           parameter
 * 
 * Note that this function does not actually encrypt anything, it just builds
 * the parameter. The parameter that will be encapsulated in the hip_encrypted
 * parameter has to be encrypted using a different function call.
 *
 * Returns: zero on success, or negative on failure
 */
int hip_build_param_encrypted_aes_sha1(struct hip_common *msg,
					struct hip_tlv_common *param)
{
	int rem, err = 0;
	struct hip_encrypted_aes_sha1 enc;
	int param_len = hip_get_param_total_len(param);
	struct hip_tlv_common *common = param;
	char *param_padded = NULL;

	hip_set_param_type(&enc, HIP_PARAM_ENCRYPTED);
	enc.reserved = htonl(0);
	memset(&enc.iv, 0, 16);

	/* copy the IV *IF* needed, and then the encrypted data */

	/* AES block size must be multiple of 16 bytes */
	rem = param_len % 16;
	if (rem) {
		HIP_DEBUG("Adjusting param size to AES block size\n");

		param_padded = (char *)HIP_MALLOC(param_len + rem, GFP_KERNEL);
		if (!param_padded) {
			err = -ENOMEM;
			goto out_err;
		}

		/* this kind of padding works against Ericsson/OpenSSL
		   (method 4: RFC2630 method) */
		/* http://www.di-mgt.com.au/cryptopad.html#exampleaes */
		memcpy(param_padded, param, param_len);
		memset(param_padded + param_len, rem, rem);

		common = (struct hip_tlv_common *) param_padded;
		param_len += rem;
	}

	hip_calc_param_len(&enc, sizeof(enc) -
			   sizeof(struct hip_tlv_common) +
			   param_len);

	err = hip_build_generic_param(msg, &enc, sizeof(enc), common);

 out_err:

	if (param_padded)
		HIP_FREE(param_padded);
		
	return err;
}

/**
 * hip_build_param_signature2_contents - build HIP signature2
 * @param msg the message 
 * @param contents pointer to the signature contents (the data to be written
 *                 after the signature field)
 * @param contents_size size of the contents of the signature (the data after the
 *                 algorithm field)
 * @param algorithm the algorithm as in the HIP drafts that was used for
 *                 producing the signature
 *                 
 * build_param_contents() is not very suitable for building a hip_sig2 struct,
 * because hip_sig2 has a troublesome algorithm field which need some special
 * attention from htons(). Thereby here is a separate builder for hip_sig2 for
 * conveniency. It uses internally hip_build_generic_param() for actually
 * writing the signature parameter into the message.
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_signature2_contents(struct hip_common *msg,
					const void *contents,
					hip_tlv_len_t contents_size,
					uint8_t algorithm)
{
	/* note: if you make changes in this function, make them also in
	   build_param_signature_contents(), because it is almost the same */

	int err = 0;
	struct hip_sig2 sig2;

	HIP_ASSERT(sizeof(struct hip_sig2) >= sizeof(struct hip_tlv_common));

	hip_set_param_type(&sig2, HIP_PARAM_HIP_SIGNATURE2);
	hip_calc_generic_param_len(&sig2, sizeof(struct hip_sig2),
				   contents_size);
	sig2.algorithm = algorithm; /* algo is 8 bits, no htons */

	err = hip_build_generic_param(msg, &sig2,
				      sizeof(struct hip_sig2), contents);

	return err;
}

/**
 * hip_build_param_signature_contents - build HIP signature1
 * @param msg the message 
 * @param contents pointer to the signature contents (the data to be written
 *                 after the signature field)
 * @param contents_size size of the contents of the signature (the data after the
 *                 algorithm field)
 * @param algorithm the algorithm as in the HIP drafts that was used for
 *                 producing the signature
 *                 
 * This is almost the same as the previous, but the type is sig1.
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_signature_contents(struct hip_common *msg,
				       const void *contents,
				       hip_tlv_len_t contents_size,
				       uint8_t algorithm)
{
	/* note: if you make changes in this function, make them also in
	   build_param_signature_contents2(), because it is almost the same */

	int err = 0;
	struct hip_sig sig;

	HIP_ASSERT(sizeof(struct hip_sig) >= sizeof(struct hip_tlv_common));

	hip_set_param_type(&sig, HIP_PARAM_HIP_SIGNATURE);
	hip_calc_generic_param_len(&sig, sizeof(struct hip_sig),
				   contents_size);
	sig.algorithm = algorithm; /* algo is 8 bits, no htons */

	err = hip_build_generic_param(msg, &sig,
				      sizeof(struct hip_sig), contents);

	return err;
}

/**
 * hip_build_param_echo - build HIP ECHO parameter
 * @param msg the message 
 * @param opaque opaque data copied to the parameter
 * @param len      the length of the parameter
 * @param sign true if parameter is under signature, false otherwise
 * @param request true if parameter is ECHO_REQUEST, otherwise parameter is ECHO_RESPONSE
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_echo(struct hip_common *msg, void *opaque, int len,
			 int sign, int request)
{
	struct hip_echo_request ping;
	int err;

	if (request)
		hip_set_param_type(&ping, sign ? HIP_PARAM_ECHO_REQUEST_SIGN : HIP_PARAM_ECHO_REQUEST);
	else
		hip_set_param_type(&ping, sign ? HIP_PARAM_ECHO_RESPONSE_SIGN : HIP_PARAM_ECHO_RESPONSE);

	hip_set_param_contents_len(&ping, len);
	err = hip_build_generic_param(msg, &ping, sizeof(struct hip_echo_request),
				      opaque);
	return err;
}

/**
 * hip_build_param_r1_counter - build HIP R1_COUNTER parameter
 * @param msg the message 
 * @param generation R1 generation counter
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_r1_counter(struct hip_common *msg, uint64_t generation)
{
	struct hip_r1_counter r1gen;
	int err = 0;

	/* note: the length cannot be calculated with calc_param_len() */
	hip_set_param_contents_len(&r1gen,
				   sizeof(struct hip_r1_counter) -
				   sizeof(struct hip_tlv_common));
	/* Type 2 (in R1) or 3 (in I2) */
	hip_set_param_type(&r1gen, HIP_PARAM_R1_COUNTER);

	/* only the random_j_k is in host byte order */
	r1gen.generation = generation;

	err = hip_build_param(msg, &r1gen);
	return err;
}

/**
 * Builds a @c FROM parameter.
 *
 * Builds a @c FROM parameter to the HIP packet @c msg.
 *
 * @param msg      a pointer to a HIP packet common header
 * @param addr     a pointer to an IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param not_used this parameter is not used, but it is needed to make the
 *                 parameter list uniform with hip_build_param_from_nat().
 * @return         zero on success, or negative error value on error.
 * @see            <a href="http://tools.ietf.org/wg/hip/draft-ietf-hip-rvs/draft-ietf-hip-rvs-05.txt">
 *                 draft-ietf-hip-rvs-05</a> section 4.2.2.
 */
int hip_build_param_from(struct hip_common *msg, const struct in6_addr *addr,
			 const in_port_t not_used)
{
	struct hip_from from;
	int err = 0;
	
	hip_set_param_type(&from, HIP_PARAM_FROM);
	memcpy((struct in6_addr *)&from.address, addr, 16);

	hip_calc_generic_param_len(&from, sizeof(struct hip_from), 0);
	err = hip_build_param(msg, &from);
	return err;
}

/**
 * Builds a @c FROM_NAT parameter.
 *
 * Builds a @c FROM_NAT parameter to the HIP packet @c msg.
 *
 * @param msg  a pointer to a HIP packet common header
 * @param addr a pointer to an IPv6 or IPv4-in-IPv6 format IPv4 address.
 * @param port port number (host byte order).
 * @return     zero on success, or negative error value on error.
 * @see        <a href="http://www.ietf.org/internet-drafts/draft-schmitt-hip-nat-traversal-01.txt">
 *             draft-schmitt-hip-nat-traversal-01</a> section 3.1.4.
 */
int hip_build_param_from_nat(struct hip_common *msg, const struct in6_addr *addr,
			     const in_port_t port)
{
	struct hip_from_nat from_nat;
	int err = 0;
	
	hip_set_param_type(&from_nat, HIP_PARAM_FROM_NAT);
	ipv6_addr_copy((struct in6_addr *)&from_nat.address, addr);
	from_nat.port = htons(port);
	hip_calc_generic_param_len(&from_nat, sizeof(struct hip_from_nat), 0);
	err = hip_build_param(msg, &from_nat);

	return err;
}

/**
 * Builds a @c VIA_RVS parameter.
 *
 * Builds a @c VIA_RVS parameter to the HIP packet @c msg.
 *
 * @param msg           a pointer to a HIP packet common header
 * @param rvs_addresses a pointer to rendezvous server IPv6 or IPv4-in-IPv6
 *                      format IPv4 addresses.
 * @param address_count number of addresses in @c rvs_addresses.
 * @return              zero on success, or negative error value on error.
 * @see                 <a href="http://tools.ietf.org/wg/hip/draft-ietf-hip-rvs/draft-ietf-hip-rvs-05.txt">
 *                      draft-ietf-hip-rvs-05</a> section 4.2.3.
 */
int hip_build_param_via_rvs(struct hip_common *msg,
			    const struct in6_addr rvs_addresses[],
			    const int address_count)
{
	HIP_DEBUG("hip_build_param_rvs() invoked.\n");
	int err = 0;
	struct hip_via_rvs viarvs;
	
	hip_set_param_type(&viarvs, HIP_PARAM_VIA_RVS);
	hip_calc_generic_param_len(&viarvs, sizeof(struct hip_via_rvs),
				   address_count * sizeof(struct in6_addr));
	err = hip_build_generic_param(msg, &viarvs, sizeof(struct hip_via_rvs),
				      (void *)rvs_addresses);
	return err;
}

/**
 * Builds a @c VIA_RVS_NAT parameter.
 *
 * Builds a @c VIA_RVS_NAT parameter to the HIP packet @c msg.
 *
 * @param msg            a pointer to a HIP packet common header
 * @param rvs_addr_ports a pointer to rendezvous server IPv6 or IPv4-in-IPv6
 *                       format IPv4 addresses.
 * @param address_count  number of address port combinations in @c rvs_addr_ports.
 * @return               zero on success, or negative error value on error.
 * @see                  <a href="http://www.ietf.org/internet-drafts/draft-schmitt-hip-nat-traversal-01.txt">
 *                       draft-schmitt-hip-nat-traversal-01</a> section 3.1.5.
 */
int hip_build_param_via_rvs_nat(struct hip_common *msg,
				const struct hip_in6_addr_port rvs_addr_ports[],
				const int address_count)
{
	HIP_DEBUG("hip_build_param_rvs_nat() invoked.\n");
	HIP_DEBUG("sizeof(struct hip_in6_addr_port): %u.\n", sizeof(struct hip_in6_addr_port));
	int err = 0;
	struct hip_via_rvs_nat viarvsnat;
	
	hip_set_param_type(&viarvsnat, HIP_PARAM_VIA_RVS_NAT);
	hip_calc_generic_param_len(&viarvsnat, sizeof(struct hip_via_rvs_nat),
				   address_count * sizeof(struct hip_in6_addr_port));
	err = hip_build_generic_param(msg, &viarvsnat, sizeof(struct hip_via_rvs_nat),
				      (void *)rvs_addr_ports);
	return err;
}

/**
 * hip_build_param_reg_info - build HIP REG_INFO parameter
 * @param msg the message
 * @param min_lifetime minimum lifetime in seconds in host byte order
 * @param max_lifetime maximum lifetime in seconds in host byte order
 * @param type_list list of types to be appended
 * @param cnt number of addresses in type_list
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_reg_info(struct hip_common *msg, uint8_t min_lifetime, 
			uint8_t max_lifetime, int *type_list, int cnt)
{
	struct hip_reg_info rinfo;
	int err = 0, i;
	uint8_t *array = NULL;

	hip_set_param_type(&rinfo, HIP_PARAM_REG_INFO);
	hip_calc_generic_param_len(&rinfo, sizeof(struct hip_reg_info),
				   cnt * sizeof(uint8_t));
	
	HIP_IFEL(!(array = (uint8_t *) HIP_MALLOC((cnt * sizeof(uint8_t)), GFP_KERNEL)), 
		-1, "Failed to allocate memory");
	memset(array, (sizeof(uint8_t) * cnt), 0);
	for (i = 0; i < cnt; i++) {
		uint8_t val = (uint8_t)type_list[i];
		array[i] = val;
	}

	rinfo.min_lifetime = min_lifetime;
	rinfo.max_lifetime = max_lifetime;
	err = hip_build_generic_param(msg, &rinfo, sizeof(struct hip_reg_info),
				      (void *)array);
out_err: 
	if (array)
		HIP_FREE(array);	
	return err;	
}

/**
 * hip_build_param_reg_request - build HIP REG_REQUEST or REG_RESPONSE parameter
 * @param msg       the message
 * @param lifetime  lifetime in seconds in host byte order
 * @param type_list list of types to be appended
 * @param cnt number of addresses in type_list
 * @param request true if parameter is REG_REQUEST, otherwise parameter is REG_RESPONSE
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_reg_request(struct hip_common *msg, uint8_t lifetime, 
			int *type_list, int cnt, int request)
{
	int err = 0;
	int i;
	struct hip_reg_request rreq;
	uint8_t *array = NULL;
	
	hip_set_param_type(&rreq, (request ? HIP_PARAM_REG_REQUEST : HIP_PARAM_REG_RESPONSE));
	hip_calc_generic_param_len(&rreq, sizeof(struct hip_reg_request),
				   cnt * sizeof(uint8_t));

	HIP_IFEL(!(array = (uint8_t *) HIP_MALLOC((cnt * sizeof(uint8_t)), GFP_KERNEL)),
		-1, "Failed to allocate memory");
	memset(array, (sizeof(uint8_t) * cnt), 0);
	for (i = 0; i < cnt; i++) {
		uint8_t val = (uint8_t)type_list[i];
		array[i] = val;
	}

	rreq.lifetime = lifetime;
	err = hip_build_generic_param(msg, &rreq, sizeof(struct hip_reg_request),
				      (void *)array);	
out_err: 
	if (array)
		HIP_FREE(array);	
	return err;		
}

/**
 * hip_build_param_reg_failed - build HIP REG_FAILED parameter
 * @param msg the message
 * @param failure_type reason for failure
 * @param type_list list of types to be appended
 * @param cnt number of addresses in type_list
 *
 * @return zero for success, or non-zero on error
 */
int hip_build_param_reg_failed(struct hip_common *msg, uint8_t failure_type, 
			int *type_list, int cnt)
{
	int err = 0;
	int i;
	struct hip_reg_failed rfail;
	uint8_t *array = NULL;

	hip_set_param_type(&rfail, HIP_PARAM_REG_FAILED);
	hip_calc_generic_param_len(&rfail, sizeof(struct hip_reg_failed),
				   cnt * sizeof(uint8_t));

	HIP_IFEL(!(array = (uint8_t *) HIP_MALLOC((cnt * sizeof(uint8_t)), GFP_KERNEL)),
		-1, "Failed to allocate memory");
	memset(array, (sizeof(uint8_t) * cnt), 0);
	for (i = 0; i < cnt; i++) {
		uint8_t val = (uint8_t)type_list[i];
		array[i] = val;
	}
	

	rfail.failure_type = failure_type;
	err = hip_build_generic_param(msg, &rfail, sizeof(struct hip_reg_failed),
				      (void *)array);
out_err: 
	if (array)
		HIP_FREE(array);	
	return err;		
}			


/**
 * hip_build_param_puzzle - build and append a HIP puzzle into the message
 * @param msg the message where the puzzle is to be appended
 * @param val_K the K value for the puzzle
 * @param lifetime lifetime field of the puzzle
 * @param opaque the opaque value for the puzzle
 * @param random_i random I value for the puzzle (in host byte order)
 *
 * The puzzle mechanism assumes that every value is in network byte order
 * except for the hip_birthday_cookie.cv union, where the value is in
 * host byte order. This is an exception to the normal builder rules, where
 * input arguments are normally always in host byte order.
 * 
 * @return zero for success, or non-zero on error
 */
int hip_build_param_puzzle(struct hip_common *msg, uint8_t val_K,
			   uint8_t lifetime, uint32_t opaque, uint64_t random_i)
{
	struct hip_puzzle puzzle;
	int err = 0;

	/* note: the length cannot be calculated with calc_param_len() */
	hip_set_param_contents_len(&puzzle,
				   sizeof(struct hip_puzzle) -
				   sizeof(struct hip_tlv_common));
	/* Type 2 (in R1) or 3 (in I2) */
	hip_set_param_type(&puzzle, HIP_PARAM_PUZZLE);

	/* only the random_j_k is in host byte order */
	puzzle.K = val_K;
	puzzle.lifetime = lifetime;
	puzzle.opaque[0] = opaque & 0xFF;
	puzzle.opaque[1] = (opaque & 0xFF00) >> 8;
	/* puzzle.opaque[2] = (opaque & 0xFF0000) >> 16; */
	puzzle.I = random_i;

        err = hip_build_generic_param(msg, &puzzle,
				      sizeof(struct hip_tlv_common),
				      hip_get_param_contents_direct(&puzzle));
	return err;

}

/**
 * hip_build_param_solution - build and append a HIP solution into the message
 * @param msg the message where the solution is to be appended
 * @param pz values from the corresponding puzzle copied to the solution
 * @param val_J J value for the solution (in host byte order)
 *
 * The puzzle mechanism assumes that every value is in network byte order
 * except for the hip_birthday_cookie.cv union, where the value is in
 * host byte order. This is an exception to the normal builder rules, where
 * input arguments are normally always in host byte order.
 * 
 * @return zero for success, or non-zero on error
 */
int hip_build_param_solution(struct hip_common *msg, struct hip_puzzle *pz,
			     uint64_t val_J)
{
	struct hip_solution cookie;
	int err = 0;

	/* note: the length cannot be calculated with calc_param_len() */
	hip_set_param_contents_len(&cookie,
				   sizeof(struct hip_solution) -
				   sizeof(struct hip_tlv_common));
	/* Type 2 (in R1) or 3 (in I2) */
	hip_set_param_type(&cookie, HIP_PARAM_SOLUTION);

	cookie.J = hton64(val_J);
	memcpy(&cookie.K, &pz->K, 12); /* copy: K (1), reserved (1),
					  opaque (2) and I (8 bytes). */
	cookie.reserved = 0;
        err = hip_build_generic_param(msg, &cookie,
				      sizeof(struct hip_tlv_common),
				      hip_get_param_contents_direct(&cookie));
	return err;
}

/**
 * hip_build_param_diffie_hellman_contents - build HIP DH contents
 * @param msg the message where the DH parameter will be appended
 * @param group_id the group id of the DH parameter as specified in the drafts
 * @param pubkey the public key part of the DH
 * @param pubkey_len length of public key part
 * 
 * @return zero on success, or non-zero on error
 *
 * XX FIXME: should support multiple D-H values
 */
int hip_build_param_diffie_hellman_contents(struct hip_common *msg,
				      uint8_t group_id,
				      void *pubkey,
				      hip_tlv_len_t pubkey_len)
{
	int err = 0;
	struct hip_diffie_hellman diffie_hellman;

	HIP_ASSERT(pubkey_len >= sizeof(struct hip_tlv_common));

	_HIP_ASSERT(sizeof(struct hip_diffie_hellman) == 5);

	hip_set_param_type(&diffie_hellman, HIP_PARAM_DIFFIE_HELLMAN);
	hip_calc_generic_param_len(&diffie_hellman,
				   sizeof(struct hip_diffie_hellman),
				   pubkey_len);
	diffie_hellman.group_id = group_id; /* 1 byte, no htons() */
	diffie_hellman.pub_len = htons(pubkey_len);

	err = hip_build_generic_param(msg, &diffie_hellman,
				      sizeof(struct hip_diffie_hellman),
				      pubkey);

	_HIP_HEXDUMP("Own DH pubkey: ", pubkey, pubkey_len);

	return err;
}

/**
 * hip_get_transform_max - find out the maximum number of transform suite ids
 * @param transform_type the type of the transform
 *
 * @return the number of suite ids that can be used for transform_type
 */
uint16_t hip_get_transform_max(hip_tlv_type_t transform_type)
{
	uint16_t transform_max = 0;

	switch (transform_type) {
	case HIP_PARAM_HIP_TRANSFORM:
		transform_max = HIP_TRANSFORM_HIP_MAX;
		break;
	case HIP_PARAM_ESP_TRANSFORM:
		transform_max = HIP_TRANSFORM_ESP_MAX;
		break;
	default:
		HIP_ERROR("Unknown transform type %d\n", transform_type);
	}

	return transform_max;

}

/**
 * hip_build_param_transform - build an HIP or ESP transform
 * @param msg the message where the parameter will be appended
 * @param transform_type HIP_PARAM_HIP_TRANSFORM or HIP_PARAM_ESP_TRANSFORM
 *                       in host byte order
 * @param transform_suite an array of transform suite ids in host byte order
 * @param transform_count number of transform suites in transform_suite (in host
 *                        byte order)
 *
 * @return zero on success, or negative on error
 */
int hip_build_param_transform(struct hip_common *msg,
			      const hip_tlv_type_t transform_type,
			      const hip_transform_suite_t transform_suite[],
			      const uint16_t transform_count)
{
	int err = 0;
	uint16_t i;
	uint16_t transform_max;
	struct hip_any_transform transform_param;

	transform_max = hip_get_transform_max(transform_type);

	if (!(transform_type == HIP_PARAM_ESP_TRANSFORM ||
	      transform_type == HIP_PARAM_HIP_TRANSFORM)) {
		err = -EINVAL;
		HIP_ERROR("Invalid transform type %d\n", transform_type);
		goto out_err;
	}

	/* Check that the maximum number of transforms is not overflowed */
	if (transform_max > 0 && transform_count > transform_max) {
		err = -E2BIG;
		HIP_ERROR("Too many transforms (%d) for type %d.\n",
			  transform_count, transform_type);
		goto out_err;
	}

	if (transform_type == HIP_PARAM_ESP_TRANSFORM) {
		((struct hip_esp_transform *)&transform_param)->reserved = 0;
	}

	/* Copy and convert transforms to network byte order. */
	for(i = 0; i < transform_count; i++) {
		if (transform_type == HIP_PARAM_ESP_TRANSFORM) {
			((struct hip_esp_transform *)&transform_param)->suite_id[i] = htons(transform_suite[i]);
		} else {
			((struct hip_hip_transform *)&transform_param)->suite_id[i] = htons(transform_suite[i]);
		}
	}

	hip_set_param_type(&transform_param, transform_type);
	if (transform_type == HIP_PARAM_ESP_TRANSFORM) {
		hip_calc_param_len(&transform_param,
				   2+transform_count * sizeof(hip_transform_suite_t));
	} else {
		hip_calc_param_len(&transform_param,
				   transform_count * sizeof(hip_transform_suite_t));
	}
	err = hip_build_param(msg, &transform_param);

 out_err:
	return err;
}

/**
 * hip_get_param_transform_suite_id - get a suite id from a transform structure
 * @param transform_tlv the transform structure
 * @param index the index of the suite id in transform_tlv
 *
 * XX FIXME: REMOVE INDEX, XX RENAME
 *
 * @return the suite id on transform_tlv on index
 */
hip_transform_suite_t hip_get_param_transform_suite_id(const void *transform_tlv,
						       const uint16_t index)
{
	/* XX FIXME: WHY DO WE HAVE HIP_SELECT_ESP_TRANSFORM SEPARATELY??? */

	hip_tlv_type_t type;
 	uint16_t supported_hip_tf[] = { HIP_HIP_NULL_SHA1,
 					HIP_HIP_3DES_SHA1,
 					HIP_HIP_AES_SHA1};
 	uint16_t supported_esp_tf[] = { HIP_ESP_NULL_SHA1,
 					HIP_ESP_3DES_SHA1,
 					HIP_ESP_AES_SHA1 };
 	uint16_t *table = NULL;
 	uint16_t *tfm;
 	int table_n = 0, pkt_tfms = 0, i;

 	_HIP_DEBUG("tfm len = %d\n", hip_get_param_contents_len(transform_tlv));

 	type = hip_get_param_type(transform_tlv);
 	if (type == HIP_PARAM_HIP_TRANSFORM) {
		table = supported_hip_tf;
		table_n = sizeof(supported_hip_tf)/sizeof(uint16_t);
		tfm = (void *)transform_tlv+sizeof(struct hip_tlv_common);
		pkt_tfms = hip_get_param_contents_len(transform_tlv)/sizeof(uint16_t);
 	} else if (type == HIP_PARAM_ESP_TRANSFORM) {
		table = supported_esp_tf;
		table_n = sizeof(supported_esp_tf)/sizeof(uint16_t);
		tfm = (void *)transform_tlv+sizeof(struct hip_tlv_common)+sizeof(uint16_t);
		pkt_tfms = (hip_get_param_contents_len(transform_tlv)-sizeof(uint16_t))/sizeof(uint16_t);
 	} else {
		HIP_ERROR("Invalid type %u\n", type);
		return 0;
 	}

 	for (i = 0; i < pkt_tfms; i++, tfm++) {
 		int j;
 		_HIP_DEBUG("testing pkt tfm=%u\n", ntohs(*tfm));
 		for (j = 0; j < table_n; j++) {
 			if (ntohs(*tfm) == table[j]) {
 				_HIP_DEBUG("found supported tfm %u, pkt tlv index of tfm=%d\n",
 					  table[j], i);
 				return table[j];  
 			}
 		}
 	}
 	HIP_ERROR("usable suite not found\n");
 	return 0;
}

#ifndef __KERNEL__
/**
 * hip_build_param_locator - build HIP locator parameter
 *
 * @param msg the message where the REA will be appended
 * @param addresses list of addresses
 * @param address_count number of addresses
 *
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_locator(struct hip_common *msg,
			struct hip_locator_info_addr_item *addresses,
			int address_count)
{
	int err = 0;
	struct hip_locator *locator_info = NULL;
	int addrs_len = address_count *
		(sizeof(struct hip_locator_info_addr_item));

	HIP_IFE(!(locator_info =
		  malloc(sizeof(struct hip_locator) + addrs_len)), -1);

	hip_set_param_type(locator_info, HIP_PARAM_LOCATOR);
	hip_calc_generic_param_len(locator_info,
				   sizeof(struct hip_locator),
				   addrs_len);
	_HIP_DEBUG("params size=%d\n", sizeof(struct hip_locator) -
		   sizeof(struct hip_tlv_common) +
		   addrs_len);

	memcpy(locator_info + 1, addresses, addrs_len);
	HIP_IFE(hip_build_param(msg, locator_info), -1);

	_HIP_DEBUG("msgtotlen=%d addrs_len=%d\n", hip_get_msg_total_len(msg),
		   addrs_len);
	//if (addrs_len > 0)
	//	memcpy((void *)msg+hip_get_msg_total_len(msg)-addrs_len,
	//	       addresses, addrs_len);

 out_err:
	if (locator_info)
		free(locator_info);

	return err;
}

int hip_build_param_locator_list(struct hip_common *msg,
			struct hip_locator_info_addr_item *addresses,
			int address_count)
{
	int err = 0;
	struct hip_locator *locator_info = NULL;
	int addrs_len = address_count *
		(sizeof(struct hip_locator_info_addr_item));

	HIP_IFE(!(locator_info =
		  malloc(sizeof(struct hip_locator) + addrs_len)), -1);

	hip_set_param_type(locator_info, HIP_PARAM_LOCATOR);
	hip_calc_generic_param_len(locator_info,
				   sizeof(struct hip_locator),
				   addrs_len);
	_HIP_DEBUG("params size=%d\n", sizeof(struct hip_locator) -
		   sizeof(struct hip_tlv_common) +
		   addrs_len);

	memcpy(locator_info + 1, addresses, addrs_len);
	HIP_IFE(hip_build_param(msg, locator_info), -1);

	_HIP_DEBUG("msgtotlen=%d addrs_len=%d\n", hip_get_msg_total_len(msg),
		   addrs_len);
	//if (addrs_len > 0)
	//	memcpy((void *)msg+hip_get_msg_total_len(msg)-addrs_len,
	//	       addresses, addrs_len);

 out_err:
	if (locator_info)
		free(locator_info);

	return err;
}
#endif /* !__KERNEL__ */

/**
 * hip_build_param_keys - build and append crypto keys parameter
 * \addtogroup params
 * @{ \todo Properly comment parameters of hip_build_param_keys() @}
 * @param msg the message where the parameter will be appended
 * @param operation_id no description
 * @param alg_id no desription
 * @param addr no description
 * @param hit no description
 * @param spi no description
 * @param spi_old no description
 * @param key_len no description
 * @param enc encryption key
 * 
 * @return 0 on success, otherwise < 0.
 */	 
int hip_build_param_keys(struct hip_common *msg, uint16_t operation_id, 
						uint16_t alg_id, struct in6_addr *addr,
						struct in6_addr *hit, struct in6_addr *peer_hit, uint32_t spi, uint32_t spi_old,
						uint16_t key_len, struct hip_crypto_key *enc)
{
	int err = 0;
	struct hip_keys keys;

	hip_set_param_type(&keys, HIP_PARAM_KEYS);
	hip_calc_generic_param_len(&keys, sizeof(struct hip_keys), 0);
	
	
	memcpy((struct in6_addr *)&keys.address, addr, 16);
	memcpy((struct in6_addr *)&keys.hit, hit, 16);
        memcpy((struct in6_addr *)&keys.peer_hit, peer_hit, 16);		
	keys.operation = htons(operation_id);
	keys.alg_id = htons(alg_id);	
	keys.spi = htonl(spi);
	keys.spi_old = htonl(spi_old);
	keys.key_len = htons(key_len);
	memcpy(&keys.enc, enc, sizeof(struct hip_crypto_key));
	
	err = hip_build_param(msg, &keys);
	return err;
}

int hip_build_param_keys_hdr(struct hip_keys *keys, uint16_t operation_id, 
						uint16_t alg_id, struct in6_addr *addr,
						struct in6_addr *hit, struct in6_addr *peer_hit, uint32_t spi, uint32_t spi_old,
						uint16_t key_len, struct hip_crypto_key *enc)
{
	int err = 0;

	hip_set_param_type(keys, HIP_PARAM_KEYS);
	hip_calc_generic_param_len(keys, sizeof(struct hip_keys), 0);
	
	memcpy((struct in6_addr *)keys->address, addr, 16);
	memcpy((struct in6_addr *)keys->hit, hit, 16);		
        memcpy((struct in6_addr *)keys->peer_hit, peer_hit, 16);                
	keys->operation = htons(operation_id);
	keys->alg_id = htons(alg_id);	
	keys->spi = htonl(spi);
	keys->spi_old = htonl(spi_old);
	keys->key_len = htons(key_len);
	memcpy(&keys->enc, enc, sizeof(struct hip_crypto_key));
	
	return err;
}

/**
 * hip_build_param_seq - build and append HIP SEQ parameter
 * @param msg the message where the parameter will be appended
 * @param update_id Update ID
 * 
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_seq(struct hip_common *msg, uint32_t update_id)
{
	int err = 0;
	struct hip_seq seq;

	hip_set_param_type(&seq, HIP_PARAM_SEQ);
	hip_calc_generic_param_len(&seq, sizeof(struct hip_seq), 0);
	seq.update_id = htonl(update_id);
	err = hip_build_param(msg, &seq);
	return err;
}

/**
 * hip_build_param_ack - build and append HIP ACK parameter
 * @param msg the message where the parameter will be appended
 * @param peer_update_id peer Update ID
 * 
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_ack(struct hip_common *msg, uint32_t peer_update_id)
{
        int err = 0;
        struct hip_ack ack;

        hip_set_param_type(&ack, HIP_PARAM_ACK);
        hip_calc_generic_param_len(&ack, sizeof(struct hip_ack), 0);
        ack.peer_update_id = htonl(peer_update_id);
        err = hip_build_param(msg, &ack);
        return err;
}

/**
 * hip_build_param_unit_test - build and insert an unit test parameter
 * @param msg the message where the parameter will be appended
 * @param suiteid the id of the test suite
 * @param caseid the id of the test case
 *
 * This parameter is used for triggering the unit test suite in the kernel.
 * It is only for implementation internal purposes only.
 *
 * @return 0 on success, otherwise < 0.
 */
int hip_build_param_unit_test(struct hip_common *msg, uint16_t suiteid,
			      uint16_t caseid)
{
	int err = 0;
	struct hip_unit_test ut;

	hip_set_param_type(&ut, HIP_PARAM_UNIT_TEST);
	hip_calc_generic_param_len(&ut, sizeof(struct hip_unit_test), 0);
	ut.suiteid = htons(suiteid);
	ut.caseid = htons(caseid);

	err = hip_build_param(msg, &ut);
	return err;
}

/**
 * hip_build_param_esp_info - build esp_info parameter
 * \addtogroup params
 * @{ \todo Properly comment parameters of hip_build_param_esp_info() @}
 *
 * @param msg the message where the parameter will be appended
 * @param keymat_index no desription
 * @param old_spi no description
 * @param new_spi no description
 * 
 * @return zero on success, or negative on failure
 */
int hip_build_param_esp_info(struct hip_common *msg, uint16_t keymat_index,
			     uint32_t old_spi, uint32_t new_spi)
{
	int err = 0;
	struct hip_esp_info esp_info;
	_HIP_DEBUG("Add SPI old: 0x%x (nwbo: 0x%x), new: 0x%x (nwbo: 0x%x)\n", 
		old_spi, htonl(old_spi), new_spi, htonl(new_spi));
	hip_set_param_type(&esp_info, HIP_PARAM_ESP_INFO);
	hip_calc_generic_param_len(&esp_info, sizeof(struct hip_esp_info), 0);
	esp_info.reserved = htonl(0);
	esp_info.keymat_index = htons(keymat_index);
	esp_info.old_spi = htonl(old_spi);
	esp_info.new_spi = htonl(new_spi);
	_HIP_DEBUG("esp param old: 0x%x , new: 0x%x \n",
		  esp_info.old_spi, esp_info.new_spi); 

	_HIP_DEBUG("keymat index = %d\n", keymat_index);
	_HIP_HEXDUMP("esp_info:", &esp_info, sizeof(struct hip_esp_info));
	err = hip_build_param(msg, &esp_info);
	return err;
}

#if 0
/**
 * hip_build_param_spi - build the SPI parameter
 * @param msg the message where the parameter will be appended
 * @param lsi the value of the lsi (in host byte order)
 * @param spi the value of the spi (in host byte order)
 * 
 * XX FIXME: Obsoleted by esp_info in draft-jokela-hip-00
 *
 * @return zero on success, or negative on failure
 */
int hip_build_param_spi(struct hip_common *msg, uint32_t spi)
{
        int err = 0;
        struct hip_spi hspi;

        hip_set_param_type(&hspi, HIP_PARAM_ESP_INFO);
        hip_calc_generic_param_len(&hspi, sizeof(struct hip_spi), 0);
        hspi.spi = htonl(spi);

        err = hip_build_param(msg, &hspi);
        return err;
}
#endif


/**
 * 
 */
/*int hip_build_param_encrypted(struct hip_common *msg,
					struct hip_tlv_common *param) 
{
	//TODO
	return 0;
}*/


/**
 * hip_build_param_encrypted_3des_sha1 - build the hip_encrypted parameter
 * @param msg the message where the parameter will be appended
 * @param param the parameter that will contained in the hip_encrypted
 *           parameter
 * 
 * Note that this function does not actually encrypt anything, it just builds
 * the parameter. The parameter that will be encapsulated in the hip_encrypted
 * parameter has to be encrypted using a different function call.
 *
 * Returns: zero on success, or negative on failure
 */
int hip_build_param_encrypted_3des_sha1(struct hip_common *msg,
					struct hip_tlv_common *param)
{
	int err = 0;
	struct hip_encrypted_3des_sha1 enc;

	hip_set_param_type(&enc, HIP_PARAM_ENCRYPTED);
	hip_calc_param_len(&enc, sizeof(enc) -
			   sizeof(struct hip_tlv_common) +
			   hip_get_param_total_len(param));
	enc.reserved = htonl(0);
	memset(&enc.iv, 0, 8);

	/* copy the IV *IF* needed, and then the encrypted data */

	err = hip_build_generic_param(msg, &enc, sizeof(enc), param);

	return err;
}

/**
 * hip_build_param_encrypted_null_sha1 - build the hip_encrypted parameter
 * @param msg the message where the parameter will be appended
 * @param param the parameter that will contained in the hip_encrypted
 *           parameter
 * 
 * Note that this function does not actually encrypt anything, it just builds
 * the parameter. The parameter that will be encapsulated in the hip_encrypted
 * parameter has to be encrypted using a different function call.
 *
 * Returns: zero on success, or negative on failure
 */
int hip_build_param_encrypted_null_sha1(struct hip_common *msg,
 					struct hip_tlv_common *param)
{
	int err = 0;
 	struct hip_encrypted_null_sha1 enc;

 	hip_set_param_type(&enc, HIP_PARAM_ENCRYPTED);
 	hip_calc_param_len(&enc, sizeof(enc) -
 			   sizeof(struct hip_tlv_common) +
 			   hip_get_param_total_len(param));
 	enc.reserved = htonl(0);

 	/* copy the IV *IF* needed, and then the encrypted data */

 	err = hip_build_generic_param(msg, &enc, sizeof(enc), param);

 	return err;
}

void hip_build_param_host_id_hdr(struct hip_host_id *host_id_hdr,
				 const char *hostname,
				 hip_tlv_len_t rr_data_len,
                                 uint8_t algorithm)
{
	uint16_t hi_len = sizeof(struct hip_host_id_key_rdata) + rr_data_len;
	uint16_t fqdn_len;

        /* reserve 1 byte for NULL termination */
	if (hostname)
		fqdn_len = (strlen(hostname) + 1) & 0x0FFF;
	else
		fqdn_len = 0;

	host_id_hdr->hi_length = htons(hi_len);
	/* length = 12 bits, di_type = 4 bits */
	host_id_hdr->di_type_length = htons(fqdn_len | 0x1000);
	/* if the length is 0, then the type should also be zero */
	if (host_id_hdr->di_type_length == ntohs(0x1000))
		host_id_hdr->di_type_length = 0;

        hip_set_param_type(host_id_hdr, HIP_PARAM_HOST_ID);
        hip_calc_generic_param_len(host_id_hdr, sizeof(struct hip_host_id),
				   hi_len -
				   sizeof(struct hip_host_id_key_rdata) +
				   fqdn_len);

        host_id_hdr->rdata.flags = htons(0x0202); /* key is for a host */
        host_id_hdr->rdata.protocol = 0xFF; /* RFC 2535 */
	/* algo is 8 bits, no htons */
        host_id_hdr->rdata.algorithm = algorithm;

	_HIP_DEBUG("hilen=%d totlen=%d contlen=%d\n",
		   ntohs(host_id_hdr->hi_length),
		   hip_get_param_contents_len(host_id_hdr),
		   hip_get_param_total_len(host_id_hdr));
}

void hip_build_param_host_id_only(struct hip_host_id *host_id,
				    const void *rr_data,
				    const char *fqdn)
{
	unsigned int rr_len = ntohs(host_id->hi_length) -
		sizeof(struct hip_host_id_key_rdata);
	char *ptr = (char *) (host_id + 1);
	uint16_t fqdn_len;

	_HIP_DEBUG("hi len: %d\n", ntohs(host_id->hi_length));
	_HIP_DEBUG("Copying %d bytes\n", rr_len);

	memcpy(ptr, rr_data, rr_len);
	ptr += rr_len;

	fqdn_len = ntohs(host_id->di_type_length) & 0x0FFF;
	_HIP_DEBUG("fqdn len: %d\n", fqdn_len);
	if (fqdn_len)
		memcpy(ptr, fqdn, fqdn_len);
}

/**
 * hip_build_param_host_id - build and append host id into message
 * \addtogroup params
 * @{ \todo Comment parameters of hip_build_param_host_id() @}
 *
 */
int hip_build_param_host_id(struct hip_common *msg,
			    struct hip_host_id *host_id_hdr,
			    const void *rr_data,
			    const char *fqdn)
{
	int err = 0;
	hip_build_param_host_id_only(host_id_hdr, rr_data, fqdn);
        err = hip_build_param(msg, host_id_hdr);
	return err;
}

int hip_get_param_host_id_di_type_len(struct hip_host_id *host, char **id, int *len)
{
	int type;
	static char *debuglist[3] = {"none", "FQDN", "NAI"};

	type = ntohs(host->di_type_length);
	*len = type & 0x0FFF;
	type = (type & 0xF000) >> 12;

	if (type > 2) {
		HIP_ERROR("Illegal DI-type: %d\n",type);
		return -1;
	}

	*id = debuglist[type];
	return 0;
}

char *hip_get_param_host_id_hostname(struct hip_host_id *hostid)
{
	int hilen;
	char *ptr;

	hilen = ntohs(hostid->hi_length) - sizeof(struct hip_host_id_key_rdata);
	_HIP_DEBUG("Hilen: %d\n",hilen);
	ptr = (char *)(hostid + 1) + hilen;
	return ptr;
}

/*
 * - endpoint is not padded
 */
void hip_build_endpoint_hdr(struct endpoint_hip *endpoint_hdr,
			    const char *hostname,
			    se_hip_flags_t endpoint_flags,
			    uint8_t host_id_algo,
			    unsigned int rr_data_len)
{
	hip_build_param_host_id_hdr(&endpoint_hdr->id.host_id,
				    hostname, rr_data_len, host_id_algo);
	endpoint_hdr->family = PF_HIP;
	/* The length is not hip-length-padded, so it has be calculated
	   manually. sizeof(hip_host_id) is already included both in the
	   sizeof(struct endpoint_hip) and get_total_len(), so it has be
	   subtracted once. */
	endpoint_hdr->length = sizeof(struct endpoint_hip) +
		hip_get_param_total_len(&endpoint_hdr->id.host_id) -
		sizeof(struct hip_host_id);
	endpoint_hdr->flags = endpoint_flags;
	endpoint_hdr->algo = host_id_algo;
	_HIP_DEBUG("%d %d %d\n",
		  sizeof(struct endpoint_hip),
		  hip_get_param_total_len(&endpoint_hdr->id.host_id),
		  sizeof(struct hip_host_id));
	_HIP_DEBUG("endpoint hdr length: %d\n", endpoint_hdr->length);
}

/*
 * - endpoint is not padded
 * - caller is responsible of reserving enough mem for endpoint
 */
void hip_build_endpoint(struct endpoint_hip *endpoint,
			const struct endpoint_hip *endpoint_hdr,
			const char *hostname,
			const unsigned char *key_rr,
			unsigned int key_rr_len)
{
	_HIP_DEBUG("len=%d ep=%d rr=%d hostid=%d\n",
		  endpoint_hdr->length,
		  sizeof(struct endpoint_hip),
		  key_rr_len,
		  sizeof(struct hip_host_id));
	HIP_ASSERT(endpoint_hdr->length == sizeof(struct endpoint_hip) +
		   hip_get_param_total_len(&endpoint_hdr->id.host_id) -
		   sizeof(struct hip_host_id));
	memcpy(endpoint, endpoint_hdr, sizeof(struct endpoint_hip));
	hip_build_param_host_id_only(&endpoint->id.host_id, key_rr, hostname);
}

int hip_build_param_eid_endpoint_from_host_id(struct hip_common *msg,
					   const struct endpoint_hip *endpoint)
{
	int err = 0;

	HIP_ASSERT(!(endpoint->flags & HIP_ENDPOINT_FLAG_HIT));

	err = hip_build_param_contents(msg, endpoint, HIP_PARAM_EID_ENDPOINT,
				       endpoint->length);
	return err;
}

int hip_build_param_eid_endpoint_from_hit(struct hip_common *msg,
					  const struct endpoint_hip *endpoint)
{
	struct hip_eid_endpoint eid_endpoint;
	int err = 0;

	HIP_ASSERT(endpoint->flags & HIP_ENDPOINT_FLAG_HIT);

	hip_set_param_type(&eid_endpoint, HIP_PARAM_EID_ENDPOINT);

	hip_calc_param_len(&eid_endpoint,
			   sizeof(struct hip_eid_endpoint) -
			   sizeof (struct hip_tlv_common));

	memcpy(&eid_endpoint.endpoint, endpoint, sizeof(struct endpoint_hip));

	err = hip_build_param(msg, &eid_endpoint);

	return err;
}

/* 
 * hip_build_param_eid_endpoint - build eid endpoint parameter
 * @param msg the message where the eid endpoint paramater will be appended
 * @param endpoint the endpoint to be wrapped into the eid endpoint structure
 * @param port the dst/src port used for the endpoint 
 * 
 * Used for passing endpoints to the kernel. The endpoint is wrapped into
 * an eid endpoint structure because endpoint_hip is not padded but all
 * parameter need to be padded in the builder interface.
 */
int hip_build_param_eid_endpoint(struct hip_common *msg,
				 const struct endpoint_hip *endpoint)
{
	int err = 0;

	if (endpoint->flags & HIP_ENDPOINT_FLAG_HIT) {
		err = hip_build_param_eid_endpoint_from_hit(msg, endpoint);
	} else {
		err = hip_build_param_eid_endpoint_from_host_id(msg, endpoint);
	}
	_HIP_DEBUG("err=%d\n", err);
	return err;
}


int hip_host_id_entry_to_endpoint(struct hip_host_id_entry *entry, struct hip_common *msg)
{
	struct endpoint_hip endpoint;
	int err = 0;

	endpoint.family = PF_HIP;	
	endpoint.length = sizeof(struct endpoint_hip); 	
	endpoint.flags = HIP_ENDPOINT_FLAG_HIT;	
	endpoint.algo= entry->lhi.algo;
	endpoint.algo=hip_get_host_id_algo(entry->host_id);
	ipv6_addr_copy(&endpoint.id.hit, &entry->lhi.hit);
		
	HIP_IFEL(hip_build_param_eid_endpoint(msg, &endpoint), -1, "build error\n");

  out_err:
	return err;
}

int hip_build_param_eid_iface(struct hip_common *msg,
			      hip_eid_iface_type_t if_index)
{
	int err = 0;
	struct hip_eid_iface param;

	hip_set_param_type(&param, HIP_PARAM_EID_IFACE);
	hip_calc_generic_param_len(&param, sizeof(param), 0);
	param.if_index = htons(if_index);
	err = hip_build_param(msg, &param);

	return err;
}

int hip_build_param_eid_sockaddr(struct hip_common *msg,
                                 struct sockaddr *sockaddr,
                                 size_t sockaddr_len)
{
        int err = 0;
	_HIP_DEBUG("build family=%d, len=%d\n", sockaddr->sa_family,
		   sockaddr_len);
        err = hip_build_param_contents(msg, sockaddr, HIP_PARAM_EID_SOCKADDR,
                                       sockaddr_len);
        return err;
}

/**
 * Builds a NOTIFICATION parameter.
 * 
 * @param msg              a pointer to the message where the parameter will be
 *                         appended
 * @param msgtype          NOTIFY message type
 * @param notification     the Notification data that will contained in the HIP
 *                         NOTIFICATION parameter
 * @param notification_len length of @c notification_data
 *
 * @return zero on success, or negative on failure
 */
int hip_build_param_notification(struct hip_common *msg, uint16_t msgtype,
				 void *data, size_t data_len)
{
	int err = 0;
	struct hip_notification notification;
	
	hip_set_param_type(&notification, HIP_PARAM_NOTIFICATION);
	hip_calc_param_len(&notification, sizeof(struct hip_notification) -
			   sizeof(struct hip_tlv_common) +
			   data_len);
	notification.reserved = 0;
	notification.msgtype = htons(msgtype);

	err = hip_build_generic_param(msg, &notification,
				      sizeof(struct hip_notification),
				      data);
	return err;
}

int hip_build_netlink_dummy_header(struct hip_common *msg)
{
	return hip_build_user_hdr(msg, SO_HIP_NETLINK_DUMMY, 0);
}

int hip_build_param_blind_nonce(struct hip_common *msg, uint16_t nonce)
{
	struct hip_blind_nonce param;
	int err = 0;

	hip_set_param_type(&param, HIP_PARAM_BLIND_NONCE);
	hip_calc_generic_param_len(&param, sizeof(param), 0);	
	param.nonce = htons(nonce);
	err = hip_build_param(msg, &param);

	return err;
}

int hip_build_param_opendht_gw_info(struct hip_common *msg,
				    struct in6_addr *addr,
				    uint32_t ttl,
				    uint16_t port)
{
	int err = 0;
	struct hip_opendht_gw_info gw_info;
	
	hip_set_param_type(&gw_info, HIP_PARAM_OPENDHT_GW_INFO);
	hip_calc_param_len(&gw_info,
			   sizeof(struct hip_opendht_gw_info) -
			   sizeof(struct hip_tlv_common));
	gw_info.ttl = ttl;
	gw_info.port = htons(port);
	ipv6_addr_copy(&gw_info.addr, addr);
	err = hip_build_param(msg, &gw_info);
	return err;
}

int dsa_to_hip_endpoint(DSA *dsa, struct endpoint_hip **endpoint,
			se_hip_flags_t endpoint_flags, const char *hostname)
{
  int err = 0;
  unsigned char *dsa_key_rr = NULL;
  int dsa_key_rr_len;
  struct endpoint_hip endpoint_hdr;

  _HIP_DEBUG("dsa_to_hip_endpoint called\n");

  dsa_key_rr_len = dsa_to_dns_key_rr(dsa, &dsa_key_rr);
  if (dsa_key_rr_len <= 0) {
    HIP_ERROR("dsa_key_rr_len <= 0\n");
    err = -ENOMEM;
    goto out_err;
  }

  /* build just an endpoint header to see how much memory is needed for the
     actual endpoint */
  hip_build_endpoint_hdr(&endpoint_hdr, hostname, endpoint_flags,
			 HIP_HI_DSA, dsa_key_rr_len);

  *endpoint = malloc(endpoint_hdr.length);
  if (!(*endpoint)) {
    err = -ENOMEM;
    goto out_err;
  }
  memset(*endpoint, 0, endpoint_hdr.length);

  _HIP_DEBUG("Allocated %d bytes for endpoint\n", endpoint_hdr.length);
  hip_build_endpoint(*endpoint, &endpoint_hdr, hostname,
		     dsa_key_rr, dsa_key_rr_len);
  _HIP_HEXDUMP("endpoint contains: ", *endpoint, endpoint_hdr.length);

 out_err:

  if (dsa_key_rr)
    free(dsa_key_rr);

  return err;
}

int rsa_to_hip_endpoint(RSA *rsa, struct endpoint_hip **endpoint,
			se_hip_flags_t endpoint_flags, const char *hostname)
{
  int err = 0;
  unsigned char *rsa_key_rr = NULL;
  int rsa_key_rr_len;
  struct endpoint_hip endpoint_hdr;

  HIP_DEBUG("rsa_to_hip_endpoint called\n");

  rsa_key_rr_len = rsa_to_dns_key_rr(rsa, &rsa_key_rr);
  if (rsa_key_rr_len <= 0) {
    HIP_ERROR("rsa_key_rr_len <= 0\n");
    err = -ENOMEM;
    goto out_err;
  }

  /* build just an endpoint header to see how much memory is needed for the
     actual endpoint */
  hip_build_endpoint_hdr(&endpoint_hdr, hostname, endpoint_flags,
			 HIP_HI_RSA, rsa_key_rr_len);

    *endpoint = malloc(endpoint_hdr.length);
  if (!(*endpoint)) {
    err = -ENOMEM;
    goto out_err;
  }
  memset(*endpoint, 0, endpoint_hdr.length);

  _HIP_DEBUG("Allocated %d bytes for endpoint\n", endpoint_hdr.length);

  hip_build_endpoint(*endpoint, &endpoint_hdr, hostname,
		     rsa_key_rr, rsa_key_rr_len);
			   
  _HIP_HEXDUMP("endpoint contains: ", *endpoint, endpoint_hdr.length);

 out_err:

  if (rsa_key_rr)
    free(rsa_key_rr);

  return err;
}

int alloc_and_set_host_id_param_hdr(struct hip_host_id **host_id,
				    unsigned int key_rr_len,
				    uint8_t algo,
				    const char *hostname)
{
  int err = 0;
  struct hip_host_id host_id_hdr;

  hip_build_param_host_id_hdr(&host_id_hdr, hostname,
			      key_rr_len, algo);

  *host_id = malloc(hip_get_param_total_len(&host_id_hdr));
  if (!host_id) {
    err = -ENOMEM;
  }  

  memcpy(*host_id, &host_id_hdr, sizeof(host_id_hdr));

  return err;
}

int alloc_and_build_param_host_id_only(struct hip_host_id **host_id,
				       unsigned char *key_rr, int key_rr_len,
				       int algo, char *hostname) {
  int err = 0;

  HIP_IFEL(alloc_and_set_host_id_param_hdr(host_id, key_rr_len, algo,
					   hostname), -1, "alloc\n");
  hip_build_param_host_id_only(*host_id, key_rr, "hostname");

 out_err:
  if (err && *host_id) {
    *host_id = NULL;
    HIP_FREE(host_id);
  }

  return err;
}

/* Note: public here means that you only have the public key,
   not the private */
int hip_any_key_to_hit(void *any_key, unsigned char *any_key_rr, int hit_type,
		       hip_hit_t *hit, int is_public, int is_dsa) {
  int err = 0, key_rr_len;
  unsigned char *key_rr = NULL;
  char hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
  struct hip_host_id *host_id = NULL;
  RSA *rsa_key = (RSA *) any_key;
  DSA *dsa_key = (DSA *) any_key;

  memset(hostname, 0, HIP_HOST_ID_HOSTNAME_LEN_MAX);
  HIP_IFEL(gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1), -1,
  	   "gethostname failed\n");

  if (is_dsa) {
    HIP_IFEL(((key_rr_len = dsa_to_dns_key_rr(dsa_key, &key_rr)) <= 0), -1,
	     "key_rr_len\n");
    HIP_IFEL(alloc_and_build_param_host_id_only(&host_id, key_rr, key_rr_len,
						HIP_HI_DSA, hostname), -1,
	     "alloc\n");
    if (is_public) {
      HIP_IFEL(hip_dsa_host_id_to_hit(host_id, hit, HIP_HIT_TYPE_HASH100),
	       -1, "conversion from host id to hit failed\n");
    } else {
      HIP_IFEL(hip_private_dsa_host_id_to_hit(host_id, hit,
					      HIP_HIT_TYPE_HASH100),
	       -1, "conversion from host id to hit failed\n");
    }
  } else /* rsa */ {
    HIP_IFEL(((key_rr_len = rsa_to_dns_key_rr(rsa_key, &key_rr)) <= 0), -1,
	     "key_rr_len\n");
    HIP_IFEL(alloc_and_build_param_host_id_only(&host_id, key_rr, key_rr_len,
						HIP_HI_RSA, hostname), -1,
	     "alloc\n");
    if (is_public) {
      HIP_IFEL(hip_rsa_host_id_to_hit(host_id, hit, HIP_HIT_TYPE_HASH100),
	       -1, "conversion from host id to hit failed\n");
    } else {
      HIP_IFEL(hip_private_rsa_host_id_to_hit(host_id, hit,
					      HIP_HIT_TYPE_HASH100),
	       -1, "conversion from host id to hit failed\n");
    }
  }

   HIP_DEBUG_HIT("hit", hit);
   HIP_DEBUG("hi is %s %s\n", (is_public ? "public" : "private"),
	     (is_dsa ? "dsa" : "rsa"));

 out_err:

  if (key_rr)
    HIP_FREE(key_rr);
  if (host_id)
    HIP_FREE(host_id);

  return err;
}

int hip_public_rsa_to_hit(RSA *rsa_key, unsigned char *rsa, int type,
			  struct in6_addr *hit) {
  return hip_any_key_to_hit(rsa_key, rsa, type, hit, 1, 0);
}

int hip_private_rsa_to_hit(RSA *rsa_key, unsigned char *rsa, int type,
			  struct in6_addr *hit) {
  return hip_any_key_to_hit(rsa_key, rsa, type, hit, 0, 0);
}

int hip_public_dsa_to_hit(DSA *dsa_key, unsigned char *dsa, int type,
			  struct in6_addr *hit) {
  return hip_any_key_to_hit(dsa_key, dsa, type, hit, 1, 1);
}

int hip_private_dsa_to_hit(DSA *dsa_key, unsigned char *dsa, int type,
			   struct in6_addr *hit) {
  return hip_any_key_to_hit(dsa_key, dsa, type, hit, 0, 1);
}
