/*
 * Building and parsing functions for hipd (and later for hip) messages.
 * These functions work both in the userspace and in the kernel. Keep in mind
 * the following things when using the builder:
 * - Never access members of hip_common and hip_tlv_common directly. Use
 *   the accessor functions to hide byte ordering and length manipulation.
 * - Remember always to use __attribute__ ((packed)) (see hip.h) with builder
 *   because compiler adds padding into the structures.
 * - This file is shared between userspace and kernel: do not put any memory
 *   allocations or other kernel/userspace specific stuff into here!
 * - If you build more functions like build_signature2_contents(), remember
 *   to use hip_build_generic_param() in them!
 * - Macros for doing ntohs() and htons() conversion? Currently they are
 *   used in a platform dependent way.
 * - Why does build network header return void whereas build daemon does not?
 * - There is a small TODO list in hip_build_network_hdr()
 *
 * Authors:
 * - Miika Komu <miika@iki.fi>
 * - Mika Kousa <mkousa@cc.hut.fi>
 *
 * USAGE EXAMPLES:
 * - sender of "add mapping", i.e. the hip module in kernel
 *   - struct hip_common *msg = k/malloc(HIP_MAX_PACKET);
 *   - hip_msg_init(msg);
 *   - err = hip_build_user_hdr(msg, HIP_USER_ADD_MAP_HIT_IP, 0);
 *   - err = hip_build_param_contents(msg, &hit,
 *             HIP_PARAM_HIT, sizeof(struct in6_addr));
 *   - err = hip_build_param_contents(msg, &ip,
 *             HIP_PARAM_IPV6_ADDR, sizeof(struct in6_addr));
 *   - send the message to user space
 * - receiver of "add mapping", i.e. the daemon
 *   - struct hip_common *msg = k/malloc(HIP_MAX_PACKET);
 *   - receive the message from kernel
 *   - if (msg->err) goto_error_handler;
 *   - hit = (struct in6addr *) hip_get_param_contents(msg, HIP_PARAM_HIT);
 *     - note: hit can be null, if the param was not found
 *   - ip = (struct in6addr *) hip_get_param_object(msg, HIP_PARAM_IPV6ADDR);
 *     - note: hit can be null
 * - note: in network packets, you should use hip_build_network_hdr()
 *   instead of hip_build_user_hdr() !
 *
 * TODO:
 * - add validation functions for host_id, host_id_eid
 * - move hip_builder.h to this dir
 * - a separate function for accessing parameters with same id (i.e. you
 *   give the "current" point of searching in the message)
 * - consider embbedding hip_tlv_common in all parameter structs in hip.h?
 * - alignment
 *   - Building of generic parameter should be done using array copy instead
 *     of memcpy()? Memcpy might involve some performance penalties when
 *     trying to read/write unaligned data.
 *   - should we have a get_sizeof_param(param_type) function instead
 *     of just relying on packed structures?
 * - consider supporting vararg for build_param()?
 *   - this complicates things too much.. especially in parsing
 * - unit tests for builder.c
 * - set the version number to something bizarre in hip daemon header builder
 *   so that e.g. dumper can tell the difference between daemon and network
 *   headers
 * - hip_dump_msg() should display also network headers
 * - uncomment commented assertions and test them
 * - Can {daemon|network} header be built before other headers?
 * - fix: get/set msg type err network byte order
 * - a new header for hipd messages? hip_daemon_msg etc.
 * - some of the builder functions could be named better
 *
 * BUGS:
 * - 
 */

#include "builder.h"
#include "debug.h"

/**
 * hip_msg_init - initialize a network/daemon message
 * @msg: the message to be initialized
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
 * Return: initialized HIP packet if successful, %NULL on error.
 */
struct hip_common *hip_msg_alloc(void)
{
        struct hip_common *ptr;

#ifdef __KERNEL__
        ptr = (struct hip_common *) kmalloc(HIP_MAX_PACKET, GFP_ATOMIC);
#else
        ptr = (struct hip_common *) malloc(HIP_MAX_PACKET);
#endif /* __KERNEL__ */
        if (!ptr)
                return NULL;
        hip_msg_init(ptr);
        return ptr;
}

/**
 * hip_msg_free - deallocate a HIP packet
 * @msg: the packet to be deallocated
 */
void hip_msg_free(struct hip_common *msg)
{
#ifdef __KERNEL__
  kfree(msg);
#else
  free(msg);
#endif /* __KERNEL__ */
}

/**
 * hip_convert_msg_total_len_to_bytes - convert message total length to bytes
 * @len: the length of the HIP header as it is in the header
 *       (in host byte order) 
 *
 * Returns: the real size of HIP header in bytes (host byte order)
 */
uint16_t hip_convert_msg_total_len_to_bytes(hip_hdr_len_t len) {
	return (len == 0) ? 0 : ((len + 1) << 3);
}

/**
 * hip_get_msg_total_len - get the real, total size of the header in bytes
 * @msg: pointer to the beginning of the message header
 *
 * Returns: the real, total size of the message in bytes (host byte order).
 */
uint16_t hip_get_msg_total_len(const struct hip_common *msg) {
	return hip_convert_msg_total_len_to_bytes(msg->payload_len);
}

/**
 * hip_get_msg_contents_len - get message size excluding type and length
 * @msg: pointer to the beginning of the message header
 *
 * Returns: the real, total size of the message in bytes (host byte order)
 *          excluding the the length of the type and length fields
 */
uint16_t hip_get_msg_contents_len(const struct hip_common *msg) {
	HIP_ASSERT(hip_get_msg_total_len(msg) >=
		   sizeof(struct hip_common));
	return hip_get_msg_total_len(msg) - sizeof(struct hip_common);
}

/**
 * hip_set_msg_total_len - set the total message length in bytes
 * @msg: pointer to the beginning of the message header
 * @len: the total size of the message in bytes (host byte order)
 */
void hip_set_msg_total_len(struct hip_common *msg, uint16_t len) {
	/* assert len % 8 == 0 ? */
	msg->payload_len = (len < 8) ? 0 : ((len >> 3) - 1);
}

/**
 * hip_get_msg_type - get the type of the message in host byte order
 * @msg: pointer to the beginning of the message header
 *
 * Returns: the type of the message (in host byte order)
 *
 */
hip_hdr_type_t hip_get_msg_type(const struct hip_common *msg) {
	return msg->type_hdr;
}

/**
 * hip_set_msg_type - set the type of the message
 * @msg:  pointer to the beginning of the message header
 * @type: the type of the message (in host byte order)
 *
 */
void hip_set_msg_type(struct hip_common *msg, hip_hdr_type_t type) {
	msg->type_hdr = type;
}

/**
 * hip_get_msg_err - get the error values from daemon message header
 * @msg: pointer to the beginning of the message header
 *
 * Returns: the error value from the message (in host byte order)
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
 * @msg: pointer to the beginning of the message header
 * @err: the error value
 */
void hip_set_msg_err(struct hip_common *msg, hip_hdr_err_t err) {
	/* note: error value is stored in checksum field for daemon messages */
	msg->checksum = err;
}

/**
 * hip_zero_msg_checksum - zero message checksum
 */
void hip_zero_msg_checksum(struct hip_common *msg) {
	msg->checksum = 0;
}


/**
 * hip_get_param_total_len - get total size of message parameter
 * @tlv_common: pointer to the parameter
 *
 * Returns: the total length of the parameter in bytes (host byte
 * order), including the padding.
 */
hip_tlv_len_t hip_get_param_total_len(const void *tlv_common) {
	return HIP_LEN_PAD(sizeof(struct hip_tlv_common) +
			   ntohs(((const struct hip_tlv_common *)
				  tlv_common)->length));
}

/**
 * hip_get_param_contents_len - get the size of the parameter contents
 * @tlv_common: pointer to the parameter
 *
 * Returns: the length of the parameter in bytes (in host byte order),
 *          excluding padding and the length of "type" and "length" fields
 */
hip_tlv_len_t hip_get_param_contents_len(const void *tlv_common) {
	return ntohs(((const struct hip_tlv_common *)tlv_common)->length);
}

/**
 * hip_set_param_contents_len - set parameter length
 * @tlv_common: pointer to the parameter
 * @len:        the length of the parameter in bytes (in host byte order),
 *              excluding padding and the length of "type" and "length" fields
 */
void hip_set_param_contents_len(void *tlv_common,
				hip_tlv_len_t len) {
	((struct hip_tlv_common *)tlv_common)->length = htons(len);
}

/**
 * hip_get_param_type - get type of parameter
 * @tlv_common: pointer to the parameter
 *
 * Returns: The type of the parameter (in host byte order).
 */
hip_tlv_type_t hip_get_param_type(const void *tlv_common) {
	return ntohs(((const struct hip_tlv_common *)tlv_common)->type);
}

/**
 * hip_set_param_type - set parameter type
 * @tlv_common: pointer to the parameter
 * @type: type of the parameter (in host byte order)
 */
void hip_set_param_type(void *tlv_common, hip_tlv_type_t type) {
	((struct hip_tlv_common *)tlv_common)->type = htons(type);
}

/**
 * hip_get_diffie_hellman_param_public_value_contents - get dh public value contents
 * @tlv_common: pointer to the dh parameter
 *
 * Returns: pointer to the public value of Diffie-Hellman parameter
 */
void *hip_get_diffie_hellman_param_public_value_contents(const void *tlv_common) {
	return (void *) tlv_common + sizeof(struct hip_diffie_hellman);
}

/**
 * hip_get_diffie_hellman_param_public_value_len - get dh public value real length
 * @dh: pointer to the Diffie-Hellman parameter
 *
 * Returns: the length of the public value Diffie-Hellman parameter in bytes
 *          (in host byte order).
 */
hip_tlv_len_t hip_get_diffie_hellman_param_public_value_len(const struct hip_diffie_hellman *dh)
{
	return hip_get_param_contents_len(dh) - sizeof(uint8_t);
}

/**
 * hip_set_param_spi_value - set the spi value in spi_lsi parameter
 * @spi_lsi: the spi_lsi parameter
 * @spi:     the value of the spi in the spi_lsi value in host byte order
 *
 */
void hip_set_param_spi_value(struct hip_spi *hspi, uint32_t spi)
{
	hspi->spi = htonl(spi);
}

/**
 * hip_get_param_spi_value - get the spi value from spi_lsi parameter
 * @spi_lsi: the spi_lsi parameter
 *
 * Returns: the spi value in host byte order
 */
uint32_t hip_get_param_spi_value(const struct hip_spi *hspi)
{
	return ntohl(hspi->spi);
}

/**
 * hip_get_unit_test_suite_param_id - get suite id from unit test parameter
 * @test: pointer to the unit test parameter
 *
 * Returns: the id of the test suite (in host byte order) of the unit test
 *          parameter
 */
uint16_t hip_get_unit_test_suite_param_id(const struct hip_unit_test *test)
{
	return ntohs(test->suiteid);
}

/**
 * hip_get_unit_test_case_param_id - get test case id from unit test parameter
 * @test: pointer to the unit test parameter
 *
 * Returns: the id of the test case (in host byte order) of the unit test
 *          parameter
 */
uint16_t hip_get_unit_test_case_param_id(const struct hip_unit_test *test)
{
	return ntohs(test->caseid);
}

uint8_t hip_get_host_id_algo(const struct hip_host_id *host_id) {
	return host_id->rdata.algorithm; /* 8 bits, no ntons() */
}

/**
 * hip_check_msg_len - check validity of message length
 * @msg: pointer to the message
 *
 * Returns: 1 if the message length is valid, or 0 if the message length is
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
 * hip_check_userspace_msg_type - check the userspace message type
 * @msg: pointer to the message
 *
 * Returns: 1 if the message type is valid, or 0 if the message type is
 *          invalid
 */
int hip_check_userspace_msg_type(const struct hip_common *msg) {

	return (hip_get_msg_type(msg) >= HIP_USER_BASE_MAX) ? 0 : 1;
}

/**
 * hip_check_network_msg_type - check the type of the network message
 * @msg: pointer to the message
 *
 * Returns: 1 if the message type is valid, or 0 if the message type is
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
			HIP_REA,
			HIP_AC,
			HIP_ACR
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
 * @param: pointer to the parameter
 *
 * Returns: 1 if parameter type is valid, or 0 if parameter type is invalid
 */
int hip_check_userspace_param_type(const struct hip_tlv_common *param)
{
	return 1;
}

/**
 * hip_check_network_param_type - check network parameter type
 * @param: the network parameter
 *
 * Returns: 1 if parameter type is valid, or 0 if parameter type
 * is not valid. "Valid" means all optional and non-optional parameters
 * in the HIP draft.
 *
 * Optional parameters are not checked, because the code just does not
 * use them if they are not supported.
 */
int hip_check_network_param_type(const struct hip_tlv_common *param)
{
	int ok = 0;
	hip_tlv_type_t i;
	hip_tlv_type_t valid[] =
		{
			HIP_PARAM_SPI,
			HIP_PARAM_R1_COUNTER,
			HIP_PARAM_REA,
			HIP_PARAM_PUZZLE,
			HIP_PARAM_SOLUTION,
			HIP_PARAM_NES,
			HIP_PARAM_SEQ,
			HIP_PARAM_ACK,
			HIP_PARAM_DIFFIE_HELLMAN,
			HIP_PARAM_HIP_TRANSFORM,
			HIP_PARAM_ESP_TRANSFORM,
			HIP_PARAM_ENCRYPTED,
			HIP_PARAM_HOST_ID,
			HIP_PARAM_CERT,
			HIP_PARAM_RVA_REQUEST,
			HIP_PARAM_RVA_REPLY,
			HIP_PARAM_REA_INFO,
			HIP_PARAM_AC_INFO,
			HIP_PARAM_FA_INFO,
			HIP_PARAM_NOTIFY,
			HIP_PARAM_ECHO_REQUEST_SIGN,
			HIP_PARAM_ECHO_RESPONSE_SIGN,
			HIP_PARAM_FROM_SIGN,
			HIP_PARAM_TO_SIGN,
			HIP_PARAM_HMAC,
			HIP_PARAM_HIP_SIGNATURE2,
			HIP_PARAM_HIP_SIGNATURE,
			HIP_PARAM_ECHO_REQUEST,
			HIP_PARAM_ECHO_RESPONSE,
			HIP_PARAM_FROM,
			HIP_PARAM_TO,
			HIP_PARAM_HMAC,
			HIP_PARAM_VIA_RVS
		};
	hip_tlv_type_t type = hip_get_param_type(param);

	/* XX TODO: check the lengths of the parameters */

	for (i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
		if (type == valid[i]) {
			ok = 1;
			break;
		}
	}

	return ok;
}

/**
 * hip_check_param_contents_len - check validity of parameter contents length
 * @msg:   pointer to the beginning of the message
 * @param: pointer to the parameter to be checked for contents length
 * 
 * The @msg is passed also in to check to the parameter will not cause buffer
 * overflows.
 *
 * Returns: 1 if the length of the parameter contents length was valid
 *          (the length was not too small or too large to fit into the
 *          message). Zero is returned on invalid contents length.
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
 * hip_get_next_param - iterate to the next parameter
 * @msg:           pointer to the beginning of the message header
 * @current_param: pointer to the current parameter, or NULL if the @msg
 *                 is to be searched from the beginning
 *
 * Returns: the next parameter after the @current_param in @msg, or NULL
 *          if no parameters were found
 */
struct hip_tlv_common *hip_get_next_param(const struct hip_common *msg,
				   const struct hip_tlv_common *current_param)
{
	struct hip_tlv_common *next_param = NULL;
	void *pos = (void *) current_param;

	_HIP_DEBUG("\n");

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

	_HIP_DEBUG("Next param is at slot: %d\n", (pos - (void *) msg));

	/* check that the next parameter does not point
	   a) out of the buffer with check_param_contents_len()
	      - or - 
	   b) to an empty slot in the message */
	if (!hip_check_param_contents_len(msg, next_param) || /* a */
	    hip_get_param_contents_len(next_param) == 0) {    /* b */
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
 * hip_get_param - get the first parameter of the given type
 * @msg:        pointer to the beginning of the message header
 * @param_type: the type of the parameter to be searched from @msg
 *              (in host byte order)
 *
 * If there are multiple parameters of the same type, one should use
 * hip_get_next_param after calling this function to iterate through
 * them all.
 *
 * Returns: a pointer to the first parameter of the type @param_type, or
 *          NULL if no parameters of the type @param_type were not found. 
 */
void *hip_get_param(const struct hip_common *msg,
		    hip_tlv_type_t param_type)
{
	void *matched = NULL;
	struct hip_tlv_common *current_param = NULL;

	_HIP_DEBUG("searching for type %d\n", param_type);

/* XXX: Optimize: stop when next parameter's type is greater than the searched one */

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
 * @msg:        pointer to the beginning of the message header
 * @param_type: the type of the parameter to be searched from @msg
 *              (in host byte order)
 *
 * If there are multiple parameters of the same type, one should use
 * hip_get_next_param after calling this function to iterate through
 * them all.
 *
 * Returns: a pointer to the contents of the first parameter of the type
 *          @param_type, or NULL if no parameters of the type @param_type
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
 * @tlv_common: pointer to a parameter
 *
 * Returns: pointer to the contents of the @tlv_common (just after the
 *          the type and length fields)
 */
void *hip_get_param_contents_direct(const void *tlv_common) {
	return ((void *)tlv_common) + sizeof(struct hip_tlv_common);
}


/* hip_get_nth_param - get nth parameter of given type from the message
 * @msg:        pointer to the beginning of the message header
 * @param_type: the type of the parameter to be searched from @msg
 *              (in host byte order)
 * @n: index number to be get
 *
 * Returns: the nth parameter from the message if found, else %NULL.
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
 * @msg: pointer to the beginning of the message header
 *
 * This function does not check whether the new parameter to be appended
 * would overflow the msg buffer. It is the responsibilty of the caller
 * to check such circumstances because this function does not know
 * the length of the object to be appended in the message. Still, this
 * function checks the special situation where the buffer is completely
 * full and returns a null value in such a case.
 *
 * Returns: pointer to the first free (padded) position, or NULL if
 *          the message was completely full
 */
void *hip_find_free_param(const struct hip_common *msg)
{
	/* XX TODO: this function should return hip_tlv_common ? */
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
 * @msg: pointer to the beginning of the message header
 *
 * This function is called always when a parameter has added or the
 * daemon/network header was written. This functions writes the new
 * header length directly into the message.
 */
void hip_calc_hdr_len(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	void *pos = (void *) msg;

	_HIP_DEBUG("\n");

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
 * @tlv_common:    pointer to the beginning of the parameter
 * @tlv_size:      size of the TLV header  (in host byte order)
 * @contents_size: size of the contents after the TLV header
 *                 (in host byte order)
 *
 * This function can be used for semi-automatic calculation of parameter
 * length field. This function should always be used instead of manual
 * calculation of parameter lengths. The @tlv_size is usually just
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
 * @tlv_common:    pointer to the beginning of the TLV structure
 * @contents_size: size of the contents after type and length fields
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
 * @msg: the message to be dumped using the HIP debug interface
 *
 * Do not call this function directly, use the HIP_DUMP_MSG macro instead.
 */
void hip_dump_msg(const struct hip_common *msg)
{
	struct hip_tlv_common *current_param = NULL;
	void *contents = NULL;

	HIP_DEBUG("msg: type=%d, len=%d, err=%d\n",
		 hip_get_msg_type(msg), hip_get_msg_total_len(msg),
		 hip_get_msg_err(msg));

	while((current_param = hip_get_next_param(msg, current_param))
	      != NULL) {
		HIP_DEBUG("param: type=%d, len=%d\n",
			 hip_get_param_type(current_param),
			 hip_get_param_contents_len(current_param));
		contents = hip_get_param_contents_direct(current_param);
		HIP_HEXDUMP("contents", contents,
			    hip_get_param_contents_len(current_param));
	}

}

/**
 * hip_check_userspace msg - check userspace message for integrity
 * @msg: the message to be verified for integrity
 *
 * Returns: zero if the message was ok, or negative error value on error.
 */
int hip_check_userspace_msg(const struct hip_common *msg) {
	struct hip_tlv_common *current_param = NULL;
	int err = 0;

	if (!hip_check_userspace_msg_type(msg)) {
		err = -EINVAL;
		HIP_ERROR("bad msg type (%d)\n", hip_get_msg_type(msg));
		goto out;
	}

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
 * @param: the parameter to checked
 *
 * This is the function where one can test special attributes such as algo,
 * groupid, suiteid, etc of a HIP parameter. If the parameter does not require
 * other than just the validation of length and type fields, one should not
 * add any checks for that parameter here.
 *
 * Returns: zero if the message was ok, or negative error value on error.
 *
 * XX TODO: this function may be unneccessary because the input handlers
 * already do some checking. Currently they are double checked..
 */
int hip_check_network_param_attributes(const struct hip_tlv_common *param)
{
	hip_tlv_type_t type = hip_get_param_type(param);
	int err = 0;

	switch(type) {
	case HIP_PARAM_HIP_TRANSFORM:
	{
		/* Search for one supported transform */
		uint16_t i;
		hip_transform_suite_t suite;
		err = -EPROTONOSUPPORT;

		HIP_DEBUG("Checking HIP transform\n");
		for (i = 0; i < HIP_TRANSFORM_HIP_MAX; i++) {
			suite = hip_get_param_transform_suite_id(param, i);
			if (suite == HIP_TRANSFORM_3DES ||
			    suite == HIP_TRANSFORM_NULL) {
				err = 0;
				HIP_DEBUG("Matched suite: %d\n", suite);
				break;
			} else {
				HIP_DEBUG("Skipping suite: %d\n", suite);
			}
		}
		if (err)
			HIP_ERROR("Could not find suitable HIP transform\n");
		break;
	}
	case HIP_PARAM_ESP_TRANSFORM:
	{
		/* Search for one supported transform */
		uint16_t i;
		hip_transform_suite_t suite;
		err = -EPROTONOSUPPORT;
		HIP_DEBUG("Checking ESP transform\n");
		HIP_HEXDUMP("ESP transform", (char *) param,
			    hip_get_param_total_len(param));
		for (i = 0; i < HIP_TRANSFORM_ESP_MAX; i++) {
			suite = hip_get_param_transform_suite_id(param, i);
			if (suite ==  HIP_ESP_3DES_SHA1 ||
			    suite == HIP_ESP_NULL_SHA1) {
				err = 0;
				break;
			}
		}
		if (err)
			HIP_ERROR("Could not find suitable ESP transform\n");
		break;
	}
	case HIP_PARAM_HOST_ID:
	{
		uint8_t algo = 
			hip_get_host_id_algo((struct hip_host_id *) param);
		if (algo != HIP_HI_DSA) {
			err = -EPROTONOSUPPORT;
			HIP_ERROR("Host id algo %d not supported\n", algo);
		}
		break;
	}
	}

	return err;
}

/**
 * hip_check_network_msg - check network message for integrity
 * @msg: the message to be verified for integrity
 *
 * Returns: zero if the message was ok, or negative error value on error.
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
		} else if (current_param_type < prev_param_type) {
			err = -ENOMSG;
			HIP_ERROR("Wrong order of parameters (%d, %d)\n",
				  prev_param_type, current_param_type);
			break;
		} else if (hip_check_network_param_attributes(current_param)) {
			err = -EINVAL;
			break;
		}
		prev_param_type = current_param_type;
	}

 out:
	return err;
}

/**
 * hip_build_generic_param - build and insert a parameter into the message
 * @msg:            the message where the parameter is to be appended
 * @parameter_hdr:  pointer to the header of the parameter
 * @param_hdr_size: size of @parameter_hdr structure (in host byte order)
 * @contents:       the contents of the parameter; the data to be inserted
 *                  after the @parameter_hdr (in host byte order)
 *
 * This to function should be used by other parameter builder functions
 * to append parameters into a message. Do not do that manually or you will
 * break the builder system.
 *
 * This function updates the message header length to keep the next free
 * parameter slot quickly accessible for faster writing of the parameters.
 *
 * Returns: zero on success, or negative on error
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
 * hip_build_param_contents - build and append parameter contents into message
 * @msg:            the message where the parameter will be appended
 * @contents:       the data after the type and length fields
 * @param_type:     the type of the parameter (in host byte order)
 * @contents_size:  the size of @contents (in host byte order)
 *
 * This function differs from hip_build_generic_param only because it
 * assumes that the parameter header is just sizeof(struct hip_tlv_common).
 *
 * This function updates the message header length to keep the next free
 * parameter slot quickly accessible for faster writing of the parameters.
 *
 * Returns: zero on success, or negative on error
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
 * hip_build_param - append a complete parameter into message
 * @msg:        the message where the parameter will be appended
 * @tlv_common: pointer to the network byte ordered parameter that will be
 *              appended into the message
 *
 * This function differs from hip_build_param_contents() and
 * hip_build_generic_param() because it takes a complete network byte ordered
 * parameter as its input. It means that this function can be used for
 * e.g. copying a parameter from a message to another.
 *
 * This function updates the message header length to keep the next free
 * parameter slot quickly accessible for faster writing of the parameters.
 *
 * Returns: zero on success, or negative on error
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
 * hip_build_user_hdr - build header for userspace-kernel communication
 * @msg:       the message where the userspace header is to be written
 * @base_type: the type of the message
 * @err_val:   a positive error value to be communicated for the receiver
 *             (usually just zero for no errors)
 * 
 * This function builds the header that can be used for HIP kernel-userspace
 * communication. It is commonly used by the daemon, hipconf, resolver or
 * the kernel module itself. This function can be called before or after
 * building the parameters for the message.
 *
 * This function does not write the header length into the message. It should
 * be written by the build_param_functions. 
 *
 * Returns: zero on success, or negative on error
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

	if (!hip_check_userspace_msg_type(msg)) {
		HIP_ERROR("bad msg type (%d)\n", hip_get_msg_type(msg));
		err = -EINVAL;
		goto out;
	}

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
 * hip_build_network_hdr - write network header into message
 * @msg:          the message where the HIP network should be written
 * @type_hdr:     the type of the HIP header as specified in the drafts
 * @control:      HIP control bits
 * @hit_sender:   source HIT in network byte order
 * @hit_receiver: destination HIT in network byte order
 *
 * This function does not write the header length into the message. It should
 * be written by the build_param_functions. The checksum field is not written
 * either because it is done in hip_csum_send().
 */
void hip_build_network_hdr(struct hip_common *msg, uint8_t type_hdr,
			  uint16_t control, const struct in6_addr *hit_sender,
			  const struct in6_addr *hit_receiver)
{
	/*
	 * XX TODO: build HIP network header in the same fashion as in
	 * build_daemon_hdr().
	 * - Write missing headers in the header using accessor functions
	 *   (see hip_get/set_XXX() functions in the beginning of this file).
	 *   You have to create couple of new ones, but daemon and network
	 *   messages use the same locations for storing len and type
	 *   (hip_common->err is stored in the hip_common->checksum) and
	 *   they can be used as they are.
	 *   - payload_proto
	 *   - payload_len: see how build_daemon_hdr() works
	 *   - ver_res
	 *   - checksum (move the checksum function from hip.c to this file
	 *     because this file is shared by kernel and userspace)
	 * - write the parameters of this function into the message
	 * - couple of notes:
	 *   - use _only_ accessors to hide byte order and size conversion
	 *     issues!!!
	 */

	msg->payload_proto = IPPROTO_NONE; /* 1 byte, no htons()    */
	/* Do not touch the length; it is written by param builders */
	msg->type_hdr = type_hdr;          /* 1 byte, no htons()    */
	msg->ver_res = HIP_VER_RES;        /* 1 byte, no htons()    */

	msg->control = htons(control);
	msg->checksum = htons(0); /* this will be written by xmit */

	memcpy(&msg->hits, hit_sender, sizeof(struct in6_addr));
	memcpy(&msg->hitr, hit_receiver, sizeof(struct in6_addr));
}

#ifdef __KERNEL__
/**
 * hip_build_param_hmac_contents - build and append a HIP hmac parameter
 * @msg:  the message where the hmac parameter will be appended
 * @key:  pointer to a key used for HMAC
 *
 * This function calculates the also the HMAC value from the whole message
 * as specified in the drafts.
 *
 * Returns: 0 on success, otherwise < 0.
 */
int hip_build_param_hmac_contents(struct hip_common *msg,
				  struct hip_crypto_key *key)
{
	int err = 0;
	struct hip_hmac hmac;

	hip_set_param_type(&hmac, HIP_PARAM_HMAC);
	hip_calc_generic_param_len(&hmac, sizeof(struct hip_hmac), 0);

	if (!hip_write_hmac(HIP_DIGEST_SHA1_HMAC, key->key, msg,
			    hip_get_msg_total_len(msg),
			    hmac.hmac_data)) {
		HIP_ERROR("Error while building HMAC\n");
		err = -EFAULT;
		goto out_err;
	  }

	err = hip_build_param(msg, &hmac);
 out_err:
	return err;
}

#endif /* __KERNEL__ */

/**
 * hip_build_param_signature2_contents - build HIP signature2
 * @msg:           the message 
 * @contents:      pointer to the signature contents (the data to be written
 *                 after the signature field)
 * @contents_size: size of the contents of the signature (the data after the
 *                 algorithm field)
 * @algorithm:     the algorithm as in the HIP drafts that was used for
 *                 producing the signature
 *                 
 * build_param_contents() is not very suitable for building a hip_sig2 struct,
 * because hip_sig2 has a troublesome algorithm field which need some special
 * attention from htons(). Thereby here is a separate builder for hip_sig2 for
 * conveniency. It uses internally hip_build_generic_param() for actually
 * writing the signature parameter into the message.
 *
 * Returns: zero for success, or non-zero on error
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
 * @msg:           the message 
 * @contents:      pointer to the signature contents (the data to be written
 *                 after the signature field)
 * @contents_size: size of the contents of the signature (the data after the
 *                 algorithm field)
 * @algorithm:     the algorithm as in the HIP drafts that was used for
 *                 producing the signature
 *                 
 * This is almost the same as the previous, but the type is sig1.
 *
 * Returns: zero for success, or non-zero on error
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

int hip_build_param_from(struct hip_common *msg, struct in6_addr *addr, int sign)
{
	struct hip_from from;
	int err;
	
	hip_set_param_type(&from, sign ? HIP_PARAM_FROM_SIGN : HIP_PARAM_FROM);
	memcpy((struct in6_addr *)&from.address, addr, 16);

	hip_calc_generic_param_len(&from, sizeof(struct hip_from), 0);
	err = hip_build_param(msg, &from);
	return err;
}


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

int hip_build_param_rva(struct hip_common *msg, uint32_t lifetime,
			int *type_list, int cnt, int request)
{
	int err = 0;
	int i;
	struct hip_rva_reply rrep;

	hip_set_param_type(&rrep, (request ? HIP_PARAM_RVA_REQUEST : HIP_PARAM_RVA_REPLY));
	hip_calc_generic_param_len(&rrep, sizeof(struct hip_rva_reply),
				   cnt * sizeof(uint16_t));

	for(i=0;i<cnt;i++)
		type_list[i] = htons(type_list[i]);

	rrep.lifetime = htonl(lifetime);
	err = hip_build_generic_param(msg, &rrep, sizeof(struct hip_rva_reply),
				      (void *)type_list);
	return err;

}

/**
 * hip_build_param_puzzle - build and append a HIP puzzle into the message
 * @msg:        the message where the cookie is to be appended
 * @solved:     1 if the cookie is already a solved cookie (as in I2),
 *              or 0 if the cookie is to be solved (as in R1)
 * @birthday:   birthday value for the cookie (in host byte order)
 * @random_i:   random i value for the cookie (in host byte order)
 * @random_j_k: random j/k value for the cookie (in host byte order)
 *
 * The cookie mechanism assumes that every value is in network byte order
 * except for the hip_birthday_cookie.cv union, where the value is in
 * host byte order. This is an exception to the normal builder rules, where
 * input arguments are normally always in host byte order.
 * 
 * Returns: zero for success, or non-zero on error
 */
int hip_build_param_puzzle(struct hip_common *msg, uint8_t val_K,
			   uint32_t opaque, uint64_t random_i)
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
	puzzle.opaque[0] = opaque & 0xFF;
	puzzle.opaque[1] = (opaque & 0xFF00) >> 8;
	puzzle.opaque[2] = (opaque & 0xFF0000) >> 16;
	puzzle.I = random_i;

        err = hip_build_generic_param(msg, &puzzle,
				      sizeof(struct hip_tlv_common),
				      hip_get_param_contents_direct(&puzzle));
	return err;

}

/**
 * hip_build_param_cookie - build and append a HIP cookie into the message
 * @msg:        the message where the cookie is to be appended
 * @solved:     1 if the cookie is already a solved cookie (as in I2),
 *              or 0 if the cookie is to be solved (as in R1)
 * @birthday:   birthday value for the cookie (in host byte order)
 * @random_i:   random i value for the cookie (in host byte order)
 * @random_j_k: random j/k value for the cookie (in host byte order)
 *
 * The cookie mechanism assumes that every value is in network byte order
 * except for the hip_birthday_cookie.cv union, where the value is in
 * host byte order. This is an exception to the normal builder rules, where
 * input arguments are normally always in host byte order.
 * 
 * Returns: zero for success, or non-zero on error
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
	memcpy(&cookie.K, &pz->K, 12); // copy: K (1), opaque (3) and I (8 bytes).

        err = hip_build_generic_param(msg, &cookie,
				      sizeof(struct hip_tlv_common),
				      hip_get_param_contents_direct(&cookie));
	return err;
}

/**
 * hip_build_param_diffie_hellman_contents - build HIP DH contents
 * @msg:      the message where the DH parameter will be appended
 * @group_id: the group id of the DH parameter as specified in the drafts
 * @pubkey:   the public key part of the DH
 * 
 * Returns:   zero on success, or non-zero on error
 */
int hip_build_param_diffie_hellman_contents(struct hip_common *msg,
				      uint8_t group_id,
				      void *pubkey,
				      hip_tlv_len_t pubkey_len)
{
	int err = 0;
	struct hip_diffie_hellman diffie_hellman;

	HIP_ASSERT(pubkey_len >= sizeof(struct hip_tlv_common));

	hip_set_param_type(&diffie_hellman, HIP_PARAM_DIFFIE_HELLMAN);
	hip_calc_generic_param_len(&diffie_hellman, sizeof(struct hip_diffie_hellman),
				   pubkey_len);
	diffie_hellman.group_id = group_id; /* 1 byte, no htons() */

	err = hip_build_generic_param(msg, &diffie_hellman,
				      sizeof(struct hip_diffie_hellman), pubkey);

	return err;
}

/**
 * hip_get_transform_max - find out the maximum number of transform suite ids
 * @transform_type: the type of the transform
 *
 * Returns: the number of suite ids that can be used for @transform_type
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
 * @msg:             the message where the parameter will be appended
 * @transform_type:  HIP_PARAM_HIP_TRANSFORM or HIP_PARAM_ESP_TRANSFORM
 *                   in host byte order
 * @transform_suite: an array of transform suite ids in host byte order
 * @transform_count: number of transform suites in @transform_suite (in host
 *                   byte order)
 *
 * Returns: zero on success, or negative on error
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
 * @transform_tlv: the transform structure
 * @index: the index of the suite id in @transform_tlv
 *
 * Returns: the suite id on @transform_tlv on index @index
 */
hip_transform_suite_t hip_get_param_transform_suite_id(const void *transform_tlv, const uint16_t index)
{
	hip_transform_suite_t suite = 0;
	hip_tlv_type_t type;
	uint16_t transform_max;
	const struct hip_any_transform *tf =
		(const struct hip_any_transform *) transform_tlv;

	type = hip_get_param_type(tf); 
	transform_max = hip_get_transform_max(type);

	/* Check that the maximum number of transforms is not overflowed */
	if (transform_max > 0 && index > transform_max) {
		HIP_ERROR("Illegal range for transform (%d) for type %d.\n",
			  index, type);
	} else {
		suite = ntohs(tf->suite_id[index]);
	}

	return suite;
}

/**
 * hip_build_param_rea_info00 - build HIP REA_INFO parameter
 *
 * @msg:             the message where the rea will be appended
 * @interface_id:    Interface ID
 * @current_spi_rev: Current SPI in reverse direction
 * @current_spi:     Current SPI
 * @new_spi:         New SPI
 * @keymat_index     Keymaterial index
 * @rea_id:          REA ID in host byte order
 * @addresses:       list of addresses
 * @address_count:   number of addresses in @addresses
 *
 * Returns: 0 on success, otherwise < 0.
 */
int hip_build_param_rea_info00(struct hip_common *msg,
			       uint32_t interface_id,
			       uint32_t current_spi_rev,
			       uint32_t current_spi,
			       uint32_t new_spi,
			       uint16_t keymat_index,
			       uint16_t rea_id,
			       struct hip_rea_info_addr_item *addresses,
			       int address_count)
{
	int err = 0;
	struct hip_rea_info00 rea_info;
	int addrs_len = address_count *
		(sizeof(struct hip_rea_info_addr_item));

	hip_set_param_type(&rea_info, HIP_PARAM_REA_INFO);
	hip_calc_generic_param_len(&rea_info,
				   sizeof(struct hip_rea_info00),
				   addrs_len);
	_HIP_DEBUG("params size=%d\n", sizeof(struct hip_rea_info00) -
		   sizeof(struct hip_tlv_common) +
		   addrs_len);
	rea_info.interface_id = interface_id; /* no conversion */
	rea_info.current_spi_rev = htonl(current_spi_rev);
	rea_info.current_spi = htonl(current_spi);
	rea_info.new_spi = htonl(new_spi);
	rea_info.keymat_index = htons(keymat_index);
	rea_info.rea_id = htons(rea_id);
	err = hip_build_param(msg, &rea_info);
	if (err)
		return err;
	_HIP_DEBUG("msgtotlen=%d addrs_len=%d\n", hip_get_msg_total_len(msg),
		   addrs_len);
	if (addrs_len > 0)
		memcpy((void *)msg+hip_get_msg_total_len(msg)-addrs_len,
		       addresses, addrs_len);

	return err;
}

/**
 * hip_build_param_rea_mm02 - build HIP REA_INFO parameter
 *
 * @msg:             the message where the rea will be appended
 * @spi:             SPI
 * @addresses:       list of addresses
 * @address_count:   number of addresses in @addresses
 *
 * Returns: 0 on success, otherwise < 0.
 */
int hip_build_param_rea_mm02(struct hip_common *msg,
			     uint32_t spi,
			     struct hip_rea_info_addr_item *addresses,
			     int address_count)
{
	int err = 0;
	struct hip_rea_mm02 rea_info;
	int addrs_len = address_count *
		(sizeof(struct hip_rea_info_addr_item));

	hip_set_param_type(&rea_info, HIP_PARAM_REA);
	hip_calc_generic_param_len(&rea_info,
				   sizeof(struct hip_rea_mm02),
				   addrs_len);
	_HIP_DEBUG("params size=%d\n", sizeof(struct hip_rea_mm02) -
		   sizeof(struct hip_tlv_common) +
		   addrs_len);
	rea_info.spi = htonl(spi);
	err = hip_build_param(msg, &rea_info);
	if (err)
		return err;
	_HIP_DEBUG("msgtotlen=%d addrs_len=%d\n", hip_get_msg_total_len(msg),
		   addrs_len);
	if (addrs_len > 0)
		memcpy((void *)msg+hip_get_msg_total_len(msg)-addrs_len,
		       addresses, addrs_len);

	return err;
}

#if 0
/**
 * hip_build_param_ac_info - build and append HIP AC parameter
 * @msg:    the message where the parameter will be appended
 * @ac_id:  AC ID in host byte order
 * @rea_id: REA ID in host byter order
 * @rtt:    RTT
 * 
 * Returns: 0 on success, otherwise < 0.
 */
int hip_build_param_ac_info(struct hip_common *msg, uint16_t ac_id,
			    uint16_t rea_id, uint32_t rtt)
{
	int err = 0;
	struct hip_ac_info ac;

	hip_set_param_type(&ac, HIP_PARAM_AC_INFO);
	hip_calc_generic_param_len(&ac, sizeof(struct hip_ac_info), 0);
	ac.ac_id = htons(ac_id);
	ac.rea_id = htons(rea_id);
	ac.rtt = rtt; /* no conversion */
	ac.reserved = htonl(0);

	err = hip_build_param(msg, &ac);
	return err;
}
#endif

/**
 * hip_build_param_nes - build and append HIP NES parameter
 * @msg: the message where the parameter will be appended
 * @is_reply: 1 if this packet is a reply to another UPDATE
 * @keymat_index: Keymat Index in host byte order
 * @old_spi: Old SPI value in host byte order
 * @new_spi: New SPI value in host byte order
 * 
 * Returns: 0 on success, otherwise < 0.
 */
int hip_build_param_nes(struct hip_common *msg, uint16_t keymat_index,
			uint32_t old_spi, uint32_t new_spi)
{
	int err = 0;
	struct hip_nes nes;

	hip_set_param_type(&nes, HIP_PARAM_NES);
	hip_calc_generic_param_len(&nes, sizeof(struct hip_nes), 0);
	nes.keymat_index = htons(keymat_index);
	nes.old_spi = htonl(old_spi);
	nes.new_spi = htonl(new_spi);
	err = hip_build_param(msg, &nes);
	return err;
}

/**
 * hip_build_param_seq - build and append HIP SEQ parameter
 * @msg: the message where the parameter will be appended
 * @seq: Update ID
 * 
 * Returns: 0 on success, otherwise < 0.
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
 * @msg: the message where the parameter will be appended
 * @peer_update_id: peer Update ID
 * 
 * Returns: 0 on success, otherwise < 0.
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
 * @msg:     the message where the parameter will be appended
 * @suiteid: the id of the test suite
 * @caseid:  the id of the test case
 *
 * This parameter is used for triggering the unit test suite in the kernel.
 * It is only for implementation internal purposes only.
 *
 * Returns: 0 on success, otherwise < 0.
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
 * hip_build_param_spi_lsi - build the SPI_LSI parameter
 * @msg: the message where the parameter will be appended
 * @lsi: the value of the lsi (in host byte order)
 * @spi: the value of the spi (in host byte order)
 * 
 * Returns: zero on success, or negative on failure
 */
int hip_build_param_spi(struct hip_common *msg, uint32_t spi)
{
	int err = 0;
	struct hip_spi hspi;

	hip_set_param_type(&hspi, HIP_PARAM_SPI);
	hip_calc_generic_param_len(&hspi, sizeof(struct hip_spi), 0);
	hspi.spi = htonl(spi);

	err = hip_build_param(msg, &hspi);
	return err;
}

/**
 * hip_build_param_encrypted - build the hip_encrypted parameter
 * @msg:     the message where the parameter will be appended
 * @host_id: the host id parameter that will contained in the hip_encrypted
 *           parameter
 * 
 * Note that this function does not actually encrypt anything, it just builds
 * the parameter. The @host_id that will be encapsulated in the hip_encrypted
 * parameter has to be encrypted using a different function call.
 *
 * Returns: zero on success, or negative on failure
 */
int hip_build_param_encrypted(struct hip_common *msg,
			      struct hip_host_id *host_id)
{
	int err = 0;
	struct hip_encrypted enc;

	hip_set_param_type(&enc, HIP_PARAM_ENCRYPTED);
	hip_calc_param_len(&enc, sizeof(struct hip_encrypted) -
			   sizeof(struct hip_tlv_common) +
			   hip_get_param_total_len(host_id));
	enc.reserved = htonl(0);
	memset(&enc.iv, 0, 8);

	/* copy the IV *IF* needed, and then the encrypted data */

	err = hip_build_generic_param(msg, &enc,
				      sizeof(struct hip_encrypted),
				      host_id);
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

        host_id_hdr->rdata.flags = htons(0x0200); /* key is for a host */
        host_id_hdr->rdata.protocol = 0xFF; /* RFC 2535 */
	/* algo is 8 bits, no htons */
        host_id_hdr->rdata.algorithm = algorithm;

	HIP_DEBUG("hilen=%d totlen=%d contlen=%d\n",
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

	HIP_DEBUG("hi len: %d\n", ntohs(host_id->hi_length));

	HIP_DEBUG("Copying %d bytes\n", rr_len);

	memcpy(ptr, rr_data, rr_len);
	ptr += rr_len;

	fqdn_len = ntohs(host_id->di_type_length) & 0x0FFF;
	HIP_DEBUG("fqdn len: %d\n", fqdn_len);
	if (fqdn_len)
		memcpy(ptr, fqdn, fqdn_len);
}

/**
 * hip_build_param_host_id - build and append host id into message
 * @XXTODO:        XX TODO
 * @algorithm:     the crypto algorithm used for the host id (as in the drafts)
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
	HIP_DEBUG("Hilen: %d\n",hilen);
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
	HIP_DEBUG("%d %d %d\n",
		  sizeof(struct endpoint_hip),
		  hip_get_param_total_len(&endpoint_hdr->id.host_id),
		  sizeof(struct hip_host_id));
	HIP_DEBUG("endpoint hdr length: %d\n", endpoint_hdr->length);
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
	HIP_DEBUG("len=%d ep=%d rr=%d hostid=%d\n",
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
 * @msg: the message where the eid endpoint paramater will be appended
 * @endpoint: the endpoint to be wrapped into the eid endpoint structure
 * @port: the dst/src port used for the endpoint 
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
 * hip_build_param_notify - build the HIP NOTIFY parameter
 * @msg:     the message where the parameter will be appended
 * @msgtype: Notify Message Type
 * @notification_data: the Notification data that will contained in the HIP NOTIFY
 *           parameter
 * @notification_data_len: length of @notification_data
 *
 * Returns: zero on success, or negative on failure
 */
int hip_build_param_notify(struct hip_common *msg, uint16_t msgtype,
			   void *notification_data, size_t notification_data_len)
{
	int err = 0;
	struct hip_notify notify;

	hip_set_param_type(&notify, HIP_PARAM_NOTIFY);
	hip_calc_param_len(&notify, sizeof(struct hip_notify) -
			   sizeof(struct hip_tlv_common) +
			   notification_data_len);
	notify.reserved = 0;
	notify.msgtype = htons(msgtype);

	err = hip_build_generic_param(msg, &notify,
				      sizeof(struct hip_notify),
				      notification_data);
	return err;
}
