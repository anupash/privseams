/*
 * Miscellaneous functions
 */

#include "misc.h"

/**
 * hip_set_sockaddr - init sockaddr and copy given address to it
 * @addr: IPv6 address to be copied
 * @sin: sockaddr where @addr is copied
 */
void hip_set_sockaddr(struct sockaddr_in6 *sin, struct in6_addr *addr)
{
	memset(sin, 0, sizeof(struct sockaddr_in6));

	sin->sin6_family = AF_INET6;
	sin->sin6_port = 0;  // Is this needed?

	ipv6_addr_copy(&sin->sin6_addr, addr);

	return;
}

/** hip_timeval_diff - calculate difference between two timevalues
 * @t1: timevalue 1
 * @t2: timevalue 2
 * @result: where the result is stored
 *
 * ** CHECK comments **
 * @result = @t1 - @t2
 *
 * Code taken from http://www.gnu.org/manual/glibc-2.2.5/html_node/Elapsed-Time.html
 *
 * Returns: 1 if @t1 is equal or later than @t2, else 0.
 */
int hip_timeval_diff(const struct timeval *t1, const struct timeval *t2,
		     struct timeval *result)
{
	struct timeval _t1, _t2;
	_t1 = *t1;
	_t2 = *t2;

	if (_t1.tv_usec < _t2.tv_usec) {
		int nsec = (_t2.tv_usec - _t1.tv_usec) / 1000000 + 1;
		_t2.tv_usec -= 1000000 * nsec;
		_t2.tv_sec += nsec;
	}
	if (_t1.tv_usec - _t2.tv_usec > 1000000) {
		int nsec = (_t1.tv_usec - _t2.tv_usec) / 1000000;
		_t2.tv_usec += 1000000 * nsec;
		_t2.tv_sec -= nsec;
	}

	result->tv_sec = _t1.tv_sec - _t2.tv_sec;
	result->tv_usec = _t1.tv_usec - _t2.tv_usec;

	return _t1.tv_sec >= _t2.tv_sec;
}
/**
 * hip_lhi_are_equal - compare two LHIs (Localhost Host Identity)
 * @lhi1: the first LHI used in comparison
 * @lhi2: the second LHI used in comparison
 *
 * Returns: 1 if @lhi1 and @lhi2 are equal, else 0.
 */
int hip_lhi_are_equal(const struct hip_lhi *lhi1,
		      const struct hip_lhi *lhi2) 
{
	return !memcmp(&lhi1->hit, &lhi2->hit, sizeof(struct in6_addr));
}

/* Extract only the "public key" part of the local host identify.
 * Enables to store the whole key in one record (secret key).
 * This function should be extended with different functionality depending on
 * the algorithm (so it should check the algorithm field).
 * The extraction is performed so that the key (and the relevant hip_host_id
 * structure) is copied to the place that the buffer argument points to.
 * 
 * Return value is buffer + struct hip_host_id + public key data or NULL if failed
 */
u8 *host_id_extract_public_key(u8 *buffer, struct hip_host_id *data)
{
	u8 *buf;
	u8 t;
	int len;

	if (!data)
		return NULL;

	buf = (u8 *)(data + 1); // skip the header
	t = *buf; /* T */

	if (t > 8) { /* error */
		HIP_ERROR("Invalid T-value in DSA key (%x)\n", t);
		return NULL; 
	}

	len = hip_get_param_contents_len(data);
	if (len < 3*(64+8*t)+2*20) { /* PQGXY 3*(64+8*t) + 2*20 */
		/*/ no private key */
		memcpy(buffer,data,len);
		buffer += hip_get_param_total_len(data);
		HIP_DEBUG("No private key\n");
	} else {
		memcpy(buffer,data,sizeof(struct hip_tlv_common) + (len - 20));
		hip_set_param_contents_len(buffer,(len-20));
		HIP_HEXDUMP("own hid",data,sizeof(struct hip_tlv_common));
		buffer += hip_get_param_total_len(buffer);
		HIP_DEBUG("Private key\n");
	}
	return buffer;
}

