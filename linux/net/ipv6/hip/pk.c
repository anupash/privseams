#include "pk.h"

#if !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE
int hip_rsa_sign(struct hip_host_id *priv, struct hip_common *msg) {
	u8 sha1_digest[HIP_AH_SHA_LEN];
	u8 signature[HIP_RSA_SIGNATURE_LEN];
	int err = 0, len;

	len = hip_get_msg_total_len(msg);
	HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, msg, len, sha1_digest) < 0,
		 -1, "Building of SHA1 digest failed\n");
	HIP_IFEL(impl_rsa_sign(sha1_digest, (u8 *)(priv + 1), signature,
			       3+128*2+64+64 /*e+n+d+p+q*/), 0, "Signing error\n");
	if (hip_get_msg_type(msg) == HIP_R1) {
		HIP_IFEL(hip_build_param_signature2_contents(msg, signature,
							     HIP_RSA_SIGNATURE_LEN,
							     HIP_SIG_RSA), -1,
			 "Building of signature failed\n");
	} else
		HIP_IFEL(hip_build_param_signature_contents(msg, signature,
							    HIP_RSA_SIGNATURE_LEN,
							    HIP_SIG_RSA), -1,
			 "Building of signature failed\n");	  
 out_err:
	return err;
}

int hip_dsa_sign(struct hip_host_id *priv, struct hip_common *msg) {
	u8 sha1_digest[HIP_AH_SHA_LEN];
	u8 signature[HIP_DSA_SIGNATURE_LEN];
	int err = 0, len;

	len = hip_get_msg_total_len(msg);
	HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, msg, len, sha1_digest) < 0,
		 -1, "Building of SHA1 digest failed\n");
	HIP_IFEL(impl_dsa_sign(sha1_digest, (u8 *)(priv + 1), signature), 
		 -1, "Signing error\n");

	if (hip_get_msg_type(msg) == HIP_R1) {
		HIP_IFEL(hip_build_param_signature2_contents(msg, signature,
							     HIP_DSA_SIGNATURE_LEN,
							     HIP_SIG_DSA), -1,
			 "Building of signature failed\n");
	} else
		HIP_IFEL(hip_build_param_signature_contents(msg, signature,
							    HIP_DSA_SIGNATURE_LEN,
							    HIP_SIG_DSA), -1,
			 "Building of signature failed\n");
 out_err:
	return err;
	
}

static int verify(struct hip_host_id *peer_pub, struct hip_common *msg, int rsa)
{
	int err = 0, len, origlen;
	struct hip_sig *sig;
	u8 sha1_digest[HIP_AH_SHA_LEN];
	struct in6_addr tmpaddr;	
	struct hip_puzzle *pz = NULL;
	uint8_t opaque[3];
	uint64_t randi;

	ipv6_addr_copy(&tmpaddr, &msg->hitr); /* so update is handled, too */

	origlen = hip_get_msg_total_len(msg);
	if (hip_get_msg_type(msg) == HIP_R1) {
		HIP_IFEL(!(sig = hip_get_param(msg, HIP_PARAM_HIP_SIGNATURE2)), -ENOENT, 
		 "Could not find signature2\n");
		
		//ipv6_addr_copy(&tmpaddr, &msg->hitr);
		memset(&msg->hitr, 0, sizeof(struct in6_addr));
		
		HIP_IFEL(!(pz = hip_get_param(msg, HIP_PARAM_PUZZLE)), -ENOENT, "Illegal R1 packet (puzzle missing)\n");
		memcpy(opaque, pz->opaque, 3);
		randi = pz->I;
		
		memset(pz->opaque, 0, 3);
		pz->I = 0;

		
	} else {
		HIP_IFEL(!(sig = hip_get_param(msg, HIP_PARAM_HIP_SIGNATURE)), -ENOENT,
			 "Could not find signature\n");
	}

	//HIP_HEXDUMP("SIG", sig, hip_get_param_total_len(sig));
	len = ((u8 *) sig) - ((u8 *) msg);
	hip_zero_msg_checksum(msg);
	HIP_IFEL(len < 0, -ENOENT, "Invalid signature len\n");
	hip_set_msg_total_len(msg, len);

	//HIP_HEXDUMP("Verifying:", msg, len);
	//HIP_HEXDUMP("Pubkey:", peer_pub, hip_get_param_total_len(peer_pub));
		
	HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, msg, len, sha1_digest), 
		 -1, "Could not calculate SHA1 digest\n");
	if (rsa) {
		int public_key_len = ntohs(peer_pub->hi_length) - 
			sizeof(struct hip_host_id_key_rdata);
		err = impl_rsa_verify(sha1_digest, (u8 *) (peer_pub + 1), sig->signature, 
				      public_key_len);
		_HIP_DEBUG("RSA verify err value: %d \n",err);		
	} else {
		err = impl_dsa_verify(sha1_digest, (u8 *) (peer_pub + 1), sig->signature);
	}

	if (hip_get_msg_type(msg) == HIP_R1) {
		memcpy(pz->opaque, opaque, 3);
		pz->I = randi;
	}
	
	ipv6_addr_copy(&msg->hitr, &tmpaddr);

	switch(err) {
	case 0:
		err = 0;
		break;
	case 1:
	default:
		err = -1;
		break;
	}

 out_err:
	hip_set_msg_total_len(msg, origlen);
	return err;
}

int hip_rsa_verify(struct hip_host_id *peer_pub, struct hip_common *msg)
{
	return verify(peer_pub, msg, 1);
}

int hip_dsa_verify(struct hip_host_id *peer_pub, struct hip_common *msg)
{
	return verify(peer_pub, msg, 0);
}
#endif /* !defined __KERNEL__ || !defined CONFIG_HIP_USERSPACE */
