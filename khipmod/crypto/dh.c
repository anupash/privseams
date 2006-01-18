#include "dh.h"

struct dh_params_str {
	const char *prime;
	unsigned int generator;
};

//static const char *dh_group_prime[] = {
static const struct dh_params_str dh_params[] = {
 /*** group 0 (invalid) ***/
	{"",0},
/*** group 1 (384-bit group) from base draft appendix ***/
	{"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"\
	 "29024E088A67CC74020BBEA63B13B202FFFFFFFFFFFFFFFF",2},
/*** group 2 (OAKLEY well defined group 1) ****/
	{"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD12"\
	 "9024E088A67CC74020BBEA63B139B22514A08798E3404DDEF"\
	 "9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E48"\
	 "5B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",2},
/*** group 3 (MODP 1536-bit) ***/
	{"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD12"\
	 "9024E088A67CC74020BBEA63B139B22514A08798E3404DDEF"\
	 "9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E48"\
	 "5B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE38"\
	 "6BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007"\
	 "CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D"\
	 "23DCA3AD961C62F356208552BB9ED529077096966D670C354"\
	 "E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",2},
/*** group 4 (MODP 3072-bit) ***/
	{"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"\
	 "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"\
	 "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"\
	 "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"\
	 "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"\
	 "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"\
	 "83655D23DCA3AD961C62F356208552BB9ED529077096966D"\
	 "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"\
	 "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"\
	 "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"\
	 "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"\
	 "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"\
	 "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"\
	 "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"\
	 "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"\
	 "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",2},
/*** group 5 (MODP 6144-bit) ***/
	{"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"\
	 "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"\
	 "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"\
	 "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"\
	 "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"\
	 "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"\
	 "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"\
	 "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"\
	 "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"\
	 "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"\
	 "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"\
	 "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"\
	 "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"\
	 "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"\
	 "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"\
	 "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"\
	 "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"\
	 "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"\
	 "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406"\
	 "AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918"\
	 "DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151"\
	 "2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03"\
	 "F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F"\
	 "BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"\
	 "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B"\
	 "B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632"\
	 "387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E"\
	 "6DCC4024FFFFFFFFFFFFFFFF",2},
/*** group 6 (MODP 8192-bit) ***/
	{"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"\
	 "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"\
	 "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"\
	 "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"\
	 "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"\
	 "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"\
	 "83655D23DCA3AD961C62F356208552BB9ED529077096966D"\
	 "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"\
	 "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"\
	 "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"\
	 "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"\
	 "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"\
	 "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"\
	 "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"\
	 "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"\
	 "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"\
	 "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"\
	 "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"\
	 "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"\
	 "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"\
	 "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"\
	 "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"\
	 "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"\
	 "179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"\
	 "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"\
	 "5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"\
	 "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"\
	 "23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"\
	 "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"\
	 "06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"\
	 "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"\
	 "12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"\
	 "38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300"\
	 "741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568"\
	 "3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"\
	 "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"\
	 "4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A"\
	 "062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36"\
	 "4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1"\
	 "B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"\
	 "4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47"\
	 "9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"\
	 "60C980DD98EDD3DFFFFFFFFFFFFFFFFF",2}
};


static
void _generate_dh_keypair(DH *dh)
{
//	priv_key = random(group_prime)
	gcry_mpi_randomize(dh->priv_key, gcry_mpi_get_nbits(dh->p)-1, 0);

//      pub_key = group_generator ^ priv_key (mod p)
	gcry_mpi_powm(dh->pub_key, dh->g, dh->priv_key, dh->p);
}

static
void _compute_dh_key(MPI res, MPI peer_key, DH *dh)
{
//	res = peer_key ^ priv_key (mod p)
	gcry_mpi_powm(res, peer_key, dh->priv_key, dh->p);
}

DH *hip_generate_dh_key(int group_id)
{
	DH *dh;

	if (group_id < 1 || group_id > HIP_MAX_DH_GROUP_ID) {
		return NULL;
	}

	dh = gcry_malloc(sizeof(DH));
	if (!dh) {
		log_error("Out of memory error\n");
		return NULL;
	}
	
	memset(dh,0,sizeof(DH));

	dh->g = mpi_alloc(1);
	dh->pub_key = mpi_alloc(1);
	dh->priv_key = mpi_alloc(1);
	if (dh->g == NULL || dh->pub_key == NULL || dh->priv_key == NULL) {
		log_error("could not allocate MPI\n");
		goto cleanup;
	}


/* use HEX */
	if (gcry_mpi_scan(&dh->p,GCRYMPI_FMT_HEX,dh_params[group_id].prime,0) != 0)
	{
		log_error("Could not read the group_prime for group_id: %d\n",group_id);
		goto cleanup;
	}


	_gcry_mpi_set_ui(dh->g, dh_params[group_id].generator);

	_generate_dh_keypair(dh);

	return dh;
 cleanup:
	hip_free_dh(dh);
	return NULL;
}

int hip_encode_dh_publickey(DH *dh, u8 *out, int outlen)
{
	size_t len;


	_HIP_HEXDUMP("DH pubkey", dh->pub_key->d, dh->pub_key->nlimbs*4);

	if (gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &len, dh->pub_key) != 0) {
		log_error("Could not process the public key: %d\n",(int)dh->pub_key);
		return -EINVAL;
	}

	_HIP_DEBUG("We need %d bytes for DH key\n",len);

	if (outlen < len) {
		log_error("Output buffer too small. %d bytes required\n",len);
		return -EINVAL;
	}

	if (gcry_mpi_print(GCRYMPI_FMT_USG, out, &len, dh->pub_key) != 0) {
		log_error("Could not export MPI to the output buffer\n");
		return -EINVAL;
	}

	return len;
}

int hip_gen_dh_shared_key(DH *dh, u8 *peer_key, size_t peer_len, u8 *out, size_t outlen)
{
	MPI peer_mpi;
	MPI shared_key = NULL;
	size_t plen = peer_len;

	if (dh == NULL) {
		log_error("No DH context\n");
		return -EINVAL;
	}

	if (gcry_mpi_scan(&peer_mpi,GCRYMPI_FMT_USG,peer_key,&plen) != 0) {
		log_error("Unable to read peer_key\n");
		return -EINVAL;
	}

	shared_key = mpi_alloc(1);
	if (!shared_key) {
		log_error("No memory for shared_key\n");
		return -EINVAL;
	}

	_compute_dh_key(shared_key, peer_mpi, dh);

	// reusing plen
	if (gcry_mpi_print(GCRYMPI_FMT_USG, NULL, &plen, shared_key) != 0) {
		log_error("Error parsing shared key\n");
		return -EINVAL;
	}

	if (plen > outlen) {
		log_error("Output buffer too small. %d bytes required\n",plen);
		return -EINVAL;
	}

	if (gcry_mpi_print(GCRYMPI_FMT_USG, out, &plen, shared_key) != 0) {
		log_error("Could not export MPI to the output buffer\n");
		return -EINVAL;
	}

	return plen;
}


void hip_free_dh(DH *target)
{
	if (target) {
		if (target->p)
			mpi_free(target->p);
		if (target->g)
			mpi_free(target->g);
		if (target->pub_key)
			mpi_free(target->pub_key);
		if (target->priv_key)
			mpi_free(target->priv_key);
		gcry_free(target);
	}
}

DH *hip_dh_clone(DH *src)
{
	DH *tgt;

	tgt = gcry_malloc(sizeof(DH));
	if (!tgt)
		return NULL;

	tgt->p = _gcry_mpi_copy(src->p);
	if (!tgt->p) {
		log_error("Cloning error (p)\n");
		goto cleanup;
	}

	tgt->g = _gcry_mpi_copy(src->g);
	if (!tgt->g) {
		log_error("Cloning error (g)\n");
		goto cleanup;
	}

	tgt->pub_key = _gcry_mpi_copy(src->pub_key);
	if (!tgt->pub_key) {
		log_error("Cloning error (pub_key)\n");
		goto cleanup;
	}

	tgt->priv_key = _gcry_mpi_copy(src->priv_key);
	if (!tgt->priv_key) {
		log_error("Cloning error (priv_key)\n");
		goto cleanup;
	}

	return tgt;
 cleanup:
	hip_free_dh(tgt);
	return NULL;
}

/**
 * hip_get_dh_size - determine the size for required to store DH shared secret
 * @hip_dh_group_type: the group type from DIFFIE_HELLMAN parameter
 *
 * Returns: 0 on failure, or the size for storing DH shared secret in bytes
 */
u16 hip_get_dh_size(u8 hip_dh_group_type)
{
	/* the same values as are supported ? HIP_DH_.. */
	int dh_size[] = { 0, 384, 768, 1536, 3072, 6144, 8192 };
	u16 ret = -1;

	_HIP_DEBUG("dh_group_type=%u\n", hip_dh_group_type);
	if (hip_dh_group_type == 0) 
		HIP_ERROR("Trying to use reserved DH group type 0\n");
	else if (hip_dh_group_type == HIP_DH_384)
		HIP_ERROR("draft-09: Group ID 1 does not exist yet\n");
	else if (hip_dh_group_type > ARRAY_SIZE(dh_size))
		HIP_ERROR("Unknown/unsupported MODP group %d\n", hip_dh_group_type);
	else
		ret = dh_size[hip_dh_group_type] / 8;

	return ret + 1;
}



