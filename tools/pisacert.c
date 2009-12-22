/** @file
 * Generate a SPKI certificate for use with PISA.
 *
 * @author Thomas Jansen <mithi@mithi.net>
 */
#include <sys/time.h>
#include <time.h>
#include <zlib.h>
#include "libhipcore/ife.h"
#include "libhipcore/icomm.h"
#include "libhipcore/debug.h"
#include "libhipcore/certtools.h"

/**
 * Get the default hit of the local HIPD.
 *
 * @param result location to store the result in
 * @return 0 on success
 */
int get_default_hit(struct in6_addr *result)
{
	int err = 0;
	hip_common_t *msg = NULL;
	struct hip_tlv_common *param = NULL;
	struct in6_addr *hit = NULL;

	msg = hip_msg_alloc();
	HIP_IFE(!msg, -1);

	HIP_IFE(hip_build_user_hdr(msg, SO_HIP_DEFAULT_HIT, 0), -1);
	HIP_IFE(hip_send_recv_daemon_info(msg, 0, 0), -ECOMM);

	param = hip_get_param(msg, HIP_PARAM_HIT);
	hit = (struct in6_addr *) hip_get_param_contents_direct(param);
	memcpy(result, hit, sizeof(struct in6_addr));

out_err:
	if (msg)
		free(msg);

	return err;
}

/**
 * Create the certificate with the given parameters.
 *
 * @param not_before start of certificate lifetime
 * @param not_after end of certificate lifetime
 * @param hit HIT of issuer and subject
 * @param certificate buffer to store the resulting certificate in
 * @param size size of the certificate buffer
 * @return 0 on success
 */
int create_certificate(time_t *not_before, time_t *not_after,
		       struct in6_addr *hit, char *certificate, size_t size)
{
	int err = 0;
	struct hip_cert_spki_info cert = { 0 };

	HIP_IFEL(!not_before || !not_after || !hit || !certificate, -1,
		 "NULL parameter found.\n");

	hip_cert_spki_create_cert(&cert, "hit", hit, "hit", hit, not_before,
				  not_after);

	snprintf(certificate, size, "(sequence %s%s%s)", cert.public_key,
		 cert.cert, cert.signature);
out_err:
	if (err != 0 && certificate)
		certificate[0] = '\0';
	return err;
}

int main(int argc, char *argv[])
{
	time_t not_before = 0, not_after = 0;
	struct in6_addr hit;
	int err = 0, days = 0;
	FILE *f = NULL;
	char certificate[1024] = "";

	HIP_IFEL(argc != 3, -1, "Wrong number of arguments.\n");

	HIP_IFEL(getuid() != 0, -1, "You're not superuser.\n");

	days = atoi(argv[1]);
	HIP_IFEL(days <= 0, -1, "Specify a positive number of days.\n");

	f = fopen(argv[2], "w");
	HIP_IFEL(f == NULL, -1, "Could not write to file.\n");

	time(&not_before);
	time(&not_after);
	not_after += days * 24 * 60 * 60;

	HIP_IFEL(get_default_hit(&hit), -1, "Could not get HIT from hipd.\n");
	HIP_IFEL(create_certificate(&not_before, &not_after, &hit,
				    certificate, sizeof(certificate)) != 0,
		 -1, "Could not create the certificate.\n");

	fwrite(certificate, strlen(certificate), 1, f);

out_err:
	if (err == -1) {
		fprintf(stderr, "usage: pisacert days filename\n");
		fprintf(stderr, "must be run as superuser, e.g. with sudo\n");
	}

	if (f)
		fclose(f);

	return err;
}
