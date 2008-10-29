#ifdef CONFIG_HIP_MIDAUTH

#include "hipd.h"

#define CERT_MAX_SIZE 1024

static char *midauth_cert = NULL;

int hip_pisa_load_certificate(void)
{
	int err = 0;
	FILE *f = NULL;

	if (midauth_cert)
		free(midauth_cert);
	midauth_cert = malloc(CERT_MAX_SIZE);
	memset(midauth_cert, 0, CERT_MAX_SIZE);

	if (!(f = fopen("/etc/hip/cert", "r"))) {
		HIP_ERROR("Could not open certificate file.\n");
		return -1;
	}

	fread(midauth_cert, CERT_MAX_SIZE - 1, 1, f);
	fclose(f);
	return 0;
}

char *hip_pisa_get_certificate(void)
{
	if (!midauth_cert)
		hip_pisa_load_certificate();
	return midauth_cert;
}
#endif
