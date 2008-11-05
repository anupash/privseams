/** @file
 * This file deals with the PISA specific handling of SPKI certificates. The
 * certificate is parsed and split into small chunks.
 *
 * @author Thomas Jansen
 */
#include "pisa_cert.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

/**
 * Extract parts of a SPKI certificate.
 *
 * @param cert pointer to the certificate text or part of a certificate text
 * @param name pointer to the pattern we are looking for
 * @param r pointer to a buffer that the search result will be copied to
 * @param size size of the buffer result
 * @return 0 on success
 */
static char* pisa_cert_get_part(char *cert, char *name, char *r, size_t size)
{
	int level = 0, len = 0;
	char *p = cert, *start = NULL;

	if (!r)
		return NULL;

	if (!cert)
		goto out_err;

	if (!name)
		goto out_err;

	len = strlen(name);
	if (len == 0)
		goto out_err;

	while (*p) {
		if (*p == '(') {
			level++;
			if (level == 2 && !strncmp(p+1, name, len)) {
				if (*(p+len+1) == ' ') {
					start = p++;
					break;
				}
			}
		}
		if (*p == ')')
			level--;
		if (level == 0)
			break;
		p++;
	}

	if (!start)
		goto out_err;

	len = 0;

	while (*p) {
		if (*p == '(') 
			level++;
		if (*p == ')') {
			level--;
			if (level == 1) {
				len = p - start + 1;
				break;
			}
		}
		if (level == 0)
			break;
		p++;
	}

	strncpy(r, start, len);
	r[len] = '\0';
	
	return r;

out_err:
	r[0] = '\0';
	return NULL;
}

/**
 * Get the content from a SPKI certificate part.
 *
 * @param cert pointer to the certificate text or part of a certificate text
 * @param name pointer to the pattern we are looking for
 * @param r pointer to a buffer that the search result will be copied to
 * @param size size of the buffer result
 * @return 0 on success
 */
static void pisa_cert_get_content(char *cert, char *name, char *r, size_t size)
{
	char *start = cert;
	int len = 0;

	if (!r)
		return;

	if (!cert || !name || !*name == '(')
		goto out_err;

	if (strlen(name) + 3 > strlen(cert))
		goto out_err;

	if (strncmp(name, cert+1, strlen(name)))
		goto out_err;
	start = cert + strlen(name) + 2;

	if (*start == '\0')
		goto out_err;

	len = strlen(start) - 1; 
	if (*(start + len) != ')')
		goto out_err;
	strncpy(r, start, len);

out_err:
	r[len] = '\0';
	return;
}

void pisa_split_cert(char *cert, struct pisa_cert *pc)
{
	struct tm t;
	char buffer1[224], buffer2[224];
	struct in6_addr addr;

	pisa_cert_get_part(cert, "not-before", buffer1, sizeof(buffer1));
	pisa_cert_get_content(buffer1, "not-before", buffer2, sizeof(buffer2));
	strptime(buffer2, "\"%Y-%m-%d_%H:%M:%S\"", &t);
	pc->not_before = mktime(&t);
	
	pisa_cert_get_part(cert, "not-after", buffer1, sizeof(buffer1));
	pisa_cert_get_content(buffer1, "not-after", buffer2, sizeof(buffer2));
	strptime(buffer2, "\"%Y-%m-%d_%H:%M:%S\"", &t);
	pc->not_after = mktime(&t);

	pisa_cert_get_part(cert, "issuer", buffer1, sizeof(buffer1));
	pisa_cert_get_part(buffer1, "hash hit", buffer2, sizeof(buffer2));
	pisa_cert_get_content(buffer2, "hash hit", buffer1, sizeof(buffer1));
	inet_pton(AF_INET6, buffer1, &addr);
	memcpy(&pc->hit_issuer, &addr, sizeof(struct in6_addr));

	pisa_cert_get_part(cert, "subject", buffer1, sizeof(buffer1));
	pisa_cert_get_part(buffer1, "hash hit", buffer2, sizeof(buffer2));
	pisa_cert_get_content(buffer2, "hash hit", buffer1, sizeof(buffer1));
	inet_pton(AF_INET6, buffer1, &addr);
	memcpy(&pc->hit_subject, &addr, sizeof(struct in6_addr));
}
