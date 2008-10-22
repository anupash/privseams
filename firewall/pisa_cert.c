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
 * @param part pointer to the pattern we are looking for
 * @param result pointer to a buffer that the search result will be copied to
 * @param len size of the buffer result
 * @param just_content copy just the content without (<part> ...) if true
 * @return 0 on success
 */
static int pisa_cert_get_part(char *cert, char *part, char *result, size_t len,
			      int just_content)
{
	char *start, *end;
	int parentheses = 1; /* the initial parenthesis */

	start = strstr(cert, part);

	if (start == NULL || (!just_content && start == cert)) {
		result[0] = '\0';
		return -2;
	}
	end = start;

	/* @todo: check if the assumed initial parenthesis is really there */

	while (parentheses > 0 && *end) {
		if (*end == '(')
			parentheses++;
		else if (*end == ')')
			parentheses--;
		end++;
	}

	if (parentheses != 0) {
		result[0] = '\0';
		return -3;
	}

	if (just_content) {
		start += strlen(part) + 2;
		end--; /* skip closing ')' */
	}

	if (len < end - start + 1) {
		strncpy(result, start - 1, len);
		result[len-1] = '\0';
		return -1;
	}

	strncpy(result, start - 1, end - start + 1);
	result[end - start + 1] = '\0';
	return 0;
}	

void pisa_split_cert(char *cert, struct pisa_cert *pc)
{
	struct tm t;
	char buffer1[224], buffer2[224];
	struct in6_addr addr;

	pisa_cert_get_part(cert, "not-before", buffer1, sizeof(buffer1), 1);
	strptime(buffer1, "\"%Y-%m-%d_%H:%M:%S\"", &t);
	pc->not_before = mktime(&t);
	
	pisa_cert_get_part(cert, "not-after", buffer1, sizeof(buffer1), 1);
	strptime(buffer1, "\"%Y-%m-%d_%H:%M:%S\"", &t);
	pc->not_after = mktime(&t);

	pisa_cert_get_part(cert, "issuer", buffer1, sizeof(buffer1), 0);
	pisa_cert_get_part(buffer1, "hash hit", buffer2, sizeof(buffer2), 1);
	inet_pton(AF_INET6, buffer2, &addr);
	memcpy(&pc->hit_issuer, &addr, sizeof(struct in6_addr));

	pisa_cert_get_part(cert, "subject", buffer1, sizeof(buffer1), 0);
	pisa_cert_get_part(buffer1, "hash hit", buffer2, sizeof(buffer2), 1);
	inet_pton(AF_INET6, buffer2, &addr);
	memcpy(&pc->hit_subject, &addr, sizeof(struct in6_addr));
}
