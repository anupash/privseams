#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <x509ac.h>
#include <x509attr.h>
#include <x509ac-supp.h>
#include <x509attr-supp.h>
#include <x509ac_utils.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "lib/core/debug.h"
#include "lib/core/common.h"


#define SHA1_DIGEST_LENGTH 20

static char issuer_cert_path[PATH_MAX];
static char issuer_key_path[PATH_MAX];
static char app_path[PATH_MAX];
static char input[500];
static int duration = 365;

enum flags {
    ISSUER = 1,
    KEY = 2,
    APP_PATH = 4,
    DURATION = 8,
    PRINT = 16
};

/**
 * This hashes a file and returns the digest.
 */
static void hash_file(char *in_file, unsigned char *digest_buffer) {
    SHA_CTX context;
    int fd;
    int i;
    unsigned char read_buffer[1024];
    FILE *f;

    f = fopen(in_file,"r");
    fd=fileno(f);
    SHA1_Init(&context);
    for (;;) {
        i = read(fd,read_buffer,1024);
        if(i <= 0)
            break;
        SHA1_Update(&context,read_buffer,(unsigned long)i);
    }
    SHA1_Final(&(digest_buffer[0]),&context);
    fclose(f);
}

UNUSED static void print_hash_hex(unsigned char *digest){
    int i;
    for (i=0; i<SHA_DIGEST_LENGTH; i++)
        printf("%02x",digest[i]);
    printf("\n");
}

static void usage(void)
{
    fprintf(stderr, "Usage: ac-cert -i <issuer cert> -k <issuer key> -p <program> [options]\n");
    fprintf(stderr, "  -i <issuer certificate> use this as the issuer for the attribute certificate\n");
    fprintf(stderr, "  -k <issuer key> use this key to sign the attribute certificate\n");
    fprintf(stderr, "  -b <file> generate an attribute certificate for this file, i.e. program\n");
    fprintf(stderr, "  -d <duration> validity duration in days starting from now\n");
    fprintf(stderr, "  -p print the certificate that was generated\n");
    fprintf(stderr, "  -h print this message\n");
    fprintf(stderr, "\n");
}


/**
 * Parse the command line options
 * @param argc  number of command line parameters
 * @param argv  command line parameters
 * @param flags pointer to the startup flags container
 * @return      nonzero if the caller should exit, 0 otherwise
 */
static int parse_cmdline_options(int argc, char *argv[], uint64_t *flags)
{
    int c;
    while ((c = getopt(argc, argv, "i:k:b:d:p::")) != -1) {
        switch (c) {
        case 'i':
            *flags |= ISSUER;
            strcpy(issuer_cert_path, optarg);
            break;
        case 'k':
            *flags |= KEY;
            strcpy(issuer_key_path, optarg);
            break;
        case 'b':
            *flags |= APP_PATH;
            strcpy(app_path, optarg);
            break;
        case 'd':
            *flags |= DURATION;
            duration = atoi(optarg);
            break;
        case 'p':
            *flags |= PRINT;
            break;
        case '?':
        case 'h':
        default:
            usage();
            return -1;
        }
    }
    return 0;
}

static void get_from_user(const char *prompt, const char *def, char *buf)
{
    char *newline;
    fprintf(stdout, "%s [%s]: ", prompt, def);
    fflush(stdout);
    if ( fgets(buf, 500, stdin) != NULL )
    {
       newline = strchr(buf, '\n'); /* search for newline character */
       if ( newline != NULL )
       {
          *newline = '\0'; /* overwrite trailing newline */
       }
    }
}

static void dn_set_field(const char *prompt, const char *field, const char *def, X509_NAME *dn) {
    get_from_user(prompt, def, input);
    if (input[0] == '\0') {
        X509_NAME_add_entry_by_txt(dn, field, MBSTRING_ASC, (const unsigned char *) def, -1, -1, 0);
    } else if (input[0] != '.') {
        X509_NAME_add_entry_by_txt(dn, field, MBSTRING_ASC, (const unsigned char *) input, -1, -1, 0);
    }
}



int main(int argc, char *argv[])
{
    uint64_t flags = 0;
    FILE *fp = NULL;
    X509 *issuercert = NULL;
    X509AC *attributecert = NULL;
    X509AC_ISSUER_SERIAL *issuerbasecertid;
    EVP_PKEY* pkey;
    X509AC_OBJECT_DIGESTINFO *odi;
    X509_ALGOR *algor;
    unsigned char md[SHA1_DIGEST_LENGTH];
    ASN1_BIT_STRING *hash;
    X509_NAME *holder_name;

    /* parse and check */
    parse_cmdline_options(argc, argv, &flags);
    if (!(flags & APP_PATH)) {
        fprintf(stderr, "Missing program to certify \n \n");
        usage();
        return 0;
    }
    if (!(flags & KEY)) {
        fprintf(stderr, "Missing issuer key \n \n");
        usage();
        return 0;
    }
    if (!(flags & ISSUER)) {
        fprintf(stderr, "Missing issuer certificate \n \n");
        usage();
        return 0;
    }

    /* Initialize openssl lib */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    /* Open issuer PKI cert */
    if (!(fp = fopen (issuer_cert_path, "r")))
    {
        fprintf(stderr, "Error opening issuer certificate.\n");
        exit(0);
    }
    if (!(issuercert = PEM_read_X509(fp, NULL, NULL, NULL)))
    {
        fprintf(stderr, "Error decoding issuer certificate.\n");
        exit(0);
    }
    fclose (fp);

    /* Initialize the attribute certificate */
    attributecert = X509AC_new();

    /* Set the version (the current version of the specification is "v2". */
    X509AC_set_version(attributecert, 2);

    /* Set the basecertid (the issuer name is contained in the basecertid). */
    issuerbasecertid = X509_get_basecertID(issuercert);
    X509AC_set_issuer_baseCertID(attributecert, issuerbasecertid);

    /* We set the issuer name, too, since the verify function uses it to find the issuer cert. */
    X509AC_set_issuer_name(attributecert, X509_get_subject_name(issuercert));

    fprintf(stdout, "You are about to be asked to enter information that will be incorporated\n" \
                    "into your attribute certificate.\n" \
                    "What you are about to enter is what is called a Distinguished Name or a DN.\n" \
                    "There are quite a few fields but you can leave some blank.\n"\
                    "For some fields there will be a default value.\n"\
                    "If you enter '.', the field will be left blank.\n" \
                    "-----\n");


    /* We set the holder name to the name of our application. */
    holder_name = X509_NAME_new();
    dn_set_field("Country Name (2 letter code)",       "C",  "DE",     holder_name);
    dn_set_field("State or Province Name (full name)", "ST", "NRW",    holder_name);
    dn_set_field("Locality Name (eg, city)",           "L",  "Aachen", holder_name);
    dn_set_field("Organization Name (eg, company)",    "O",  "RWTH",   holder_name);
    dn_set_field("Organizational Unit Name",           "OU", "COMSYS", holder_name);
    dn_set_field("Common Name (eg name of program)",   "CN", "HIPL", holder_name);
    dn_set_field("Serial Number",                      "serialNumber", "", holder_name);
    dn_set_field("Email Address",                      "emailAddress", "", holder_name);
    X509AC_set_holder_entity_name(attributecert, holder_name);

    /* We set the holder object digest information */
    /* Init Type */
    odi = X509AC_OBJECT_DIGESTINFO_new();
    odi->type = ASN1_ENUMERATED_new();
    ASN1_ENUMERATED_set(odi->type, ODI_otherObjectTypes);

    /* Init OtherType
     * TODO: What value has to be set here? */
    odi->othertype = NULL;

    /* Init digest algorithm */
    algor =X509_ALGOR_new();
    algor->algorithm=ASN1_OBJECT_new();
    algor->algorithm = OBJ_nid2obj(EVP_MD_type(EVP_sha1()));
    odi->algor = algor;

    /* Init digest of object */
    hash_file(app_path, md);
    hash = ASN1_BIT_STRING_new();
    ASN1_BIT_STRING_set(hash,md,20);
    odi->digest = hash;

    /* Now set the object digest information... */
    if(!X509AC_set_holder_objectDigestInfo(attributecert, odi)) {
        printf("Error setting the object digest info for the holder!\n");
    }

    /* Set the validity period of the certificate.
     * Time period is specified in second (here: 7 days) */
    if(!X509_gmtime_adj(attributecert->info->validity->notBefore,0))
        fprintf(stderr, "Error setting the notBefore information");
    if(!X509_gmtime_adj(attributecert->info->validity->notAfter, 60*60*24*duration))
        fprintf(stderr, "Error setting the notAfter information");

    /* Add the signature */
    if (!(fp = fopen(issuer_key_path,"r"))) {
        fprintf(stderr, "Could not open issuer key for signing \n");
    } else {
        pkey = PEM_read_PrivateKey(fp,NULL,NULL,NULL);
        if (pkey->type == EVP_PKEY_EC) {
            X509AC_sign_pkey(attributecert, pkey, EVP_ecdsa());
        } else if (pkey->type == EVP_PKEY_DSA) {
            X509AC_sign_pkey(attributecert, pkey, EVP_dss1());
        } else {
            X509AC_sign_pkey(attributecert, pkey, EVP_sha1());
        }
    }

    if (flags & PRINT) {
        /* Print the application certificate */
        printf("Printing the attribute certificate\n");
        printf("----------------------------------\n\n");
        X509AC_print(attributecert);
    }

    /* Write the certificate to stdout */
    PEM_write_X509AC(stdout, attributecert);

    /* Free memory */
    X509AC_free(attributecert);
    return 0;
}

