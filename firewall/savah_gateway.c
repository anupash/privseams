/* required for s6_addr32 */
#define _BSD_SOURCE

#include <string.h>

#include "savah_gateway.h"
#include "helpers.h"

HIP_HASHTABLE *sava_mac_db = NULL;

/* hash functions used for calculating the entries' hashes */
#define INDEX_HASH_FN           HIP_DIGEST_SHA1
/* the length of the hash value used for indexing */
#define INDEX_HASH_LENGTH       SHA_DIGEST_LENGTH

#define IP_VERSION_4            4
#define IP_VERSION_6            6
#define MAC_LENGTH              18

typedef struct hip_sava_mac_entry {
    struct in6_addr *ip;
    char *           mac;
} hip_sava_mac_entry_t;

static int __hip_sava_mac_db_init(void);
static char *__arp_get_c(char *ip);
static char *__savah_inet_ntop(struct in6_addr *addr);
static int __hip_sava_mac_entry_add(struct in6_addr *ip, char *mac);
static hip_sava_mac_entry_t *__hip_sava_mac_entry_find(struct in6_addr *ip);

static unsigned long __hip_sava_mac_entry_hash(
        const hip_sava_mac_entry_t *entry)
{
    unsigned char hash[INDEX_HASH_LENGTH];
    struct in6_addr addrs[1];
    int err = 0;
    _HIP_DEBUG_HIT("IP address in hip_sava_mac_entry_hash()", entry->ip);

    HIP_ASSERT(entry != NULL && entry->ip != NULL);

    memcpy(&addrs[0], (char *) entry->ip, sizeof(struct in6_addr));

    memset(hash, 0, INDEX_HASH_LENGTH);

    HIP_IFEL(hip_build_digest(INDEX_HASH_FN, (void *) addrs,
                              sizeof(struct in6_addr), hash),
             -1, "failed to hash addresses\n");

out_err:
    if (err) {
        *hash = 0;
    }

    return *((unsigned long *) hash);
}

static IMPLEMENT_LHASH_HASH_FN(__hip_sava_mac_entry,
                               const hip_sava_mac_entry_t)

static int __hip_sava_mac_entries_cmp(const hip_sava_mac_entry_t *entry1,
                                      const hip_sava_mac_entry_t *entry2)
{
    int err             = 0;
    unsigned long hash1 = 0;
    unsigned long hash2 = 0;

    // values have to be present
    HIP_ASSERT(entry1 != NULL && entry1->ip != NULL);
    HIP_ASSERT(entry2 != NULL && entry2->ip != NULL);

    HIP_IFEL(!(hash1 = __hip_sava_mac_entry_hash(entry1)),
             -1, "failed to hash sa entry\n");

    HIP_IFEL(!(hash2 = __hip_sava_mac_entry_hash(entry2)),
             -1, "failed to hash sa entry\n");

    err = (hash1 != hash2);

out_err:
    return err;
    return 0;
}

static IMPLEMENT_LHASH_COMP_FN(__hip_sava_mac_entries,
                               const hip_sava_mac_entry_t)

static
int __hip_sava_mac_db_init(void)
{
    int err = 0;
    HIP_IFEL(!(sava_mac_db = hip_ht_init(LHASH_HASH_FN(__hip_sava_mac_entry),
                                         LHASH_COMP_FN(__hip_sava_mac_entries))), -1,
             "failed to initialize sava_mac_db \n");
    HIP_DEBUG("sava mac db initialized\n");
out_err:
    return err;
}

static hip_sava_mac_entry_t *__hip_sava_mac_entry_find(struct in6_addr *ip)
{
    hip_sava_mac_entry_t *search_link = NULL, *stored_link = NULL;
    int err                           = 0;

    HIP_IFEL(!(search_link =
                   (hip_sava_mac_entry_t *) malloc(sizeof(hip_sava_mac_entry_t))),
             -1, "failed to allocate memory\n");
    memset(search_link, 0, sizeof(hip_sava_mac_entry_t));

    // search the linkdb for the link to the corresponding entry
    search_link->ip = ip;

    HIP_DEBUG("looking up link entry with following index attributes:\n");
    HIP_DEBUG_HIT("IP address", search_link->ip);

    HIP_IFEL(!(stored_link = hip_ht_find(sava_mac_db, search_link)), -1,
             "failed to retrieve link entry\n");
out_err:
    if (err) {
        stored_link = NULL;
    }
    if (search_link) {
        free(search_link);
    }
    return stored_link;
}

static int __hip_sava_mac_entry_add(struct in6_addr *ip, char *mac)
{
    hip_sava_mac_entry_t *entry = malloc(sizeof(hip_sava_mac_entry_t));

    HIP_ASSERT(ip != NULL && mac != NULL);

    memset(entry, 0, sizeof(hip_sava_mac_entry_t));

    entry->ip  =
        (struct in6_addr *) malloc(sizeof(struct in6_addr));
    entry->mac =
        (char *) malloc(MAC_LENGTH);

    memcpy(entry->ip, (char *) ip,
           sizeof(struct in6_addr));

    memcpy(entry->mac, (char *) mac,
           MAC_LENGTH);

    hip_ht_add(sava_mac_db, entry);

    return 0;
}

#if 0
static
int __hip_sava_mac_entry_delete(struct in6_addr *ip)
{
    hip_sava_mac_entry_t *stored_link = NULL;
    int err                           = 0;

    // find link entry and free members
    HIP_IFEL(!(stored_link = __hip_sava_mac_entry_find(ip)), -1,
             "failed to retrieve ip-mac entry\n");

    hip_ht_delete(sava_mac_db, stored_link);
    // we still have to free the link itself
    free(stored_link);

out_err:
    return err;
    return 0;
}

#endif

/**
 * Get an IP's MAC address from the ARP cache.
 * Go through all the entries in /proc/net/arp until we find the requested
 * IP address and return the MAC address bound to it.
 * @todo Make this function portable (using shell scripts?)
 */
static char *__arp_get_c(char *req_ip)
{
    FILE *proc  = NULL;
    char ip[16];
    //char mac[18];
    char *reply = NULL;
    char *mac   = (char *) malloc(30);

    if (!(proc = fopen("/proc/net/arp", "r"))) {
        return NULL;
    }

    /* Skip first line */
    while (!feof(proc) && fgetc(proc) != '\n') {
        ;
    }

    /* Find ip, copy mac in reply */
    reply = NULL;
    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[a-fA-F0-9:] %*s %*s", ip, mac) == 2)) {
        _HIP_DEBUG("IP: %s\n", ip);
        _HIP_DEBUG("MAC: %s \n", mac);
        _HIP_DEBUG("Requested IP: %s \n", req_ip);

        if (strcmp(ip, req_ip) == 0) {
            fclose(proc);
            _HIP_DEBUG("FOUND MAC: %s \n", mac);
            return mac;
        }
    }

    fclose(proc);

    return NULL;
}

static char *__savah_inet_ntop(struct in6_addr *addr)
{
    char buf_in6[INET6_ADDRSTRLEN];
    char buf_in[INET_ADDRSTRLEN];
    char *res = NULL;
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        struct in_addr in_addr;
        IPV6_TO_IPV4_MAP(addr, &in_addr);
        inet_ntop(AF_INET, &in_addr, buf_in, sizeof(buf_in));
        HIP_DEBUG("Address: %s \n", buf_in);
        res = strdup(buf_in);
    } else {
        hip_in6_ntop(addr, buf_in6);
        HIP_DEBUG("Address: %s \n", buf_in6);
        res = strdup(buf_in6);
    }
    return res;
}

/** Set if a specific client has access through the firewall */
int savah_fw_access(fw_access_t type,
                    struct in6_addr *ip,
                    const char *mac,
                    fw_marks_t tag,
                    int ip_version)
{
    int err      = 0;
    char *ip_buf = __savah_inet_ntop(ip);

    switch (type) {
    case FW_ACCESS_DENY:
        if (ip_version == IP_VERSION_4) {
            iptables_do_command("iptables -t mangle -A PREROUTING -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip_buf, mac, tag);
        } else {
            iptables_do_command("ip6tables -t mangle -A PREROUTING  -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip_buf, mac, tag);
        }
        break;
    case FW_ACCESS_ALLOW:
        if (ip_version == IP_VERSION_4) {
            iptables_do_command("iptables -t mangle -D PREROUTING -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip_buf, mac, tag);
        } else {
            iptables_do_command("ip6tables -t mangle -D PREROUTING  -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip_buf, mac, tag);
        }
        break;
    default:
        err = -1;
        break;
    }
    free(ip_buf);
    return err;
}

char *arp_get(struct in6_addr *ip)
{
    char *mac;
    char *buf;
    int err = 0;

    hip_sava_mac_entry_t *entry;
    if (!sava_mac_db) {
        __hip_sava_mac_db_init();
        goto mac_cache_request;
    }

    entry =  __hip_sava_mac_entry_find(ip);
    if (entry != NULL) {
        mac = entry->mac;
        goto out_err;
    }

mac_cache_request:
    buf = __savah_inet_ntop(ip);
    HIP_DEBUG("After: %s \n", buf);
    mac = __arp_get_c(buf);
    if (mac) {
        HIP_IFEL(__hip_sava_mac_entry_add(ip, mac), -1, "Failed to add new entry");
    }
    free(buf);
out_err:
    HIP_DEBUG("FOUND MAC: %s \n", mac);
    return mac;
}

int iptables_do_command(const char *format, ...)
{
    va_list vlist;
    char cmd[256];
    int err    = 0;
    int ignore = 0;

    va_start(vlist, format);
    ignore = vsprintf(cmd, format, vlist);
    va_end(vlist);
    HIP_DEBUG("%s \n", cmd);
    system_print(cmd);
    return err;
}
