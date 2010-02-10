#ifndef HIT_DB_H
#define HIT_DB_H

#include <netinet/in.h>
#include <string.h>

#define HIT_ACCEPT              1
#define HIT_DENY                2

/* NOTE following two values affect the db create tbl queries in sqlitedbapi.h */
/*
 *      Maximum length for name-strings. Notice that this and the max URL length
 *      are statically set when reading values from database-file. So if these
 *      values here are changed, they should be manually changed to database-file
 *      loading routines.
 *
 *      example: sscanf(buf, "\"%64[^\"]\" %s", name, hit);
 *                               ^^
 */
#define MAX_NAME_LEN            64
/* Maximum length for URLs. */
#define MAX_URL_LEN             1024

/*
 *      This macro is for copying name string. It sets NULL characters and so on.
 *      strncpy() does not always do this properly, so this macro is here.
 *      Actually, when using this macro, the buffer being destination, must
 *      have MAX_NAME_LEN + 1 size.
 */
#define NAMECPY(dst, src) \
    { \
        strncpy(dst, src, MAX_NAME_LEN); \
        dst[MAX_NAME_LEN - 1] = '\0'; \
    }

/* This macro is for copying url string, see NAMECPY for more info. */
#define URLCPY(dst, src) \
    { \
        strncpy(dst, src, MAX_URL_LEN); \
        dst[MAX_URL_LEN - 1] = '\0'; \
    }

/* This structure stores one local HIT and information needed for it. */
typedef struct {
    /* Local HIT name. */
    char            name[MAX_NAME_LEN + 1];
    /** HIT. */
    struct in6_addr lhit;
    /* Next group item. */
    void *          next;
} HIT_Local;

/* This structure stores one group information. */
typedef struct {
    /* Group name. */
    char       name[MAX_NAME_LEN + 1];
    /* Stores pointer to local HIT with which this group is associated. */
    HIT_Local *l;
    /* Style of this group, 1 for accept, 0 for deny. */
    int        accept;
    /* Is group lightweight or not. */
    int        lightweight;
    /* Number of remote HITs in this group. */
    int        remotec;
    /* Next group item. */
    void *     next;
} HIT_Group;

/* This structure stores one remote HIT and information needed for it. */
typedef struct {
    /*
     *      Stores HIT item 'human' identifier, it's name.
     *      Maximum length for this is 64 + null.
     */
    char            name[MAX_NAME_LEN + 1];
    /* Stores HIT of this item. */
    struct in6_addr hit;
    /*
     *      Stores url of this item.
     *      Used for accepting connections for this HIT.
     */
    char url[MAX_URL_LEN + 1];
    /*
     *      Stores port information for this item.
     *      Used for accepting connections for this HIT.
     *      This should be able to contain different forms of
     *      port info, like range, single, descriptive strings and so on.
     *      Example string: "80,443,7780-7790,ftp,ntp"
     */
    char       port[MAX_URL_LEN + 1];
    /* Remote HIT group. */
    HIT_Group *g;
    /* Next remote item. */
    void *     next;
} HIT_Remote;

/* Set up for C function definitions, even when using C++ */
#ifdef __cplusplus
extern "C" {
#endif

int hit_db_init(char *);
void hit_db_quit(void);

HIT_Remote *hit_db_add_hit(HIT_Remote *, int);
HIT_Remote *hit_db_add(char *, struct in6_addr *, char *, char *, HIT_Group *, int);
int hit_db_del(char *);
HIT_Remote *hit_db_find(char *, struct in6_addr *);

HIT_Group *hit_db_add_rgroup(char *, HIT_Local *, int, int);
int hit_db_del_rgroup(char *);
HIT_Group *hit_db_find_rgroup(const char *);

HIT_Local *hit_db_add_local(char *, struct in6_addr *);
HIT_Local *hit_db_find_local(char *, struct in6_addr *);
int hit_db_enum_locals(int (*)(HIT_Local *));

int hit_db_count_locals(void);

/* Ends C function definitions when using C++ */
#ifdef __cplusplus
}
#endif

#endif /* HIT_DB_H */
