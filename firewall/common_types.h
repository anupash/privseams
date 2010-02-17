#ifndef HIP_FIREWALL_COMMON_TYPES_H
#define HIP_FIREWALL_COMMON_TYPES_H

typedef struct _SList SList;
struct _SList {
    void *         data;
    struct _SList *next;
};

typedef struct _DList DList;
struct _DList {
    void *         data;
    struct _DList *next;
    struct _DList *prev;
};

typedef struct _TimeVal TimeVal;

struct _TimeVal {
    long tv_sec;
    long tv_usec;
};

#endif /*HIP_FIREWALL_COMMON_TYPES_H*/
