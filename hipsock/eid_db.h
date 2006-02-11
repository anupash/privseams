#ifndef EID_DB_H
#define EID_DB_H

#include <linux/list.h>
#include <linux/spinlock.h>

struct hip_db_struct {
	struct list_head  db_head;
        rwlock_t          db_lock;
	char *            db_name;
        int               db_cnt;
};

#define HIP_INIT_DB(name,id) \
        struct hip_db_struct name = { LIST_HEAD_INIT(name.db_head), \
        RW_LOCK_UNLOCKED, id, 0}

#endif /* EID_DB_H */
