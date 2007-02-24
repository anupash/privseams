#include <stdlib.h>
#include <stdio.h>
#include "list.h"


struct hip_db_struct {
	struct list_head  db_head;
	rwlock_t          db_lock;
	char *            db_name;
	int               db_cnt;
};

struct hip_host_id_entry {
	/* this needs to be first (list_for_each_entry, list 
	   head being of different type) */
	struct list_head next; 
	int foo;
};

int main(int argc, char **argv) {
	struct list_head db[20];
	struct hip_host_id_entry *id_entry, *tmp;

	memset(&db, 0, sizeof(db));

	id_entry = malloc(sizeof(*id_entry));
	memset(id_entry, 0, sizeof(struct hip_host_id_entry));
							       
	list_add((struct list_head *) id_entry, db);
	list_add((struct list_head *) id_entry, db);
	printf("should find two entries now\n");

	list_for_each_entry_safe(id_entry, tmp, db, next) {
		printf("found entry\n");
	}
	list_del(db);
	printf("and only one now\n");
	list_for_each_entry_safe(id_entry, tmp, db, next) {
		printf("found entry\n");
	}
}
