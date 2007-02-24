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
	struct hip_db_struct db = LIST_HEAD_INIT(db.db_head);
	struct hip_host_id_entry *id_entry;
	id_entry = malloc(sizeof(*id_entry));
	memset(id_entry, 0, sizeof(struct hip_host_id_entry));
							       
	list_add(&id_entry->next, &db.db_head);
	list_add(&id_entry->next, &db.db_head);
	free(id_entry);
	printf("should find two entries now\n");
	list_for_each_entry(id_entry, &db.db_head, next) {
		printf("found entry\n");
	}
	list_del(&db.db_head);
	printf("and only one now\n");
	list_for_each_entry(id_entry, &db.db_head, next) {
		printf("found entry\n");
	}
}
