/*
 * HIPL GTK GUI
 *
 * License: GNU/GPL
 * Authors: Antti Partanen <aehparta@cc.hut.fi>
 */

#ifndef _TOOLS_H
#define _TOOLS_H

/******************************************************************************/
/* INCLUDES */
#include <gtk/gtk.h>

#include "agent/hitdb.h"


/******************************************************************************/
/* DEFINES */

/** Structure for tree update function. */
struct tree_update_data
{
	char old_name[MAX_NAME_LEN + 1];
	char new_name[MAX_NAME_LEN + 1];
	int depth;
	int indices_first;
};


/******************************************************************************/
/* FUNCTION DEFINITIONS */
void _info_set(const char *str, int safe);

void info_set(const char *string, ...);
void about(void);

gboolean update_tree_value(GtkTreeModel *, GtkTreePath *, GtkTreeIter *, gpointer);
int local_add(HIT_Local *);

int combo_box_find(const char *, GtkWidget *);

void hit_remote_add(const char *, const char *);
int group_remote_create(const char *);

int check_name_hit(const char *, HIT_Remote *);
int check_apply_hit(const char *, HIT_Remote *);
int check_apply_hit_move(const char *, HIT_Remote *);
int check_apply_local_edit(void);

void edit_reset(void);
void edit_hit_remote(char *hit_name);
void edit_group_remote(char *);

void edit_apply(void);
void edit_delete(void);

void edit_set_remote_group(HIT_Group *);
void hit_dlg_set_remote_group(HIT_Group *);

void exec_application(void);


#endif /* END OF HEADER FILE */
/******************************************************************************/

