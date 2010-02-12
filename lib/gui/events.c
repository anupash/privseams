/**
 * @file libhipgui/events.c
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * This file contains event handlers for every button etc. in agent GUI excluding
 * drag'n'drop events that are in libhipgui/dragndrop.c
 *
 * @brief event handlers for GUI
 *
 * @author Antti Partanen <aehparta@cc.hut.fi>
 *
 * @note The documentation may be inaccurate please feel free to fix it -Samu
 */
#include "events.h"
#include "hipgui.h"
#include "widgets.h"
#include "tools.h"
#include "agent/tools.h"
#include "agent/language.h"
#include "agent/hitdb.h"
#include "agent/connhipd.h"
#include "lib/core/debug.h"

/**
 * e_delete - Default window close event. This occurs when user presses that cross
 *            usually placed in right top corner of windows.
 *
 * @param *w Widget that caused this event
 * @param *event Pointer to the event
 * @param data Pointer to optional data for the delete handler not used
 *
 * @return TRUE if don't close or FALSE if close.
 */
gboolean e_delete(GtkWidget *w, GdkEvent *event, gpointer data)
{
    gtk_widget_hide(GTK_WIDGET(w));
    return TRUE;
}

/**
 * e_delete_main - When closing the main application window.
 *
 * @param *w Widget that caused this event
 * @param *event Pointer to the event
 * @param data Pointer to optional data for the delete handler not used
 *
 * @return TRUE if don't close or FALSE if close.
 */
gboolean e_delete_main(GtkWidget *w, GdkEvent *event, gpointer data)
{
#if (GTK_MAJOR_VERSION >= 2) && (GTK_MINOR_VERSION >= 10)
    gtk_widget_hide(GTK_WIDGET(w));
    return TRUE;
#else
    return FALSE;
#endif
}

/**
 * e_destroy main - When main window is destroyed.
 *
 * @param *w Widget that caused this event
 * @param data Pointer to optional data for the delete handler not used
 *
 * @return void
 */
void e_destroy_main(GtkWidget *w, gpointer data)
{
    connhipd_quit();
    gtk_main_quit();
}

/**
 * e_button - When button is pressed.
 *
 * @param *warg Widget that caused this event
 * @param data Pointer to optional data for the delete handler not used
 *
 * @return void
 */
void e_button(GtkWidget *warg, gpointer data)
{
    GtkWidget *w = NULL;
    HIT_Group *g;
    HIT_Remote *r;
    int id       = GPOINTER_TO_INT(data), i, err;
    char *ps;

    switch (id) {
    case IDB_TW_RGROUPS:
    case IDB_NH_RGROUPS:
        ps = (char *) gtk_combo_box_get_active_text(GTK_COMBO_BOX(warg));
        g  = hit_db_find_rgroup(ps);
        if (g) {
            if (id == IDB_TW_RGROUPS) {
                edit_set_remote_group(g);
            }
            if (id == IDB_NH_RGROUPS) {
                hit_dlg_set_remote_group(g);
            }
        } else if (strcmp(lang_get("combo-newgroup"), ps) == 0)   {
            if (id == IDB_TW_RGROUPS) {
                w  = widget(ID_TWR_RGROUP);
                r  = pointer(ID_EDIT_REMOTE);
                ps = r->g->name;
            }
            if (id == IDB_NH_RGROUPS) {
                w  = widget(ID_NH_RGROUP);
                ps = lang_get("default-group-name");
            }
            err = group_remote_create("");
            if (!err) {
                i = 0;
            } else {                      i = combo_box_find(ps, w);
            }
            gtk_combo_box_set_active(GTK_COMBO_BOX(w), i);
        }
        break;

    case IDB_TW_APPLY:
        edit_apply();
        break;

    case IDB_TW_DELETE:
        edit_delete();
        break;

    case IDM_TRAY_SHOW:
        gtk_widget_show(GTK_WIDGET(widget(ID_MAINWND)));
        break;
        break;

    case IDM_TRAY_ABOUT:
    case IDM_ABOUT:
        about();
        break;

    case IDM_TRAY_EXIT:
        gtk_main_quit();
        break;

    case IDM_RLIST_DELETE:
        HIP_DEBUG("Delete\n");
        break;

    case IDM_TRAY_EXEC:
    case IDM_RUNAPP:
        exec_application();
        break;

    case IDM_NEWHIT:
        gui_hit_remote_ask(NULL, 2);
        break;

    case IDM_NEWGROUP:
        group_remote_create("");
        break;

    case IDB_NH_EXPANDER:
        break;

    case IDB_OPT_NAT:
    case IDB_DBG_RSTALL:
    case IDB_DBG_RESTART:
//      opt_handle_action(warg, id);
        break;
    }
}

/**
 * e_cell_data_func - Tell HIT list cell renderer which icon to show where.
 *
 * @param *tree_column Pointer to the tree column
 * @param *cell Pointer to the renderer
 * @param *model Pointer to the tree model
 * @param *iter Pointer to the tree iterator
 * @param data Optional data for the handler
 *
 * @return void
 */
void e_cell_data_func(GtkTreeViewColumn *tree_column, GtkCellRenderer *cell,
                      GtkTreeModel *model, GtkTreeIter *iter, gpointer data)
{
    GtkTreePath *path = gtk_tree_model_get_path(GTK_TREE_MODEL(model), iter);
    int depth         = gtk_tree_path_get_depth(path);
    char *stock_id    = GTK_STOCK_ABOUT;
    char *value;
    HIT_Group *g;

    gtk_tree_model_get(GTK_TREE_MODEL(model), iter, 0, &value, -1);
    if (depth == 1) {
        g = hit_db_find_rgroup(value);
        if (!g) {
            ;
        } else if (g->remotec > 0) {
            stock_id = GTK_STOCK_OPEN;
        } else {stock_id = GTK_STOCK_DIRECTORY;
        }
    } else if (strcmp(value, lang_get("hits-group-emptyitem")) == 0)   {
        stock_id = GTK_STOCK_STOP;
    } else {stock_id = GTK_STOCK_ORIENTATION_PORTRAIT;
    }
    g_object_set(cell, "stock-id", stock_id, NULL);
    g_free(value);
}

/**
 * e_cursor_changed - When user selects item on list (with mouse or keyboard).
 *
 * @param *tree Pointer to tree object that triggered this event
 * @param data Optional data for the handler
 *
 * @return gboolean TRUE always
 */
gboolean e_cursor_changed(GtkTreeView *tree, gpointer data)
{
    GtkTreeIter iter;
    GtkTreeModel *model;
    GtkTreePath *path;
    GtkTreeSelection *selection;
    char *str;
    int depth, *indices;

    selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree));

    if (gtk_tree_selection_get_selected(selection, &model, &iter)) {
        path    = gtk_tree_model_get_path(model, &iter);
        depth   = gtk_tree_path_get_depth(path);
        indices = gtk_tree_path_get_indices(path);
        gtk_tree_model_get(model, &iter, 0, &str, -1);

        if (data == NULL) {
            ;
        } else if (strcmp(data, "remote-hit-list") == 0) {
            edit_reset();
            if (str[0] == ' ') {
                ;
            } else if (depth == 1) {
                edit_group_remote(str);
            } else if (depth == 2) {
                edit_hit_remote(str);
            }
        }

        gtk_tree_path_free(path);
        g_free(str);
    }

    return TRUE;
}

/**
 * e_button_press - called when button is pressed
 *
 * @param *tree Tree that caused this event
 * @param *button Button event
 * @param data Optional data for the handler
 *
 * @return gboolean FALSE always
 */
gboolean e_button_press(GtkTreeView *tree, GdkEventButton *button, gpointer data)
{
    return FALSE;
}

/**
 * e_row_activated - Usually occurs when user double clicks list item.
 *
 * @param *selection Pointer to what is selected in the activated column
 * @param *path Path to the activated column
 * @param *column Pointer to the activated column
 * @param data Optional data for the handler
 *
 * @return gboolean FALSE always
 */
gboolean e_row_activated(GtkTreeSelection *selection, GtkTreePath *path,
                         GtkTreeViewColumn *column, gpointer data)
{
    /* ... */

    return FALSE;
}

/**
 * e_menu_status_icon - Called when systray is activated.
 *
 * @param *warg
 * @param bid
 * @param atime Call time
 * @param data Additional data for the handler
 *
 * @return void
 */
void e_menu_status_icon(void *warg, guint bid, guint atime, gpointer data)
{
    gtk_menu_popup(GTK_MENU(widget(ID_SYSTRAYMENU)), NULL, NULL, NULL, NULL, 0, atime);
}

/**
 * Set local HIT info to local hit edit dialog.
 *
 * @param *warg
 * @param hit_name Name of remote HIT.
 *
 * @return void
 */
void e_local_edit(GtkWidget *warg, char *hit_name)
{
    GtkWidget *dialog = widget(ID_LOCALDLG);
    HIT_Local *hit;
    char str[320];
    int err;

    hit = hit_db_find_local(hit_name, NULL);

    if (hit) {
        gtk_entry_set_text(GTK_ENTRY(widget(ID_TWL_NAME)), hit->name);
        print_hit_to_buffer(str, &hit->lhit);
        gtk_entry_set_text(GTK_ENTRY(widget(ID_TWL_LOCAL)), str);
        pointer_set(ID_EDIT_LOCAL, hit);
        gtk_widget_grab_focus(GTK_WIDGET(widget(ID_TWL_NAME)));

        gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_YES);
        gtk_window_set_keep_above(GTK_WINDOW(dialog), TRUE);
        gtk_widget_show(GTK_WIDGET(dialog));
        do {
            err = gtk_dialog_run(GTK_DIALOG(dialog));
            if (err != GTK_RESPONSE_YES) {
                break;
            }
        } while (!check_apply_local_edit());
        gtk_widget_hide(GTK_WIDGET(dialog));
    }
}
