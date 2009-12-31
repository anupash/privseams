/**
 * @file libhipgui/widgets.c
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * This file contains functions to init all the widgets needed for the GUI as 
 * well as the deinitialization of the widget system. Also functions how to set
 * ID to a widget and how to get a pointer to a widget based on the ID
 *
 * @brief Widget functions for the GUI
 *
 * @author Antti Partanen <aehparta@cc.hut.fi>
 **/
#include "widgets.h"
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include "libhipcore/debug.h"
#include "libhipcore/ife.h"

void **gui_widgets = NULL;

/**
 * widget_init - Initialize GUI widgets system. This system stores pointers to widgets in use.
 *
 * @return 0 on success, -1 on errors.
 **/
int widget_init(void)
{
	int err = 0;

	/* had to call calloc here to avoid the following error with -enable-optimizations:
	  /usr/include/bits/string3.h:82: error: call to ‘__warn_memset_zero_len’ declared with attribute warning: memset used with constant zero length parameter; this could be due to transposed parameters -miika */

	//gui_widgets = (void **)alloc(sizeof(void *) * WIDGET_IDS_N);
	gui_widgets = (void **)calloc(WIDGET_IDS_N, sizeof(void *));
	HIP_IFEL(gui_widgets == NULL, -1, "Failed to allocate widgets pointers.\n");
	//memset(gui_widgets, sizeof(GtkWidget *) * WIDGET_IDS_N, 0);

out_err:
	return (err);
}

/** 
 * widget_quit - Deinitalize GUI widgets system. 
 * 
 * @return void 
 **/
void widget_quit(void)
{
	if (gui_widgets) free(gui_widgets);
	gui_widgets = NULL;
}

/** 
 * widget_set - Set pointer for given widget. This function set's pointer of given widget
 *              ID. This ID should be declared in widgets.h enum WIDGET_IDS.
 *
 * @param n Widget identifier.
 * @param p Pointer to widget.
 **/
void widget_set(int n, void *p)
{
	if (n >= 0 && n < WIDGET_IDS_N) gui_widgets[n] = p;
}

/**
 * widget - Returns pointer to given widget.
 *	
 * @param n Widget identifier.
 * @return Pointer to widget.
*/
void *widget(int n)
{
	if (n < 0 || n >= WIDGET_IDS_N) return (NULL);
	return (gui_widgets[n]);
}
