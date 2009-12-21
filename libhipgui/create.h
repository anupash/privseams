#ifndef _CREATE_H
#define _CREATE_H
/*
 * HIPL GTK GUI
 *
 * License: GNU/GPL
 * Authors: Antti Partanen <aehparta@cc.hut.fi>
 */

#include "widgets.h"
#include "events.h"
#include "hipgui.h"
#include "dragndrop.h"

int create_content_main(void);
int create_content_local_edit(void);
int create_content_msgdlg(void);
int create_content_ngdlg(void);
int create_content_nhdlg(void);
int create_content_execdlg(void);

#endif /* _CREATE_H */
