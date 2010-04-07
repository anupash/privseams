#ifndef HIP_LIB_GUI_HIPGUI_H
#define HIP_LIB_GUI_HIPGUI_H
/*
 * HIPL GTK GUI
 *
 * License: GNU/GPL
 * Authors: Antti Partanen <aehparta@cc.hut.fi>
 */

#include "agent/hitdb.h"

/*!
 * \addtogroup libhipgui
 * @{
 */

/* Basic funtions. */
int gui_init(void);
void gui_main(void);
void gui_quit(void);

/* About HITs. */
int gui_hit_remote_ask(HIT_Remote *, int);
void gui_hit_remote_add(const char *, const char *);
void gui_hit_remote_del(const char *, const char *);
void gui_group_remote_add(const char *);
void gui_group_remote_del(const char *);

/* Status update. */
void gui_set_info(const char *, ...);
void gui_update_nat(int);

/* HITs in use. */
void gui_hiu_clear(void);
void gui_hiu_add(HIT_Remote *);
void gui_hiu_count(int);

/*! @} addtogroup libhipgui */


#endif /* HIP_LIB_GUI_HIPGUI_H */
