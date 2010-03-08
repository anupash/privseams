#ifndef HIP_LIB_CORE_FILEMANIP_H
#define HIP_LIB_CORE_FILEMANIP_H

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

int hip_create_lock_file(char *filename, int killold);
int hip_remove_lock_file(char *filename);
int check_and_create_dir(char *dirname, mode_t mode);
void change_key_file_perms(char *filenamebase);

#endif /* HIP_LIB_CORE_FILEMANIP_H */
