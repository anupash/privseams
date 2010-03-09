#ifndef HIP_LIB_CORE_FILEMANIP_H
#define HIP_LIB_CORE_FILEMANIP_H

#include <sys/types.h>

#include "config.h"

int hip_create_lock_file(char *filename, int killold);
int hip_remove_lock_file(char *filename);
int check_and_create_dir(char *dirname, mode_t mode);
int check_and_create_file(char *filename, mode_t mode);
void change_key_file_perms(char *filenamebase);

#endif /* HIP_LIB_CORE_FILEMANIP_H */
