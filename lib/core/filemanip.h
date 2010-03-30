/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
#ifndef HIP_LIB_CORE_FILEMANIP_H
#define HIP_LIB_CORE_FILEMANIP_H

#include <sys/types.h>

#include "config.h"

#ifdef CONFIG_HIP_OPENWRT
# define HIP_CREATE_FILE(x)     check_and_create_file(x, 0644)
#else
# define HIP_CREATE_FILE(x)     open((x), O_RDWR | O_CREAT, 0644)
#endif

#define HIP_DEFAULT_EXEC_PATH "/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin"

int hip_create_lock_file(char *filename, int killold);
int hip_remove_lock_file(char *filename);
int check_and_create_dir(char *dirname, mode_t mode);
int check_and_create_file(char *filename, mode_t mode);
void change_key_file_perms(char *filenamebase);

#endif /* HIP_LIB_CORE_FILEMANIP_H */
