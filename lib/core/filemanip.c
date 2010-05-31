/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief file manipulation tools
 *
 * @author Miika Komu <miika@iki.fi>
 */

#include <stdlib.h>
#include <unistd.h>

#include "config.h"
#include "crypto.h"
#include "filemanip.h"

/**
 * get rid of a lock file
 *
 * @param filename the file name of the lock file
 * @return zero on success and negative on error
 */
int hip_remove_lock_file(const char *filename)
{
    return unlink(filename);
}

/**
 * create a new lock file
 *
 * @param filename the file name of the lock
 * @param killold one if the function should steal the lock from
 *        and existing process and kill it, or zero otherwise
 * @return zero on success and negative on error
 */
int hip_create_lock_file(const char *filename, int killold)
{
    int err     = 0, fd = 0, old_pid = 0, new_pid_str_len = 0;
    char old_pid_str[64], new_pid_str[64];
    int pid_set = 0;     /* the pid was read successfully */
    memset(old_pid_str, 0, sizeof(old_pid_str));
    memset(new_pid_str, 0, sizeof(new_pid_str));

    /* New pid */
    snprintf(new_pid_str, sizeof(new_pid_str) - 1, "%d\n", getpid());
    new_pid_str_len = strlen(new_pid_str);
    HIP_IFEL((new_pid_str_len <= 0), -1, "pID length error.\n");

    /* Read old pid */
    fd              = HIP_CREATE_FILE(filename);
    HIP_IFEL((fd <= 0), -1, "opening lock file failed\n");

    /** @todo This is possibly unsafe: the pid is read from the file without checking
     * file permissions and the process with the number is simply killed.
     * THIS COULD BE USED TO ATTACK THE SYSTEM
     */
    pid_set         = read(fd, old_pid_str, sizeof(old_pid_str) - 1);
    old_pid         = atoi(old_pid_str);

    if (lockf(fd, F_TLOCK, 0) < 0) {
        HIP_IFEL(!killold, -12,
                 "\nHIP daemon already running with pid %d\n"
                 "Give: -k option to kill old daemon.\n", old_pid);

        HIP_INFO("\nDaemon is already running with pid %d\n"
                 "-k option given, terminating old one...\n", old_pid);
        /* Erase the old lock file to avoid having multiple pids
         * in the file */
        if (lockf(fd, F_ULOCK, 0) == -1) {
            HIP_ERROR("Cannot unlock pid lock.");
        }

        close(fd);
        HIP_IFEL(hip_remove_lock_file(filename), -1,
                 "Removing lock file failed.\n");

        /* fd = open(filename, O_RDWR | O_CREAT, 0644); */
        fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);

        /* Don't close file descriptor because new started process is
         * running. */
        HIP_IFEL((fd <= 0), -1, "Opening lock file failed.\n");
        HIP_IFEL(lockf(fd, F_TLOCK, 0), -1, "Lock attempt failed.\n");
        if (pid_set) {
            err = kill(old_pid, SIGKILL);
        }
        if (err != 0) {
            HIP_ERROR("\nError when trying to send signal SIGKILL " \
                      "process identified by process identifier " \
                      "%d.\n", old_pid);
            HIP_PERROR("errno after kill() is: ");
        }
    }

    lseek(fd, 0, SEEK_SET);

    HIP_IFEL((write(fd, new_pid_str, new_pid_str_len) != new_pid_str_len),
             -1, "Writing new process identifier failed.\n");

out_err:
    if (err == -12) {
        exit(0);
    }

    return err;
}

/**
 * check and create a directory
 * @param dirname the name of the directory
 * @param mode creation mode for the directory, if it does not exist
 *
 * @return 0 if successful, or negative on error.
 */
int check_and_create_dir(const char *dirname, mode_t mode)
{
    int err = 0;
    struct stat dir_stat;

    HIP_INFO("dirname=%s mode=%o\n", dirname, mode);
    err = stat(dirname, &dir_stat);
    if (err && errno == ENOENT) {     /* no such file or directory */
        err = mkdir(dirname, mode);
        if (err) {
            HIP_ERROR("mkdir %s failed: %s\n", dirname,
                      strerror(errno));
        }
    } else if (err) {
        HIP_ERROR("stat %s failed: %s\n", dirname,
                  strerror(errno));
    }

    return err;
}

/**
 * check and create a file
 * @param filename the name of the file
 * @param mode creation mode for the file, if it does not exist
 *
 * @return file descriptor of the created file
 */
int check_and_create_file(const char *filename, mode_t mode)
{
    int err = 0, fd = 0;
    struct stat file_stat;

    HIP_INFO("filename=%s mode=%o\n", filename, mode);
    err = stat(filename, &file_stat);
    if (err && errno == ENOENT) {     /* no such file or file */
        fd = open(filename, O_RDWR | O_CREAT, 0644);
        if (fd < 0) {
            HIP_ERROR("creating file %s failed: %s\n", filename,
                      strerror(errno));
        }
    } else {
        fd = open(filename, O_RDWR);
        if (fd < 0) {
            HIP_ERROR("opening file %s failed: %s\n", filename,
                      strerror(errno));
        }
    }

    return fd;
}

/**
 * make /etc/hip file permissions more secure
 *
 * @param filenamebase the file name based for keys
 */
void change_key_file_perms(const char *filenamebase)
{
    char *pubfilename = NULL;
    int pubfilename_len;

    pubfilename_len =
        strlen(filenamebase) + strlen(DEFAULT_PUB_FILE_SUFFIX) + 1;
    pubfilename     = malloc(pubfilename_len);
    if (!pubfilename) {
        HIP_ERROR("malloc(%d) failed\n", pubfilename_len);
        goto out_err;
    }

    /* check retval */
    snprintf(pubfilename, pubfilename_len, "%s%s", filenamebase,
             DEFAULT_PUB_FILE_SUFFIX);

    chmod(filenamebase, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    chmod(pubfilename, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);

out_err:
    if (pubfilename) {
        free(pubfilename);
    }

    return;
}
