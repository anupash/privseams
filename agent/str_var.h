#ifndef _STR_VAR_H
#define _STR_VAR_H

/** Maximum length of normal string. */
#define MAX_STRING			260

/** Length of short string. */
#define SHORT_STRING		64

/** Length of long string. */
#define LONG_STRING			1024

/** Length of long string. */
#define HUGE_STRING			4096

/** Maximum length of path and filename string. */
#ifndef MAX_PATH
#define MAX_PATH			1024
#endif

int str_var_init(void);
void str_var_quit(void);
void str_var_set(const char *, const char *, ...);
char *str_var_get(const char *);
int str_var_is(const char *, const char *);
int str_var_valid(const char *);
int str_var_empty(const char *);

#endif /* _STR_VAR_H */


