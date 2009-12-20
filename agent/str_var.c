/**
 * @file agent/str_var.c
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * This file contains functions that are used to create the memory 
 * representation (linked list) of the language file.
 *
 * @brief Functions to load the language files to memory
 *
 * @author Antti Partanen <aehparta@cc.hut.fi>
 **/
#include "str_var.h"

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "debug.h"
#include "ife.h"

typedef struct
{
	char name[MAX_STRING];
	char data[HUGE_STRING];
	void *next;
} StringData;

/** String data container. */
StringData *str_data = NULL;
/** Last string data. */
StringData *str_data_last = NULL;
/** Number of strings. */
int str_count = 0;

/**
  This macro is for copying max string. It sets NULL characters and so on.
  strncpy() does not always do this properly, so this macro is here.
  Actually, when using this macro, the buffer being destination, must
  have MAX_STRING + 1 size.
*/
#define STRCPY(dst, src) \
do { \
	strncpy(dst, src, MAX_STRING); \
	dst[MAX_STRING - 1] = '\0'; \
} while (0)

#define SPRINTHUGESTR(dst, string, args...) \
do { \
	snprintf(dst, HUGE_STRING, string, args); \
	dst[HUGE_STRING - 1] = '\0'; \
} while (0)

#define VSPRINTHUGESTR(dst, string, list) \
do { \
	vsnprintf(dst, HUGE_STRING, string, list); \
	dst[HUGE_STRING - 1] = '\0'; \
} while (0)

static StringData *str_var_find(const char *);

/**
 * str_var_init - Initialize data strings linked list.
 *
 * @param void
 *
 * @return always zero
 **/
int str_var_init(void)
{
	int err = 0;

	str_data = NULL;
	str_data_last = NULL;
	str_count = 0;
	
	return err;
}

/**
 * str_var_quit - Deinitalize (frees) data strings linked list.
 *
 * @param void
 * @return void
 **/
void str_var_quit(void)
{
	StringData *st = str_data;
	
	while (st)
	{
		st = (StringData *)str_data->next;
		free(str_data);
		str_data = st;
	}
	
	str_data = NULL;
	str_data_last = NULL;
	str_count = 0;
}

/**
 * str_var_set - Set or add data string, depending whether string is already defined.
 *
 * @param name Name of the string 
 * @param string String in the language initialized
 * @param ...
 * @return void
 **/
void str_var_set(const char *name, const char *string, ...)
{
	StringData *st;
	va_list args;
	void *err;

	st = str_var_find(name);
	
	if (!st)
	{
		st = (StringData *)malloc(sizeof(StringData));
		HIP_IFEL(!st, NULL, "malloc()");
		memset(st, 0, sizeof(StringData));
		STRCPY(st->name, name);
		
		if (str_data_last)
		{
			str_data_last->next = (void *)st;
			str_data_last = st;
		}
		else
		{
			str_data = st;
			str_data_last = st;
		}

		str_count++;
	}
	
	va_start(args, string);
	VSPRINTHUGESTR(st->data, string, args);
	va_end(args);
 out_err:
	return;
}

/**
 * str_var_get - Get data string.
 * 
 * @param name Name of data string to get.
 *
 * @return Pointer to data string, or pointer to "" (empty string), if
 *	   no such data exists.
 **/
char *str_var_get(const char *name)
{
	StringData *st;
	
	st = str_var_find(name);
	if (st) return st->data;
	
	return "";
}

/**
 * str_var_find - Find data string.
 *
 * @param name Name of data string to get.
 *
 * @return Pointer to data string struct, or NULL.
 **/
StringData *str_var_find(const char *name)
{
	StringData *st = str_data;
	
	while (st)
	{
		if (strcmp(name, st->name) == 0) break;
		st = (StringData *)st->next;
	}
	
	return st;
}

/**
 * str_var_is - Compare string variables value, and return 1 or 0.
 *	
 * @param name Name of data string to get.
 * @param value Value to be compared against.
 *
 *@return 1 if value is same, 0 if not.
 **/
int str_var_is(const char *name, const char *value)
{
	StringData *st;
	
	st = str_var_find(name);
	if (st)
	{
		if (strcmp(st->data, value) == 0) return (1);
	}
	
	return (0);
}

/**
 * str_var_empty - Check whether string var has some content or is just empty string.
 *	
 * @param name Name of data string to get.
 *
 * @return 0 if variable is non-empty string, 1 if it is empty.
 **/
int str_var_empty(const char *name)
{
	StringData *st;
	
	st = str_var_find(name);
	if (st)
	{
		if (strlen(st->data) < 1) return (1);
	}
	
	return (0);
}

