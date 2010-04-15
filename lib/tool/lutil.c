/**
 * @file
 *
 * Distributed under
 * <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief Utilities borrowed from libinet6. Function hip_timeval_diff()
 * is borrowed from glibc project.
 */

#include "lutil.h"
#include "lib/conf/hipconf.h"

/**
 * Read characters to a buffer from a file. Works like fgets() but
 * removes the trailing '\n' from the end.
 *
 * @param buffer writes the characters to here
 * @param count read at most one less than @c count characters
 * @param f the file from where to read the characters
 * @return a pointer to the @c buffer on success or NULL error
 */
char *getwithoutnewline(char *buffer, int count, FILE *f)
{
    char *result = buffer, *np;
    if ((buffer == NULL) || (count < 1)) {
        result = NULL;
    } else if (count == 1) {
        *result = '\0';
    } else if ((result = fgets(buffer, count, f)) != NULL) {
        if ((np = strchr(buffer, '\n'))) {
            *np = '\0';
        }
    }
    return result;
}

/**
 * Checks if a string contains a particular substring.
 *
 * @param string a string
 * @param substring match this substring to the given @c string
 *
 * @return If string contains substring, the return value is the location of
 * the first matching instance of substring in string.  If string doesn't
 * contain substring, the return value is NULL.
 */
char *findsubstring(const char *string, const char *substring)
{
    char *str = (char *) string, *sub = (char *) substring;
    char *a, *b;

    for (b = sub; *str != 0; str += 1) {
        if (*str != *b) {
            continue;
        }
        a = str;
        for (;; ) {
            if (*b == 0) {
                return str;
            }
            if (*a++ != *b++) {
                break;
            }
        }
        b = sub;
    }
    return (char *) NULL;
}

/**
 * Extracts tabular delimited substrings from the given string and
 * inserts them to the given list. Caller deallocates the list.
 *
 * @param string the string to be extracted
 * @param list tabular delimited substrings will be stored into this
 *             list as list elements
 */
void extractsubstrings(char *string, List *list)
{
    char *sub_string;
    char delims[] = " \t";

    sub_string = strtok(string, delims);

    if (sub_string) {
        insert(list, sub_string);
    } else {
        return;
    }

    sub_string = NULL;

    while ((sub_string = strtok(NULL, delims)) != NULL) {
        insert(list, sub_string);
        sub_string = NULL;
    }
}

/**
 * initialize a list
 *
 * @param ilist the linked list to initialized
 */
void initlist(List *ilist)
{
    ilist->head = NULL;
}

/**
 * insert a new element to the linked list (caller deallocates)
 * @param ilist the linked list where to add the element
 * @param data the contents of the element to be added
 */
void insert(List *ilist, char *data)
{
    Listitem *new;
    new         = malloc(sizeof(Listitem));
    new->next   = ilist->head;
    strncpy(new->data, data, MAX_ITEM_LEN);
    ilist->head = new;
}

/**
 * determine the number of elements in a linked list
 *
 * @param ilist the linked list
 * @return the number of elements in the linked list
 */
int length(List *ilist)
{
    Listitem *ptr;
    int count = 1;

    if (!ilist->head) {
        return 0;
    }
    ptr = ilist->head;
    while (ptr->next) {
        ptr = ptr->next;
        count++;
    }
    return count;
}

/**
 * deallocate and destroy a linked list
 *
 * @param ilist the linked list to be deallocated and destroyed
 */
void destroy(List *ilist)
{
    Listitem *ptr1, *ptr2;
    if (!ilist) {
        return;
    }
    ptr1 = ilist->head;
    while (ptr1) {
        ptr2 = ptr1;
        ptr1 = ptr1->next;
        free(ptr2);
    }
    ilist->head = NULL;
}

/**
 * get the Nth item from the linked list
 *
 * @param ilist the linked list
 * @param n a number denoting the Nth item to be fetched
 * @return a pointer to the contents of the linked list
 */
char *getitem(List *ilist, int n)
{
    Listitem *ptr;
    int count = 0;

    if (!ilist->head) {
        return NULL;
    }
    ptr = ilist->head;
    if (n == 0) {
        return ptr->data;
    }
    while (ptr->next) {
        ptr = ptr->next;
        count++;
        if (n == count) {
            return ptr->data;
        }
    }
    return NULL;
}

#if 0
/**
 * copy the given contents to the Nth element in the linked list
 *
 * @param ilist the linked list
 * @param n denotes which Nth item to insert the contents
 * @return NULL (on failure) or the a pointer to the contents
 */
char *setdataitem(List *ilist, int n, char *data)
{
    Listitem *ptr;
    int count = 0;

    if (!ilist->head) {
        return NULL;
    }
    ptr = ilist->head;
    if (n == 0) {
        return ptr->data;
    }
    while (ptr->next) {
        ptr = ptr->next;
        count++;
        if (n == count) {
            //memset(new->data, 0, MAX_ITEM_LEN);
            strncpy(ptr->data, data, MAX_ITEM_LEN);
            return ptr->data;
        }
    }
    return NULL;
}
#endif /* 0 */

/**
 * calculate difference between two timevalues
 *
 * @param t1 timevalue 1
 * @param t2 timevalue 2
 * @param result where the result is stored
 *
 * ** CHECK comments **
 * result = t1 - t2
 *
 * Code taken from http://www.gnu.org/manual/glibc-2.2.5/html_node/Elapsed-Time.html
 *
 * @return 1 if t1 is equal or later than t2, else 0.
 */
int hip_timeval_diff(const struct timeval *t1,
                     const struct timeval *t2,
                     struct timeval *result)
{
    struct timeval _t1, _t2;
    _t1 = *t1;
    _t2 = *t2;

    if (_t1.tv_usec < _t2.tv_usec) {
        int nsec = (_t2.tv_usec - _t1.tv_usec) / 1000000 + 1;
        _t2.tv_usec -= 1000000 * nsec;
        _t2.tv_sec  += nsec;
    }
    if (_t1.tv_usec - _t2.tv_usec > 1000000) {
        int nsec = (_t1.tv_usec - _t2.tv_usec) / 1000000;
        _t2.tv_usec += 1000000 * nsec;
        _t2.tv_sec  -= nsec;
    }

    result->tv_sec  = _t2.tv_sec - _t1.tv_sec;
    result->tv_usec = _t2.tv_usec - _t1.tv_usec;

    return _t1.tv_sec >= _t2.tv_sec;
}

/**
 * find the maximum value from a variable list of integers
 *
 * @param num_args number of list items
 * @param ... the integers from which to find maximum
 * @return the integer with the largest value from the
 *         list provided
 */
int maxof(int num_args, ...)
{
    int max, i, a;
    va_list ap;

    va_start(ap, num_args);
    max = va_arg(ap, int);
    for (i = 2; i <= num_args; i++) {
        if ((a = va_arg(ap, int)) > max) {
            max = a;
        }
    }
    va_end(ap);
    return max;
}
