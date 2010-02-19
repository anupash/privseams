/** @file
 * A small test program for the modularization lib.
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * @brief  Runs various tests in the data structures and functions provided by
 *         libmodularization.
 *
 * @author Tim Just <tim.just@rwth-aachen.de>
 *
 */
#include <stdio.h>
#include <malloc.h>
#include <sys/types.h>

#include "lib/modularization/modularization.h"

struct ha_state {
    int id;
    char name[10];
};

struct update_state {
    int id;
    char name[10];
};


static int test_function(void)
{
    printf("test_function\n");
    return 0;
}

static int test_function2(void)
{
    printf("test_function2\n");
    return 0;
}

/*
int test_modular_state(void)
{
    struct ha_state ha_state_item1;
    struct update_state update_state_item1;
    struct ha_state ha_state_item2;
    struct update_state update_state_item2;
    struct modular_state *entry1, *entry2;
    void *tmp = NULL;

    ha_state_item1.id = 11;
    update_state_item1.id = 12;

    ha_state_item2.id = 21;
    update_state_item2.id = 22;

    entry1 = hip_init_state();
    entry2 = hip_init_state();

    hip_add_state_item(entry1, &ha_state_item1, "ha");
    hip_add_state_item(entry1, &update_state_item1, "update");

    hip_add_state_item(entry2, &ha_state_item2, "ha");
    hip_add_state_item(entry2, &update_state_item2, "update");

    printf("update_state1: %p\n", hip_get_state_item(entry1, "update"));
    tmp = hip_get_state_item(entry1, "update");
    printf("ha_state2: %p\n", hip_get_state_item(entry1, "ha"));
    printf("\n");
    printf("update_state2: %p\n", hip_get_state_item(entry2, "update"));
    tmp = hip_get_state_item(entry2, "update");
    printf("ha_state2: %p\n", hip_get_state_item(entry2, "ha"));

    hip_free_state(entry1);
    hip_free_state(entry2);

    return 0;
}
*/

int test_handle_functions(void)
{
    hip_register_handle_function(1, 1, &test_function);
    hip_register_handle_function(1, 1, &test_function2);

    hip_run_handle_functions(1, 1, NULL);

    hip_uninit_handle_functions();

    return 0;
}

int main(void)
{
    test_handle_functions();

    return 0;
}
