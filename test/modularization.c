/** @file
 * A small test program for the modularization lib.
 *
 * @brief  Runs various tests in the data structures and functions provided by
 *         libmodularization.
 *
 * @author  Tim Just
 * @version 0.1
 * @date    04.02.2010
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#include <stdio.h>

#include "lib/modularization/modularization.h"

struct ha_state {
    int id;
    char name[10];
};

struct update_state {
    int id;
    char name[10];
};

int main(void)
{
    struct ha_state ha_state_item1;
    struct update_state update_state_item1;
    struct ha_state ha_state_item2;
    struct update_state update_state_item2;
    struct modular_state *entry1, *entry2;
    void *tmp;
    struct update_state *tmp2;

    ha_state_item1.id = 11;
//    ha_state_item1.name = {"h", "a", "1"};

    update_state_item1.id = 12;
//    update_state_item1.name = {"u", ,"p", "1"};

    ha_state_item2.id = 21;
//    ha_state_item2.name = {"h", "a", "2"};

    update_state_item2.id = 22;
//    update_state_item2.name = {"u", "p","2"};

    entry1 = hip_init_state();
    entry2 = hip_init_state();

    hip_add_state_item(entry1, &ha_state_item1, "ha");
    hip_add_state_item(entry1, &update_state_item1, "update");

    hip_add_state_item(entry2, &ha_state_item2, "ha");
    hip_add_state_item(entry2, &update_state_item2, "update");

    printf("update_state1: %p\n", hip_get_state_item(entry1, "update"));
    tmp = hip_get_state_item(entry1, "update");
    tmp2 = tmp;
    printf("id update 1: %d\n", tmp2->id);
    //printf("update_state1: %p\n", &update_state_item);
    printf("ha_state2: %p\n", hip_get_state_item(entry1, "ha"));
    //printf("ha_state2: %p\n", &ha_state_item);

    printf("\n");

    printf("update_state2: %p\n", hip_get_state_item(entry2, "update"));
    tmp = hip_get_state_item(entry2, "update");
    tmp2 = tmp;
    printf("id update 2: %d\n", tmp2->id);
//    printf("update state: %p\n", &ha_state_item);
    printf("ha_state2: %p\n", hip_get_state_item(entry2, "ha"));
    //printf("ha state: %p\n", &update_state_item);

    hip_free_state(entry1);
    hip_free_state(entry2);

    return 0;
}
