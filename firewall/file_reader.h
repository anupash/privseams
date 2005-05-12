#ifndef FILE_READER_H
#define FILE_READER_H

#include <glib.h>
#include <glib/glist.h>

#include "firewall.h"

#define RULE_MAX_LEN 300; //TODO akateemisempi arvaus 
struct GList;

//struct rule * parse_rule(char * string);
void get_rules(char * file_name, struct GList ** list);

#endif //FILE_READER_H
