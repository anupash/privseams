/**
 * @file agent/language.c
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * Functions that load different defined languages and how to search 
 * specific strings in that language
 *
 * @brief Functionality to change language of the GUI
 *
 * @author Antti Partanen <aehparta@cc.hut.fi>
 **/
#include "language.h"
 
/* Languages. */
#include "lang_english.h"
#include "lang_finnish.h"

/**
 * lang_init - Initialize language support
 *
 * @param lang Language to use fi/en
 * @param land_file From what file the language is loaded from 
 *
 * @return 0 on success, -1 on error
 **/
int 
lang_init(const char *lang, const char *lang_file)
{
	int err = 0, i;
	char **lang_sel;
	
	/* Check which language is wanted, english is default. */
	if (strcmp(lang_finnish[0], lang) == 0) lang_sel = lang_finnish;
	else lang_sel = lang_english;
	HIP_DEBUG("Loading language \"%s\"...\n", lang_sel[0]);

	for (i = 2; lang_sel[i] != NULL; i += 2)
	{
		str_var_set(lang_sel[i], lang_sel[i + 1]);
	}
	
	/* If language file is given, load it last. */
	if (!lang_file);
	else if (strlen(lang_file) > 0)
	{
		HIP_DEBUG("Loading language file \"%s\"...\n", lang_file);
		HIP_IFEL(config_read(lang_file), -1, "Failed to load language file!\n");
	}

out_err:
	return (err);
}

/**
 * lang_get - Get specified string from currently selected language.
 *
 * @param name Name of the string to be fetched.
 *
 * @return Pointer to the string in the initialized language
 **/
char *
lang_get(const char *name)
{
	return str_var_get(name);
}
