/*
    HIP Agent
    
    English language table file for HIP GUI.

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef LANG_ENGLISH_H
#define LANG_ENGLISH_H

/******************************************************************************/
/* LANGUAGE TABLE */

char *lang_english[] =
{
	/* Set language prefix. */
	"english",
	/* Set language description. */
	"English",
	
	/* First is variable name, second is content. */
	
	/* Different window titles. */
	"title-main",				"HIP Config",
	"title-newhit",				"New HIT",
	"title-newgroup",			"Create new group",
	"title-runapp",				"Run application",
	
	"combo-newgroup",			"<create new...>",
	
	/* System tray menu. */
	"systray-hide",				"Hide",
	"systray-show",				"Show",
	"systray-exit",				"Exit",
	
	/* Main window menu. */
	"menu-file",				"File",
	"menu-file-exit",			"Exit",
	
	"menu-tools-runapp",		"Run",
	"menu-tools-newgroup",		"New group",
	"menu-tools-addhit",		"Add HIT",

	/* Toolbar items. */
	"tb-newgroup",				"New group",
	"tb-newgroup-tooltip",		"Create new group",
	"tb-runapp",				"Run",
	"tb-runapp-tooltip",		"Run new application using HIP libraries",
	
	/* Tabs. */
	"tabs-hits",				"HITs",
	
	/* New HIT dialog. */
	"nhdlg-button-accept",		"Accept",
	"nhdlg-button-drop",		"Drop",
	"nhdlg-err-invalid",		"Invalid HIT name given!",
	"nhdlg-err-exists",			"HIT with given name already exists!",
	
	/* New group dialog. */
	"ngdlg-name",				"Name:",
	"ngdlg-localhit",			"Local HIT:",
	"ngdlg-type",				"Type:",
	"ngdlg-type2",				"Lightweight:",
	"ngdlg-button-create",		"Create",
	"ngdlg-button-cancel",		"Cancel",
	"ngdlg-err-invalid",		"Invalid group name given!",
	"ngdlg-err-exists",			"Group already exists!",
	
	/* Tool window (HIT handling). */
	"tw-button-apply",			"Apply",
	"tw-button-cancel",			"Cancel",
	"tw-button-delete",			"Delete",
	"tw-hit-info",				"HIT information",
	"tw-hit-name",				"Name:",
	"tw-hit-group",				"Group:",
	"tw-hit-advanced",			"Advanced:",
	"tw-hit-hit",				"HIT:",
	"tw-hit-port",				"Port:",
	"tw-hit-url",				"URL:",
	"tw-hit-groupinfo",			"Group info:",
	
	/* Local HIT handling. */
	"lh-button-apply",			"Apply",
	"lh-button-cancel",			"Cancel",
	"lh-button-delete",			"Delete",

	/* Other strings. */
	"newgroup-error-nolocals",	"Can't create new group,\nno local HITs defined.\nCheck HIP daemon.",
	"hits-group-emptyitem",		" <empty> ",
	"ask-delete-hit",			"Are you sure you want to delete selected HIT?",
	"ask-delete-group",			"Are you sure you want to delete selected group?",
	
	"group-type-accept",		"accept",
	"group-type-deny",			"deny",

	"group-type2-lightweight",	"lightweight",
	"group-type2-normal",		"normal",

	"hits-number-of-used",		"Number of HITs in use",

	"default-group-name",		"ungrouped",

	NULL
};


#endif /* END OF HEADER FILE */
/******************************************************************************/

