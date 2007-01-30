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
	"en",
	/* Set language description. */
	"English",
	
	/* First is variable name, second is content. */
	
	/* Different window titles. */
	"title-main",				"HIP configuration",
	"title-newhit",				"New HIT",
	"title-newgroup",			"Create new group",
	"title-runapp",				"Run application",
	"title-locals",				"Local HIT",
	"title-msgdlg",				"Question",

	/* System tray menu. */
	"systray-hide",				"Hide",
	"systray-show",				"Show",
	"systray-exit",				"Exit",
	
	/* Main window menu. */
	"menu-file",				"File",
	"menu-file-exit",			"Exit",
	
	"menu-edit",				"Edit",
	"menu-edit-locals",			"Local HITs",
	
	"menu-tools",				"Tools",
	"menu-tools-runapp",		"Run",
	"menu-tools-newgroup",		"New group",
	"menu-tools-addhit",		"Add new HIT",

	/* Toolbar items. */
	"tb-newgroup",				"New group",
	"tb-newgroup-tooltip",		"Create new group",
	"tb-runapp",				"Run",
	"tb-runapp-tooltip",		"Run new application using HIP libraries",
	"tb-newhit",				"New HIT",
	"tb-newhit-tooltip",		"Add new HIT",
	
	/* Tabs. */
	"tabs-hits",				"HITs",
	
	/* New HIT dialog. */
	"nhdlg-button-accept",		"Accept",
	"nhdlg-button-drop",		"Drop",
	"nhdlg-err-invalid",		"Invalid HIT name given!",
	"nhdlg-err-exists",			"HIT with given name already exists!",
	"nhdlg-err-reserved",		"Given HIT name is reserved!\nChoose another one.",
	"nhdlg-err-invchar",		"HIT name contains invalid characters!\nRename.",
	"nhdlg-err-hit",			"HIT is invalid!",
	"nhdlg-newinfo",			"New HIT information",
	"nhdlg-newhit",				"New HIT:",
	"nhdlg-name",				"Name:",
	"nhdlg-group",				"Group:",
	"nhdlg-advanced",			"Advanced",
	"nhdlg-url",				"URL:",
	"nhdlg-port",				"Port:",
	"nhdlg-g-info",				"Group info",
	"nhdlg-g-localhit",			"Local HIT:",
	"nhdlg-g-type",				"Type:",
	"nhdlg-g-lightweight",		"Lightweight:",

	/* New group dialog. */
	"ngdlg-name",				"Name:",
	"ngdlg-localhit",			"Local HIT:",
	"ngdlg-type",				"Type:",
	"ngdlg-type2",				"Encryption:",
	"ngdlg-button-create",		"Create",
	"ngdlg-button-cancel",		"Cancel",
	"ngdlg-err-invalid",		"Invalid group name!",
	"ngdlg-err-exists",			"Group already exists!",
	"ngdlg-err-reserved",		"Given group name is reserved!\nChoose another one.",
	"ngdlg-err-invchar",		"Group name contains invalid characters!\nRename.",
	
	/* Tool window (HIT handling). */
	"tw-button-apply",			"Apply",
	"tw-button-cancel",			"Cancel",
	"tw-button-delete",			"Delete",
	"tw-button-edit",			"Edit",
	"tw-hit-info",				"HIT information",
	"tw-hit-name",				"Name:",
	"tw-hit-group",				"Group:",
	"tw-hit-advanced",			"Advanced",
	"tw-hit-hit",				"HIT:",
	"tw-hit-port",				"Port:",
	"tw-hit-url",				"URL:",
	"tw-hit-groupinfo",			"Group info:",
	"tw-hit-local",				"Local HIT:",
	"tw-group-info",			"Group information",
	"tw-group-name",			"Name:",
	"tw-group-advanced",		"Advanced",
	"tw-group-local",			"Local HIT:",
	
	"tw-hitgroup-type",			"Type:",
	"tw-hitgroup-lightweight",	"Encryption:",
	
	/* Local HIT handling. */
	"lhdlg-button-apply",		"Apply",
	"lhdlg-button-cancel",		"Cancel",
	"lh-info",					"Local HIT information:",
	"lh-hit",					"HIT:",
	"lh-name",					"Name:",
	"lhdlg-err-invalid",		"Invalid name for local HIT!",
	"lhdlg-err-exists",			"Local HIT name is already in use!",
	"lhdlg-err-invchar",		"Name of local HIT contains invalid characters!",

	/* General message dialog. */
	"msgdlg-button-ok",			"OK",
	"msgdlg-button-cancel",		"Cancel",

	/* Other strings. */
	"newgroup-error-nolocals",	"Can't create new group,\nno local HITs defined.\nCheck HIP daemon.",
	"hits-group-emptyitem",		" <empty> ",
	"ask-delete-hit",			"Are you sure you want to delete selected HIT?",
	"ask-delete-group",			"Are you sure you want to delete selected group?",
	"ask-apply-hit",			"Are you sure you want to apply the changes?",
	"ask-apply-hit-move",		"Are you sure you want move the hit?",
	"ask-apply-group",			"Are you sure you want to apply the changes?",
	
	"group-type-accept",		"accept",
	"group-type-deny",			"deny",
	"group-type2-lightweight",	"lightweight",
	"group-type2-normal",		"normal",
	
	"hits-number-of-used",		"Number of HITs in use",
	"default-group-name",		"ungrouped",
	"combo-newgroup",			"<create new...>",

	NULL
};


#endif /* END OF HEADER FILE */
/******************************************************************************/

