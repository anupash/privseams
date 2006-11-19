/*
    HIP Agent
    
    English language table file for HIP GUI.

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef LANG_FINNISH_H
#define LANG_FINNISH_H

/******************************************************************************/
/* LANGUAGE TABLE */

char *lang_finnish[] =
{
	/* Set language prefix. */
	"finnish",
	/* Set language description. */
	"Suomi",
	
	/* First is variable name, second is content. */
	
	/* Different window titles. */
	"title-main",				"HIP Säädöt",
	"title-newhit",				"Uusi HIT",
	"title-newgroup",			"Luo uusi ryhmä",
	"title-runapp",				"Käynnistä sovellus",
	
	"combo-newgroup",			"<luo uusi...>",
	
	/* System tray menu. */
	"systray-hide",				"Piilota",
	"systray-show",				"Näytä",
	"systray-exit",				"Lopeta",
	
	/* Main window menu. */
	"menu-file",				"Tiedosto",
	"menu-file-exit",			"Lopeta",
	
	"menu-tools-runapp",		"Käynnistä",
	"menu-tools-newgroup",		"Uusi ryhmä",
	"menu-tools-addhit",		"Lisää HIT",

	/* Toolbar items. */
	"tb-newgroup",				"Uusi ryhmä",
	"tb-newgroup-tooltip",		"Luo uusi ryhmä",
	"tb-runapp",				"Käynnistä",
	"tb-runapp-tooltip",		"Käynnistä uusi sovellus käyttäen HIP kirjastoja",
	
	/* Tabs. */
	"tabs-hits",				"HIT:t",
	
	/* New HIT dialog. */
	"nhdlg-button-accept",		"Lisää tietokantaan",
	"nhdlg-button-drop",		"Unohda",
	
	/* New group dialog. */
	"ngdlg-name",				"Nimi:",
	"ngdlg-localhit",			"Paikallinen HIT:",
	"ngdlg-type",				"Tyyppi:",
	"ngdlg-type2",				"Salaus:",
	"ngdlg-button-create",		"Luo ryhmä",
	"ngdlg-button-cancel",		"Peruuta",
	
	/* Tool window (HIT handling). */
	"tw-button-apply",			"Hyväksy",
	"tw-button-cancel",			"Peruuta",
	"tw-button-delete",			"Poista",
	
	/* Local HIT handling. */
	"lh-button-apply",			"Hyväksy",
	"lh-button-cancel",			"Peruuta",
	"lh-button-delete",			"Poista",
	
	/* Other strings. */
	"newgroup-error-nolocals",	"Ei voi luoda uutta ryhmää,\npaikallisia HIT:jä ei ole määritelty.\nTarkista HIP daemon.",
	"hits-group-emptyitem",		" <tyhjä ryhmä> ",
	"ask-delete-hit",			"Oletko varma että haluat poistaa valitun HIT:n?",
	"ask-delete-group",			"Oletko varma että haluat poistaa valitun ryhmän?",
	
	"group-type-accept",		"hyväksy",
	"group-type-deny",			"kiellä",

	"group-type2-lightweight",	"kevyt",
	"group-type2-normal",		"normaali",

	"hits-number-of-used",		"Käytettyjen HIT:n määrä",

	NULL
};


#endif /* END OF HEADER FILE */
/******************************************************************************/

