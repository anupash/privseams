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
	"fi",
	/* Set language description. */
	"Suomi",
	
	/* First is variable name, second is content. */
	
	/* Different window titles. */
	"title-main",				"HIP säädöt",
	"title-newhit",				"Uusi HIT",
	"title-newgroup",			"Luo uusi ryhmä",
	"title-runapp",				"Käynnistä sovellus",
	"title-locals",				"Paikallinen HIT",
	"title-msgdlg",				"Kysymys",

	/* System tray menu. */
	"systray-hide",				"Piilota",
	"systray-show",				"Näytä",
	"systray-exit",				"Lopeta",
	
	/* Main window menu. */
	"menu-file",				"Tiedosto",
	"menu-file-exit",			"Lopeta",
	
	"menu-edit",				"Muokkaa",
	"menu-edit-locals",			"Paikalliset HIT:t",
	
	"menu-tools",				"Työkalut",
	"menu-tools-runapp",		"Käynnistä",
	"menu-tools-newgroup",		"Uusi ryhmä",
	"menu-tools-addhit",		"Lisää uusi HIT",

	/* Toolbar items. */
	"tb-newgroup",				"Uusi ryhmä",
	"tb-newgroup-tooltip",		"Luo uusi ryhmä",
	"tb-runapp",				"Käynnistä",
	"tb-runapp-tooltip",		"Käynnistä uusi sovellus käyttäen HIP kirjastoja",
	"tb-newhit",				"Uusi HIT",
	"tb-newhit-tooltip",		"Lisää uusi HIT",
	
	/* Tabs. */
	"tabs-hits",				"HIT:t",
	
	/* New HIT dialog. */
	"nhdlg-button-accept",		"Lisää tietokantaan",
	"nhdlg-button-drop",		"Älä lisää",
	"nhdlg-err-invalid",		"HIT:n nimi ei ole hyväksyttävä!",
	"nhdlg-err-exists",			"Samanniminen HIT on jo olemassa!",
	"nhdlg-err-reserved",		"Annettu HIT:n nimi on varattu!",
	"nhdlg-err-invchar",		"HIT:n nimi sisältää ei hyväksyttyjä merkkejä.",
	"nhdlg-err-hit",			"HIT ei ole hyväksyttävä.",
	"nhdlg-newinfo",			"Uuden HIT:n tiedot",
	"nhdlg-newhit",				"Uusi HIT:",
	"nhdlg-name",				"Nimi:",
	"nhdlg-group",				"Ryhmä:",
	"nhdlg-advanced",			"Lisävalinnat",
	"nhdlg-url",				"URL:",
	"nhdlg-port",				"Portti:",
	"nhdlg-g-info",				"Ryhmän tiedot",
	"nhdlg-g-localhit",			"Paikallinen HIT:",
	"nhdlg-g-type",				"Tyyppi:",
	"nhdlg-g-lightweight",		"Salaus:",

	/* New group dialog. */
	"ngdlg-name",				"Nimi:",
	"ngdlg-localhit",			"Paikallinen HIT:",
	"ngdlg-type",				"Tyyppi:",
	"ngdlg-type2",				"Salaus:",
	"ngdlg-button-create",		"Luo ryhmä",
	"ngdlg-button-cancel",		"Peruuta",
	"ngdlg-err-invalid",		"Ryhmän nimi ei ole hyväksyttävä!",
	"ngdlg-err-exists",			"Ryhmä on jo olemassa!",
	"ngdlg-err-reserved",		"Annettu ryhmän nimi on varattu!",
	"ngdlg-err-invchar",		"Ryhmän nimi sisältää epäsopivia merkkejä!",
	
	/* Tool window (HIT handling). */
	"tw-button-apply",			"Hyväksy",
	"tw-button-cancel",			"Peruuta",
	"tw-button-delete",			"Poista",
	"tw-button-edit",			"Muokkaa",
	"tw-hit-info",				"HIT:n tiedot",
	"tw-hit-name",				"Nimi:",
	"tw-hit-group",				"Ryhmä:",
	"tw-hit-advanced",			"Lisävalinnat",
	"tw-hit-hit",				"HIT:",
	"tw-hit-port",				"Portti:",
	"tw-hit-url",				"URL:",
	"tw-hit-groupinfo",			"Ryhmän tiedot:",
	"tw-hit-local",				"Paikallinen HIT:",
	"tw-group-info",			"Ryhmän tiedot",
	"tw-group-name",			"Nimi:",
	"tw-group-advanced",		"Lisävalinnat",
	"tw-group-local",			"Paikallinen HIT:",
	
	"tw-hitgroup-type",			"Tyyppi:",
	"tw-hitgroup-lightweight",	"Salaus:",
	
	/* Local HIT handling. */
	"lhdlg-button-apply",		"Hyväksy",
	"lhdlg-button-cancel",		"Peruuta",
	"lh-info",					"Paikallisen HIT:n tiedot:",
	"lh-hit",					"HIT:",
	"lh-name",					"Nimi:",
	"lhdlg-err-invalid",		"Paikallisen HIT:n nimi ei ole hyväksyttävä!",
	"lhdlg-err-exists",			"Paikallisen HIT:n nimi on jo käytössä!",
	"lhdlg-err-invchar",		"Paikallisen HIT:n nimi sisältää ei hyväksyttyjä merkkejä!",

	/* General message dialog. */
	"msgdlg-button-ok",			"Hyväksy",
	"msgdlg-button-cancel",		"Peruuta",

	/* Other strings. */
	"newgroup-error-nolocals",	"Ei voi luoda uutta ryhmää,\npaikallisia HIT:jä ei ole määritelty!\nTarkista HIP daemon.",
	"hits-group-emptyitem",		" <tyhjä ryhmä> ",
	"ask-delete-hit",			"Oletko varma että haluat poistaa valitun HIT:n?",
	"ask-delete-group",			"Oletko varma että haluat poistaa valitun ryhmän?",
	"ask-apply-hit",			"Oletko varma että haluat toteuttaa muokkauksen?",
	"ask-apply-hit-move",		"Haluatko varmasti siirtää ryhmän?",
	"ask-apply-group",			"Oletko varma että haluat toteuttaa muokkauksen?",
	
	"group-type-accept",		"hyväksy",
	"group-type-deny",			"kiellä",
	"group-type2-lightweight",	"kevyt",
	"group-type2-normal",		"normaali",

	"hits-number-of-used",		"Käytettyjen HIT:en määrä",
	"default-group-name",		"ungrouped",
	"combo-newgroup",			"<luo uusi...>",

	NULL
};


#endif /* END OF HEADER FILE */
/******************************************************************************/

