/*
    HIP Agent
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */

/* THIS */
#include "interface.h"


/******************************************************************************/
/* VARIABLES */
extern wxWindow *main_window;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Initialize GUI interface.
	
	@return 0 on success, -1 on errors.
*/
int gui_init_interface(void)
{
	int err = 0;
	
//	HipAgentApp &app = (HipAgentApp &)wxGetApp();
//	if (!guiapp) goto out_err;
//	guiapp->OnInit();

	return (0);
	
out_err:
	return (-1);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Ask user for accept or denial of HIT.

	@return 0 on success, -1 on errors.
*/
int gui_ask_hit_accept(char *)
{
	int err = 0;

	wxMessageDialog dialog(main_window, _T("Test content"),
	                       _T("Title"), wxNO_DEFAULT | wxYES_NO | wxICON_INFORMATION);
	
	switch (dialog.ShowModal())
	{
	case wxID_YES:
	    err = 0;
	    break;
	
	case wxID_NO:
	    err = -1;
	    break;
	
	default:
	    err = -1;
	}
	
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

