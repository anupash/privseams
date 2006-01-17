/*
    HIP GUI
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
             Matti Saarinen
*/

#ifndef __HIPTAB_H__
#define __HIPTAB_H__

#include "wx/wx.h"
#include "hippersonality.h"

#include <wx/dynarray.h>

WX_DECLARE_OBJARRAY( wxPanel, PanelArray );

class HipInterface;

class HipTab : public wxScrolledWindow
{
public:
	void DestroyKeyInformation();
	void DetachSizer();
	void CreateControls(int context = -1);
	HipTab( HipInterface& _interface, HipPersonality& personality, wxBookCtrlBase *book );
	virtual ~HipTab();

	void KeysUpdated();


protected:

	void SetHipKeys( HipContext& context, wxSizer& sizer);
	void SetContexts(HipContextArray& contexts);


	void OnText(wxCommandEvent& WXUNUSED(event));
	void OnListClick(wxCommandEvent& event);

protected:

	HipInterface& m_interface;
	HipPersonality& m_personality;

	// ui components
	wxSizer *m_sizer;
	wxSizer *m_sizerLeft;
	wxSizer *m_sizerRight;
	wxListBox *m_lbox;
	wxPanel *m_keypanel;

	wxStaticBox* m_staticBoxes[100];
	int m_staticBoxCount;

	wxTextCtrl* m_textCtrls[100];
	int	m_textCtrlCount;

	wxStaticText* m_staticTexts[100];
	int m_staticTextCount;

	wxButton *m_staticButtons[100];
	int m_staticButtonsCount;

	int current_context;


#ifdef __HIPTAB_CPP__
    DECLARE_EVENT_TABLE()
#endif
};

#endif /* END OF HEADER FILE */
/******************************************************************************/
