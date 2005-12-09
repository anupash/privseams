// HipTab.cpp: implementation of the HipTab class.
//
//////////////////////////////////////////////////////////////////////
#define __HIPTAB_CPP__

#include "hiptab.h"
#include "hipinterface.h"

#include <stdio.h>

#include <wx/arrimpl.cpp>

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

// control ids
enum
{
	HipContextListBox = 100,
	HipField = 200,
	HipUrlField = 300,
	HipHiField = 400,
	HipPortField = 500
};

BEGIN_EVENT_TABLE(HipTab, wxPanel)
    EVT_TEXT(HipField, HipTab::OnText)
	EVT_TEXT(HipField+1, HipTab::OnText)
	EVT_TEXT(HipField+2, HipTab::OnText)
	EVT_TEXT(HipField+3, HipTab::OnText)
	EVT_TEXT(HipField+4, HipTab::OnText)
	EVT_TEXT(HipField+5, HipTab::OnText)
	EVT_TEXT(HipField+6, HipTab::OnText)
	EVT_TEXT(HipField+7, HipTab::OnText)
	EVT_TEXT(HipField+8, HipTab::OnText)
	EVT_TEXT(HipField+9, HipTab::OnText)
	EVT_LISTBOX(HipContextListBox, HipTab::OnListClick)
	EVT_TOOL_RCLICKED(HipField, HipTab::OnListClick) 
END_EVENT_TABLE()

void HipTab::OnText(wxCommandEvent& event) 
{
	HipKey& updatedKey = m_personality.m_contexts[current_context].m_keys[event.m_id - HipField];
	m_interface.UpdateHipKey(updatedKey);
}

void HipTab::OnListClick(wxCommandEvent& event) 
{
	DestroyKeyInformation();
	DetachSizer();
	CreateControls(event.GetSelection());
	GetSizer()->Layout();

	m_interface.m_activeContext = event.GetSelection();
}
void HipTab::SetHipKeys( HipContext& context, wxSizer& sizer) 
{
  //  printf("HipTab::SetHipKeys\n");
	wxList& children = GetChildren();
	int count = children.GetCount();

	for( size_t i(0); i<context.m_keys.Count(); i++ )
	{
		wxStaticBox *keyBox = m_staticBoxes[m_staticBoxCount] = new wxStaticBox(this, HipField, context.m_keys[i].m_name);
		m_staticBoxCount++;
		wxSizer *keyBoxSizer = new wxStaticBoxSizer(keyBox, wxVERTICAL);
	
		sizer.Add(keyBoxSizer, 1, wxALL, 5);

		{
			wxStaticText *control = m_staticTexts[m_staticTextCount] = new wxStaticText(this, HipField+i, _T("HI:"));
			m_staticTextCount++;
			wxSizer *sizerRow = new wxBoxSizer(wxHORIZONTAL);
			wxTextCtrl *text = m_textCtrls[m_textCtrlCount] = new wxTextCtrl(this, HipField+i, context.m_keys[i].m_hi,
			wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
			m_textCtrlCount++;

			text->SetMinSize(wxSize(200, 20));
			control->SetMinSize(wxSize(50, 20));

			sizerRow->Add(control, 0, wxRIGHT | wxALIGN_CENTRE_VERTICAL, 5);
			sizerRow->Add(text, 1, wxLEFT | wxRIGHT | wxALIGN_CENTRE_VERTICAL, 5);
			sizerRow->SetMinSize(260,20);

			keyBoxSizer->Add(sizerRow, 1, wxALIGN_LEFT, 10);
		}
		{
			wxStaticText *control = m_staticTexts[m_staticTextCount] = new wxStaticText(this, HipField+i, _T("Url:"));
			m_staticTextCount++;
			wxSizer *sizerRow = new wxBoxSizer(wxHORIZONTAL);
			wxTextCtrl *text = m_textCtrls[m_textCtrlCount] = new wxTextCtrl(this, HipField+i, context.m_keys[i].m_url,
			wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
			m_textCtrlCount++;

			text->SetMinSize(wxSize(200, 20));
			control->SetMinSize(wxSize(50, 20));

			sizerRow->Add(control, 0, wxRIGHT | wxALIGN_CENTRE_VERTICAL, 5);
			sizerRow->Add(text, 1, wxLEFT | wxRIGHT | wxALIGN_CENTRE_VERTICAL, 5);
			sizerRow->SetMinSize(260,20);

			keyBoxSizer->Add(sizerRow, 1, wxALIGN_LEFT, 10);
		}
		{
			wxStaticText *control = m_staticTexts[m_staticTextCount] = new wxStaticText(this, HipField+i, _T("Port:"));
			m_staticTextCount++;
			wxSizer *sizerRow = new wxBoxSizer(wxHORIZONTAL);
			wxTextCtrl *text = m_textCtrls[3*i+2] = new wxTextCtrl(this, HipField+i, context.m_keys[i].m_port,
			wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);
			m_textCtrlCount++;

			text->SetMinSize(wxSize(200, 20));
			control->SetMinSize(wxSize(50, 20));

			sizerRow->Add(control, 0, wxRIGHT | wxALIGN_CENTRE_VERTICAL, 5);
			sizerRow->Add(text, 1, wxLEFT | wxRIGHT | wxALIGN_CENTRE_VERTICAL, 5);
			sizerRow->SetMinSize(260,20);

			keyBoxSizer->Add(sizerRow, 1, wxALIGN_LEFT, 10);
		}
	}	
	children = GetChildren();
	count = children.GetCount();
}


HipTab::HipTab( HipInterface& _interface, HipPersonality& personality, wxBookCtrlBase *book )
: wxScrolledWindow(book, wxID_ANY,
                     wxDefaultPosition, wxDefaultSize,
                     wxNO_FULL_REPAINT_ON_RESIZE |
                     wxCLIP_CHILDREN |
                     wxTAB_TRAVERSAL | wxHSCROLL | wxVSCROLL), m_interface(_interface), m_personality(personality)
{
  //  printf("HipTab::HipTab\n");

  m_staticBoxCount = 0;
  m_textCtrlCount = 0;
  m_staticTextCount = 0;


	DestroyKeyInformation();
	DetachSizer();
	CreateControls();
	GetSizer()->Layout();
	if (m_personality.m_contexts.Count() > 0) 
		m_interface.m_activeContext = 0;
	else
		m_interface.m_activeContext = -1;
}

HipTab::~HipTab()
{

}

void HipTab::SetContexts(HipContextArray& contexts)
{
  //  printf("HipTab::SetContexts\n");
	for( size_t i(0); i<contexts.Count(); i++ )
	{
		m_lbox->Append(contexts[i].m_name);
	}
}

void HipTab::CreateControls(int context)
{
  //  printf("HipTab::CreateControls\n");
SetScrollbars(0, 20, 0, 20);

	if( context == -1 )
	{
		m_lbox = new wxListBox(this, HipContextListBox,
                           wxPoint(1,1), wxDefaultSize,
                           0, NULL,
                           wxLB_HSCROLL);
		m_lbox->SetMinSize(wxSize(150,300));
		m_sizerLeft->Add(m_lbox, 1, wxALL, 5);
		m_sizerLeft->SetMinSize(150,300);
		SetContexts(m_personality.m_contexts);

		if( m_personality.m_contexts.Count() > 0) 
		{
			current_context = 0;
			SetHipKeys(m_personality.m_contexts[0], *m_sizerRight);
		}
		else
		{
			current_context = -1;
		}
	}
	else
	{
		m_sizerLeft->Add(m_lbox, 1, wxALL, 5);
		m_sizerLeft->SetMinSize(150,300);

		SetHipKeys(m_personality.m_contexts[context], *m_sizerRight);
		current_context = context;
	}
}

void HipTab::DetachSizer()
{
  //  printf("HipTab::DetachSizer\n");
    m_sizer = new wxBoxSizer(wxHORIZONTAL);
	m_sizer->SetMinSize(430, 1);

    m_sizerLeft = new wxBoxSizer(wxHORIZONTAL);
    m_sizerLeft->SetMinSize(150, 300);

	m_sizerRight = new wxBoxSizer(wxVERTICAL);
	m_sizerRight->SetMinSize(270, 10);
	
	m_sizer->Add(m_sizerLeft, 0, wxALIGN_TOP, 10);
	m_sizer->Add(m_sizerRight, 0, wxALIGN_TOP|wxVSCROLL, 10);

	SetSizer(m_sizer);
	m_sizer->SetSizeHints(this);
}

void HipTab::DestroyKeyInformation()
{
  //  printf("HipTab::DestroyKeyInformation\n");
  int i(0);
	for(i=0; i<m_staticTextCount; i++)
	{
		m_staticTexts[i]->Destroy();
	}
	m_staticTextCount = 0;

	for(i=0; i<m_textCtrlCount; i++)
	{
		m_textCtrls[i]->Destroy();
	}
	m_textCtrlCount = 0;

	for(i=0; i<m_staticBoxCount; i++)
	{
		m_staticBoxes[i]->Destroy();
	}
	m_staticBoxCount = 0;
}

void HipTab::KeysUpdated()
{
  //  printf("HipTab::KeysUpdated\n");
	DestroyKeyInformation();
	DetachSizer();
	CreateControls(current_context);
	GetSizer()->Layout();
}
