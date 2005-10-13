/////////////////////////////////////////////////////////////////////////////
// Program:     HipAgent 
// Name:        HipAgent.cpp
// Purpose:     ... ... ... lost? ;)
// Author:      Matti Saarinen
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// for compilers that support precompilation, includes "wx/wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

// for all others, include the necessary headers
#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/log.h"
    #include "wx/frame.h"
    #include "wx/menu.h"

    #include "wx/button.h"
    #include "wx/checkbox.h"
    #include "wx/listbox.h"
    #include "wx/statbox.h"
    #include "wx/stattext.h"
    #include "wx/textctrl.h"
    #include "wx/msgdlg.h"
#endif

#include "wx/sysopt.h"
#include "wx/bookctrl.h"
#include "wx/sizer.h"
#include "wx/colordlg.h"
#include "wx/fontdlg.h"
#include "wx/textdlg.h"
#include "wx/file.h"

#include <stdio.h>

#include "hipagent.h"
#include "hiptab.h"
#include "hipinterface.h"


extern "C"
{
	int agent_main(void);
}


wxWindow *main_window = NULL;


// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// control ids
enum
{
    HipAgent_ClearLog = 100,
    HipAgent_Quit,
#if wxUSE_TOOLTIPS
    HipAgent_SetTooltip,
#endif // wxUSE_TOOLTIPS
    HipAgent_SetFgColour,
    HipAgent_SetBgColour,
    HipAgent_SetFont,
    HipAgent_Enable,
	HipAgent_ImportKey,
	HipAgent_ExportKey,

	HipAgent_Notebook
};

#include <wx/arrimpl.cpp>
WX_DEFINE_OBJARRAY( HipPersonalityArray );



// ----------------------------------------------------------------------------
// our classes
// ----------------------------------------------------------------------------

// Define a new application type, each program should derive a class from wxApp
class HipAgentApp : public wxApp
{
public:
    // override base class virtuals
    // ----------------------------

    // this one is called on application startup and is a good place for the app
    // initialization (doing it here and not in the ctor allows to have an error
    // return: if OnInit() returns false, the application terminates)
    virtual bool OnInit();
};

// Define a new frame type: this is going to be our main frame
class HipAgentFrame : public wxFrame
{
public:
	void OnPageChanged(wxNotebookEvent& event);
	void RefreshTabs();
	void OnExportKey(wxCommandEvent& event);
	void OnImportKey(wxCommandEvent& event);
    // ctor(s) and dtor
    HipAgentFrame(const wxString& title);
    virtual ~HipAgentFrame();

protected:
    // event handlers
#if USE_LOG
    void OnButtonClearLog(wxCommandEvent& event);
#endif // USE_LOG
    void OnExit(wxCommandEvent& event);

#if wxUSE_MENUS
#if wxUSE_TOOLTIPS
    void OnSetTooltip(wxCommandEvent& event);
#endif // wxUSE_TOOLTIPS
    void OnSetFgCol(wxCommandEvent& event);
    void OnSetBgCol(wxCommandEvent& event);
    void OnSetFont(wxCommandEvent& event);
    void OnEnable(wxCommandEvent& event);
#endif // wxUSE_MENUS

    // initialize the book: add all pages to it
    void InitBook();

private:
    // the panel containing everything
    wxPanel *m_panel;

	// list for personality data
	HipPersonalityArray m_personalities;

	HipInterface* m_hipInterface;

    // the book containing the test pages
    wxBookCtrlBase *m_book;

    // and the image list for it
    wxImageList *m_imaglist;

#if wxUSE_MENUS
    // last chosen fg/bg colours and font
    wxColour m_colFg,
             m_colBg;
    wxFont   m_font;
#endif // wxUSE_MENUS

    // any class wishing to process wxHipAgent events must use this macro
    DECLARE_EVENT_TABLE()
};

#if USE_LOG
// A log target which just redirects the messages to a listbox
class LboxLogger : public wxLog
{
public:
    LboxLogger(wxListBox *lbox, wxLog *logOld)
    {
        m_lbox = lbox;
        //m_lbox->Disable(); -- looks ugly under MSW
        m_logOld = logOld;
    }

    virtual ~LboxLogger()
    {
        wxLog::SetActiveTarget(m_logOld);
    }

private:
    // implement sink functions
    virtual void DoLog(wxLogLevel level, const wxChar *szString, time_t t)
    {
        // don't put trace messages into listbox or we can get into infinite
        // recursion
        if ( level == wxLOG_Trace )
        {
            if ( m_logOld )
            {
                // cast is needed to call protected method
                ((LboxLogger *)m_logOld)->DoLog(level, szString, t);
            }
        }
        else
        {
            wxLog::DoLog(level, szString, t);
        }
    }

    virtual void DoLogString(const wxChar *szString, time_t WXUNUSED(t))
    {
        wxString msg;
        TimeStamp(&msg);
        msg += szString;

        #ifdef __WXUNIVERSAL__
            m_lbox->AppendAndEnsureVisible(msg);
        #else // other ports don't have this method yet
            m_lbox->Append(msg);
            m_lbox->SetFirstItem(m_lbox->GetCount() - 1);
        #endif
    }

    // the control we use
    wxListBox *m_lbox;

    // the old log target
    wxLog *m_logOld;
};
#endif // USE_LOG

// array of pages
WX_DEFINE_ARRAY_PTR(HipAgentPage *, ArrayHipAgentPage);

// ----------------------------------------------------------------------------
// misc macros
// ----------------------------------------------------------------------------

#ifndef CONFIG_HIPGUI_COMMANDLINE
IMPLEMENT_APP(HipAgentApp)
#endif

// ----------------------------------------------------------------------------
// event tables
// ----------------------------------------------------------------------------

BEGIN_EVENT_TABLE(HipAgentFrame, wxFrame)
#if USE_LOG
    EVT_BUTTON(HipAgent_ClearLog, HipAgentFrame::OnButtonClearLog)
#endif // USE_LOG
    EVT_BUTTON(HipAgent_Quit, HipAgentFrame::OnExit)

#if wxUSE_TOOLTIPS
    EVT_MENU(HipAgent_SetTooltip, HipAgentFrame::OnSetTooltip)
#endif // wxUSE_TOOLTIPS

    EVT_MENU(HipAgent_SetFgColour, HipAgentFrame::OnSetFgCol)
    EVT_MENU(HipAgent_SetBgColour, HipAgentFrame::OnSetBgCol)
    EVT_MENU(HipAgent_SetFont,     HipAgentFrame::OnSetFont)
    EVT_MENU(HipAgent_Enable,      HipAgentFrame::OnEnable)

	EVT_MENU(HipAgent_ImportKey,	HipAgentFrame::OnImportKey)
	EVT_MENU(HipAgent_ExportKey,	HipAgentFrame::OnExportKey)


	EVT_NOTEBOOK_PAGE_CHANGED(HipAgent_Notebook, HipAgentFrame::OnPageChanged)
    EVT_MENU(wxID_EXIT, HipAgentFrame::OnExit)
END_EVENT_TABLE()

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// app class
// ----------------------------------------------------------------------------

bool HipAgentApp::OnInit()
{
  //  printf("HipAgentApp::OnInit\n");

if ( !wxApp::OnInit() )
        return false;

    // the reason for having these ifdef's is that I often run two copies of
    // this sample side by side and it is useful to see which one is which

#ifndef CONFIG_HIPGUI_COMMANDLINE
	agent_main();
#endif

    wxFrame *frame = new HipAgentFrame(_T("HIP GUI"));
    frame->Show();
	main_window = frame;

    //wxLog::AddTraceMask(_T("listbox"));
    //wxLog::AddTraceMask(_T("scrollbar"));
    //wxLog::AddTraceMask(_T("focus"));

    return true;
}

// ----------------------------------------------------------------------------
// HipAgentFrame construction
// ----------------------------------------------------------------------------

HipAgentFrame::HipAgentFrame(const wxString& title)
            : wxFrame(NULL, wxID_ANY, title,
                      wxPoint(0, 50), wxDefaultSize,
                      wxDEFAULT_FRAME_STYLE |
                      wxFULL_REPAINT_ON_RESIZE |
                      wxCLIP_CHILDREN |
                      wxTAB_TRAVERSAL)
{
  //  printf("HipAgentFrame::HipAgentFrame\n");
  
    // init everything
    m_book = (wxBookCtrlBase *)NULL;
    m_imaglist = (wxImageList *)NULL;

	m_hipInterface = new HipInterface(m_personalities);
	m_hipInterface->InitHipKeys();

#if wxUSE_MENUS
    // create the menubar
    wxMenuBar *mbar = new wxMenuBar;
    wxMenu *menuWidget = new wxMenu;
#if wxUSE_TOOLTIPS
    menuWidget->Append(HipAgent_ImportKey, _T("&Import key...\tCtrl-I"));
	menuWidget->Append(HipAgent_ExportKey, _T("E&xport key...\tCtrl-X"));
    menuWidget->AppendSeparator();
#endif // wxUSE_TOOLTIPS
    menuWidget->Append(HipAgent_SetBgColour, _T("&Apply changes...\tCtrl-A"));
    menuWidget->AppendSeparator();
    menuWidget->Append(wxID_EXIT, _T("&Quit\tCtrl-Q"));
    mbar->Append(menuWidget, _T("&HIP"));
    SetMenuBar(mbar);

#endif // wxUSE_MENUS

    // create controls
    m_panel = new wxPanel(this, wxID_ANY,
        wxDefaultPosition, wxDefaultSize, wxCLIP_CHILDREN);

    wxSizer *sizerTop = new wxBoxSizer(wxVERTICAL);

    // we have 2 panes: book with pages demonstrating the controls in the
    // upper one and the log window with some buttons in the lower

    int style = wxNO_FULL_REPAINT_ON_RESIZE|wxCLIP_CHILDREN|wxBC_DEFAULT;
    // Uncomment to suppress page theme (draw in solid colour)
    //style |= wxNB_NOPAGETHEME;

    m_book = new wxBookCtrl(m_panel, HipAgent_Notebook, wxDefaultPosition,
#ifdef __WXMOTIF__
        wxSize(400, -1), // under Motif, height is a function of the width...
#else
        wxSize(300,300),//wxDefaultSize,
#endif
        style);
        InitBook();

    // put everything together
    sizerTop->Add(m_book, 1, wxGROW | (wxALL & ~(wxTOP | wxBOTTOM)), 10);
    sizerTop->Add(0, 5, 0, wxGROW); // spacer in between

    m_panel->SetSizer(sizerTop);

    sizerTop->Fit(this);
    sizerTop->SetSizeHints(this);
}

void HipAgentFrame::InitBook()
{
  //   printf("HipAgentFrame::InitBook\n");
	for( size_t i(0); i<m_personalities.Count(); i++ )
	{
		HipTab* tab = new HipTab( *m_hipInterface, m_personalities[i], m_book );
//        tab->SetBackgroundColour(*wxLIGHT_GREY);
		m_book->AddPage( tab, m_personalities[i].m_name);
		}	
}

HipAgentFrame::~HipAgentFrame()
{
	delete m_hipInterface;
}

// ----------------------------------------------------------------------------
// HipAgentFrame event handlers
// ----------------------------------------------------------------------------

void HipAgentFrame::OnExit(wxCommandEvent& WXUNUSED(event))
{
    Close();
}

#if USE_LOG
void HipAgentFrame::OnButtonClearLog(wxCommandEvent& WXUNUSED(event))
{

}
#endif // USE_LOG

#if wxUSE_MENUS

#if wxUSE_TOOLTIPS

void HipAgentFrame::OnSetTooltip(wxCommandEvent& WXUNUSED(event))
{
    static wxString s_tip = _T("This is a tooltip");

    wxString s = wxGetTextFromUser
                 (
                    _T("Tooltip text: "),
                    _T("HipAgent sample"),
                    s_tip,
                    this
                 );

    if ( s.empty() )
        return;

    s_tip = s;

    if( wxMessageBox( _T("Test multiline tooltip text?"),
                      _T("HipAgent sample"),
                      wxYES_NO,
                      this
                    ) == wxYES )
    {
        s = _T("#1 ") + s_tip + _T("\n") + _T("#2 ") + s_tip;
    }

    HipAgentPage *page = wxStaticCast(m_book->GetCurrentPage(), HipAgentPage);
    page->GetWidget()->SetToolTip(s);

    wxControl *ctrl2 = page->GetWidget2();
    if ( ctrl2 )
        ctrl2->SetToolTip(s);
}

#endif // wxUSE_TOOLTIPS

void HipAgentFrame::OnSetFgCol(wxCommandEvent& WXUNUSED(event))
{
#if wxUSE_COLOURDLG
    // allow for debugging the default colour the first time this is called
    HipAgentPage *page = wxStaticCast(m_book->GetCurrentPage(), HipAgentPage);
    if (!m_colFg.Ok())
        m_colFg = page->GetForegroundColour();

    wxColour col = wxGetColourFromUser(this, m_colFg);
    if ( !col.Ok() )
        return;

    m_colFg = col;

    page->GetWidget()->SetForegroundColour(m_colFg);
    page->GetWidget()->Refresh();

    wxControl *ctrl2 = page->GetWidget2();
    if ( ctrl2 )
    {
        ctrl2->SetForegroundColour(m_colFg);
        ctrl2->Refresh();
    }
#else
    wxLogMessage(_T("Colour selection dialog not available in current build."));
#endif
}

void HipAgentFrame::OnSetBgCol(wxCommandEvent& WXUNUSED(event))
{
#if wxUSE_COLOURDLG
    HipAgentPage *page = wxStaticCast(m_book->GetCurrentPage(), HipAgentPage);
    if ( !m_colBg.Ok() )
        m_colBg = page->GetBackgroundColour();

    wxColour col = wxGetColourFromUser(this, m_colBg);
    if ( !col.Ok() )
        return;

    m_colBg = col;

    page->GetWidget()->SetBackgroundColour(m_colBg);
    page->GetWidget()->Refresh();

    wxControl *ctrl2 = page->GetWidget2();
    if ( ctrl2 )
    {
        ctrl2->SetBackgroundColour(m_colFg);
        ctrl2->Refresh();
    }
#else
    wxLogMessage(_T("Colour selection dialog not available in current build."));
#endif
}

void HipAgentFrame::OnSetFont(wxCommandEvent& WXUNUSED(event))
{
#if wxUSE_FONTDLG
    HipAgentPage *page = wxStaticCast(m_book->GetCurrentPage(), HipAgentPage);
    if (!m_font.Ok())
        m_font = page->GetFont();

    wxFont font = wxGetFontFromUser(this, m_font);
    if ( !font.Ok() )
        return;

    m_font = font;

    page->GetWidget()->SetFont(m_font);
    page->GetWidget()->Refresh();

    wxControl *ctrl2 = page->GetWidget2();
    if ( ctrl2 )
    {
        ctrl2->SetFont(m_font);
        ctrl2->Refresh();
    }
#else
    wxLogMessage(_T("Font selection dialog not available in current build."));
#endif
}

void HipAgentFrame::OnEnable(wxCommandEvent& event)
{
    HipAgentPage *page = wxStaticCast(m_book->GetCurrentPage(), HipAgentPage);
    page->GetWidget()->Enable(event.IsChecked());
}

#endif // wxUSE_MENUS

// ----------------------------------------------------------------------------
// HipAgentPageInfo
// ----------------------------------------------------------------------------

HipAgentPageInfo *HipAgentPage::ms_widgetPages = NULL;

HipAgentPageInfo::HipAgentPageInfo(Constructor ctor, const wxChar *label)
               : m_label(label)
{
    m_ctor = ctor;

    m_next = NULL;

    // dummy sorting: add and immediately sort on list according to label

    if(HipAgentPage::ms_widgetPages)
    {
        HipAgentPageInfo *node_prev = HipAgentPage::ms_widgetPages;
        if(wxStrcmp(label,node_prev->GetLabel().c_str())<0)
        {
            // add as first
            m_next = node_prev;
            HipAgentPage::ms_widgetPages = this;
        }
        else
        {
            HipAgentPageInfo *node_next;
            do
            {
                node_next = node_prev->GetNext();
                if(node_next)
                {
                    // add if between two
                    if(wxStrcmp(label,node_next->GetLabel().c_str())<0)
                    {
                        node_prev->SetNext(this);
                        m_next = node_next;
                        // force to break loop
                        node_next = NULL;
                    }
                }
                else
                {
                    // add as last
                    node_prev->SetNext(this);
                    m_next = node_next;
                }
                node_prev = node_next;
            }while(node_next);
        }
    }
    else
    {
        // add when first

        HipAgentPage::ms_widgetPages = this;

    }

}

// ----------------------------------------------------------------------------
// HipAgentPage
// ----------------------------------------------------------------------------

HipAgentPage::HipAgentPage(wxBookCtrlBase *book)
           : wxPanel(book, wxID_ANY,
                     wxDefaultPosition, wxDefaultSize,
                     wxNO_FULL_REPAINT_ON_RESIZE |
                     wxCLIP_CHILDREN |
                     wxTAB_TRAVERSAL)
{
}

wxSizer *HipAgentPage::CreateSizerWithText(wxControl *control,
                                          wxWindowID id,
                                          wxTextCtrl **ppText)
{
    wxSizer *sizerRow = new wxBoxSizer(wxHORIZONTAL);
    wxTextCtrl *text = new wxTextCtrl(this, id, wxEmptyString,
        wxDefaultPosition, wxDefaultSize, wxTE_PROCESS_ENTER);

    sizerRow->Add(control, 0, wxRIGHT | wxALIGN_CENTRE_VERTICAL, 5);
    sizerRow->Add(text, 1, wxLEFT | wxALIGN_CENTRE_VERTICAL, 5);

    if ( ppText )
        *ppText = text;

    return sizerRow;
}

// create a sizer containing a label and a text ctrl
wxSizer *HipAgentPage::CreateSizerWithTextAndLabel(const wxString& label,
                                                  wxWindowID id,
                                                  wxTextCtrl **ppText)
{
    return CreateSizerWithText(new wxStaticText(this, wxID_ANY, label),
        id, ppText);
}

// create a sizer containing a button and a text ctrl
wxSizer *HipAgentPage::CreateSizerWithTextAndButton(wxWindowID idBtn,
                                                   const wxString& label,
                                                   wxWindowID id,
                                                   wxTextCtrl **ppText)
{
    return CreateSizerWithText(new wxButton(this, idBtn, label), id, ppText);
}

wxCheckBox *HipAgentPage::CreateCheckBoxAndAddToSizer(wxSizer *sizer,
                                                     const wxString& label,
                                                     wxWindowID id)
{
    wxCheckBox *checkbox = new wxCheckBox(this, id, label);
    sizer->Add(checkbox, 0, wxLEFT | wxRIGHT, 5);
    sizer->Add(0, 2, 0, wxGROW); // spacer

    return checkbox;
}


void HipAgentFrame::OnImportKey(wxCommandEvent &event)
{
	wxString filename = "";

	wxFileDialog* dlg = new wxFileDialog(this, "Choose a file");
	int ret = dlg->ShowModal();

	if( ret == wxID_OK )
	{
		filename = dlg->GetPath();

		wxTextEntryDialog* textDlg = new wxTextEntryDialog(
			this, 
			"Give a name for the key", 
			"Imported key");

		ret = textDlg->ShowModal();

		if( ret == wxID_OK )
		{
			HipKey* key = new HipKey;
			key->m_name = textDlg->GetValue();
			wxFile file(filename);
			unsigned char* buffer = new unsigned char[file.Length()];
			file.Read(buffer, file.Length());
			file.Close();
			key->m_hi = wxString(buffer);

			delete buffer;

			m_hipInterface->AddHipKey(*key);
			RefreshTabs();
	//		delete key;
		}
	}

	delete dlg;
}

void HipAgentFrame::OnExportKey(wxCommandEvent &event)
{
	wxFileDialog* dlg = new wxFileDialog(this, "Choose a file");
	int ret = dlg->ShowModal();

	if( ret == wxID_OK )
	{
		wxString filename = dlg->GetFilename();
	}

	delete dlg;
}

void HipAgentFrame::RefreshTabs()
{
	int pcount = m_book->GetPageCount();

	for(int i(0); i<pcount; i++)
	{
		HipTab* tab = (HipTab*)m_book->GetPage(i);
		tab->KeysUpdated();

	}
}

void HipAgentFrame::OnPageChanged(wxNotebookEvent &event)
{
	m_hipInterface->m_activePersonality = event.GetSelection();
}
