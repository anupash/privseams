/*
    HIP GUI
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
             Matti Saarinen
*/

/////////////////////////////////////////////////////////////////////////////
// Program:     wxHipAgent HipAgent Sample
// Name:        HipAgent.h
// Purpose:     Common stuff for all HipAgent project files
// Author:      Vadim Zeitlin
// Created:     27.03.01
// Id:          $Id: hipagent.h,v 1.1 2005/11/14 11:26:48 west Exp $
// Copyright:   (c) 2001 Vadim Zeitlin
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_SAMPLE_HipAgent_H_
#define _WX_SAMPLE_HipAgent_H_

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

#include "hiptab.h"

WX_DECLARE_OBJARRAY( HipPersonality, HipPersonalityArray );

#include "hipinterface.h"

#include "agent_interface.h"

class WXDLLEXPORT wxCheckBox;
class WXDLLEXPORT wxBookCtrlBase;
class WXDLLEXPORT wxSizer;
class WXDLLEXPORT wxTextCtrl;

class HipAgentPageInfo;

#include "wx/panel.h"

// all source files use wxImageList
#include "wx/imaglist.h"

#if wxUSE_LOG && !defined(__SMARTPHONE__)
    #define USE_LOG 1
#else
    #define USE_LOG 0
#endif

#include "hippersonality.h"
// create a class: linked list for containing personality data


// ----------------------------------------------------------------------------
// HipAgentPage: a book page demonstrating some widget
// ----------------------------------------------------------------------------

class HipAgentPage : public wxPanel
{
public:
    HipAgentPage(wxBookCtrlBase *book);

    // return the control shown by this page
    virtual wxControl *GetWidget() const = 0;

    // some pages show 2 controls, in this case override this one as well
    virtual wxControl *GetWidget2() const { return NULL; }

protected:
    // several helper functions for page creation

    // create a horz sizer containing the given control and the text ctrl
    // (pointer to which will be saved in the provided variable if not NULL)
    // with the specified id
    wxSizer *CreateSizerWithText(wxControl *control,
                                 wxWindowID id = wxID_ANY,
                                 wxTextCtrl **ppText = NULL);

    // create a sizer containing a label and a text ctrl
    wxSizer *CreateSizerWithTextAndLabel(const wxString& label,
                                         wxWindowID id = wxID_ANY,
                                         wxTextCtrl **ppText = NULL);

    // create a sizer containing a button and a text ctrl
    wxSizer *CreateSizerWithTextAndButton(wxWindowID idBtn,
                                          const wxString& labelBtn,
                                          wxWindowID id = wxID_ANY,
                                          wxTextCtrl **ppText = NULL);

    // create a checkbox and add it to the sizer
    wxCheckBox *CreateCheckBoxAndAddToSizer(wxSizer *sizer,
                                            const wxString& label,
                                            wxWindowID id = wxID_ANY);

public:
    // the head of the linked list containinginfo about all pages
    static HipAgentPageInfo *ms_widgetPages;
};

// ----------------------------------------------------------------------------
// dynamic HipAgentPage creation helpers
// ----------------------------------------------------------------------------

class HipAgentPageInfo
{
public:
    typedef HipAgentPage *(*Constructor)(wxBookCtrlBase *book,
                                        wxImageList *imaglist);

    // our ctor
    HipAgentPageInfo(Constructor ctor, const wxChar *label);

    // accessors
    const wxString& GetLabel() const { return m_label; }
    Constructor GetCtor() const { return m_ctor; }
    HipAgentPageInfo *GetNext() const { return m_next; }

    void SetNext(HipAgentPageInfo *next) { m_next = next; }

private:
    // the label of the page
    wxString m_label;

    // the function to create this page
    Constructor m_ctor;

    // next node in the linked list or NULL
    HipAgentPageInfo *m_next;
};

// to declare a page, this macro must be used in the class declaration
#define DECLARE_HipAgent_PAGE(classname)                                     \
    private:                                                                \
        static HipAgentPageInfo ms_info##classname;                          \
    public:                                                                 \
        const HipAgentPageInfo *GetPageInfo() const                          \
            { return &ms_info##classname; }

// and this one must be inserted somewhere in the source file
#define IMPLEMENT_HipAgent_PAGE(classname, label)                            \
    HipAgentPage *wxCtorFor##classname(wxBookCtrlBase *book,                 \
                                      wxImageList *imaglist)                \
        { return new classname(book, imaglist); }                           \
    HipAgentPageInfo classname::                                             \
        ms_info##classname(wxCtorFor##classname, label)


// Define a new frame type: this is going to be our main frame
class HipAgentFrame : public wxFrame
{
public:
	void OnPageChanged(wxNotebookEvent& event);
	void RefreshTabs();
	void OnExportKey(wxCommandEvent& event);
	void OnImportKey(wxCommandEvent& event);
	void OnAskQuit(wxCommandEvent& event);
	void OnTimer(wxTimerEvent &event);
	void OnDeleteKey(wxCommandEvent &event);
	
	int MsgBox(char *title, char *content);


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

	HipInterface *m_hipInterface;

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

	wxTimer timer;

    // any class wishing to process wxHipAgent events must use this macro
    DECLARE_EVENT_TABLE()
};

#define TIMER_ID 0
#define BUTTON_DELETE_KEY_ID 1000


#endif /* END OF HEADER FILE */
/******************************************************************************/
