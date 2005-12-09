#ifndef __HIPKEY_H__
#define __HIPKEY_H__

#include "wx/string.h"

class HipKey  
{
public:
	HipKey();
	virtual ~HipKey();

public: // no getters yet for these
	wxString m_name;
	wxString m_hi;
	wxString m_url;
	wxString m_port;

	wxString m_extended;

	int m_id;
};

#endif 
