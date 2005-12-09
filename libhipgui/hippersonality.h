#ifndef __HIPPERSONALITY_H__
#define __HIPPERSONALITY_H__

#include "hipcontext.h"
#include <wx/dynarray.h>

WX_DECLARE_OBJARRAY( HipContext, HipContextArray );

class HipPersonality  
{
public:
	HipPersonality();
	virtual ~HipPersonality();

public: // no getters yet for these
	wxString m_name;

	HipContextArray m_contexts;

	int m_id;
};

#endif 
