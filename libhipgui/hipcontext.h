/*
    HIP GUI
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
             Matti Saarinen
*/

#ifndef __HIPCONTEXT_H__
#define __HIPCONTEXT_H__

#include <wx/dynarray.h>
#include "hipkey.h"

/* Create a class: linked list for containing personality data. */
WX_DECLARE_OBJARRAY( HipKey, HipKeyArray );


class HipContext  
{
public:
	HipContext();
	virtual ~HipContext();

public: // no getters yet
	wxString m_name;
	
	HipKeyArray m_keys;

	int m_id;
};


#endif /* END OF HEADER FILE */
/******************************************************************************/
