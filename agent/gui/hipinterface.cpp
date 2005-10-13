// HipInterface.cpp: implementation of the HipInterface class.
//
//////////////////////////////////////////////////////////////////////

#include "hipinterface.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

HipInterface::HipInterface(HipPersonalityArray& personalities)
: m_personalities(personalities)
{
	m_activeContext = 0;
	m_activePersonality = 0;
}

HipInterface::~HipInterface()
{

}

// this file is for Antti to fill

// interface to hip daemon

// this file contains the implementations of the functions
// that require some interaction to the real hip keys

// this function should load all the keys from the hip daemon
// and append them to the m_personalities (whose content is then shown 
// in the agent application
void HipInterface::InitHipKeys()
{
	// for each hip key, 
	// create a HipKey instance 
	// remember to set the id of the instance to identify it later
	// and append the key to the m_personalities: m_personalities->Add( (HipKey*) ... );

	// TEST IMPLEMENTATION:
    for( int i(0); i<5; i++ )
	{
		HipPersonality* personality = new HipPersonality;
		personality->m_id = i;
		if( i == 0)
			personality->m_name = "Matti";	
		else
			personality->m_name = "Default user";

		HipContext* context = new HipContext;
		context->m_id = 0;
		context->m_name = "Financial services";

		HipKey* key = new HipKey;
		key->m_id = 0;
		key->m_hi = "1234-1234-1234";
		key->m_name = "Nordea Solo";
		key->m_port = "80";
		key->m_url = "http://solo.nordea.fi";
		context->m_keys.Add( key );
		
		key = new HipKey;
		key->m_id = 1;
		key->m_hi = "5678-5678-5678";
		key->m_name = "OP Verkkopankki";
		key->m_port = "80";
		key->m_url = "http://www.op.fi";

		context->m_keys.Add( key );

		personality->m_contexts.Add( context );

		context = new HipContext;
		context->m_id = 0;
		context->m_name = "Games";

		key = new HipKey;
		key->m_id = 0;
		key->m_hi = "1234-1234-1234";
		key->m_name = "Warcraft 3";
		key->m_port = "1100";
		key->m_url = "http://www.warcraft3.com";
		context->m_keys.Add( key );

		key = new HipKey;
		key->m_id = 0;
		key->m_hi = "ABCD-1234-1234";
		key->m_name = "Grand Theft Auto";
		key->m_port = "5005";
		key->m_url = "http://www.gta.com";
		context->m_keys.Add( key );

		key = new HipKey;
		key->m_id = 1;
		key->m_hi = "5678-5678-5678";
		key->m_name = "Halflife Counter-Strike";
		key->m_port = "52007";
		key->m_url = "http://www.hl.net";

		context->m_keys.Add( key );

		personality->m_contexts.Add( context );

		context = new HipContext;
		context->m_id = 0;
		context->m_name = "Messaging";

		key = new HipKey;
		key->m_id = 0;
		key->m_hi = "s24-s24-s24-s24-s24";
		key->m_name = "Suomi24";
		key->m_port = "80";
		key->m_url = "http://www.suomi24.fi";

		context->m_keys.Add( key );

		personality->m_contexts.Add( context );

		m_personalities.Add( personality );
	}
}
 
// this function should update one or more fields of a hip key
// the integer identifier of the key should be used to 
// identify the key; (all fields updated? ;)
void HipInterface::UpdateHipKey( HipKey& key )
{
	key.m_hi = wxString("ak");
}

// this function should add this key to the actual hip daemon
void HipInterface::AddHipKey( HipKey& key )
{
	m_personalities[m_activePersonality].m_contexts[m_activeContext].m_keys.Add(key);
	
	// please set the identifier of the key, it has not been set before
	// key.m_id = xxx;
}

void HipInterface::DeleteHipKey( HipKey& /*key*/ )
{
	// delete the hip key corresponding to this key instance
}
