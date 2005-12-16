// HipInterface.h: interface for the HipInterface class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_HIPINTERFACE_H__9FE14465_BDA2_4CA3_BCBB_01786E423553__INCLUDED_)
#define AFX_HIPINTERFACE_H__9FE14465_BDA2_4CA3_BCBB_01786E423553__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "hit_db.h"
#include "wx/wx.h"
#include "hipagent.h"
#include "hipkey.h"


class HipInterface  
{
public:
	HipInterface(HipPersonalityArray& personalities);
	virtual ~HipInterface();

	void InitHipKeys();
	void UpdateHipKey( HipKey &key );
	void AddHipKey( HipKey &key );
	void DeleteHipKey(int);

	int m_activeContext;
	int m_activePersonality;
	HipPersonalityArray& m_personalities;
};

#endif // !defined(AFX_HIPINTERFACE_H__9FE14465_BDA2_4CA3_BCBB_01786E423553__INCLUDED_)
