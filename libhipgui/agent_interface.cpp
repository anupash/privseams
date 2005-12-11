/*
    HIP Agent
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */

/* THIS */
#include "agent_interface.h"


/******************************************************************************/
/* DEFINES */
enum
{
	HIT_NO_MSG = 0,
	HIT_ASK1,
	HIT_ASK2,
	HIT_ACCEPT,
	HIT_DENY,
	HIT_RESERVED1,
	HIT_ADD1,
	HIT_ADD2,
	HIT_DEL1,
	HIT_DEL2
};


/******************************************************************************/
/* VARIABLES */
int hit_msg = HIT_NO_MSG;
char ask_title[128];
char ask_content[1024];
HIT_Item hit_add_del;


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
	
out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Close GUI interface.
*/
void gui_quit_interface(void)
{
	hit_db_quit("/etc/hip/agentdb");
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Ask user for accept or denial of HIT.

	@return 0 on success, -1 on errors.
*/
int gui_ask_hit_accept(char *title, char *content)
{
	int err = 0;

	while (hit_msg != HIT_NO_MSG) wxUsleep(100);
	hit_msg = HIT_ASK1;
	strncpy(ask_title, title, 128);
	strncpy(ask_content, content, 1024);
	hit_msg = HIT_ASK2;
	while (hit_msg == HIT_ASK2) wxUsleep(100);

	switch (hit_msg)
	{
	case HIT_ACCEPT:
	    err = 0;
	    break;
	
	default:
	case HIT_DENY:
	    err = -1;
	    break;
	}

	hit_msg = HIT_NO_MSG;

	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Inform GUI of new HIT.
*/
void gui_add_new_hit(HIT_Item *hit)
{
	while (hit_msg != HIT_NO_MSG) wxUsleep(100);
	hit_msg = HIT_ADD1;
	memcpy(&hit_add_del, hit, sizeof(HIT_Item));
	hit_msg = HIT_ADD2;
//	while (hit_msg == HIT_ADD2) wxUsleep(100);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Check for messages from agent.
*/
void HipAgentFrame::OnTimer(wxTimerEvent &event)
{
	HipKey *key;
	char rhit_str[64], lhit_str[64], port_str[32];
	
	switch (hit_msg)
	{
	case HIT_ASK2:
	{
		wxMessageDialog dialog(NULL, _T(ask_content), _T(ask_title),
		                       wxNO_DEFAULT | wxYES_NO | wxICON_INFORMATION);
		
		switch (dialog.ShowModal())
		{
		case wxID_YES:
			hit_msg = HIT_ACCEPT;
			break;
		
		default:
		case wxID_NO:
			hit_msg = HIT_DENY;
			break;
		}

		break;
	}

	case HIT_ADD2:
	{
		HipKey *key = new HipKey;
		print_hit_to_buffer(lhit_str, &hit_add_del.lhit);
		print_hit_to_buffer(rhit_str, &hit_add_del.rhit);
		sprintf(port_str, "%d", hit_add_del.port);
		key->m_id = hit_add_del.index;
		key->m_lhi = lhit_str;
		key->m_hi = rhit_str;
		key->m_name = hit_add_del.name;
		key->m_port = port_str;
		key->m_url = hit_add_del.url;
		m_hipInterface->AddHipKey(*key);
		RefreshTabs();
		hit_msg = HIT_NO_MSG;
		break;
	}

	} /* switch */
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Delete currently selected key.
*/
void HipAgentFrame::OnDeleteKey(wxCommandEvent &event)
{
	HipKey *key = new HipKey;
	struct in6_addr lhit, rhit;
	char *lhit_str, *rhit_str;

	HipContext& context = m_hipInterface->m_personalities[m_hipInterface->m_activePersonality].m_contexts[m_hipInterface->m_activeContext];
	
	memcpy(key, &context.m_keys[0], sizeof(HipKey));
	lhit_str = (char *)key->m_lhi.c_str();
	rhit_str = (char *)key->m_hi.c_str();
	read_hit_from_buffer(&lhit, lhit_str);
	read_hit_from_buffer(&rhit, rhit_str);
	
	m_hipInterface->DeleteHipKey(0);
	RefreshTabs();
	hit_db_del(&lhit, &rhit, 1);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

