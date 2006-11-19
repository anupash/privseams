/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "agent_tools.h"


/******************************************************************************/
/* VARIABLES */
/** This determines whether agent is executing or not. */
int agent_exec_state = 1;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Check whether agent should be executing or not.

	@return 1 if executing, 0 if not.
*/
int agent_exec(void)
{
	/* Return. */
	return (agent_exec_state);
}
/* END OF FUNCTION */

/******************************************************************************/
/**
	Stop and exit agent.
*/
void agent_exit(void)
{
	agent_exec_state = 0;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Prints given hit to buffer as text.
*/
void print_hit_to_buffer(char *buffer, struct in6_addr *hit)
{
	int n, b;
	
	buffer[0] ='\0';
	b = 0;
	
	for (n = 0; n < 16; n++)
	{
		sprintf(&buffer[b], "%02x", (int)hit->s6_addr[n]);
		b += 2;

		if ((n % 2) == 1 && n > 0 && n < 15)
		{
			strcat(buffer, ":");
			b++;
		}
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Read hit from text buffer as hit.
*/
void read_hit_from_buffer(struct in6_addr *hit, char *buffer)
{
	int n, i;
	int v[8];
	
	memset(v, 0, sizeof(int) * 8);

	sscanf(buffer, "%x:%x:%x:%x:%x:%x:%x:%x",
	       &v[7], &v[6], &v[5], &v[4],
	       &v[3], &v[2], &v[1], &v[0]);
	
	n = 0;
	for (i = 7; i >= 0; i--)
	{
		hit->s6_addr[n + 1] = v[i] & 0xff;
		hit->s6_addr[n] = (v[i] >> 8) & 0xff;
		n += 2;
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Read current config.
	
	@param file Config file.
	@return 0 on success, -1 on errors.
*/
int config_read(const char *file)
{
	/* Variables. */
	FILE *f;
	int err = -1, i, n;
	char ch, buf[LONG_STRING], *p1, *p2;

	/* Open file for reading. */
	f = fopen(file, "r");
	HIP_IFEL(!f, -1, "Couldn't open config file: \"%s\"\n", file);

	/* Start parsing. */
	memset(buf, '\0', LONG_STRING); i = 0;
	for (ch = fgetc(f); ch != EOF; ch = fgetc(f))
	{
		/* Remove whitespaces from line start. */
		if (i == 0 && (ch == ' ' || ch == '\t'))
		{
			continue;
		}
		
		/* Find end of line. */
		if (ch != '\n')
		{
			buf[i] = ch;
			i++;
			continue;
		}

		/*
			Check whether there is carriage return
			in the stream and remove it.
		*/
		ch = fgetc(f);
		
		if (ch != '\r')
		{
			ungetc(ch, f);
		}
		
		/* Check for empty lines and for commented lines. */
		if (strlen(buf) < 1) goto loop_end;
		if (buf[0] == '#') goto loop_end;
		
		/* Find '=' character and split string from there. */
		p1 = strtok(buf, "=");
		if (p1 == NULL) goto loop_end;
		p2 = strtok(NULL, "\0");
		if (p2 == NULL) goto loop_end;
		
		/* Set values. */
		str_var_set(p1, p2);
		HIP_DEBUG("config string read: %s=%s\n", p1, p2);
		
	loop_end:
		/* Clear buffer. */
		memset(buf, '\0', LONG_STRING); i = 0;
	}

	err = 0;

out_err:
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

