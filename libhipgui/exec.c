/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "exec.h"


/******************************************************************************/
/* DEFINES */
#define EXEC_LOCK_PIDS() { while (exec_pids_lock); exec_pids_lock = 1; }
#define EXEC_UNLOCK_PIDS() { exec_pids_lock = 0; }


/******************************************************************************/
/* VARIABLES */
/** Process IDs for applications executed trough GUI. */
int exec_pids[MAX_EXEC_PIDS];
/* Lock for process IDs. */
int exec_pids_lock = 0;
/** Timer thread keeper. */
pthread_t exec_timer_pthread;
/** Execute timer if not zero. */
int exec_timer_run = 0;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/** Initialize execution "environment" for debugging mostly. */
int exec_init(void)
{
	/* Variables. */
	int err = 0, i;
	
	/* Clear globals. */
	for (i = 0; i < MAX_EXEC_PIDS; i++) exec_pids[i] = -1;
	exec_pids_lock = 0;
	
	/* Initialize timer. */
	exec_timer_run = 1;
	err = pthread_create(&exec_timer_pthread, NULL, exec_timer_thread, NULL);
	HIP_IFEL(err, -1, "Failed to create execute timer thread!\n");
	
out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Deinitialize execution "environment". */
void exec_quit(void)
{
	if (exec_timer_run)
	{
		HIP_DEBUG("Stopping timer...\n");
		exec_timer_run = 0;
		pthread_join(exec_timer_pthread, NULL);
	}
}
/* END OF FUNCTION */
	

/******************************************************************************/
/** Execute new application. */
void exec_application(void)
{
	/* Variables. */
	GtkWidget *dialog;
	int err, cpid;
	char *ps, *ps2, *ps3;

	dialog = widget(ID_EXECDLG);
	gtk_widget_show(dialog);
	gtk_widget_grab_focus(widget(ID_RUN_COMMAND));

	err = gtk_dialog_run(GTK_DIALOG(dialog));
	if (err == GTK_RESPONSE_OK)
	{
		/* Find empty place for process ID. */
		EXEC_LOCK_PIDS();
		cpid = exec_empty_pid();
		if (cpid < 0)
		{
			HIP_DEBUG("Failed to get empty process ID space, "
		              "too many processes running under GUI.\n");
			EXEC_UNLOCK_PIDS();
			goto out_err;
		}
		
		ps = gtk_entry_get_text(widget(ID_RUN_COMMAND));
		if (strlen(ps) > 0) err = fork();
		else err = -1;
		
		/* Get environment variables. */
		ps2 = gtk_entry_get_text(widget(ID_RUN_LDPRELOAD));
		ps3 = gtk_entry_get_text(widget(ID_RUN_LDLIBRARYPATH));
		
		if (err < 0) HIP_DEBUG("Failed to exec new application.\n");
		else if (err > 0)
		{
			exec_pids[cpid] = err;
			gui_add_process(err, ps, 0, 0);
		}
		else if(err == 0)
		{
			HIP_DEBUG("Exec new application.\n");
			/* Set environment variables for new process. */
			if (strlen(ps2) > 0)
			{
				setenv("LD_PRELOAD", ps2, 1);
				HIP_DEBUG("Set LD_PRELOAD=%s\n", ps2);
			}
			if (strlen(ps3) > 0)
			{
				setenv("LD_LIBRARY_PATH", ps3, 1);
				HIP_DEBUG("Set LD_LIBRARY_PATH=%s\n", ps3);
			}
			err = execlp(ps, "", (char *)0);
			if (err != 0)
			{
				HIP_DEBUG("Executing new application failed!\n");
				exit(1);
			}
		}

		EXEC_UNLOCK_PIDS();
	}

out_err:
	gtk_widget_hide(dialog);
	return;
}
/* END OF FUNCTION */


/******************************************************************************/
/** Find empty process ID. */
int exec_empty_pid(void)
{
	/* Variables. */
	int err = -1, i;

	for (i = 0; i < MAX_EXEC_PIDS; i++)
	{
		if (exec_pids[i] <= 0)
		{
			err = i;
			break;
		}
	}
	
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Find empty process ID. */
void *exec_timer_thread(void *data)
{
	/* Variables. */
	struct rusage ru;
	int err = 0, i, valid;
	GtkWidget *w;
	GtkTreeIter iter;

	while (exec_timer_run)
	{
		w = widget(ID_PLISTMODEL);

		for (i = 0; i < MAX_EXEC_PIDS; i++)
		{
			if (exec_pids[i] <= 0) continue;

			valid = gtk_tree_model_get_iter_first(w, &iter);
			while (valid)
			{
				gtk_tree_model_get(w, &iter, 0, &err, -1);
				if (err == exec_pids[i]) break;
				valid = gtk_tree_model_iter_next(w, &iter);
			}
			if (!valid)
			{
				HIP_DEBUG("Warning: did not find PID from process list!\n");
				continue;
			}
			
			err = wait4(exec_pids[i], NULL, WNOHANG, &ru);
			if (err == 0)
			{
				gtk_tree_store_set(w, &iter, 3, ru.ru_msgsnd + ru.ru_msgrcv, -1);
			}
			else if (err < 0)
			{
				HIP_DEBUG("wait4() returned error: %d\n", err);
				exec_pids[i] = -1;
			}
			else if (err > 0)
			{
				HIP_DEBUG("Child process terminated, PID: %d.\n", err);
				exec_pids[i] = -1;
				gtk_tree_store_remove(w, &iter);
			}
		}
		
		usleep(500 * 1000);
	}
	
out_err:
	HIP_DEBUG("Execute \"environment\" timer thread exiting.\n");
	exec_timer_run = 0;
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

