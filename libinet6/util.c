
#include "util.h"

/*
 * Checks if a string contains a particular substring.
 *
 * If string contains substring, the return value is the location of
 * the first matching instance of substring in string.  If string doesn't
 * contain substring, the return value is NULL.  
 */
char *findsubstring(string, substring)
     register char *string;		
     char *substring;
{
  register char *a, *b;
  
  for (b = substring; *string != 0; string += 1) {
    if (*string != *b)
      continue;
    a = string;
    for (;;) {
      if (*b == 0)
	return(string);
      if (*a++ != *b++)
	break;
    }
    b = substring;
  }
  return((char *) NULL);
}

/*
 * Finds HIP key files from the directory specified by 'path'.
 * Stores the file names into linked list (type listelement).
 */ 
listelement *findkeyfiles(char *path, listelement *files) {
  
  struct dirent *entry;	     
  struct stat file_status;   
  DIR *dir = opendir(path);  

  if (!dir) {
    perror("opendir failure");
    exit(1);
  }
  
  chdir(path);
  
  //Loop through all files and directories
  while ( (entry = readdir(dir)) != NULL) {
    if ((strcmp(entry->d_name, ".") != 0) && 
	(strcmp(entry->d_name, "..") != 0)) {
      //Get the status info for the current file
      if (stat(entry->d_name, &file_status) == 0) {
	//Is this a directory, or a file?
	//Go through all private key files
	if (!S_ISDIR(file_status.st_mode) && 
	    !findsubstring(entry->d_name, ".pub") &&
	    findsubstring(entry->d_name, "hip_host_")) {
	  _HIP_DEBUG("Private key file: %s \n",entry->d_name);
	  files = add_list_item(files, entry->d_name);
	  
	}
      }
    }
  }

  if (closedir(dir) == -1) {
    perror("closedir failure");
    exit(1);
  }
  
  return files;	
}


/* utility functions for simple linked list */

listelement *add_list_item(listelement * listpointer, char *data) {
  listelement * lp = listpointer;

  if (listpointer != NULL) {
    while (listpointer -> link != NULL)
      listpointer = listpointer -> link;
    listpointer -> link = (struct listelement  *) 
      malloc (sizeof (listelement));
    listpointer = listpointer -> link;
    listpointer -> link = NULL;
    strcpy(listpointer -> data, data);
    _HIP_DEBUG("inserted %s\n",listpointer->data);
    return lp;
  }
  
  else {
    listpointer = (listelement  *) malloc (sizeof (listelement));
    listpointer -> link = NULL;
    strcpy(listpointer -> data, data);
    _HIP_DEBUG("inserted %s\n",listpointer->data);
    return listpointer;
  }
}

listelement *remove_list_item(listelement * listpointer) {

    listelement * tempp;
    HIP_DEBUG ("Element removed is %s\n", listpointer -> data);
    free(listpointer->data);
    tempp = listpointer -> link;
    free (listpointer);
    return tempp;
}

void print_list(listelement * listpointer) {
  
  if (listpointer == NULL)
    HIP_DEBUG ("queue is empty!\n");
  else
    while (listpointer != NULL) {
      HIP_DEBUG ("%s\n", listpointer -> data);
      listpointer = listpointer -> link;
    }
}

void clear_list(listelement * listpointer) {
  
  while (listpointer != NULL) {
    listpointer = remove_list_item (listpointer);
  }
}
