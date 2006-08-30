#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "environ.h"
#include "sha.h"
#include "config.h"

int shaFQDN();
static sha_digest mydigest;

int readConf(FQDN *r)
{
  FILE *file;
  int i;
  int count=0;
  char *output;
  char tmpdomain[255];
  char tmphit[50];
  
  file=fopen("domain.conf","r");
  if (!file)
    {
      printf("Could not read or find the domain.conf\n");
      printf("Exiting...\n");
      return 1;
    }
  while(fscanf(file,"%s %s",r[i].domain,r[i].HIT) != EOF)
    {
      i++;
    }
  count = i;
  fclose(file);


  output = malloc(sizeof(char[SHF_DIGESTSIZE]));

  int j;
  for (j = 0; j<count;j++) {
    shaFQDN(r[j].domain,output);
    strcpy(r[j].domain,output);


    if (count > MAXDOMAIN){
      printf("Error...");
      exit(1);
    }
  }	
  return count;
}

int shaFQDN(char *arg, char* output){
  int loop;
  char tmp[3];
  bzero(output,sizeof(output));
  
  shaInit   (NULL, 1);
  shaUpdate (NULL, (BITS8 *) arg, strlen (arg));
  shaFinal  (NULL, mydigest);
  
  /* print it out. */
  for (loop=0; loop<SHF_DIGESTSIZE; loop++)
    {
      //	  printf("%02lX",mydigest[loop]);
      sprintf(tmp,"%02lX",mydigest[loop]);
      strcat(output,tmp);
    }
  return 0;
}    
