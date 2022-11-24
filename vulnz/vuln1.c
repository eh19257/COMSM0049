// Vuln3 from lab 4 but has been editted to take an input from the command line 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int copyData(char *string)
{
	char buf[32];
	strcpy(buf, string);
    printf("%s", buf);
	return (0);
}

int main(int argc, char *argv[])
{
	char buffer[700];
	//FILE *file;
    if (argc != 2)
    {
        printf("[*] invalid arguments!\n [*] > %s file_name\n",argv[0]);
        exit(0);
    }
    strcpy(buffer, argv[1]);
    //printf("%s", *argv);
    
    // mash the args together
    for (int i = 2; i < argc; i++){
        strcat(buffer, argv[i]);
        //printf("%s", argv[i]);
    }  

	copyData(buffer);
	return (0);
}