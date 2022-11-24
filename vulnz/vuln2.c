// Modified Vuln3 from lab 4


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int copyData(char *string)
{
	char buf[32];
	strcpy(buf, string);

    printf("%s\n", buf);
	return (0);
}

int main(int argc, char *argv[])
{
	char buffer[700];
	//FILE *file;
    if (argc !=1)
    {
        printf("[*] invalid arguments!\n [*] > %s file_name\n",argv[0]);
        exit(0);
    }
	printf("Enter input: \n");
    
    scanf("%s", buffer);
	copyData(buffer);
	return (0);
}