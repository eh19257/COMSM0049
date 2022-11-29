// Vuln3 from lab 4


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int copyData(char *string)
{
	char buf[32];
	strcpy(buf, string);

	//printf("DATA IN BUFFER: %x\n", string);
	//printf("DATA IN buf: %x\n", buf);
	return (0);
}

int main(int argc, char *argv[])
{
	char buffer[10000];
	FILE *file;
    if (argc !=2)
    {
        printf("[*] invalid arguments!\n [*] > %s file_name\n",argv[0]);
        exit(0);
    }
	printf("opening file\n");
	file = fopen(argv[1],"rb");
	if (!file)
	{ 
		//printf("file not opened %s", strerror(errno));
		fprintf(stderr,"file not opened %s", strerror(errno));
		//printf("error");
		return (0);
	}
	printf("file opened\n");
	fread(buffer, 699, 1, file);
	fclose(file);
	copyData(buffer);
	return (0);
}
