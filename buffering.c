#include <stdio.h>
int main(int argc, char **argv, char **envp)
{
	puts("===================================================");
	printf("\tWelcome to %s!\n", argv[0]);
	puts("===================================================");
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 1);

	return vuln(argc, argv, envp);
}
