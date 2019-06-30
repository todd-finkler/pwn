#include <stdio.h>
int main()
{
	char name[10] = {0};
	printf("Name: ");
	read(0, name, 10);
	printf("Hello %s!\n", name);
}
