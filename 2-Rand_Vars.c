#include <stdio.h>
#include <stdlib.h>
#include <time.h>

char Letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

int main()
{
	srand((unsigned int)(time(NULL) ^ clock()));
	for (int j = 0; j < 10; j++)
	{
		for (int i = 0; i < 40; i++)
		{
			printf("%c", Letters[rand() % 52]);
		}
		printf("\n");
	}
	return 0;
}
