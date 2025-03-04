#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t CreateHash(char *Buffer)
{
	size_t Hash = 0;
	while (*Buffer != '\0' && *Buffer != '\n')
	{
		Hash = (Hash * 2) + (2 ^ *Buffer);
		Buffer++;
	}
	Hash = Hash / 4;
	return Hash;
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		printf("Usage: %s file.txt\n", argv[0]);
		return 1;
	}

	FILE *fp = fopen(argv[1], "r");
	if (fp == NULL)
	{
		printf("Failed to open: '%s'\n", argv[1]);
		return 1;
	}

	printf("Opened: '%s'\n", argv[1]);

	fseek(fp, 0L, SEEK_END);
	long Size = ftell(fp);
	if (Size == -1)
	{
		printf("Failed to get filesize\n");
		fclose(fp);
		return 1;
	}
	rewind(fp);

	printf("Filesize is: '%ld' bytes\n\n", Size);

	int LinesRead = 0;
	char Buffer[50] = {0};
	while(fgets(Buffer, sizeof(Buffer), fp) != NULL)
	{
		size_t StringLength = strlen(Buffer);
		if (StringLength > 0 && Buffer[StringLength - 1] == '\n')
		{
			Buffer[StringLength - 1] = '\0';
		}

		size_t NewHash = CreateHash(Buffer);
		printf("%-50s | %-20zu (DEC) | 0x%-016zx (HEX)\n", Buffer, NewHash, NewHash);
		LinesRead++;
	}

	printf("\nLines read from '%s': %d\n", argv[1], LinesRead);
	fclose(fp);
	printf("File closed\n");

	return 0;
}
