#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		printf("Usage: %s input.exe bytes-to-add output.exe\n", argv[0]);
		return 1;
	}

	char *InputFile = argv[1];
	char *OutputFile = argv[3];

	FILE *Input = fopen(InputFile, "rb");
	if (Input == NULL)
	{
		printf("[-] Failed to open: '%s'\n", InputFile);
		return 1;
	}

	int BytesToAdd = atoi(argv[2]);
	if (BytesToAdd < 0 || BytesToAdd > 900000000)
	{
		printf("[-] Can't give bytes < 0 or bytes > 900000000 (900 MB)\n");
		fclose(Input);
		return 1;
	}

	fseek(Input, 0L, SEEK_END);
	long Size = ftell(Input);
	rewind(Input);

	if (Size == -1)
	{
		printf("[-] Error getting filesize of '%s'\n", InputFile);
		fclose(Input);
		return 1;
	}

	printf("[+] Filename: '%s' Filesize: '%ld' bytes\n", InputFile, Size);
	printf("[+] Creating new file: '%s'\n", OutputFile);

	FILE *Output = fopen(OutputFile, "wb");
	if (Output == NULL)
	{
		printf("[-] Failed to open: '%s'\n", OutputFile);
		fclose(Input);
		return 1;
	}

	size_t TotalBytes = Size + BytesToAdd;

	char *Buffer = (char *)malloc(TotalBytes);
	if (Buffer == NULL)
	{
		printf("[-] Memory allocation failed!\n");
		fclose(Input);
		fclose(Output);
		return 1;
	}

	size_t BytesRead = fread(Buffer, 1, Size, Input);
	if (BytesRead != (size_t) Size)
	{
		printf("[-] Error reading size from '%s'\n", InputFile);
		free(Buffer);
		fclose(Input);
		fclose(Output);
		return 1;
	}

	size_t Seed;
	if (getrandom(&Seed, sizeof(Seed), 0) == -1)
	{
		time_t Seed2 = time(NULL);
		srand((unsigned int) Seed2);
		printf("[-] Random seed generation failed. Defaulting to srand with time(NULL). Seed is: %zX\n", Seed2);
	}
	else
	{
		srand((unsigned int)Seed);
		printf("[+] Random seed: 0x%zX\n", Seed);
	}

	for (int i = 0; i < BytesToAdd; i++)
	{
		Buffer[Size + i] = rand() % 256;
	}

	size_t BytesWritten = fwrite(Buffer, 1, TotalBytes, Output);
	if (BytesWritten != TotalBytes)
	{
		printf("[-] Error writing to file '%s'\n", OutputFile);
		free(Buffer);
		fclose(Input);
		fclose(Output);
		return 1;
	}

	free(Buffer);
	fclose(Input);
	fclose(Output);

	printf("[+] Created file '%s' with extra '%d' bytes\n", OutputFile, BytesToAdd);

	return 0;
}
