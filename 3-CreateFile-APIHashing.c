#include <stdio.h>
#include <string.h>
#include <windows.h>

DWORD HashOfFunctions[] = {44112, 12415, 44346};

typedef HANDLE(WINAPI *CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI *WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI *CloseHandle_t)(HANDLE);

DWORD CreateHash(const char *str)
{
	DWORD Hash = 0;
	while (*str != '\0' && *str != '\n')
	{
		Hash = (Hash * 2) + (2 ^ *str);
		str++;
	}
	Hash = Hash / 4;
	return Hash;
}

FARPROC GetProcAddressByHash(HMODULE Module, DWORD Hash)
{
	unsigned char *BaseAddress = (unsigned char *)Module;

	IMAGE_DOS_HEADER *DOSHeader = (IMAGE_DOS_HEADER *)BaseAddress;
	if (DOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[-] Error: e_magic not valid!\n");
		return NULL;
	}

	IMAGE_NT_HEADERS *NTHeaders = (IMAGE_NT_HEADERS *)(BaseAddress + DOSHeader->e_lfanew);
	if (NTHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("[-] Error: Not a valid PE\n");
		return NULL;
	}

	IMAGE_DATA_DIRECTORY ExportDataDir = NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (ExportDataDir.VirtualAddress == 0)
	{
		printf("[-] Error: Export Table missing!\n");
		return NULL;
	}

	IMAGE_EXPORT_DIRECTORY *ExportDir = (IMAGE_EXPORT_DIRECTORY *)(BaseAddress + ExportDataDir.VirtualAddress);

	DWORD *FunctionRVAs = (DWORD *)(BaseAddress + ExportDir->AddressOfFunctions);
	DWORD *NameRVAs = (DWORD *)(BaseAddress + ExportDir->AddressOfNames);
	WORD *NameOrdinals = (WORD *)(BaseAddress + ExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < ExportDir->NumberOfNames; i++)
	{
		char *FunctionName = (char *)(BaseAddress + NameRVAs[i]);
		DWORD CurrentHash = CreateHash(FunctionName);

		if (CurrentHash == Hash)
		{
			WORD Ordinal = NameOrdinals[i];
			DWORD FuncRVA = FunctionRVAs[Ordinal];
			FARPROC FunctionAddress = (FARPROC)(BaseAddress + FuncRVA);
			return FunctionAddress;
		}
	}

	return NULL;
}

int main()
{
	HMODULE Kernel32 = GetModuleHandleA("kernel32.dll");
	if (Kernel32 == NULL)
	{
		printf("[-] Failed to get handle for kernel32.dll: %ld\n", GetLastError());
		return 1;
	}

	unsigned char *BAddr = (unsigned char *)Kernel32;
	printf("[+] Base address of kernel32.dll: 0x%p\n", BAddr);

	WriteFile_t pWriteFile = NULL;
	CreateFileA_t pCreateFileA = NULL;
	CloseHandle_t pCloseHandle = NULL;

	for (int i = 0; i < sizeof(HashOfFunctions) / sizeof(HashOfFunctions[0]); i++)
	{
		FARPROC func = GetProcAddressByHash(Kernel32, HashOfFunctions[i]);
		if (func == NULL)
		{
			printf("[-] Failed to resolve function for hash: %ld\n", HashOfFunctions[i]);
			return 1;
		}

		if (i == 0) pCreateFileA = (CreateFileA_t)func;
		else if (i == 1) pWriteFile = (WriteFile_t)func;
		else if (i == 2) pCloseHandle = (CloseHandle_t)func;
	}

	if (!pCreateFileA || !pWriteFile || !pCloseHandle)
	{
		printf("[-] Error: Not all functions were resolved!\n");
		return 1;
	}

	HANDLE hFile = pCreateFileA("output.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[-] Error: Failed to create output.txt!\n");
		return 1;
	}

	char Data[] = "Hello, all functions resolved via API hashing!";
	DWORD BytesWritten = 0;
	if (pWriteFile(hFile, Data, (DWORD)strlen(Data), &BytesWritten, NULL))
	{
		printf("[+] Successfully wrote %d bytes to output.txt!\n", BytesWritten);
	}
	else
	{
		printf("[-] WriteFile call failed.\n");
	}

	pCloseHandle(hFile);

	printf("[+] Success\n");

	return 0;
}
