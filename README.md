# BypassAV
This repository contains files and ideas that can be used to try and bypass AV software.

Basic stuff such as 1-XOR_String.c won't bypass any AV, but it should be seen as an idea to build on.

By using 5-TsarWiper-APIHashing.c and 4-ModFile.c, I was able to bypass Windows Defender.

## Files
1-XOR_String.c : Simple reverse shell that uses a XOR encrypted shellcode.

2-Rand_Vars.c : Generates 'random' variable names. Can be used to replace variable names in other C files.

3-APIHashing.c : Opens 3-Functions.txt and prints the corresponding Decimal and Hexadecimal values for each function present in the txt file. Useful for other API hashing projects.

3-Functions.txt : File containing Windows API functions. It doesn't contain all of them.

3-CreateFile-APIHashing.c : Program that creates and writes contents into a new file using API hashing.

3-Shellcode-APIHashing.c : Shellcode injection using API hashing (No VirtualProtect).

3-Shellcode2-APIHashing.c : Shellcode injection using API hashing (VirtualProtect).

4-ModFile.c : Add zeros up to 900 MBs of space to increase the size of an executable.

5-TsarWiper-APIHashing.c : TsarWiper using API hashing (No MBR Wiper)

## Compilation
If you are compiling from Linux, you can use:

x86_64-w64-mingw32-gcc file.c -o file.exe : To compile Windows executables

gcc file.c -o file : To compile Linux ELF executables
