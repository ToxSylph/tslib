#pragma once
#include <windows.h>
#include <vector>
#include <iostream>
#include <TlHelp32.h>
#include <Psapi.h>
#include <stdio.h>
#include <tchar.h>

namespace ts
{
	int* FloatToIntPointer(float& f);
	char* AobsEx(HANDLE hProc, char* pattern, char* mask, char* begin, intptr_t size);
	PBYTE Aobs(PCHAR pattern, PCHAR mask, PBYTE begin, SIZE_T size);
	void HP(PBYTE destination, PBYTE source, SIZE_T size, BYTE* oldBytes);
	void Nop(PBYTE destination, SIZE_T size, BYTE* oldBytes);
	void HPX(HANDLE hProcess, PBYTE destination, PBYTE source, SIZE_T size, BYTE* oldBytes);
	void NopX(HANDLE hProcess, PBYTE destination, SIZE_T size, BYTE* oldBytes);

	bool Hook32(PBYTE hooked, PVOID hook32Template, SIZE_T bytes);
	bool Hook64(PBYTE hooked, PVOID shellcode, SIZE_T shellSize, SIZE_T bytes);

	uintptr_t ResolveAddr(uintptr_t ptr, std::vector<unsigned int> offsets);
	uintptr_t ResolveAddrEx(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets);

	DWORD GetPID(const PWCHAR pName);
	PVOID GetMBA(DWORD pid, const  PWCHAR mName, DWORD_PTR mSize);
}
