#include "tslib.h"

HANDLE hProcess;
uintptr_t mba;
DWORD mbasize;
uintptr_t toHook;

/* ESTADO
* HP, NOP, HPX, NOPX = LISTO
* GETPID, GETMBA = LISTO
* HOOK32 = LISTO, para funciones, funciones naked (shellcode-asm inline)
* HOOK64 = LISTO, inyeccion por shellcode
* Aobs LISTO

*/

int* ts::FloatToIntPointer(float& f)
{
	float* pointer = &f;
	int* intpointer = (int*)pointer;
	return intpointer;
}

PBYTE ts::Aobs(PCHAR pattern, PCHAR mask, PBYTE begin, SIZE_T size)
{
	SIZE_T patternSize = strlen((char*)mask);

	for (int i = 0; i < size; i++)
	{
		bool match = true;
		for (int j = 0; j < patternSize; j++)
		{
			if(*(char*)((uintptr_t)begin + i + j) != pattern[j] && mask[j] != '?')
			{
				match = false;
				break;
			}
		}
		if (match) return (begin + i);
	}
	return nullptr;
}

char* ts::AobsEx(HANDLE hProc, char* pattern, char* mask, char* begin, intptr_t size)
{
	char* match{ nullptr };
	SIZE_T bytesRead;
	DWORD oldprotect;
	char* buffer{ nullptr };
	MEMORY_BASIC_INFORMATION mbi;
	mbi.RegionSize = 0x1000; // Tamano de region de una pagina, SIZE_T cubre este rango

	VirtualQueryEx(hProc, (LPCVOID)begin, &mbi, sizeof(mbi));

	for (char* curr = begin; curr < begin + size; curr += mbi.RegionSize)
	{
		if (!VirtualQueryEx(hProc, curr, &mbi, sizeof(mbi))) continue;

		if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) continue;

		delete[] buffer;
		buffer = new char[mbi.RegionSize];

		if (VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldprotect))
		{
			ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead);
			VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, oldprotect, &oldprotect);

			char* internalAddr = (char*)Aobs(pattern, mask, (PBYTE)buffer, (intptr_t)bytesRead);

			if (internalAddr != nullptr)
			{
				match = curr + (internalAddr - buffer); // De direccion interna a externa
				break;
			}
		}
	}
	delete[] buffer;
	return match;
}

void ts::HP(PBYTE destination, PBYTE source, SIZE_T size, BYTE* oldBytes)
{
	DWORD oldProtection;
	VirtualProtect(destination, size, PAGE_EXECUTE_READWRITE, &oldProtection);
	memcpy(oldBytes, destination, size);
	memcpy(destination, source, size);
	VirtualProtect(destination, size, oldProtection, &oldProtection);
}

void ts::Nop(PBYTE destination, SIZE_T size, BYTE* oldBytes)
{
	PBYTE nop = new BYTE[size];
	memset(nop, 0x90, size);
	HP(destination, nop, size, oldBytes);
}

void ts::HPX(HANDLE hProcess, PBYTE destination, PBYTE source, SIZE_T size, BYTE* oldBytes)
{
	DWORD oldProtection;
	VirtualProtectEx(hProcess, destination, size, PAGE_READWRITE, &oldProtection);
	ReadProcessMemory(hProcess, destination, oldBytes, size, nullptr);
	WriteProcessMemory(hProcess, destination, source, size, nullptr);
	VirtualProtectEx(hProcess, destination, size, oldProtection, &oldProtection);
}

void ts::NopX(HANDLE hProcess, PBYTE destination, SIZE_T size, BYTE* oldBytes)
{
	PBYTE nop = new BYTE[size];
	memset(nop, 0x90, size);
	HPX(hProcess, destination, nop, size, oldBytes);
}

bool ts::Hook32(PBYTE hooked, PVOID hook32Template, SIZE_T bytes)
{
	DWORD oldProtection;
	VirtualProtect(hooked, bytes, PAGE_EXECUTE_READWRITE, &oldProtection);
	memset(hooked, 0x90, bytes);
	uintptr_t relativeAddress = ((uintptr_t)hook32Template - (uintptr_t)hooked) - 5;
	*hooked = 0xE8;
	*(DWORD*)(hooked + 1) = (DWORD)relativeAddress;
	VirtualProtect(hooked, bytes, oldProtection, &oldProtection);

	return true;
}

bool ts::Hook64(PBYTE hooked, PVOID shellcode, SIZE_T shellSize, SIZE_T bytes) // bytes = total stolenbytes
{
	DWORD oldProtection;
	VirtualProtect(hooked, bytes, PAGE_EXECUTE_READWRITE, &oldProtection);

	PBYTE stolenBytes = new BYTE[bytes];
	ts::Nop(hooked, bytes, stolenBytes);

	// Usamos el registro rdx para saltar, por eso lo salvamos antes del hook
	                 // push rdx mov rdx, 0000000000000000          jmp rdx  pop rdx
	char jumpArray[] = "\x52\x48\xba\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe2\x5a";
	char returnArray[] = "\x48\xba\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe2"; // = 12
	PVOID mAllocated = VirtualAlloc(0, shellSize + bytes + 12, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (mAllocated != 0)
	{
		memcpy(jumpArray + 3, &mAllocated, sizeof(mAllocated));
		uintptr_t ptrrtn = (uintptr_t)hooked + bytes;
		memcpy(returnArray + 2, (void*)&ptrrtn, sizeof(hooked));
	}
	else
	{
		return false;
	}

	// Inyecta un jump a nuestra funcion, copia nuestro shellcode, luego los bytes robados y por ultimo, el jump de regreso
	memcpy(hooked, jumpArray, sizeof(jumpArray) - 1);
	memcpy(mAllocated, shellcode, shellSize); 
	memcpy((PBYTE)mAllocated + shellSize, stolenBytes, bytes);
	memcpy((PBYTE)mAllocated + shellSize + bytes, returnArray, 12);


	VirtualProtect(hooked, bytes, oldProtection, &oldProtection);


	return true;
}


//void* ptrs = &ppp;
//DWORD hookedAddress = 0x002450B9;
//DWORD hookedAddressLengthBytesOverwritten = 5;
//ts::Hook32((PBYTE)hookedAddress, (PVOID)ptrs, hookedAddressLengthBytesOverwritten);
//void ppp()
//{
//	std::cout << "Hooked" << std::endl;
//}

//DWORD hookedAddress = 0x002450B9;
//DWORD hookedAddressLengthBytesOverwritten = 5;
//DWORD jmpBack = hookedAddress + hookedAddressLengthBytesOverwritten; // hookedAddress + hookedAddressLengthBytesOverwritten // naked no disponible en x64
//void _declspec(naked) hook32Template()
//{
//	_asm
//	{
//		nop // MyCode
//		nop // MyCode
//		mov eax, [ebp + 0x0C] // StolenBytes
//		jmp[jmpBack] //JumpBack
//	}
//}



DWORD ts::GetPID(const PWCHAR pName)
{
	DWORD pid = 0;
	PROCESSENTRY32 pCurrent;
	pCurrent.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!(hSnap == INVALID_HANDLE_VALUE)) {
		if (Process32First(hSnap, &pCurrent))
		{
			do
			{
				if (!wcscmp(pCurrent.szExeFile, pName))
				{
					pid = pCurrent.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &pCurrent));
		}
	}
	if (hSnap != 0)
		CloseHandle(hSnap);
	return pid;
}

PVOID ts::GetMBA(DWORD pid, const  PWCHAR mName, DWORD_PTR mSize)
{
	PVOID addr = 0;
	MODULEENTRY32 mCurrent;
	mCurrent.dwSize = sizeof(mCurrent);
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnap == INVALID_HANDLE_VALUE) {
		if (Module32First(hSnap, &mCurrent))
		{
			do
			{
				if (!wcscmp(mCurrent.szModule, mName))
				{
					addr = (PVOID)mCurrent.modBaseAddr;
					mSize = mCurrent.modBaseSize;
					break;
				}
			} while (Module32Next(hSnap, &mCurrent));
		}
	}
	if (hSnap != 0)
		CloseHandle(hSnap);
	return addr;
}

int hook()
{
	//uintptr_t tohook = 0x7FF60C0555E6;
	//char org[] = "\xf3\x0f\x11\x40\x18";
	//BYTE* buffer = new BYTE[5];
	//ts::NopX(hProcess, (BYTE*)tohook, 5, buffer);
	//ts::HPX(hProcess, (PBYTE)tohook, (PBYTE)org, 5, buffer);

	//void* ptrs = &ppp;
	//DWORD hookedAddress = 0x002450B9;
	//DWORD hookedAddressLengthBytesOverwritten = 5;
	//ts::Hook32((PBYTE)hookedAddress, (PVOID)ptrs, hookedAddressLengthBytesOverwritten);



	PBYTE tohook = (PBYTE)0x7FF731097BFC;
	char shellcodeArray[] = "\x83\xC0\x04"; // add eax,0x4
	ts::Hook64(tohook, shellcodeArray, 3, 20); // (hookedfunc, shellcode, shellcodesize, stolenbytessize)

	//char aob[] = "\x89\x85\x00\x00\x00\x00\x48\x8d\x15\x00\x00\x00\x00\x48\x8b\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x8b\x95";
	//char mask[] = "xx????xxx????xxx????x????xx";
	//std::cout << "MBA: " << mba << std::endl;
	//std::cout << "MBA size: " << mbasize << std::endl;
	//PBYTE aobaddr = ts::Aobs((PCHAR)aob, (PCHAR)mask, (PBYTE)mba, (SIZE_T)mbasize);
	//std::cout << "AOBaddr: " << (void*)aobaddr << std::endl;

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		DWORD pid = ts::GetPID((PWCHAR)L"DummyProject1.exe");
		std::cout << "PID VAL: " << std::dec << pid << std::endl;
		if (pid != 0)
		{
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
			HMODULE hModule = GetModuleHandle(NULL);
			MODULEINFO hmInfo;
			GetModuleInformation(hProcess, hModule, &hmInfo, sizeof(MODULEINFO));
			mba = (uintptr_t)hmInfo.lpBaseOfDll;
			mbasize = hmInfo.SizeOfImage;
			std::cout << "MODULE Addr: " << std::hex << hModule << std::endl;
			//CreateThread(0, 0, (LPTHREAD_START_ROUTINE)hook, 0, 0, 0);
			hook();
			std::cout << "FLAG EXIT!" << std::endl;
		}
	}
	return true;
}


//int main()
//{
//	DWORD pid = ts::GetPID((PWCHAR)L"DummyProject1.exe");
//	if (pid != 0)
//	{
//		hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
//		mba = (uintptr_t) ts::GetMBA(pid, (PWCHAR)L"DummyProject1.exe", mbasize);
//		hook();
//	}
//	char ctest = getchar();
//	return 0;
//}