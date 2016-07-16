#include "stdafx.h"
#include <Psapi.h>
#include <stdlib.h>
#include <vector>
#include <psapi.h>

using namespace std;
#pragma comment(lib, "psapi.lib")
#define UCHAR_MAX 0xff

struct patchInfo_struct
{
	HANDLE hProcess;
	DWORD dwProcessId;
	LPBYTE addr;
	BYTE data[255];
	int patchSize;
};
vector<patchInfo_struct> patchInfo;

// Modified BMH - http://en.wikipedia.org/wiki/Boyer-Moore-Horspool_algorithm
int search_ptn(LPWORD ptn, size_t ptn_size, LPBYTE *addr, HANDLE hProcess, HMODULE hModule)
{
	MODULEINFO dllInfo;
	if (!GetModuleInformation(hProcess, hModule, &dllInfo, sizeof(dllInfo)))
	{
		//MessageBox(0, L"GetModuleInformation Failed", 0, MB_ICONERROR);
		return 0;
	}


	UINT i;
	int scan;
	LPBYTE p;

	UINT defSkipLen;
	UINT skipLen[UCHAR_MAX + 1];
	UINT searchSuccessCount;

	UINT ptnEnd = ptn_size - 1;
	while ((HIBYTE(ptn[ptnEnd]) != 0x00) && (ptnEnd > 0))
		ptnEnd--;

	defSkipLen = ptnEnd;
	for (i = 0; i < ptnEnd; i++)
		if (HIBYTE(ptn[i]) != 0x00)
			defSkipLen = ptnEnd - i;

	for (i = 0; i < UCHAR_MAX + 1; i++)
		skipLen[i] = defSkipLen;

	for (i = 0; i < ptnEnd; i++)
		if (HIBYTE(ptn[i]) == 0x00)
			skipLen[LOBYTE(ptn[i])] = ptnEnd - i;

	searchSuccessCount = 0;
	p = (LPBYTE)dllInfo.lpBaseOfDll;
	LPBYTE searchEnd = (LPBYTE)dllInfo.lpBaseOfDll + dllInfo.SizeOfImage;
	BYTE ps;
	while (p + ptn_size < searchEnd)
	{
		scan = ptnEnd;
		while (scan >= 0)
		{
			ReadProcessMemory(hProcess, p + scan, &ps, sizeof(BYTE), NULL);
			if ((HIBYTE(ptn[scan]) == 0x00) && (LOBYTE(ptn[scan]) != ps))
				break;
			if (scan == 0)
			{
				*addr = p;
				searchSuccessCount++;
			}
			scan--;
		}
		ReadProcessMemory(hProcess, p + ptnEnd, &ps, sizeof(BYTE), NULL);
		p += skipLen[ps];
	}
	if (searchSuccessCount != 1) addr = 0;
	return searchSuccessCount;
}

void patch_ptn(HANDLE hProcess, DWORD dwProcessId, LPBYTE addr, const BYTE* Patch, int PatchSize)
{
	DWORD OldProtect, OldProtect2;
	HANDLE hHandle;
	hHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, dwProcessId);
	VirtualProtectEx(hHandle, (void *)addr, PatchSize, PAGE_EXECUTE_READWRITE, &OldProtect);

	patchInfo_struct pis;
	pis.hProcess = hProcess;
	pis.dwProcessId = dwProcessId;
	pis.addr = addr;
	ReadProcessMemory(hProcess, addr, pis.data, PatchSize, 0);
	pis.patchSize = PatchSize;
	patchInfo.push_back(pis);

	WriteProcessMemory(hProcess, addr, Patch, PatchSize, NULL);
	hHandle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, dwProcessId);
	VirtualProtectEx(hHandle, (void *)addr, PatchSize, OldProtect, &OldProtect2);
	return;
}

bool MemoryPatch(HANDLE hProcess, DWORD dwProcessId, HMODULE hModule)
{
	WORD ptn[] = { 0x8B, 0xD0, 0x89, 0x16, 0x85, 0xD2, 0x75, 0x04, 0x32, 0xC0, 0xEB, 0x49, 0x57 };
	WORD ptn2[] = { 0xFF, 0x15, -1, -1, -1, -1, 0x85, 0xC0, 0x0F, 0x84, -1, -1, -1, -1, 0x6A, 0x09, 0x59, 0x33, 0xC0, 0xC7, 0x45 };
	WORD ptn3[] = { 0x8B, 0x43, 0x0C, 0x25, 0xFF, 0xFF, 0x3B, 0xFF, 0x50, 0x6A, 0xF0, 0xFF, 0x33, 0xFF, 0xD7 };
	WORD ptn4[] = { 0x8D, 0x45, 0xD8, 0x50, 0x8D, 0x4D, 0xC4, 0xE8, -1, -1, -1, -1, 0x6A, 0x34, 0xFF };

	LPBYTE addr = 0;
	int r;
	//52FFDE83 | .  6A 00         PUSH 0; / Flags = MONITOR_DEFAULTTONULL
	//52FFDE85 | .  50            PUSH EAX; | pRect = >[ARG.1]
	//52FFDE86 | .  894D D0       MOV DWORD PTR SS : [LOCAL.12], ECX; |
	//52FFDE89 | .FF15 2CAC2554 CALL DWORD PTR DS : [<&user32.MonitorFromR; \USER32.MonitorFromRect
	//52FFDE8F | .  8BD0          MOV EDX, EAX
	//52FFDE91 | .  8916          MOV DWORD PTR DS : [ESI], EDX
	//52FFDE93 | .  85D2          TEST EDX, EDX
	//52FFDE95      75 04         JNZ SHORT 52FFDE9B; fullscreen validate
	//52FFDE97 | .  32C0          XOR AL, AL
	//52FFDE99 | .EB 49         JMP SHORT 52FFDEE4
	//52FFDE9B | >  57            PUSH EDI

	r = search_ptn(ptn, _countof(ptn), &addr, hProcess, hModule);

	if (r == 0 || r > 1)
		return false;
	else
	{
		BYTE Patch[] = { 0x8B, 0xD0, 0x89, 0x16, 0x85, 0xD2, 0x90, 0x90, 0x32, 0xC0, 0xEB, 0x49, 0x57 };
		int PatchSize = _countof(Patch);
		patch_ptn(hProcess, dwProcessId, addr, Patch, PatchSize);
	}
	//530007B3 | .  57            PUSH EDI; / hWnd
	//530007B4 | .FF15 CCAA2554 CALL DWORD PTR DS : [<&user32.IsWindow>]; \USER32.IsWindow
	//530007BA | .  85C0          TEST EAX, EAX
	//530007BC      0F81 A3000000 JNO 53000865
	//530007C2 | .  6A 09         PUSH 9
	//530007C4 | .  59            POP ECX
	//530007C5 | .  33C0          XOR EAX, EAX

	addr = 0;
	r = search_ptn(ptn2, _countof(ptn2), &addr, hProcess, hModule);

	if (r == 0 || r > 1)
		return false;
	else
	{
		BYTE Patch[] = { 0x81 };
		int PatchSize = _countof(Patch);
		addr += 9;
		patch_ptn(hProcess, dwProcessId, addr, Patch, PatchSize);
	}
	//5300D8EC | .  50            PUSH EAX; / Rect
	//5300D8ED | .FF33          PUSH DWORD PTR DS : [EBX]; | hWnd
	//5300D8EF | .FF15 4CAA2554 CALL DWORD PTR DS : [<&user32.GetWindowRec; \USER32.GetWindowRect
	//5300D8F5 | >  8A45 08       MOV AL, BYTE PTR SS : [ARG.1]
	//5300D8F8 | .  8B3D 28AA2554 MOV EDI, DWORD PTR DS : [<&user32.SetWindow
	//5300D8FE | .  8843 04       MOV BYTE PTR DS : [EBX + 4], AL
	//5300D901 | .  84C0          TEST AL, AL
	//5300D903 | .  74 60         JZ SHORT 5300D965
	//5300D905 | .  8B43 0C       MOV EAX, DWORD PTR DS : [EBX + 0C]

	addr = 0;
	r = search_ptn(ptn3, _countof(ptn3), &addr, hProcess, hModule);

	if (r == 0 || r > 1)
		return false;
	else
	{
		BYTE Patch[] = { 0xEB, 0x05 };
		int PatchSize = _countof(Patch);
		addr += 8;
		patch_ptn(hProcess, dwProcessId, addr, Patch, PatchSize);
	}
	//5300D92D | .  50            PUSH EAX; / pMonitorinfo = > OFFSET LOCAL.11
	//5300D92E | .  6A 02         PUSH 2; | / Flags = MONITOR_DEFAULTTONEAREST
	//5300D930 | .FF33          PUSH DWORD PTR DS : [EBX]; || hWnd
	//5300D932 | .FF15 38AB2554 CALL DWORD PTR DS : [<&user32.MonitorFromW; | \USER32.MonitorFromWindow
	//5300D938 | .  50            PUSH EAX; | hMonitor
	//5300D939 | .FF15 34AB2554 CALL DWORD PTR DS : [<&user32.GetMonitorIn; \USER32.GetMonitorInfoW
	//5300D93F | .  8D45 D8       LEA EAX, [LOCAL.10]
	//5300D942 | .  50            PUSH EAX; / Arg1 = > OFFSET LOCAL.10
	//5300D943 | .  8D4D C4       LEA ECX, [LOCAL.15]; |
	//5300D946 | .E8 28F52800   CALL 5329CE73; \chrome_dll.5329CE73
	//5300D94B      6A 34         PUSH 34
	//5300D94D | .FF75 D0       PUSH DWORD PTR SS : [LOCAL.12]; Cy = >[LOCAL.12]
	//5300D950 | .FF75 CC       PUSH DWORD PTR SS : [LOCAL.13]; Cx = >[LOCAL.13]
	//5300D953 | .FF75 C8       PUSH DWORD PTR SS : [LOCAL.14]; Y = >[LOCAL.14]
	//5300D956 | .FF75 C4       PUSH DWORD PTR SS : [LOCAL.15]; X = >[LOCAL.15]
	//5300D959      6A 00         PUSH 0
	//5300D95B | .FF33          PUSH DWORD PTR DS : [EBX]; hWnd
	//5300D95D | .FF15 E4AA2554 CALL DWORD PTR DS : [<&user32.SetWindowPos

	addr = 0;
	r = search_ptn(ptn4, _countof(ptn4), &addr, hProcess, hModule);

	if (r == 0 || r > 1)
		return false;
	else
	{
		BYTE Patch[] = { 0x03 };
		int PatchSize = _countof(Patch);
		addr += 0x0D;
		patch_ptn(hProcess, dwProcessId, addr, Patch, PatchSize);
	}
	return true;
}

bool Patch()
{
	return MemoryPatch(GetCurrentProcess(), GetCurrentProcessId(), LoadLibrary(L"chrome.dll"));
}

bool UnPatch()
{
	for (const auto &x : patchInfo)
		patch_ptn(x.hProcess, x.dwProcessId, x.addr, x.data, x.patchSize);
	return true;
}