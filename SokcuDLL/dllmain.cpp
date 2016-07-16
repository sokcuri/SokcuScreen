// dllmain.cpp: DLL ���� ���α׷��� �������� �����մϴ�.
#include "stdafx.h"

bool Patch();
bool UnPatch();

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		Patch();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		UnPatch();
		break;
	}
	return TRUE;
}

