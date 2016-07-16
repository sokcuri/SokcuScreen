// SokcuScreen.cpp : 응용 프로그램에 대한 진입점을 정의합니다.
//

#include "stdafx.h"
#include "SokcuScreen.h"
#include "resource.h"
#include "tlhelp32.h"
#include <process.h>
#include <Psapi.h>
#include <string>
#include <vector>
#pragma comment(lib, "psapi.lib")
using namespace std;

#define MAX_LOADSTRING 100

// 전역 변수:
HINSTANCE hInst;                                // 현재 인스턴스입니다.
WCHAR szTitle[MAX_LOADSTRING];                  // 제목 표시줄 텍스트입니다.
WCHAR szWindowClass[MAX_LOADSTRING];            // 기본 창 클래스 이름입니다.
BOOL bExit = false;
vector<DWORD> pidList;

// 이 코드 모듈에 들어 있는 함수의 정방향 선언입니다.
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

wstring getLoadPath();
DWORD _EnableNTPrivilege(LPCTSTR szPrivilege, DWORD dwState);
BOOL InjectAllProcess(int nMode, LPCTSTR szDllPath);
BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath);
BOOL EjectDll(DWORD dwPID, LPCTSTR szDllPath);
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: 여기에 코드를 입력합니다.

    // 전역 문자열을 초기화합니다.
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_SOKCUSCREEN, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

	wstring path = getLoadPath() + L"\\SokcuDLL.dll";
	HMODULE hDLL = LoadLibrary(path.c_str());
	if (!hDLL)
	{
		MessageBox(0, L"SokcuDLL.dll 파일이 없습니다.", L"오류", MB_ICONERROR);
		return FALSE;
	}
	FreeLibrary(hDLL);

    // 응용 프로그램 초기화를 수행합니다.
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_SOKCUSCREEN));

    MSG msg;

    // 기본 메시지 루프입니다.
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

	// Unload
	bExit = true;
	path = getLoadPath() + L"\\SokcuDLL.dll";
	InjectAllProcess(1, path.c_str());

    return (int) msg.wParam;
}



//
//  함수: MyRegisterClass()
//
//  목적: 창 클래스를 등록합니다.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_SOKCUSCREEN));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = 0;
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SOKCUSCREEN));

    return RegisterClassExW(&wcex);
}

//
//   함수: InitInstance(HINSTANCE, int)
//
//   목적: 인스턴스 핸들을 저장하고 주 창을 만듭니다.
//
//   설명:
//
//        이 함수를 통해 인스턴스 핸들을 전역 변수에 저장하고
//        주 프로그램 창을 만든 다음 표시합니다.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // 인스턴스 핸들을 전역 변수에 저장합니다.

   int width = 530;
   int height = 222;
   int x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
   int y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX,
      x, y, width, height, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   unsigned int id;
   HANDLE hThread = reinterpret_cast<HANDLE>(_beginthreadex(0, 0,
	   [](LPVOID pData) -> unsigned int {
	   HWND hWnd = (HWND)pData;
	   STARTUPINFO StartupInfo;
	   PROCESS_INFORMATION ProcessInformation;

	   memset(&StartupInfo, 0, sizeof(STARTUPINFO));
	   memset(&ProcessInformation, 0, sizeof(PROCESS_INFORMATION));

	   DWORD dwClrTick = 0;

	   while (!bExit)
	   {
		   HMODULE hMods[1024];
		   DWORD cbNeeded;
		   TCHAR szModName[MAX_PATH];
		   HWND hTarget = NULL;

		   DWORD dwPID = 0;
		   HANDLE hSnapShot = INVALID_HANDLE_VALUE;
		   PROCESSENTRY32 pe;

		   if (dwClrTick && dwClrTick < GetTickCount())
		   {
			   wstring str = L"소쿠릿 스크린";
			   SetWindowText(hWnd, str.c_str());
			   dwClrTick = 0;
		   }

		   // Get the snapshot of the system
		   pe.dwSize = sizeof(PROCESSENTRY32);
		   hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

		   int i = 0;
		   // find process
		   Process32First(hSnapShot, &pe);
		   do
		   {
			   dwPID = pe.th32ProcessID;

			   if (!wcscmp(pe.szExeFile, L"chrome.exe"))
			   {
				   HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pe.th32ProcessID);
				   if (find(pidList.begin(), pidList.end(), pe.th32ProcessID) == pidList.end() && hProcess)
				   {
					   if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
					   {
						   bool bExistDLL = false;
						   for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
						   {
							   if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
							   {
								   _wcslwr_s(szModName, MAX_PATH);
								   if (wcsstr(szModName, L"sokcudll.dll"))
								   {
									   bExistDLL = true;
									   break;
								   }
							   }
						   }

						   if (!bExistDLL)
						   {
							   wstring str = L"소쿠릿 스크린 - 크롬 패치 중 >> " + to_wstring(dwPID);
							   SetWindowText(hWnd, str.c_str());
							   dwClrTick = GetTickCount() + 5000;

							   wstring path = getLoadPath() + L"\\SokcuDLL.dll";

							   // change privilege
							   _EnableNTPrivilege(SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED);

							   //InjectAllProcess(0, path.c_str());
							   InjectDll(dwPID, path.c_str());
							   pidList.push_back(dwPID);
						   }

					   }
					   else
					   {
						   int err = GetLastError();
						   wstring str = L"소쿠릿 스크린 - EnumProcessModules FAIL : " + to_wstring(err);
						   SetWindowText(hWnd, str.c_str());
						   dwClrTick = GetTickCount() + 5000;
					   }
					   CloseHandle(hProcess);
				   }
			   }

		   } while (Process32Next(hSnapShot, &pe));

		   CloseHandle(hSnapShot);

		   Sleep(100);
		   }
	   return 0;
	   }, hWnd, 0, &id));

   return TRUE;
}

//
//  함수: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  목적:  주 창의 메시지를 처리합니다.
//
//  WM_COMMAND  - 응용 프로그램 메뉴를 처리합니다.
//  WM_PAINT    - 주 창을 그립니다.
//  WM_DESTROY  - 종료 메시지를 게시하고 반환합니다.
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
	case WM_CREATE:
	{
		// change privilege
		//_EnableNTPrivilege(SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED);
		
		//wstring path = getLoadPath() + L"\\SokcuDLL.dll";
		//InjectAllProcess(0, path.c_str());
	}
	break;
	case WM_DESTROY:
	{
		PostQuitMessage(0);
	}
	break;
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // 메뉴 선택을 구문 분석합니다.
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
			HDC MemDC = CreateCompatibleDC(hdc);
			HBITMAP bit = LoadBitmap(hInst, MAKEINTRESOURCE(IDB_BITMAP1));
			HBITMAP obit = (HBITMAP)SelectObject(MemDC, bit);
			BitBlt(hdc, 0, 0, 550, 220, MemDC, 30, 30, SRCCOPY);
			SelectObject(MemDC, bit);
			DeleteObject(bit);
			DeleteDC(MemDC);
            // TODO: 여기에 hdc를 사용하는 그리기 코드를 추가합니다.
            EndPaint(hWnd, &ps);
        }
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// 정보 대화 상자의 메시지 처리기입니다.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
wstring getLoadPath()
{
	wchar_t fileName[MAX_PATH];
	GetModuleFileName(0, fileName, MAX_PATH);
	for (int i = wcslen(fileName) - 1; i > 0; i--)
		if (fileName[i] == L'\\')
		{
			fileName[i] = 0;
			break;
		}
	return fileName;
}
DWORD _EnableNTPrivilege(LPCTSTR szPrivilege, DWORD dwState)
{
	DWORD dwRtn = 0;
	HANDLE hToken;
	LUID luid;
	DWORD cbTP;

	if (OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		if (LookupPrivilegeValue(NULL, szPrivilege, &luid))
		{
			BYTE t1[sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)];
			BYTE t2[sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES)];
			cbTP = sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES);

			PTOKEN_PRIVILEGES pTP = (PTOKEN_PRIVILEGES)t1;
			PTOKEN_PRIVILEGES pPrevTP = (PTOKEN_PRIVILEGES)t2;

			pTP->PrivilegeCount = 1;
			pTP->Privileges[0].Luid = luid;
			pTP->Privileges[0].Attributes = dwState;

			if (AdjustTokenPrivileges(hToken, FALSE, pTP,
				cbTP, pPrevTP, &cbTP))
				dwRtn = pPrevTP->Privileges[0].Attributes;
		}

		CloseHandle(hToken);
	}
	return dwRtn;
}

BOOL InjectAllProcess(int nMode, LPCTSTR szDllPath)
{
	DWORD dwPID = 0;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;

	HWND hTarget = NULL;
	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	Process32First(hSnapShot, &pe);
	do
	{
		dwPID = pe.th32ProcessID;

		if (dwPID < 100)
			continue;

		if (!wcscmp(pe.szExeFile, L"chrome.exe"))
		{
			if (nMode == 0) InjectDll(dwPID, szDllPath);
			else if (nMode == 1) EjectDll(dwPID, szDllPath);
		}
	} while (Process32Next(hSnapShot, &pe));

	CloseHandle(hSnapShot);
	return TRUE;
}

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HANDLE                  hProcess, hThread;
	LPVOID                  pRemoteBuf;
	DWORD                   dwBufSize = lstrlen(szDllPath) * 2 + 1;
	LPTHREAD_START_ROUTINE  pThreadProc;

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		wchar_t buff[32] = { 0, };
		swprintf(buff, _countof(buff), L"OpenProcess(%d) failed!!!", dwPID);
		OutputDebugString(buff);
		return FALSE;
	}

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);

	char buff[255];
	DWORD dwReadBytes;
	ReadProcessMemory(hProcess, pRemoteBuf, buff, 255, &dwReadBytes);

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}

BOOL EjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	BOOL                    bMore = FALSE, bFound = FALSE;
	HANDLE                  hSnapshot, hProcess, hThread;
	MODULEENTRY32           me = { sizeof(me) };
	LPTHREAD_START_ROUTINE  pThreadProc;

	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)) == INVALID_HANDLE_VALUE)
		return FALSE;

	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		if (!_wcsicmp(me.szModule, szDllPath) ||
			!_wcsicmp(me.szExePath, szDllPath))
		{
			bFound = TRUE;
			break;
		}
	}

	if (!bFound)
	{
		CloseHandle(hSnapshot);
		return FALSE;
	}

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		CloseHandle(hSnapshot);
		return FALSE;
	}

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary");
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, me.modBaseAddr, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hSnapshot);

	return TRUE;
}
