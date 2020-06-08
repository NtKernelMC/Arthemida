#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <string>
#include <Psapi.h>
#include <TlHelp32.h>
#include "SafeLaunch.h"

int __cdecl main()
{
	SafeLaunch::ProcessGate procGate(CreateProcessW);
	STARTUPINFO info = { sizeof(info) };
	PROCESS_INFORMATION processInfo;
	if (procGate.SafeProcess<const wchar_t*, LPSTARTUPINFOW>
		(L"C:\\Users\\dutchman101\\source\\repos\\NtKernelMC\\Athemida\\Build\\Win32\\Tester\\Tester.exe", L"", NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo))
	{
		printf("Process created. Press any key to exit launcher.\n");
	}
	else printf("Error: %d\nPress any key to exit launcher.", GetLastError());
	_getch();
	return EXIT_SUCCESS;
}