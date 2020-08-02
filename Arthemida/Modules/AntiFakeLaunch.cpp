#include "Arthemida.h"
// Проверка на наличие секретного байта в памяти, который должен выставить лаунчер
void __stdcall ART_LIB::ArtemisLibrary::CheckLauncher(ART_LIB::ArtemisLibrary::ArtemisConfig* cfg)
{
	THREADENTRY32 th32; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (Thread32First(hSnapshot, &th32))
	{
		do
		{
			if (th32.th32OwnerProcessID == GetCurrentProcessId() && th32.th32ThreadID != GetCurrentThreadId())
			{
				typedef NTSTATUS(__stdcall* tNtQueryInformationThread)
					(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
						PVOID ThreadInformation, ULONG ThreadInformationLength,
						PULONG ReturnLength);

				tNtQueryInformationThread NtQueryInformationThread = (tNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");

				HANDLE pThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID);
				if (pThread)
				{
					MEMORY_BASIC_INFORMATION mbi = { 0 }; DWORD_PTR tempBase = 0x0;
					SuspendThread(pThread); CONTEXT context = { 0 };
					NtQueryInformationThread(pThread, (THREADINFOCLASS)9, &tempBase, sizeof(DWORD_PTR), NULL);
					VirtualQuery((void*)tempBase, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
					if (tempBase >= (DWORD_PTR)GetModuleHandleA(NULL) && tempBase <=
						((DWORD_PTR)GetModuleHandleA(NULL) + mbi.RegionSize))
					{
						context.ContextFlags = CONTEXT_ALL;
						GetThreadContext(pThread, &context);

						ARTEMIS_DATA data;
						data.type = DetectionType::ART_FAKE_LAUNCHER;

						bool checkPassed = true;
						if (context.Dr7 != NULL)
						{
							DWORD_PTR ctrlAddr = context.Dr2;
							if (ctrlAddr != NULL)
							{
								BYTE nop[1] = { 0x0 }; memcpy(nop, (void*)ctrlAddr, 0x1);
								if (nop[0] == 0x90)
								{
									VirtualFree((void*)ctrlAddr, 0, MEM_RELEASE);
									context.Dr2 = 0x0; context.Dr7 = 0x0;
									SetThreadContext(pThread, &context);
									ResumeThread(pThread); CloseHandle(pThread);
									break;
								}
								else checkPassed = false;
							}
							else checkPassed = false;
						}
						else checkPassed = false;

						if (!checkPassed) cfg->callback(&data);
					}
					else
					{
						ResumeThread(pThread); CloseHandle(pThread);
					}
				}
			}
		} while (Thread32Next(hSnapshot, &th32));
	}
	if (hSnapshot != NULL) CloseHandle(hSnapshot);
}