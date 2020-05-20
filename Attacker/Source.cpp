#include <Windows.h>
#include <conio.h>
#include <stdio.h>
#include <TlHelp32.h>
#pragma warning(disable : 4477)

// Поиск хендла процесса по имени
HANDLE OpenProcessByName(const char* szName) {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (_stricmp(entry.szExeFile, szName) == 0)
            {
                return OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
            }
        }
    }
    CloseHandle(snapshot);
}

int FindDelta(DWORD DestinationAddress, DWORD SourceAddress, size_t InstructionLength) {
    return DestinationAddress - (SourceAddress + InstructionLength);
}

// Создание удаленного потока в целевом процессе (Tester.exe) который зацикливается на себе (спинлок)
DWORD __stdcall CreateSpinlockThread(HANDLE processHandle) {
    if (processHandle != NULL) {
        // Выделение нужной памяти в процессе
        LPVOID pThread = VirtualAllocEx(processHandle, 0, 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        // Шеллкод спинлока (jmp на себя)
        BYTE spinlock[] = { 0xE9, 0x90, 0x90, 0x90, 0x90 };
        // Дельта выделенной памяти (релокация адресов)
        int Delta = FindDelta((DWORD)pThread, (DWORD)pThread, 5);
        // Запись в шеллкод базового адреса выделенной памяти (то что после инструкции jmp (0xE9))
        memcpy(&spinlock[1], &Delta, 4);
        // Запись шеллкода в память целевого процесса
        WriteProcessMemory(processHandle, pThread, spinlock, 5, NULL);
        // Создание удаленного потока шеллкода в целевом процессе
        CreateRemoteThread(processHandle, NULL, NULL, (LPTHREAD_START_ROUTINE)pThread, NULL, NULL, NULL);
        return (DWORD)pThread;
    }
}

void GetInput() {
    char ans = _getch();
    if (ans == '1') {
        // Получение хендла процесса по имени
        HANDLE hProc = OpenProcessByName("Tester.exe");
        if (!hProc) { printf("Error opening handle to Tester.exe."); return; }
        // Создание удаленного потока с спинлоком
        DWORD dwThread = CreateSpinlockThread(hProc);
        printf("Thread base: 0x%08X\n", dwThread);
        CloseHandle(hProc);

        printf("Attack finished.\nPress any key to exit attacker.\n");
        _getch();
        return;
    }
    else if (ans == '2') {
        // Получение хендла окна по имени
        HWND hwnd = FindWindowA(NULL, "TESTER");
        DWORD pid = 0x0;
        // Получение ид потока который создал окно
        DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
        // Загрузка чит длл
        HMODULE cheatDll = LoadLibraryExA("cheat.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!cheatDll) { printf("Error loading cheat.dll. Press any key to exit attacker.\n"); _getch();  return; }
        // Получение адреса экспортированной функции NextHook
        HOOKPROC NextHookAddr = (HOOKPROC)GetProcAddress(cheatDll, "NextHook");
        // Выставление хука на GetMessage (часть обработчика окна)
        HHOOK hookHandle = SetWindowsHookExA(WH_GETMESSAGE, NextHookAddr, cheatDll, tid);
        // Вызов хука путем отправки сообщения целевому потоку
        PostThreadMessageA(tid, WM_NULL, NULL, NULL);

        printf("Attack finished.\nPress any key to exit attacker.\n");
        _getch();
        UnhookWindowsHookEx(hookHandle);
        return;
    }
    else if (ans == '3') {
        DWORD ProcID = GetProcessId(OpenProcessByName("Tester.exe"));
        
        auto ParseThreadsAndInjectAPC = [&, ProcID]() -> DWORD
        {
            THREADENTRY32 th32; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
            hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (Thread32First(hSnapshot, &th32))
            {
                do
                {
                    if (th32.th32OwnerProcessID != ProcID) continue;
                    {
                        HANDLE pThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID);
                        if (pThread)
                        {
                            SuspendThread(pThread); // Заморозка потока
                            QueueUserAPC((PAPCFUNC)LoadLibraryA, pThread, 0x0); // Добавление LoadLibraryA(0) в APC очередь потока, для теста не обязательно указывать дллку
                            ResumeThread(pThread); // Разморозка потока
                        }
                    }
                } while (Thread32Next(hSnapshot, &th32));
            }
            if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
            return 0;
        }; 
        
        if(ProcID) ParseThreadsAndInjectAPC();

        printf("Attack finished.\nPress any key to exit attacker.\n");
        _getch();
        return;
    }
    else {
        GetInput();
    }
}

int main()
{
    system("color 4F");
    printf("Please, choose attack type: \n[1] - Remote thread code injection\n[2] - SetWindowsHookEx injection\n[3] - QueueUserAPC injection\n\n");
    GetInput();
	return 1;
}