#include "Arthemida.h"

// Сканнер потоков
void __stdcall ART_LIB::ArtemisLibrary::ScanForDllThreads(ArtemisConfig* cfg)
{
	if (cfg == nullptr) return;
	if (cfg->callback == nullptr) return;
	if (cfg->ThreadScanner) return;
	cfg->ThreadScanner = true;
	typedef NTSTATUS(__stdcall* tNtQueryInformationThread)
		(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
	tNtQueryInformationThread NtQueryInformationThread =
		(tNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"); // Получение функции из ntdll
	while (true) // Цикл сканнера
	{
		THREADENTRY32 th32; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (Thread32First(hSnapshot, &th32))
		{
			do
			{
				if (th32.th32OwnerProcessID == GetCurrentProcessId() && th32.th32ThreadID != GetCurrentThreadId()) // Работаем только с текущим процессом, исключая текущий поток (самого Сканера)
				{
					HANDLE targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID); // Открытие хендла к потоку для доступа
					if (targetThread)
					{
						SuspendThread(targetThread); DWORD_PTR tempBase = 0x0; // Временная заморозка потока для получения информации
						NtQueryInformationThread(targetThread, (THREADINFOCLASS)9, &tempBase, sizeof(DWORD_PTR), NULL); // Получение базового адреса потока
						ResumeThread(targetThread); CloseHandle(targetThread); // Разморозка потока и закрытие хендла к нему
						if (!Utils::IsMemoryInModuledRange((LPVOID)tempBase) && !Utils::IsVecContain(cfg->ExcludedThreads, (LPVOID)tempBase)) // Проверка на легальность потока (в if заходит в случае нелегального)
						{
							MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data;
							VirtualQueryEx(GetCurrentProcess(), (LPCVOID)tempBase, &mme, sizeof(th32.dwSize)); // Получение подробной информации по региону памяти потока
							data.baseAddr = (LPVOID)tempBase; // Запись базового адреса в data
							data.MemoryRights = mme.AllocationProtect; // Запись прав доступа к региону в data
							data.regionSize = mme.RegionSize; // Запись размера региона в data
							data.type = DetectionType::ART_ILLEGAL_THREAD; // Выставление типа детекта
							data.dllName = "unknown"; data.dllPath = "unknown"; // Название модуля неизвестно, ибо мы сканируем потоки, у смапленных модулей нет названий, а поток можно и вовсе создать без модуля
							cfg->callback(&data); cfg->ExcludedThreads.push_back((LPVOID)tempBase); // Вызов коллбека и добавление базового адреса потока в список уже просканированных
							break;
						}
					}
				}
			} while (Thread32Next(hSnapshot, &th32));
			if (hSnapshot != NULL) CloseHandle(hSnapshot);
		}
		Sleep(cfg->ThreadScanDelay);
	}
}