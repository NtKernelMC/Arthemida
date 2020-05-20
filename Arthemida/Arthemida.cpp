/*
    Artemis Library for MTA Province
	Target Platform: Win x86-64
	Module by holmes0

	<TASK> TODO:
	Первый этап >>>
	+ Обнаружения сторонних потоков в процессе
	+ Защита против загрузки прокси-dllок
	+ Защита от инжекта через глобальные хуки SetWindowsHookEx
	Второй этап >>>
	+ Отсутствие защиты против DLL инжекта посредством запуска с фейк-лаунчера.
	+ Отсутствие проверки адресов возвратов с важных игровых функций
	+ APC монитор против QueueUserAPC инъекций
	Третий этап >>>
	- Отсутствие сканнера для обнаружения смапленных DLL посредством manual-mapping`a
	- Отсутствие сканнера хуков в памяти и защиты её целостности
	- Навешивание виртуализации протектора на юзермодный модуль античита (VM Protect 3.4.0)
*/
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#pragma warning(disable : 4244)

#include "Arthemida.h"

typedef struct
{
	bool installed;
	ART_LIB::ArtemisLibrary::ArtemisCallback callback;
	std::map<PVOID, const char*> ForbiddenApcList;
} APC_FILTER, *PAPC_FILTER;
APC_FILTER flt;

extern "C" void __stdcall KiApcStub(); // Работает через ASM, вызывает ApcHandler

// Обработчик APC
extern "C" void __stdcall HandleApc(PVOID ApcRoutine, PVOID Argument, PCONTEXT Context)
{
	auto IsRoutineForbidden = [](PVOID Routine) -> bool
	{
		if (SearchForSingleMapMatch<PVOID, const char*>(flt.ForbiddenApcList, Routine)) return true;
		return false;
	};
	if (IsRoutineForbidden(Argument))
	{
		ART_LIB::ArtemisLibrary::ARTEMIS_DATA ApcInfo;
		char ForbiddenName[45]; memset(ForbiddenName, 0, sizeof(ForbiddenName));
		strcpy(ForbiddenName, SearchForSingleMapMatchAndRet(flt.ForbiddenApcList, Argument).c_str());
		ApcInfo.ApcInfo = std::make_tuple(Argument, Context, ForbiddenName);
		ApcInfo.type = ART_LIB::ArtemisLibrary::DetectionType::ART_APC_INJECTION;
		flt.callback(&ApcInfo);
	}
}

#ifdef _WIN64
extern "C" void __stdcall ApcHandler(PCONTEXT Context)
{
	HandleApc(reinterpret_cast<PVOID>(Context->P4Home), reinterpret_cast<PVOID>(Context->P1Home), Context);
}
#else
extern "C" void __stdcall ApcHandler(PVOID ApcRoutine, PVOID Arg, PCONTEXT Context)
{
	HandleApc(ApcRoutine, Arg, Context);
}
#endif

extern "C" void(__stdcall * OriginalApcDispatcher)(PVOID NormalRoutine, PVOID SysArg1, PVOID SysArg2, CONTEXT Context) = nullptr;
using ApcDispatcherPtr = void(__stdcall*)(PVOID NormalRoutine, PVOID SysArg1, PVOID SysArg2, CONTEXT Context);

// Функция для создания APC диспетчера (хук)
bool __stdcall ART_LIB::ArtemisLibrary::InstallApcDispatcher(ArtemisCallback callback)
{
	if (flt.installed || callback == nullptr) return false;
	flt.callback = callback;
	OriginalApcDispatcher = (ApcDispatcherPtr)GetProcAddress(GetModuleHandleA("ntdll.dll"), "KiUserApcDispatcher");
	if (OriginalApcDispatcher == nullptr) return false;
	auto MakeForbiddenList = []() -> std::map<PVOID, const char*>
	{
		std::map<PVOID, const char*> forbidden;
		forbidden.insert(std::pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), "LoadLibraryA"));
		forbidden.insert(std::pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW"), "LoadLibraryW"));
		forbidden.insert(std::pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryExA"), "LoadLibraryExA"));
		forbidden.insert(std::pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryExW"), "LoadLibraryExW"));
		forbidden.insert(std::pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "LoadLibraryA"), "LoadLibraryA"));
		forbidden.insert(std::pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "LoadLibraryW"), "LoadLibraryW"));
		forbidden.insert(std::pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "LoadLibraryExA"), "LoadLibraryExA"));
		forbidden.insert(std::pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "LoadLibraryExW"), "LoadLibraryExW"));
		forbidden.insert(std::pair<PVOID, const char*>((PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll"), "LdrLoadDll"));
		return forbidden;
	}; 
	flt.ForbiddenApcList = MakeForbiddenList();
	MH_CreateHook(OriginalApcDispatcher, KiApcStub, reinterpret_cast<PVOID*>(&OriginalApcDispatcher)); // Создание хука
	MH_EnableHook(MH_ALL_HOOKS);
	flt.installed = true;
	return true;
}

// Функция для удаления APC диспетчера
bool __stdcall ART_LIB::ArtemisLibrary::DeleteApcDispatcher()
{
	if (!flt.installed || OriginalApcDispatcher == nullptr) return false;
	MH_DisableHook(MH_ALL_HOOKS);
	MH_RemoveHook(OriginalApcDispatcher);
	flt.installed = false;
	return true;
}

// Функция для дампа экспортов указанного модуля (hModule) в ExportsList
void ART_LIB::ArtemisLibrary::DumpExportTable(HMODULE hModule, std::multimap<PVOID, std::string>& ExportsList)
{
#if defined( _WIN32 )  
	unsigned char* lpBase = reinterpret_cast<unsigned char*>(hModule);
	IMAGE_DOS_HEADER* idhDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(lpBase);
	if (idhDosHeader->e_magic == 0x5A4D)
	{
#if defined( _M_IX86 )  
		IMAGE_NT_HEADERS32* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS32*>(lpBase + idhDosHeader->e_lfanew);
#elif defined( _M_AMD64 )  
		IMAGE_NT_HEADERS64* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(lpBase + idhDosHeader->e_lfanew);
#endif  
		if (inhNtHeader->Signature == 0x4550)
		{
			IMAGE_EXPORT_DIRECTORY* iedExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(lpBase + inhNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			for (unsigned int uiIter = 0; uiIter < iedExportDirectory->NumberOfFunctions; ++uiIter)
			{
				unsigned short usOrdinal = reinterpret_cast<unsigned short*>(lpBase + iedExportDirectory->AddressOfNameOrdinals)[uiIter];
				char ordNum[25]; memset(ordNum, 0, sizeof(ordNum)); sprintf(ordNum, "Ordinal: %d | 0x%X", usOrdinal, usOrdinal);
				ExportsList.insert(ExportsList.begin(), std::pair<PVOID, std::string>((PVOID)usOrdinal, ordNum));
			}
		}
	}
#endif  
}

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
				if (th32.th32OwnerProcessID == GetCurrentProcessId() && th32.th32ThreadID != GetCurrentThreadId()) // Работаем только с текущим процессом, исключая текущий поток (самого сканнера)
				{
					HANDLE targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID); // Открытие хендла к потоку для доступа
					if (targetThread)
					{
						SuspendThread(targetThread); DWORD_PTR tempBase = 0x0; // Временная заморозка потока для получения информации
						NtQueryInformationThread(targetThread, (THREADINFOCLASS)9, &tempBase, sizeof(DWORD_PTR), NULL); // Получение базового адреса потока
						ResumeThread(targetThread); CloseHandle(targetThread); // Разморозка потока и закрытие хендла к нему
						if (!IsMemoryInModuledRange((LPVOID)tempBase) && !IsVecContain(cfg->ExcludedThreads, (LPVOID)tempBase)) // Проверка на легальность потока (в if заходит в случае нелегального)
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

// Сканнер модулей
void __stdcall ART_LIB::ArtemisLibrary::ModuleScanner(ArtemisConfig* cfg)
{
	if (cfg == nullptr) return;
	if (cfg->callback == nullptr) return;
	if (cfg->ModuleScanner) return;
	cfg->ModuleScanner = true;
	auto LegalModule = [&, cfg](HMODULE mdl) -> bool
	{
		char moduleName[256]; memset(moduleName, 0, sizeof(moduleName));
		cfg->lpGetMappedFileNameA(GetCurrentProcess(), mdl, moduleName, sizeof(moduleName));
		if (CheckCRC32(mdl, cfg->ModuleSnapshot)) return true;
		return false;
	};
	while (true)
	{
		std::map<LPVOID, DWORD> NewModuleMap = BuildModuledMemoryMap(); // Получение списка базовых адресов загруженных модулей и их размера
		for (const auto& it : NewModuleMap)
		{
			if ((it.first != GetModuleHandleA(NULL) && it.first != cfg->hSelfModule) && // Условия: 1. Модуль не является текущим процессом; 2. Модуль не является текущим модулем (в котором используется античит)
			!IsVecContain(cfg->ExcludedModules, it.first)) // 3. Модуль еще не проверен
			{
				CHAR szFileName[MAX_PATH + 1]; std::multimap<PVOID, std::string> ExportsList;
				GetModuleFileNameA((HMODULE)it.first, szFileName, MAX_PATH + 1);
				std::string NameOfDLL = GetDllName(szFileName);
				DumpExportTable(GetModuleHandleA(NameOfDLL.c_str()), ExportsList); // Получение списка экспортов модуля
				if (!LegalModule((HMODULE)it.first) || (std::find(cfg->ModulesWhitelist.begin(), cfg->ModulesWhitelist.end(), NameOfDLL) == cfg->ModulesWhitelist.end() && ExportsList.size() < 2)) // Если модуль нелегальный (детект пока только на дубликаты длл (прокси)) или же у него меньше двух экспортов и он не в белом списке, вход в if
				{
					MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data;
					VirtualQueryEx(GetCurrentProcess(), it.first, &mme, it.second); // Получение подробной информации о регионе памяти модуля
					data.baseAddr = it.first; // Запись базового адреса модуля в data
					data.MemoryRights = mme.AllocationProtect; // Запись прав доступа региона в data
					data.regionSize = mme.RegionSize; // Запись размера региона в data
					data.dllName = NameOfDLL; data.dllPath = szFileName;
					data.type = DetectionType::ART_ILLEGAL_MODULE; // Выставление типа детекта на нелегальный модуль
					cfg->callback(&data); cfg->ExcludedModules.push_back(it.first); // Вызов коллбека и добавление модуля в список уже проверенных
				}
			}
		}
		Sleep(cfg->ModuleScanDelay);
	}
}
bool __stdcall ART_LIB::ArtemisLibrary::InstallGameHooks(ART_LIB::ArtemisLibrary::ArtemisConfig* cfg)
{
	if (cfg == nullptr) return false;
	if (cfg->GameFuncAddrs.empty()) return false;
	for (const auto& it : cfg->GameFuncAddrs)
	{
		if ((DWORD)it.first == 0x0 || (DWORD)it.first >= 0xFFFFFF) continue;
		//MH_CreateHook(OriginalApcDispatcher, it.first, reinterpret_cast<PVOID*>(&OriginalApcDispatcher)); 
		//MH_EnableHook(MH_ALL_HOOKS);
	}
	return true;
}
bool __stdcall ART_LIB::ArtemisLibrary::DeleteGameHooks(ART_LIB::ArtemisLibrary::ArtemisConfig* cfg)
{
	if (cfg == nullptr) return false;
	if (cfg->GameFuncAddrs.empty()) return false;
	for (const auto& it : cfg->GameFuncAddrs)
	{
		if ((DWORD)it.first == 0x0 || (DWORD)it.first >= 0xFFFFFF) continue;
	}
	return true;
}
void __stdcall ART_LIB::ArtemisLibrary::ArtemisDestructor(ART_LIB::ArtemisLibrary::ArtemisConfig* cfg)
{
	if (cfg == nullptr) return;
	DeleteApcDispatcher();
	DeleteGameHooks(cfg);
	MH_Uninitialize();
}
// Инициализация библиотеки
ART_LIB::ArtemisLibrary* __cdecl alInitializeArtemis(ART_LIB::ArtemisLibrary::ArtemisConfig *cfg)
{
	if (cfg == nullptr) return nullptr;
	if (cfg->callback == nullptr) return nullptr;
	if (cfg->DetectReturnAddresses && cfg->GameFuncAddrs.empty()) return nullptr;
	static ART_LIB::ArtemisLibrary art_lib;
	MH_Initialize();
	if (cfg->DetectThreads) // Детект сторонних потоков
	{
		if (!cfg->ThreadScanDelay) cfg->ThreadScanDelay = 1000;
		if (!cfg->ExcludedThreads.empty()) cfg->ExcludedThreads.clear(); // [Не настраивается юзером] Очистка на случай повторной инициализации с тем же cfg
		std::thread AsyncScanner(ART_LIB::ArtemisLibrary::ScanForDllThreads, cfg);
		AsyncScanner.detach(); // Создание и запуск асинхронного потока сканнера ScanForDllThreads
	}
	if (cfg->DetectModules) // Детект сторонних модулей
	{
		if (!cfg->ModuleScanDelay) cfg->ModuleScanDelay = 1000;
		if (!cfg->ExcludedModules.empty()) cfg->ExcludedModules.clear(); // [Не настраивается юзером] Очистка на случай повторной инициализации с тем же cfg
		HMODULE hPsapi = LoadLibraryA("psapi.dll"); // Загрузка нужной системной библиотеки для последующего получения из нее функции
		cfg->lpGetMappedFileNameA = (ART_LIB::ArtemisLibrary::LPFN_GetMappedFileNameA)GetProcAddress(hPsapi, "GetMappedFileNameA"); // Получение функции GetMappedFileNameA из загруженной библиотеки
		std::thread AsyncScanner(ART_LIB::ArtemisLibrary::ModuleScanner, cfg);
		AsyncScanner.detach(); // Создание и запуск асинхронного потока сканнера ModuleScanner
	}
	if (cfg->DetectAPC)
	{
		std::thread AsyncScanner(ART_LIB::ArtemisLibrary::InstallApcDispatcher, cfg->callback);
		AsyncScanner.detach(); // Создание и запуск асинхронного APC диспетчера
	}
	if (cfg->DetectReturnAddresses)
	{
		std::thread CreateGameHooks(ART_LIB::ArtemisLibrary::InstallGameHooks, cfg);
		CreateGameHooks.detach();
	}
	return &art_lib;
}