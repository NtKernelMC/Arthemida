/*
    Artemis Library for MTA Province
	Target Platform: Win x86-64
	Module by holmes0

	<TASK> TODO:
	Первый этап >>>
	+ Сканер для обнаружения анонимных потоков в процессе
	+ Защита против загрузки Proxy-DLL`ок в процесс
	+ Защита от инжекта через глобальные хуки SetWindowsHookEx
	Второй этап >>>
	+ Защита против DLL инжекта посредством запуска с фейк-лаунчера
	+ Сканер памяти для обнаружения смапленных DLL образов
	+ APC монитор против QueueUserAPC инъекций DLL библиотек
	Третий этап >>>
	+ Сделана проверка адресов возвратов с важных игровых функций
	+ Добавлена возможность отключения и перезагрузки античита
	+ Организована безопасная работа с установкой и удалением хуков
	- Cканнер для защиты целостности памяти в местах хуков античита
	- Сигнатурный cканер модулей в PEB на предмет поиска известных читов
*/
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#pragma warning(disable : 4244)

#include "Arthemida.h"

ART_LIB::ArtemisLibrary* __cdecl alInitializeArtemis(ART_LIB::ArtemisLibrary::ArtemisConfig* cfg); // прототипирование
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
		if (Utils::SearchForSingleMapMatch<PVOID, const char*>(flt.ForbiddenApcList, Routine)) return true;
		return false;
	};
	if (IsRoutineForbidden(Argument))
	{
		ART_LIB::ArtemisLibrary::ARTEMIS_DATA ApcInfo;
		char ForbiddenName[45]; memset(ForbiddenName, 0, sizeof(ForbiddenName));
		strcpy(ForbiddenName, Utils::SearchForSingleMapMatchAndRet(flt.ForbiddenApcList, Argument).c_str());
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
// Сканер потоков
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
	while (true) // Цикл Сканера
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
// Сканер модулей
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
		if (Utils::CheckCRC32(mdl, cfg->ModuleSnapshot)) return true;
		return false;
	};
	while (true)
	{
		std::map<LPVOID, DWORD> NewModuleMap = Utils::BuildModuledMemoryMap(); // Получение списка базовых адресов загруженных модулей и их размера
		for (const auto& it : NewModuleMap)
		{
			if ((it.first != GetModuleHandleA(NULL) && it.first != cfg->hSelfModule) && // Условия: 1. Модуль не является текущим процессом; 2. Модуль не является текущим модулем (в котором используется античит)
			!Utils::IsVecContain(cfg->ExcludedModules, it.first)) // 3. Модуль еще не проверен
			{
				CHAR szFileName[MAX_PATH + 1]; std::multimap<PVOID, std::string> ExportsList;
				GetModuleFileNameA((HMODULE)it.first, szFileName, MAX_PATH + 1);
				std::string NameOfDLL = Utils::GetDllName(szFileName);
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
		Sleep(cfg->MemoryScanDelay);
	}
}
// Сканер памяти (анти-ммап)
void __stdcall ART_LIB::ArtemisLibrary::MemoryScanner(ArtemisConfig* cfg)
{
	if (cfg == nullptr) return;
	while (true)
	{
		auto WatchMemoryAllocations = [&, cfg]
		(const void* ptr, size_t length, MEMORY_BASIC_INFORMATION* info, int size)
		{
			if (ptr == nullptr || info == nullptr) return;
			const void* end = (const void*)((const char*)ptr + length);
			DWORD mask = (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ);
			while (ptr < end && VirtualQuery(ptr, &info[0], sizeof(*info)) == sizeof(*info))
			{
				MEMORY_BASIC_INFORMATION* i = &info[0];
				if ((i->State != MEM_FREE && i->State != MEM_RELEASE) && i->Type & (MEM_IMAGE | MEM_PRIVATE) && i->Protect & mask)
				{
					bool complete_sequence = false; DWORD_PTR foundIAT = 0x0;
					if (i->RegionSize > 0x1000 && i->RegionSize != 0x7D000 && i->RegionSize != 0xF000)
					{
						for (DWORD_PTR z = (DWORD_PTR)ptr; z < ((DWORD_PTR)ptr + i->RegionSize); z++)
						{
							for (DWORD x = 0; x < (10 * 6); x += 0x6)
							{
								if ((x + z) < ((DWORD_PTR)ptr + i->RegionSize) && (x + z + 0x1) < ((DWORD_PTR)ptr + i->RegionSize))
								{
									if (*(BYTE*)(z + x) == 0xFF && *(BYTE*)(x + z + 0x1) == 0x25)
									{
										foundIAT = (x + z);
										complete_sequence = true;
									}
									else complete_sequence = false;
								}
								else complete_sequence = false;
							}
							if (complete_sequence)
							{
								if (!Utils::IsMemoryInModuledRange((PVOID)z))
								{
									typedef DWORD(__stdcall* LPFN_GetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPCSTR lpFilename, DWORD nSize);
									LPFN_GetMappedFileNameA g_GetMappedFileNameA = nullptr; HMODULE hPsapi = LoadLibraryA("psapi.dll");
									g_GetMappedFileNameA = (LPFN_GetMappedFileNameA)GetProcAddress(hPsapi, "GetMappedFileNameA");
									char MappedName[256]; memset(MappedName, 0, sizeof(MappedName));
									g_GetMappedFileNameA(GetCurrentProcess(), (PVOID)z, MappedName, sizeof(MappedName));
									if (strlen(MappedName) < 4 && !Utils::IsVecContain(cfg->ExcludedImages, i->BaseAddress))
									{
										ARTEMIS_DATA data; data.baseAddr = (PVOID)foundIAT;
										data.MemoryRights = i->Protect; data.regionSize = i->RegionSize;
										data.dllName = "unknown"; data.dllPath = "unknown";
										data.type = DetectionType::ART_MANUAL_MAP;
										cfg->callback(&data); cfg->ExcludedImages.push_back(i->BaseAddress);
									}
								}
							}
						}
					}
				}
				ptr = (const void*)((const char*)(i->BaseAddress) + i->RegionSize);
			}
		};
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		WatchMemoryAllocations(START_ADDRESS, END_ADDRESS, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		Sleep(cfg->MemoryScanDelay);
	}
}
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
// Метод для инициализации APC обработчика (заполнение связанного списка опасных APC и установка перехватчика)
bool __stdcall ART_LIB::ArtemisLibrary::InstallApcDispatcher(ArtemisConfig* cfg)
{
	if (flt.installed || cfg == nullptr || cfg->callback == nullptr) return false; // защита от повторной установки обработчика и краша пустым указателем
	flt.callback = cfg->callback; // копируем указатель на коллбэк т.к наш обработчик внешний
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
	flt.ForbiddenApcList = MakeForbiddenList(); // Заполняем связанный список запрещенных APC
	if (MH_CreateHook(OriginalApcDispatcher, KiApcStub, reinterpret_cast<PVOID*>(&OriginalApcDispatcher)) == MH_OK) flt.installed = true; 
	else
	{
		flt.installed = false; // Ставим флаг что APC обработчик не был включен из-за ошибки
		return false; // информируем что произошла ошибка в установке перехвата
	}
	return true; // даем знать что APC обработчик был успешно установлен
}
bool __stdcall ART_LIB::ArtemisLibrary::InstallGameHooks(ArtemisConfig* cfg)
{
	if (cfg == nullptr) return false;
	if (MH_Initialize() == MH_OK) // инициализация минхука для возможности установки хуков
	{
		if (cfg->DetectAPC) // если указана опция античита проверять APC инъекции то ставим обработчик
		{
			if (!InstallApcDispatcher(cfg)) return false; // Вызываем установщик APC обрабочтика который ставит хук и производит заполнение APC-списка
		}
		if (cfg->DetectReturnAddresses) // если указана опция античита проверять адреса возвратов то ставим гейм-хуки
		{
			if (MH_CreateHook((void*)FUNC_ProcessLineOfSight, ProcessLineOfSight, reinterpret_cast<PVOID*>(&callProcessLineOfSight)) != MH_OK)
				return false;
			if (MH_CreateHook((void*)FUNC_IsLineOfSightClear, IsLineOfSightClear, reinterpret_cast<PVOID*>(&callIsLineOfSightClear)) != MH_OK)
				return false;
			if (MH_CreateHook((void*)FUNC_GetBonePosition, GetBonePosition, reinterpret_cast<PVOID*>(&callGetBonePosition)) != MH_OK)
				return false;
			if (MH_CreateHook((void*)FUNC_GetTransformedBonePosition, GetTransformedBonePosition, 
				reinterpret_cast<PVOID*>(&callGetTransformedBonePosition)) != MH_OK)
				return false; 
			if (MH_CreateHook((void*)FUNC_Teleport, Teleport, reinterpret_cast<PVOID*>(&callTeleport)) != MH_OK)
				return false;
			if (MH_CreateHook((void*)FUNC_FindGroundZForCoord, FindGroundZForPosition, 
				reinterpret_cast<PVOID*>(&callFindGroundZForPosition)) != MH_OK)
				return false;
			if (MH_CreateHook((void*)FUNC_FindGroundZFor3DCoord, FindGroundZFor3DPosition, 
				reinterpret_cast<PVOID*>(&callFindGroundZFor3DPosition)) != MH_OK)
				return false;
			if (MH_CreateHook((void*)FUNC_GiveWeapon, GiveWeapon, reinterpret_cast<PVOID*>(&callGiveWeapon)) != MH_OK)
				return false;
		}
		MH_EnableHook(MH_ALL_HOOKS); // включаем все наши хуки (используем общий флаг т.к хуков много и указывать их по одному безрассудно)
	}
	else return false; // информируем что произошла ошибка в установке перехвата
	return true; // даем знать что все хуки и обработчики установлены успешно
}
bool __stdcall ART_LIB::ArtemisLibrary::DeleteGameHooks()
{
	if (flt.installed || OriginalApcDispatcher != nullptr) // Снимаем APC обработчик если он был включен
	{
		flt.installed = false; // меняем флаг на "APC обработчик выключен" для возможности повторной установки
	}
	MH_DisableHook(MH_ALL_HOOKS); // снимаем все наши хуки (используем общий флаг т.к хуков много и указывать их по одному безрассудно)
	MH_Uninitialize(); // деинициализация минхука для возможности его повторного использования после перезапуска античита
	return true; // даем знать что все хуки были безопасно сняты и можно приступать к отключению античита
}
bool __stdcall ART_LIB::ArtemisLibrary::DisableArtemis() // Метод отключения античита (жизненно необходим для его перезапуска)
{
	if (DeleteGameHooks())
	{
#ifdef ARTEMIS_DEBUG
		Utils::LogInFile(ARTEMIS_LOG, "Artemis Library unloaded.\n");
#endif
		return true; // заботимся о снятии всех хуков и обработчиков чтобы избежать краша после отключения античита
	}
	return false;
}
ART_LIB::ArtemisLibrary* __cdecl ART_LIB::ArtemisLibrary::ReloadArtemis(ArtemisConfig* cfg) // Метод для удобного перезапуска античита
{
	if (cfg == nullptr) return nullptr; 
	if (DisableArtemis()) // безопасное отключение античита
	{
		ArtemisLibrary* art_lib = alInitializeArtemis(cfg); // запускаем античит повторно
		return art_lib; // возращаем двухуровневый указатель на оригинал содержащий настройки античита
	}
	return nullptr; // возращаем нулевой указатель если не удалось безопасно перезапустить античит
}
// Инициализация библиотеки
ART_LIB::ArtemisLibrary* __cdecl alInitializeArtemis(ART_LIB::ArtemisLibrary::ArtemisConfig *cfg)
{
	if (cfg == nullptr) return nullptr;
	if (cfg->callback == nullptr) return nullptr;
	static ART_LIB::ArtemisLibrary art_lib;
	if (cfg->DetectFakeLaunch) // Детект лаунчера (должен запускаться в первую очередь)
	{
		ART_LIB::ArtemisLibrary::CheckLauncher(cfg);
	}
	if (cfg->DetectThreads) // Детект сторонних потоков
	{
		if (!cfg->ThreadScanDelay) cfg->ThreadScanDelay = 1000;
		if (!cfg->ExcludedThreads.empty()) cfg->ExcludedThreads.clear(); // [Не настраивается юзером] Очистка на случай повторной инициализации с тем же cfg
		std::thread AsyncScanner(ART_LIB::ArtemisLibrary::ScanForDllThreads, cfg);
		AsyncScanner.detach(); // Запуск асинхронного cканера безымянных потоков которые используются читерами для обхода детекта мануал мап сканнера
	}
	if (cfg->DetectModules) // Детект сторонних модулей
	{
		if (!cfg->ModuleScanDelay) cfg->ModuleScanDelay = 1000;
		if (!cfg->ExcludedModules.empty()) cfg->ExcludedModules.clear(); // [Не настраивается юзером] Очистка на случай повторной инициализации с тем же cfg
		HMODULE hPsapi = LoadLibraryA("psapi.dll"); // Загрузка нужной системной библиотеки для последующего получения из нее функции
		cfg->lpGetMappedFileNameA = (ART_LIB::ArtemisLibrary::LPFN_GetMappedFileNameA)GetProcAddress(hPsapi, "GetMappedFileNameA"); // Получение функции GetMappedFileNameA из загруженной библиотеки (Таков необходим для совместимости на Win Vista & XP т.к там эта функция не хранится в экспортах другого модуля)
		std::thread AsyncScanner(ART_LIB::ArtemisLibrary::ModuleScanner, cfg);
		AsyncScanner.detach(); // Создание и запуск асинхронного потока сканера модулей процесса
	}
	if (cfg->DetectAPC || cfg->DetectReturnAddresses) // Менеджер управляющий процессом распределения установки хуков
	{
		std::thread CreateGameHooks(ART_LIB::ArtemisLibrary::InstallGameHooks, cfg);
		CreateGameHooks.detach();
	}
	if (cfg->DetectManualMap) // Детектор мануал маппинга
	{
		if (!cfg->MemoryScanDelay) cfg->MemoryScanDelay = 1000;
		std::thread MmapThread(ART_LIB::ArtemisLibrary::MemoryScanner, cfg);
		MmapThread.detach(); // Запуск асинхронного cканера для поиска смапленных образов DLL-библиотек
	}
	return &art_lib;
}