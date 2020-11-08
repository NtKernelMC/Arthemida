/*
    Artemis Library for MTA Province
	Target Platform: Win x86-64
	Module by NtKernelMC & holmes0

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
	+ Cканнер для защиты целостности памяти в местах хуков античита
	+ Сигнатурный cканер модулей в PEB на предмет поиска известных читов
*/

#include "GameHooks.h"
#include "Arthemida.h"
bool WasReloaded = false;
ART_LIB::ArtemisLibrary* __cdecl alInitializeArtemis(ART_LIB::ArtemisLibrary::ArtemisConfig* cfg);
ART_LIB::ArtemisLibrary::ArtemisConfig* g_cfg = nullptr;

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

// Метод отключения античита (жизненно необходим для его перезапуска)
bool __cdecl DisableArtemis()
{
	if (GameHooks::DeleteGameHooks()) // Снимает и игровые хуки и APC диспетчер!
	{
#ifdef ARTEMIS_DEBUG
		if (!WasReloaded) Utils::LogInFile(ARTEMIS_LOG, "Artemis Library unloaded.\n");
		else Utils::LogInFile(ARTEMIS_LOG, "Reloading Artemis Library...\n");
#endif
		return true;
	}
	return false;
}

// Метод для удобного перезапуска античита
ART_LIB::ArtemisLibrary* __cdecl ReloadArtemis(ART_LIB::ArtemisLibrary::ArtemisConfig* cfg)
{
	if (cfg == nullptr) return nullptr; 
	WasReloaded = true;
	if (DisableArtemis())
	{
		ART_LIB::ArtemisLibrary* art_lib = alInitializeArtemis(cfg);
		return art_lib; // Возращаем указатель на оригинал содержащий настройки античита
	}
	return nullptr; // Возращаем нулевой указатель если не удалось безопасно перезапустить античит
}

// Инициализация библиотеки
ART_LIB::ArtemisLibrary* __cdecl alInitializeArtemis(ART_LIB::ArtemisLibrary::ArtemisConfig *cfg)
{
#ifdef ARTEMIS_DEBUG
	if (!WasReloaded) DeleteFileA(ARTEMIS_LOG);
	else WasReloaded = false;
	Utils::LogInFile(ARTEMIS_LOG, "Artemis Library loaded!\n");
#endif

	if (cfg == nullptr) return nullptr;
	if (cfg->callback == nullptr) return nullptr;

	static ART_LIB::ArtemisLibrary art_lib;
	g_cfg = cfg; // Копируем указатель конфига артемиды для связи с внешними хуками

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

	if (cfg->DetectReturnAddresses) // Детект нелегальных адресов возврата
	{
		GameHooks::InstallModuleHook(); // Установка NtDll хуки на загрузку и выгрузку client.dll для установки игровых хуков
	}

	if (cfg->DetectAPC) // Детект APC инъекций
	{
		if (!ART_LIB::ArtemisLibrary::InstallApcDispatcher(cfg)) return nullptr; // Установка APC обрабочтика который ставит хук и производит заполнение APC-списка
	}

	if (cfg->DetectManualMap) // Детект мануал маппинга
	{
		if (!cfg->MemoryScanDelay) cfg->MemoryScanDelay = 1000;
		std::thread MmapThread(ART_LIB::ArtemisLibrary::MemoryScanner, cfg);
		MmapThread.detach(); // Запуск асинхронного cканнера для поиска смапленных образов DLL-библиотек
	}

	if (cfg->DetectPatterns)
	{
		if (!cfg->PatternScanDelay) cfg->PatternScanDelay = 1000;
		std::thread HookThread(ART_LIB::ArtemisLibrary::SigScanner, cfg);
		HookThread.detach();
	}

	return &art_lib;
}
