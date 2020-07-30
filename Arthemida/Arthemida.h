#pragma once
#include "GameHooks.h"
#ifdef _WIN64
#define START_ADDRESS (PVOID)0x00000000010000
#define END_ADDRESS (0x00007FF8F2580000 - 0x00000000010000)
#else
#define START_ADDRESS (PVOID)0x10000
#define END_ADDRESS (0x7FFF0000 - 0x10000)
#endif
namespace ART_LIB
{
	class ArtemisLibrary : public GameHooks 
	{
	public:
		ArtemisLibrary() : GameHooks() { }
		static void DumpExportTable(HMODULE hModule, std::multimap<PVOID, std::string>& ExportsList);
		static void __stdcall ScanForDllThreads(ArtemisConfig* cfg);
		static void __stdcall ModuleScanner(ArtemisConfig* cfg);
		static bool __stdcall InstallApcDispatcher(ArtemisConfig* cfg);
		static void __stdcall MemoryScanner(ArtemisConfig* cfg);
		static bool __stdcall InstallGameHooks(ArtemisConfig* cfg);
		static bool __stdcall DeleteGameHooks(void);
		static bool __stdcall DisableArtemis(void);
		static ArtemisLibrary* __cdecl ReloadArtemis(ArtemisConfig* cfg);
		static void __stdcall CheckLauncher(ArtemisConfig* cfg);
	};
};