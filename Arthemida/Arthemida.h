#pragma once
#include <Windows.h>
#include <stdio.h>
#include <thread>
#include <vector>
#include <string>
#include <map>
#include <tuple>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <algorithm>
#include "Utils.h"
#include "..\MinHook\include\MinHook.h"

namespace ART_LIB
{
	class ArtemisLibrary
	{
	public:
		enum class DetectionType
		{
			ART_ILLEGAL_THREAD = 1,
			ART_ILLEGAL_MODULE = 2,
			ART_FAKE_LAUNCHER = 3,
			ART_APC_INJECTION = 4,
			ART_RETURN_ADDRESS = 5,
			ART_MANUAL_MAP = 6,
			ART_INLINE_HOOK = 7,
			ART_MEMORY_CHANGED = 8
		};
		typedef DWORD(__stdcall* LPFN_GetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPCSTR lpFilename, DWORD nSize);
		struct ARTEMIS_DATA
		{
			PVOID baseAddr;
			SIZE_T regionSize;
			DWORD MemoryRights;
			DetectionType type;
			std::string dllName;
			std::string dllPath;
			std::tuple<PVOID, PCONTEXT, const char*> ApcInfo;
		};
		typedef void(__stdcall* ArtemisCallback)(ARTEMIS_DATA* artemis);
		struct ArtemisConfig
		{
			HANDLE hSelfModule = nullptr;
			std::multimap<DWORD, std::string> ModuleSnapshot;
			LPFN_GetMappedFileNameA lpGetMappedFileNameA = nullptr;
			ArtemisCallback callback = nullptr;
			std::vector<PVOID> ExcludedThreads;
			bool DetectThreads = false;
			volatile bool ThreadScanner = false;
			volatile bool ModuleScanner = false;
			DWORD ThreadScanDelay = 0x0;
			std::vector<PVOID> ExcludedModules;
			bool DetectModules = false;
			DWORD ModuleScanDelay = 0x0;
			bool DetectFakeLaunch = false;
			bool DetectAPC = false;
			bool DetectReturnAddresses = false;
			bool DetectManualMap = false;
			bool DetectInlineHooks = false;
			bool DetectMemoryPatch = false;
			// Белый список модулей, у которых пропускается проверка экспортов, на случай если экспортов нет (иначе будет ложно-положительный детект). Конкретно на провинции сейчас только один такой модуль - yacl.asi, его нужно сюда добавить.
			std::vector<std::string> ModulesWhitelist;
		};
		static void DumpExportTable(HMODULE hModule, std::multimap<PVOID, std::string>& ExportsList);
		static void __stdcall ScanForDllThreads(ArtemisConfig* cfg);
		static void __stdcall ModuleScanner(ArtemisConfig* cfg);
		static bool __stdcall InstallApcDispatcher(ArtemisCallback callback);
		static bool __stdcall DeleteApcDispatcher();
		static bool __stdcall InstallGameHooks(void);
		static bool __stdcall DeleteGameHooks(void);
		static void __stdcall ArtemisDestructor(void);
		static void __stdcall CheckLauncher(ArtemisConfig* cfg);
	};
};