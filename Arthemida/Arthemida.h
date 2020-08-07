#pragma once

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#pragma warning(disable : 4244)

#include "Utils.h"
#ifdef _WIN64
#define START_ADDRESS (PVOID)0x00000000010000
#define END_ADDRESS (0x00007FF8F2580000 - 0x00000000010000)
#else
#define START_ADDRESS (PVOID)0x10000
#define END_ADDRESS (0x7FFF0000 - 0x10000)
#endif
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
			ART_MEMORY_CHANGED = 7,
			ART_SIGNATURE_DETECT = 8,
			ART_SIGNATURES_MODIFIED = 9
		};
		struct ARTEMIS_DATA
		{
			PVOID baseAddr;
			SIZE_T regionSize;
			DWORD MemoryRights;
			DetectionType type;
			std::string dllName;
			std::string dllPath;
			std::string HackName;
			std::tuple<PVOID, PCONTEXT, const char*> ApcInfo;
		};
		typedef void(__stdcall* ArtemisCallback)(ARTEMIS_DATA* artemis);
		typedef DWORD(__stdcall* LPFN_GetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPCSTR lpFilename, DWORD nSize);
		struct ArtemisConfig
		{
			HANDLE hSelfModule = nullptr;
			std::multimap<DWORD, std::string> ModuleSnapshot;
			LPFN_GetMappedFileNameA lpGetMappedFileNameA = nullptr;
			ArtemisCallback callback = nullptr;
			std::vector<PVOID> ExcludedThreads;
			std::vector<PVOID> ExcludedMethods;
			bool DetectThreads = false;
			volatile bool ThreadScanner = false;
			volatile bool ModuleScanner = false;
			DWORD ThreadScanDelay = 0x0;
			std::vector<PVOID> ExcludedModules;
			std::vector<PVOID> ExcludedImages;
			bool DetectModules = false;
			DWORD ModuleScanDelay = 0x0;
			DWORD MemoryScanDelay = 0x0;
			DWORD PatternScanDelay = 0x0;
			bool DetectFakeLaunch = false;
			bool DetectAPC = false;
			bool DetectReturnAddresses = false;
			bool DetectManualMap = false;
			bool DetectMemoryPatch = false;
			bool DetectPatterns = false;
			DWORD MemoryGuardDelay;
			std::vector<PVOID> ExcludedPatches;
			std::vector<std::string> ModulesWhitelist;
			std::map<std::string, std::tuple<const char*, const char*>> IllegalPatterns;
			std::vector<PVOID> DetectedSigAddresses;
		};
		static void DumpExportTable(HMODULE hModule, std::multimap<PVOID, std::string>& ExportsList);
		static void __stdcall ScanForDllThreads(ArtemisConfig* cfg);
		static void __stdcall ModuleScanner(ArtemisConfig* cfg);
		static bool __stdcall InstallApcDispatcher(ArtemisConfig* cfg);
		static bool __stdcall DeleteApcDispatcher(void);
		static void __stdcall MemoryScanner(ArtemisConfig* cfg);
		static void __stdcall CheckLauncher(ArtemisConfig* cfg);
		static void __stdcall SigScanner(ArtemisConfig* cfg);
	};
};
extern ART_LIB::ArtemisLibrary::ArtemisConfig* g_cfg;