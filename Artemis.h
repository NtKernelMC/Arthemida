#pragma once
/*
	Artemis Library for MTA Province
	Target Platform: Win x86-64
	Module by holmes0
*/
#include <Windows.h>
#include <stdio.h>
#include <thread>
#include <string>
#include <vector>
#include <map>
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
			ART_SIGNATURE_DETECT = 8
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
			std::string HackName;
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
			std::vector<PVOID> ExcludedImages;
			bool DetectModules = false;
			DWORD ModuleScanDelay = 0x0;
			DWORD MemoryScanDelay = 0x0;
			DWORD HookScanDelay = 0x0;
			bool DetectFakeLaunch = false;
			bool DetectAPC = false;
			bool DetectReturnAddresses = false;
			bool DetectManualMap = false;
			bool DetectMemoryPatch = false;
			bool DetectHooks = false;
			std::vector<std::string> ModulesWhitelist;
			std::map<std::string, std::tuple<std::string, std::string>> ProtectedFunctionPatterns;
			std::vector<PVOID> ExcludedPatterns;
		};
	};
};
ART_LIB::ArtemisLibrary* __cdecl alInitializeArtemis(ART_LIB::ArtemisLibrary::ArtemisConfig* cfg);
ART_LIB::ArtemisLibrary* __cdecl ReloadArtemis(ART_LIB::ArtemisLibrary::ArtemisConfig* cfg);
bool __cdecl DisableArtemis();