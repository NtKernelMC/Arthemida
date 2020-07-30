#pragma once
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "Utils.h"
class GameHooks
{
public:
	GameHooks();
    typedef void CWeapon;
    typedef void CVehicle;
    typedef void CColPoint;
    typedef void CEntity;
	typedef void CClientEntity;
	typedef void CLuaFunctionRef;
	typedef void CLuaMain;
	enum class DetectionType
	{
		ART_ILLEGAL_THREAD = 1,
		ART_ILLEGAL_MODULE = 2,
		ART_FAKE_LAUNCHER = 3,
		ART_APC_INJECTION = 4,
		ART_RETURN_ADDRESS = 5,
		ART_MANUAL_MAP = 6,
		ART_MEMORY_CHANGED = 7
	};
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
		bool DetectFakeLaunch = false;
		bool DetectAPC = false;
		bool DetectReturnAddresses = false;
		bool DetectManualMap = false;
		bool DetectMemoryPatch = false;
		std::vector<std::string> ModulesWhitelist;
	};
	static ArtemisConfig* cfg; static HMODULE client_dll; 
	typedef NTSTATUS(__stdcall* ptrLdrLoadDll)(PWCHAR PathToFile, ULONG FlagsL, PUNICODE_STRING ModuleFileName, HMODULE* ModuleHandle);
	static ptrLdrLoadDll callLdrLoadDll;
	typedef NTSTATUS(__stdcall* ptrLdrUnloadDll)(HMODULE ModuleHandle);
	static ptrLdrUnloadDll callLdrUnloadDll;
    static void CheckIfReturnIsLegit(const char* function_name, PVOID return_address);
	typedef bool(__cdecl* ptrAddEventHandler)(CLuaMain* LuaMain, const char* szName, CClientEntity* Entity,
	const CLuaFunctionRef* iLuaFunction, bool bPropagated, DWORD eventPriority, float fPriorityMod);
	static ptrAddEventHandler callAddEventHandler;
	typedef void* (__thiscall* callGetCustomData)(CClientEntity* ECX, const char* szName, bool bInheritData, bool* pbIsSynced);
	static callGetCustomData ptrGetCustomData;
	typedef void(__thiscall* callSetCustomData)(void* ECX, const char* szName, void* Variable, bool bSynchronized);
	static callSetCustomData ptrSetCustomData;
	typedef bool(__cdecl* ptrCheckUTF8BOMAndUpdate)(char** pcpOutBuffer, unsigned int* puiOutSize);
	static ptrCheckUTF8BOMAndUpdate callCheckUTF8BOMAndUpdate;
	typedef bool (__cdecl* ptrTriggerServerEvent)(const char* szName, CClientEntity* CallWithEntity, void* Arguments);
	static ptrTriggerServerEvent callTriggerServerEvent;
	static NTSTATUS __stdcall LdrLoadDll(PWCHAR PathToFile, ULONG FlagsL, PUNICODE_STRING ModuleFileName, HMODULE* ModuleHandle);
	static NTSTATUS __stdcall LdrUnloadDll(HMODULE ModuleHandle);
	static bool __cdecl CheckUTF8BOMAndUpdate(char** pcpOutBuffer, unsigned int* puiOutSize);
	static void* __fastcall GetCustomData(CClientEntity* ECX, void* EDX, const char* szName, bool bInheritData, bool* pbIsSynced);
	static void __fastcall SetCustomData(CClientEntity* ECX, void* EDX, const char* szName, void* Variable, bool bSynchronized = true);
	static bool __cdecl AddEventHandler(CLuaMain* LuaMain, const char* szName, CClientEntity* Entity,
	const CLuaFunctionRef* iLuaFunction, bool bPropagated, DWORD eventPriority, float fPriorityMod);
	static bool __cdecl TriggerServerEvent(const char* szName, CClientEntity* CallWithEntity, void* Arguments);
	static bool __stdcall InstallModuleHooks(ArtemisConfig *cfg);
};