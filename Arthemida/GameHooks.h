#pragma once
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "Utils.h"
#include "Arthemida.h"
using namespace ART_LIB;
class GameHooks 
{
public:
    typedef void CWeapon;
    typedef void CVehicle;
    typedef void CColPoint;
    typedef void CEntity;
	typedef void CClientEntity;
	typedef void CLuaFunctionRef;
	typedef void CLuaMain;
	static HMODULE client_dll; 
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
	static bool __stdcall InstallModuleHooks(void);
};