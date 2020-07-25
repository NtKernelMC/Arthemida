#pragma once
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "Utils.h"
// Used for AimBot/TriggerBot/WallHack
#define FUNC_GiveWeapon 0x5E608E // custom hooks
#define FUNC_ProcessLineOfSight 0x56BA17 // custom hooks
#define FUNC_IsLineOfSightClear 0x56A4A7 // custom hooks
#define FUNC_GetBonePosition 0x5E4295 // custom hooks
#define FUNC_GetTransformedBonePosition 0x5E01D5 // custom hooks
// Used for Teleport/CoordMaster
#define FUNC_FindGroundZForCoord 0x56968F // custom hooks
#define FUNC_FindGroundZFor3DCoord 0x5696F7 // custom hooks 
static BYTE prologue[5]; static BYTE prologue_t[5];
static BYTE prologue_p[5]; static BYTE prologue_pp[5];
static BYTE prologue_g[5]; static DWORD trampoline_g = 0x0;
static BYTE prologue_c[5]; static DWORD trampoline_c = 0x0;
static BYTE prologue_c3[5]; static DWORD trampoline_c3 = 0x0;
static DWORD trampoline = 0x0; static DWORD trampoline_t = 0x0;
static DWORD trampoline_p = 0x0; static DWORD trampoline_pp = 0x0;
class GameHooks
{
public:
	GameHooks();
    typedef void CWeapon;
    typedef void CVehicle;
    typedef void CColPoint;
    typedef void CEntity;
    typedef void SLineOfSightBuildingResult;
    struct SLineOfSightFlags
    {
        SLineOfSightFlags()
            : bCheckBuildings(true),
            bCheckVehicles(true),
            bCheckPeds(true),
            bCheckObjects(true),
            bCheckDummies(true),
            bSeeThroughStuff(false),
            bIgnoreSomeObjectsForCamera(false),
            bShootThroughStuff(false),
            bCheckCarTires(false)
        {
        }
        bool bCheckBuildings;
        bool bCheckVehicles;
        bool bCheckPeds;
        bool bCheckObjects;
        bool bCheckDummies;
        bool bSeeThroughStuff;
        bool bIgnoreSomeObjectsForCamera;
        bool bShootThroughStuff;
        bool bCheckCarTires;
    };
    static DWORD MakeJump(DWORD jmp_address, DWORD hookAddr, BYTE* prologue, size_t prologue_size);
    static bool RestorePrologue(DWORD addr, BYTE* prologue, size_t prologue_size);
    static void CheckIfReturnIsLegit(const char* function_name, PVOID return_address);
};
static __declspec(naked) void __stdcall FindGroundZForPosition()
{
    __asm pusha
    __asm pushfd
    __asm pushad
    GameHooks::CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    __asm popad
    __asm popfd
    __asm popa
    __asm jmp trampoline_c
}
static __declspec(naked) void __stdcall FindGroundZFor3DPosition()
{
    __asm pusha
    __asm pushfd
    __asm pushad
    GameHooks::CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    __asm popad
    __asm popfd
    __asm popa
    __asm jmp trampoline_c3
}
static __declspec(naked) void __stdcall GiveWeapon()
{
    __asm pusha
    __asm pushfd
    __asm pushad
    GameHooks::CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    __asm popad
    __asm popfd
    __asm popa
    __asm jmp trampoline_g
}
static __declspec(naked) void __stdcall ProcessLineOfSight()
{
    __asm pusha
    __asm pushfd
    __asm pushad
    GameHooks::CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    __asm popad
    __asm popfd
    __asm popa
    __asm jmp trampoline_p
}
static __declspec(naked) void __stdcall IsLineOfSightClear()
{
    __asm pusha
    __asm pushfd
    __asm pushad
    GameHooks::CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    __asm popad
    __asm popfd
    __asm popa
    __asm jmp trampoline_pp
}
static __declspec(naked) void __stdcall GetBonePosition()
{
    __asm pusha
    __asm pushfd
    __asm pushad
    GameHooks::CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    __asm popad
    __asm popfd
    __asm popa
    __asm jmp trampoline
}
static __declspec(naked) void __stdcall GetTransformedBonePosition()
{
    __asm pusha
    __asm pushfd
    __asm pushad
    GameHooks::CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    __asm popad
    __asm popfd
    __asm popa
    __asm jmp trampoline_t
}