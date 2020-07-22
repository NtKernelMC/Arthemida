#pragma once
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "Utils.h"
// Used for AimBot/TriggerBot/WallHack
#define FUNC_GiveWeapon 0x5E6080 // наш хук
#define FUNC_ProcessLineOfSight 0x56BA00 // multiplayer_sa.dll 
#define FUNC_IsLineOfSightClear 0x56A490 // multiplayer_sa.dll 
#define FUNC_GetBonePosition 0x5E4295 // custom hooks
#define FUNC_GetTransformedBonePosition 0x5E01D5 // custom hooks
// Used for Teleport/CoordMaster
#define FUNC_Teleport 0x4F5690 // наш хук
#define FUNC_FindGroundZForCoord 0x569660 // наш хук
#define FUNC_FindGroundZFor3DCoord 0x5696C0 // нет хука (закоменчен)
static BYTE prologue[5]; static BYTE prologue_t[5];
static DWORD trampoline = 0x0; static DWORD trampoline_t = 0x0;
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
    typedef bool (__thiscall* ptrProcessLineOfSight)(void *ECX, const CVector* vecStart, const CVector* vecEnd, CColPoint** colCollision, 
    CEntity** CollisionEntity, const SLineOfSightFlags flags, SLineOfSightBuildingResult* pBuildingResult);
    static ptrProcessLineOfSight callProcessLineOfSight;
    static bool __fastcall ProcessLineOfSight(void* ECX, void* EDX, const CVector* vecStart, const CVector* vecEnd, 
    CColPoint** colCollision, CEntity** CollisionEntity, const SLineOfSightFlags flags, SLineOfSightBuildingResult* pBuildingResult);
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    typedef bool (__thiscall* ptrIsLineOfSightClear)(void* ECX, const CVector* vecStart, const CVector* vecEnd, const SLineOfSightFlags flags);
    static ptrIsLineOfSightClear callIsLineOfSightClear;
    static bool __fastcall IsLineOfSightClear(void* ECX, void *EDX, const CVector* vecStart, const CVector* vecEnd, const SLineOfSightFlags flags);
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    typedef void (__thiscall* ptrTeleport)(void* ECX, CVector* vecPoint);
    static ptrTeleport callTeleport;
    static void __fastcall Teleport(void *ECX, void *EDX, CVector* vecPoint);
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    typedef float (__thiscall* ptrFindGroundZForPosition)(void* ECX, float fX, float fY);
    static ptrFindGroundZForPosition callFindGroundZForPosition;
    static float __fastcall FindGroundZForPosition(void* ECX, void* EDX, float fX, float fY);
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    typedef float (__thiscall* ptrFindGroundZFor3DPosition)(void* ECX, CVector* vecPosition);
    static ptrFindGroundZFor3DPosition callFindGroundZFor3DPosition;
    static float __fastcall FindGroundZFor3DPosition(void* ECX, void* EDX, CVector* vecPosition);
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    typedef CWeapon* (__thiscall* ptrGiveWeapon)(void* ECX, Utils::eWeaponType weaponType, unsigned int uiAmmo, Utils::eWeaponSkill skill);
    static ptrGiveWeapon callGiveWeapon;
    static CWeapon* __fastcall GiveWeapon(void* ECX, void* EDX, Utils::eWeaponType weaponType, unsigned int uiAmmo, Utils::eWeaponSkill skill);
};
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