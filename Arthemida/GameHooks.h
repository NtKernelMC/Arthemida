#pragma once
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "Utils.h"
// Used for AimBot/TriggerBot/WallHack
#define FUNC_ProcessLineOfSight 0x56BA00
#define FUNC_IsLineOfSightClear 0x56A490
#define FUNC_GetBonePosition 0x5E4280
#define FUNC_GetTransformedBonePosition 0x5E01C0
// Used for Teleport/CoordMaster
#define FUNC_Teleport 0x4F5690
#define FUNC_WarpPedIntoCar 0x4EF8B0
#define FUNC_FindGroundZFor3DCoord 0x5696C0
#define FUNC_FindGroundZForCoord 0x569660
// Used for Weapon Hacks
#define FUNC_GiveWeapon 0x5E6080
#define FUNC_SetCurrentWeapon 0x5E61F0
#define FUNC_GetWeaponSlot 0x5DF200
#define FUNC_SetCurrentWeaponFromID 0x4FF8E0
#define FUNC_SetCurrentWeaponFromSlot 0x4FF900
class GameHooks
{
public:
	GameHooks();
	~GameHooks();
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
    typedef CVector* (__thiscall* ptrGetBonePosition)(void* ECX, Utils::eBone bone, CVector* vecPosition);
    static ptrGetBonePosition callGetBonePosition;
    static CVector* __fastcall GetBonePosition(void* ECX, void* EDX, Utils::eBone bone, CVector* vecPosition);
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    typedef CVector* (__thiscall* ptrGetTransformedBonePosition)(void* ECX, Utils::eBone bone, CVector* vecPosition);
    static ptrGetTransformedBonePosition callGetTransformedBonePosition;
    static CVector* __fastcall GetTransformedBonePosition(void* ECX, void* EDX, Utils::eBone bone, CVector* vecPosition);
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    typedef void (__thiscall* ptrTeleport)(void* ECX, CVector* vecPoint);
    static ptrTeleport callTeleport;
    static void __fastcall Teleport(void *ECX, void *EDX, CVector* vecPoint);
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

};