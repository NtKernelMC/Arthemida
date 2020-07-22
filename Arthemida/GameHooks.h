#pragma once
#include <Windows.h>
#include "CVector.h"
#include "..\MinHook\include\MinHook.h"
// Used for AimBot/TriggerBot
#define FUNC_ProcessLineOfSight 0x56BA00
#define FUNC_IsLineOfSightClear 0x56A490
// Used for Teleport/CoordMaster
#define FUNC_FindGroundZFor3DCoord 0x5696C0
#define FUNC_FindGroundZForCoord 0x569660
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
    typedef bool (__thiscall* ptrProcessLineOfSight)(const CVector* vecStart, const CVector* vecEnd, CColPoint** colCollision, 
    CEntity** CollisionEntity, const SLineOfSightFlags flags, SLineOfSightBuildingResult* pBuildingResult);
    static ptrProcessLineOfSight callProcessLineOfSight;
    static bool ProcessLineOfSight(const CVector* vecStart, const CVector* vecEnd, CColPoint** colCollision, CEntity** CollisionEntity,
    const SLineOfSightFlags flags, SLineOfSightBuildingResult* pBuildingResult);
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
};