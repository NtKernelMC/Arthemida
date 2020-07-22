#include "GameHooks.h"
GameHooks::ptrProcessLineOfSight GameHooks::callProcessLineOfSight = nullptr;
GameHooks::ptrIsLineOfSightClear GameHooks::callIsLineOfSightClear = nullptr;
GameHooks::GameHooks(){}
GameHooks::~GameHooks(){}
bool __fastcall GameHooks::ProcessLineOfSight(void* ECX, const CVector* vecStart, const CVector* vecEnd, CColPoint** colCollision, 
CEntity** CollisionEntity, const SLineOfSightFlags flags, SLineOfSightBuildingResult* pBuildingResult)
{
    bool rslt = callProcessLineOfSight(ECX, vecStart, vecEnd, colCollision, CollisionEntity, flags, pBuildingResult);
    return rslt;
}
bool __fastcall GameHooks::IsLineOfSightClear(void* ECX, const CVector* vecStart, const CVector* vecEnd, const SLineOfSightFlags flags)
{
    bool rslt = callIsLineOfSightClear(ECX, vecStart, vecEnd, flags);
    return rslt;
}