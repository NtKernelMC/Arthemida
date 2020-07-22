#include "GameHooks.h"
GameHooks::ptrProcessLineOfSight GameHooks::callProcessLineOfSight = nullptr;
GameHooks::GameHooks(){}
GameHooks::~GameHooks(){}
bool GameHooks::ProcessLineOfSight(const CVector* vecStart, const CVector* vecEnd, CColPoint** colCollision, CEntity** CollisionEntity,
const SLineOfSightFlags flags, SLineOfSightBuildingResult* pBuildingResult)
{
    bool rslt = callProcessLineOfSight(vecStart, vecEnd, colCollision, CollisionEntity, flags, pBuildingResult);
    return rslt;
}