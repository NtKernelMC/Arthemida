#include "GameHooks.h"
GameHooks::ptrProcessLineOfSight GameHooks::callProcessLineOfSight = nullptr;
GameHooks::ptrIsLineOfSightClear GameHooks::callIsLineOfSightClear = nullptr;
GameHooks::ptrGetBonePosition GameHooks::callGetBonePosition = nullptr;
GameHooks::ptrGetTransformedBonePosition GameHooks::callGetTransformedBonePosition = nullptr;
GameHooks::ptrTeleport GameHooks::callTeleport = nullptr;
GameHooks::ptrFindGroundZForPosition GameHooks::callFindGroundZForPosition = nullptr;
GameHooks::ptrFindGroundZFor3DPosition GameHooks::callFindGroundZFor3DPosition = nullptr;
GameHooks::ptrGiveWeapon GameHooks::callGiveWeapon = nullptr;
GameHooks::GameHooks()
{
#ifdef ARTEMIS_DEBUG
    DeleteFileA(ARTEMIS_LOG);
    Utils::LogInFile(ARTEMIS_LOG, "Artemis Library loaded!\n");
#endif
}
void GameHooks::CheckIfReturnIsLegit(const char* function_name, PVOID return_address)
{
#ifdef ARTEMIS_DEBUG
    Utils::LogInFile(ARTEMIS_LOG, "Returned from %s function to 0x%X\n", function_name, return_address);
#endif
}
bool __fastcall GameHooks::ProcessLineOfSight(void* ECX, void* EDX, const CVector* vecStart, const CVector* vecEnd, CColPoint** colCollision, 
CEntity** CollisionEntity, const SLineOfSightFlags flags, SLineOfSightBuildingResult* pBuildingResult)
{
    CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    bool rslt = callProcessLineOfSight(ECX, vecStart, vecEnd, colCollision, CollisionEntity, flags, pBuildingResult);
    return rslt;
}
bool __fastcall GameHooks::IsLineOfSightClear(void* ECX, void* EDX, const CVector* vecStart, const CVector* vecEnd, const SLineOfSightFlags flags)
{
    CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    bool rslt = callIsLineOfSightClear(ECX, vecStart, vecEnd, flags);
    return rslt;
}
CVector* __fastcall GameHooks::GetBonePosition(void* ECX, void* EDX, Utils::eBone bone, CVector* vecPosition)
{
    CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    CVector* rslt = callGetBonePosition(ECX, bone, vecPosition);
    return rslt;
}
CVector* __fastcall GameHooks::GetTransformedBonePosition(void* ECX, void* EDX, Utils::eBone bone, CVector* vecPosition)
{
    CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    CVector* rslt = callGetTransformedBonePosition(ECX, bone, vecPosition);
    return rslt;
}
void __fastcall GameHooks::Teleport(void* ECX, void* EDX, CVector* vecPoint)
{
    CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    callTeleport(ECX, vecPoint);
}
float __fastcall GameHooks::FindGroundZForPosition(void* ECX, void* EDX, float fX, float fY)
{
    CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    float rslt = callFindGroundZForPosition(ECX, fX, fY);
    return rslt;
}
float __fastcall GameHooks::FindGroundZFor3DPosition(void* ECX, void* EDX, CVector* vecPosition)
{
    CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    float rslt = callFindGroundZFor3DPosition(ECX, vecPosition);
    return rslt;
}
GameHooks::CWeapon* __fastcall GameHooks::GiveWeapon(void* ECX, void* EDX, Utils::eWeaponType weaponType, unsigned int uiAmmo, Utils::eWeaponSkill skill)
{
    CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    CWeapon* rslt = callGiveWeapon(ECX, weaponType, uiAmmo, skill);
    return rslt;
}