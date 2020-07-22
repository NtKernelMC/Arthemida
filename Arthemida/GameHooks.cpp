#include "GameHooks.h"
GameHooks::ptrProcessLineOfSight GameHooks::callProcessLineOfSight = nullptr;
GameHooks::ptrIsLineOfSightClear GameHooks::callIsLineOfSightClear = nullptr;
GameHooks::ptrGetBonePosition GameHooks::callGetBonePosition = nullptr;
GameHooks::ptrGetTransformedBonePosition GameHooks::callGetTransformedBonePosition = nullptr;
GameHooks::ptrTeleport GameHooks::callTeleport = nullptr;
GameHooks::ptrFindGroundZForPosition GameHooks::callFindGroundZForPosition = nullptr;
GameHooks::ptrFindGroundZFor3DPosition GameHooks::callFindGroundZFor3DPosition = nullptr;
GameHooks::ptrGiveWeapon GameHooks::callGiveWeapon = nullptr;
BYTE GameHooks::prologue[7];
BYTE GameHooks::prologue_t[7];
DWORD GameHooks::trampoline = 0x0;
DWORD GameHooks::trampoline_t = 0x0;
GameHooks::GameHooks()
{
#ifdef ARTEMIS_DEBUG
    DeleteFileA(ARTEMIS_LOG);
    Utils::LogInFile(ARTEMIS_LOG, "Artemis Library loaded!\n");
#endif
}
void GameHooks::CheckIfReturnIsLegit(const char* function_name, PVOID return_address)
{
    string moduleName = Utils::GetNameOfModuledAddressSpace(return_address, Utils::GenerateModuleNamesList());
#ifdef ARTEMIS_DEBUG
    Utils::LogInFile(ARTEMIS_LOG, "Returned from %s function to 0x%X in to module %s\n", function_name, return_address, moduleName.c_str());
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
void __stdcall GameHooks::GetBonePosition(Utils::eBone bone, CVector* vecPosition)
{
    CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    __asm jmp trampoline
}
void __stdcall GameHooks::GetTransformedBonePosition(Utils::eBone bone, CVector* vecPosition)
{
    CheckIfReturnIsLegit(__FUNCTION__, _ReturnAddress());
    __asm jmp trampoline_t
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