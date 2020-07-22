#include "GameHooks.h"
GameHooks::ptrProcessLineOfSight GameHooks::callProcessLineOfSight = nullptr;
GameHooks::ptrIsLineOfSightClear GameHooks::callIsLineOfSightClear = nullptr;
GameHooks::ptrTeleport GameHooks::callTeleport = nullptr;
GameHooks::ptrFindGroundZForPosition GameHooks::callFindGroundZForPosition = nullptr;
GameHooks::ptrFindGroundZFor3DPosition GameHooks::callFindGroundZFor3DPosition = nullptr;
GameHooks::ptrGiveWeapon GameHooks::callGiveWeapon = nullptr;
DWORD GameHooks::MakeJump(DWORD jmp_address, DWORD hookAddr, BYTE* prologue, size_t prologue_size)
{
	DWORD old_prot = 0x0;
	if (prologue == nullptr) return 0x0;
	VirtualProtect((void*)jmp_address, prologue_size, PAGE_EXECUTE_READWRITE, &old_prot);
	memcpy(prologue, (void*)jmp_address, prologue_size);
	BYTE addrToBYTEs[5] = { 0xE9, 0x90, 0x90, 0x90, 0x90 };
	DWORD JMPBYTEs = (hookAddr - jmp_address - 5);
	memcpy(&addrToBYTEs[1], &JMPBYTEs, 4);
	memcpy((void*)jmp_address, addrToBYTEs, 5);
	PVOID Trampoline = VirtualAlloc(0, (5 + (prologue_size - 5)), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	BYTE TrampolineBYTEs[5] = { 0xE9, 0x90, 0x90, 0x90, 0x90 };
	if (prologue_size > 5)
	{
		BYTE nop[] = { 0x90 };
		for (BYTE x = 0; x < (prologue_size - 5); x++) memcpy((void*)(jmp_address + 0x5 + x), nop, 1);
		memcpy(Trampoline, &prologue[3], (prologue_size - 3));
		DWORD Delta = (jmp_address + prologue_size) - (((DWORD)Trampoline + (prologue_size - 3)) + 5);
		memcpy(&TrampolineBYTEs[1], &Delta, 4);
		memcpy((void*)((DWORD)Trampoline + (prologue_size - 3)), TrampolineBYTEs, 5);
	}
	else
	{
		DWORD Delta = (jmp_address + prologue_size) - ((DWORD)Trampoline + 5);
		memcpy(&TrampolineBYTEs[1], &Delta, 4);
		memcpy(Trampoline, TrampolineBYTEs, 5);
	}
	VirtualProtect((void*)jmp_address, prologue_size, old_prot, 0);
	return (DWORD)Trampoline;
}
bool GameHooks::RestorePrologue(DWORD addr, BYTE* prologue, size_t prologue_size)
{
	if (prologue == nullptr) return false;
	DWORD old_prot = 0;
	VirtualProtect((void*)addr, prologue_size, PAGE_EXECUTE_READWRITE, &old_prot);
	memcpy((void*)addr, prologue, prologue_size);
	VirtualProtect((void*)addr, prologue_size, old_prot, &old_prot);
	return true;
}
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