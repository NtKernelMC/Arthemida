#pragma once
#define ARTEMIS_DEBUG
#define ARTEMIS_LOG "!0_ArtemisDebug.log"
#include <Windows.h>
#include <stdio.h>
#include <thread>
#include <vector>
#include <string>
#include <map>
#include <tuple>
#include <winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <conio.h>
#include <algorithm>
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)
#include "CVector.h"
#include "..\MinHook\include\MinHook.h"
#include "CRC32.h"
class Utils
{
public:
	static void LogInFile(const char* log_name, const char* log, ...)
	{
		FILE* hFile = fopen(log_name, "a+");
		if (hFile)
		{
			va_list arglist; va_start(arglist, log);
			vfprintf(hFile, log, arglist);
			fclose(hFile); va_end(arglist);
		}
	}
	// Выстраивает и возвращает список базовых адресов загруженных в процесс модулей и их размера
	static std::map<LPVOID, DWORD> __stdcall BuildModuledMemoryMap()
	{
		std::map<LPVOID, DWORD> memoryMap; HMODULE hMods[1024]; DWORD cbNeeded;
		typedef BOOL(__stdcall* PtrEnumProcessModules)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);
		PtrEnumProcessModules EnumProcModules = (PtrEnumProcessModules)
			GetProcAddress(LoadLibraryA("psapi.dll"), "EnumProcessModules");
		EnumProcModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded);
		typedef BOOL(__stdcall* GetMdlInfoP)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
		GetMdlInfoP GetMdlInfo = (GetMdlInfoP)GetProcAddress(LoadLibraryA("psapi.dll"), "GetModuleInformation");
		for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			MODULEINFO modinfo; GetMdlInfo(GetCurrentProcess(), hMods[i], &modinfo, sizeof(modinfo));
			memoryMap.insert(memoryMap.begin(), std::pair<LPVOID, DWORD>(modinfo.lpBaseOfDll, modinfo.SizeOfImage));
		}
		return memoryMap;
	}
	// 
	static bool __stdcall IsMemoryInModuledRange(LPVOID base)
	{
		std::map<LPVOID, DWORD> memory = BuildModuledMemoryMap();
		for (const auto& it : memory)
		{
			if (base >= it.first && base <= (LPVOID)((DWORD_PTR)it.first + it.second)) return true;
		}
		return false;
	}
	// Генерация CRC32 хеша файла
	static DWORD GenerateCRC32(const std::string filePath)
	{
		if (filePath.empty()) return 0x0;
		auto getFileSize = [](FILE* file) -> long
		{
			long lCurPos, lEndPos;
			lCurPos = ftell(file);
			fseek(file, 0, 2);
			lEndPos = ftell(file);
			fseek(file, lCurPos, 0);
			return lEndPos;
		};
		FILE* hFile = fopen(filePath.c_str(), "rb");
		if (hFile == nullptr) return 0x0;
		BYTE* fileBuf; long fileSize;
		fileSize = getFileSize(hFile);
		fileBuf = new BYTE[fileSize];
		fread(fileBuf, fileSize, 1, hFile);
		fclose(hFile); DWORD crc = CRC::Calculate(fileBuf, fileSize, CRC::CRC_32());
		delete[] fileBuf; return crc;
	}
	template<typename First, typename Second>
	static bool SearchForSingleMapMatch(const std::map<First, Second>& map, const First key)
	{
		for (auto it : map)
		{
			if (it.first == key) return true;
		}
		return false;
	}
	template <typename T>
	static const bool Contains(std::vector<T>& Vec, const T& Element)
	{
		if (std::find(Vec.begin(), Vec.end(), Element) != Vec.end()) return true;
		return false;
	}
	static std::string SearchForSingleMapMatchAndRet(const std::map<PVOID, const char*>& map, const PVOID key)
	{
		for (auto it : map)
		{
			if (it.first == key) return it.second;
		}
		return "EMPTY";
	}
	// Поиск субстринга без case-sensevity
	static bool findStringIC(const std::string& strHaystack, const std::string& strNeedle)
	{
		auto it = std::search(strHaystack.begin(), strHaystack.end(),
			strNeedle.begin(), strNeedle.end(),
			[](char ch1, char ch2) { return std::toupper(ch1) == std::toupper(ch2); });
		return (it != strHaystack.end());
	}
	// 
	static bool SearchForSingleMultiMapMatch2(const std::multimap<DWORD, std::string>& map, DWORD first, std::string second, bool firstOrSecond)
	{
		for (auto it : map)
		{
			if (findStringIC(it.second, second) && firstOrSecond) return true;
			if (it.first == first && !firstOrSecond) return true;
		}
		return false;
	}
	//
	static char* strdel(char* s, size_t offset, size_t count)
	{
		size_t len = strlen(s);
		if (offset > len) return s;
		if ((offset + count) > len) count = len - offset;
		strcpy(s + offset, s + offset + count);
		return s;
	}
	static std::string GetDllName(char* szDllNameTmp)
	{
		char szDllName[300]; memset(szDllName, 0, sizeof(szDllName));
		strcpy(szDllName, szDllNameTmp);
		char fname[256]; char* ipt = strrchr(szDllName, '\\');
		memset(fname, 0, sizeof(fname));
		strdel(szDllName, 0, (ipt - szDllName + 1));
		strncpy(fname, szDllName, strlen(szDllName));
		std::string ProcName(fname);
		return ProcName;
	}
	static bool IsVecContain(const std::vector<PVOID>& source, PVOID element)
	{
		for (const auto it : source)
		{
			if (it == element) return true;
		}
		return false;
	}
	static bool CheckCRC32(HMODULE mdl, std::multimap<DWORD, std::string>& ModuleSnapshot)
	{
		if (mdl == nullptr) return false;
		CHAR szFileName[MAX_PATH + 1]; GetModuleFileNameA(mdl, szFileName, MAX_PATH + 1);
		DWORD CRC32 = GenerateCRC32(szFileName); std::string DllName = GetDllName(szFileName);
		if (SearchForSingleMultiMapMatch2(ModuleSnapshot, 0x0, DllName, true) &&
			SearchForSingleMultiMapMatch2(ModuleSnapshot, CRC32, "", false))
		{
			std::multimap<std::string, DWORD> tmpModuleSnapshot;
			for (const auto& it : ModuleSnapshot)
			{
				tmpModuleSnapshot.insert(tmpModuleSnapshot.begin(), std::pair<std::string, DWORD>(it.second, it.first));
			}
			if (tmpModuleSnapshot.count(DllName) == 0x1) return true;
		}
		else
		{
			ModuleSnapshot.insert(ModuleSnapshot.begin(), std::pair<DWORD, std::string>(CRC32, DllName));
			return true;
		}
		return false;
	}
	enum class eBone {
		BONE_PELVIS1 = 1,
		BONE_PELVIS,
		BONE_SPINE1,
		BONE_UPPERTORSO,
		BONE_NECK,
		BONE_HEAD2,
		BONE_HEAD1,
		BONE_HEAD,
		BONE_RIGHTUPPERTORSO = 21,
		BONE_RIGHTSHOULDER,
		BONE_RIGHTELBOW,
		BONE_RIGHTWRIST,
		BONE_RIGHTHAND,
		BONE_RIGHTTHUMB,
		BONE_LEFTUPPERTORSO = 31,
		BONE_LEFTSHOULDER,
		BONE_LEFTELBOW,
		BONE_LEFTWRIST,
		BONE_LEFTHAND,
		BONE_LEFTTHUMB,
		BONE_LEFTHIP = 41,
		BONE_LEFTKNEE,
		BONE_LEFTANKLE,
		BONE_LEFTFOOT,
		BONE_RIGHTHIP = 51,
		BONE_RIGHTKNEE,
		BONE_RIGHTANKLE,
		BONE_RIGHTFOOT
	};
	enum class eWeaponType
	{
		WEAPONTYPE_UNARMED = 0,
		WEAPONTYPE_BRASSKNUCKLE,
		WEAPONTYPE_GOLFCLUB,
		WEAPONTYPE_NIGHTSTICK,
		WEAPONTYPE_KNIFE,
		WEAPONTYPE_BASEBALLBAT,
		WEAPONTYPE_SHOVEL,
		WEAPONTYPE_POOL_CUE,
		WEAPONTYPE_KATANA,
		WEAPONTYPE_CHAINSAW,
		WEAPONTYPE_DILDO1,
		WEAPONTYPE_DILDO2,
		WEAPONTYPE_VIBE1,
		WEAPONTYPE_VIBE2,
		WEAPONTYPE_FLOWERS,
		WEAPONTYPE_CANE,
		WEAPONTYPE_GRENADE,
		WEAPONTYPE_TEARGAS,
		WEAPONTYPE_MOLOTOV,
		WEAPONTYPE_ROCKET,
		WEAPONTYPE_ROCKET_HS,
		WEAPONTYPE_FREEFALL_BOMB,
		WEAPONTYPE_PISTOL,
		WEAPONTYPE_PISTOL_SILENCED,
		WEAPONTYPE_DESERT_EAGLE,
		WEAPONTYPE_SHOTGUN,
		WEAPONTYPE_SAWNOFF_SHOTGUN,
		WEAPONTYPE_SPAS12_SHOTGUN,
		WEAPONTYPE_MICRO_UZI,
		WEAPONTYPE_MP5,
		WEAPONTYPE_AK47,
		WEAPONTYPE_M4,
		WEAPONTYPE_TEC9,
		WEAPONTYPE_COUNTRYRIFLE,
		WEAPONTYPE_SNIPERRIFLE,
		WEAPONTYPE_ROCKETLAUNCHER,
		WEAPONTYPE_ROCKETLAUNCHER_HS,
		WEAPONTYPE_FLAMETHROWER,
		WEAPONTYPE_MINIGUN,
		WEAPONTYPE_REMOTE_SATCHEL_CHARGE,
		WEAPONTYPE_DETONATOR,
		WEAPONTYPE_SPRAYCAN,
		WEAPONTYPE_EXTINGUISHER,
		WEAPONTYPE_CAMERA,
		WEAPONTYPE_NIGHTVISION,
		WEAPONTYPE_INFRARED,
		WEAPONTYPE_PARACHUTE,
		WEAPONTYPE_LAST_WEAPONTYPE,
		WEAPONTYPE_ARMOUR,
		WEAPONTYPE_RAMMEDBYCAR,
		WEAPONTYPE_RUNOVERBYCAR,
		WEAPONTYPE_EXPLOSION,
		WEAPONTYPE_UZI_DRIVEBY,
		WEAPONTYPE_DROWNING,
		WEAPONTYPE_FALL,
		WEAPONTYPE_UNIDENTIFIED,
		WEAPONTYPE_ANYMELEE,
		WEAPONTYPE_ANYWEAPON,
		WEAPONTYPE_FLARE,
		WEAPONTYPE_TANK_GRENADE,
		WEAPONTYPE_INVALID = 255,
	};
	enum class eWeaponSkill
	{
		WEAPONSKILL_POOR = 0,
		WEAPONSKILL_STD,
		WEAPONSKILL_PRO,
		WEAPONSKILL_SPECIAL,    
		WEAPONSKILL_MAX_NUMBER
	};
	enum class eWeaponSlot
	{
		WEAPONSLOT_TYPE_UNARMED = 0,
		WEAPONSLOT_TYPE_MELEE,
		WEAPONSLOT_TYPE_HANDGUN,
		WEAPONSLOT_TYPE_SHOTGUN,
		WEAPONSLOT_TYPE_SMG,        //4
		WEAPONSLOT_TYPE_MG,
		WEAPONSLOT_TYPE_RIFLE,
		WEAPONSLOT_TYPE_HEAVY,
		WEAPONSLOT_TYPE_THROWN,
		WEAPONSLOT_TYPE_SPECIAL,    //9
		WEAPONSLOT_TYPE_GIFT,       //10
		WEAPONSLOT_TYPE_PARACHUTE,  //11
		WEAPONSLOT_TYPE_DETONATOR,  //12

		WEAPONSLOT_MAX
	};

	enum class eWeaponState
	{
		WEAPONSTATE_READY,
		WEAPONSTATE_FIRING,
		WEAPONSTATE_RELOADING,
		WEAPONSTATE_OUT_OF_AMMO,
		WEAPONSTATE_MELEE_MADECONTACT
	};
};