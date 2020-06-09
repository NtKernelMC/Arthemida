#pragma once
#include <Windows.h>
// Used for AimBot/TriggerBot
#define FUNC_ProcessLineOfSight 0x56BA00
#define FUNC_IsLineOfSightClear 0x56A490
class GameHooks
{
public:
	GameHooks();
	~GameHooks();
};