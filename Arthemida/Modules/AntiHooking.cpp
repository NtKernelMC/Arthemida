#include "Arthemida.h"

void __stdcall ART_LIB::ArtemisLibrary::HookScanner(ArtemisConfig* cfg)
{
	return; // В разработке
	if (cfg == nullptr) return;
	if (cfg->callback == nullptr) return;
	
	// Распаковка и сканирование указанных сигнатур
	if (cfg->ProtectedFunctionPatterns.empty()) return;
	for (auto PatternPair : cfg->ProtectedFunctionPatterns)
	{
		
	}

	while (true) 
	{
		

		Sleep(cfg->HookScanDelay);
	}
}