#include "Arthemida.h"

void __stdcall ART_LIB::ArtemisLibrary::HookScanner(ArtemisConfig* cfg)
{
	if (cfg == nullptr) return;
	if (cfg->callback == nullptr) return;
	
	if (!cfg->ProtectedFunctionPatterns.empty())
	{
		std::map<LPVOID, DWORD> NewModuleMap = Utils::BuildModuledMemoryMap();
		for (const auto& PatternPair : cfg->ProtectedFunctionPatterns)
		{
			for (const auto& it : NewModuleMap)
			{
				CHAR szFileName[MAX_PATH + 1]; GetModuleFileNameA((HMODULE)it.first, szFileName, MAX_PATH + 1);
				std::string NameOfDLL = Utils::GetDllName(szFileName);
				DWORD scanAddr = SigScan::FindPattern(NameOfDLL.c_str(), 
				std::get<0>(PatternPair.second).c_str(), std::get<1>(PatternPair.second).c_str());
				if (scanAddr != NULL && !Utils::IsVecContain(cfg->ExcludedPatterns, it.first))
				{
					MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data;
					VirtualQueryEx(GetCurrentProcess(), it.first, &mme, it.second); // Получение подробной информации о регионе памяти модуля
					data.baseAddr = it.first; // Запись базового адреса модуля в data
					data.MemoryRights = mme.AllocationProtect; // Запись прав доступа региона в data
					data.regionSize = mme.RegionSize; // Запись размера региона в data
					data.dllName = NameOfDLL; data.dllPath = szFileName;
					data.HackName = PatternPair.first; // Имя спаленного чита
					data.type = DetectionType::ART_SIGNATURE_DETECT; // Выставление типа детекта 
					cfg->callback(&data); cfg->ExcludedPatterns.push_back(it.first);
				}
			}
		}
	}

	while (true) 
	{
		

		Sleep(cfg->HookScanDelay);
	}
}