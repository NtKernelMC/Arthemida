#include "Arthemida.h"

// —каннер модулей из PEB (обычно загруженные, не смапленные модули) на наличие известных нелегальных паттернов
void __stdcall ART_LIB::ArtemisLibrary::SigScanner(ArtemisConfig* cfg)
{
	if (cfg == nullptr) return;
	if (cfg->callback == nullptr) return;
	if (cfg->IllegalPatterns.empty()) return;

	// ÷икл сканнера
	while (true) 
	{
		// ѕостроение карты загруженных в процесс модулей
		std::map<LPVOID, DWORD> ModuleMap = Utils::BuildModuledMemoryMap();
		// KeyValuePair содержит в себе название чита и кортеж с паттерном и маской, что указываетс€ в конфиге
		for (const auto& KeyValuePair : cfg->IllegalPatterns)
		{
			for (const auto& it : ModuleMap)
			{
				// ѕропуск kernel32.dll, основной системный модуль, возникают проблемы с правами доступа/выходом за пределы адресного пространства
				if (it.first == GetModuleHandleA("kernel32.dll")) continue;
				DWORD scanAddr = SigScan::FindPatternExplicit((DWORD)it.first, it.second,
				std::get<0>(KeyValuePair.second), std::get<1>(KeyValuePair.second));
				if (scanAddr != NULL && !Utils::IsVecContain(cfg->DetectedSigAddresses, it.first))
				{
					CHAR szFilePath[MAX_PATH + 1]; 
					GetModuleFileNameA((HMODULE)it.first, szFilePath, MAX_PATH + 1);
					std::string NameOfDLL = Utils::GetDllName(szFilePath);
					MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data;
					VirtualQueryEx(GetCurrentProcess(), it.first, &mme, it.second); // ѕолучение подробной информации о регионе пам€ти модул€
					data.baseAddr = it.first; // «апись базового адреса модул€ в data
					data.MemoryRights = mme.AllocationProtect; // «апись прав доступа региона в data
					data.regionSize = mme.RegionSize; // «апись размера региона в data
					data.dllName = NameOfDLL; // «апись имени дллки 
					data.dllPath = szFilePath; // «апись пути к дллке
					data.HackName = KeyValuePair.first; // »м€ спаленного чита
					data.type = DetectionType::ART_SIGNATURE_DETECT; // ¬ыставление типа детекта 
					cfg->callback(&data); cfg->DetectedSigAddresses.push_back(it.first);
				}
			}
		}
		Sleep(cfg->PatternScanDelay);
	}
}