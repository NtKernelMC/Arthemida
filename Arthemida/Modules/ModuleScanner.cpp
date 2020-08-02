#include "Arthemida.h"

// Сканер модулей
void __stdcall ART_LIB::ArtemisLibrary::ModuleScanner(ArtemisConfig* cfg)
{
	if (cfg == nullptr) return;
	if (cfg->callback == nullptr) return;
	if (cfg->ModuleScanner) return;
	cfg->ModuleScanner = true;
	auto LegalModule = [&, cfg](HMODULE mdl) -> bool
	{
		char moduleName[256]; memset(moduleName, 0, sizeof(moduleName));
		cfg->lpGetMappedFileNameA(GetCurrentProcess(), mdl, moduleName, sizeof(moduleName));
		if (Utils::CheckCRC32(mdl, cfg->ModuleSnapshot)) return true;
		return false;
	};
	while (true)
	{
		std::map<LPVOID, DWORD> NewModuleMap = Utils::BuildModuledMemoryMap(); // Получение списка базовых адресов загруженных модулей и их размера
		for (const auto& it : NewModuleMap)
		{
			if ((it.first != GetModuleHandleA(NULL) && it.first != cfg->hSelfModule) && // Условия: 1. Модуль не является текущим процессом; 2. Модуль не является текущим модулем (в котором используется античит)
				!Utils::IsVecContain(cfg->ExcludedModules, it.first)) // 3. Модуль еще не проверен
			{
				CHAR szFileName[MAX_PATH + 1]; std::multimap<PVOID, std::string> ExportsList;
				GetModuleFileNameA((HMODULE)it.first, szFileName, MAX_PATH + 1);
				std::string NameOfDLL = Utils::GetDllName(szFileName);
				DumpExportTable(GetModuleHandleA(NameOfDLL.c_str()), ExportsList); // Получение списка экспортов модуля
				if (!LegalModule((HMODULE)it.first) || (std::find(cfg->ModulesWhitelist.begin(), cfg->ModulesWhitelist.end(), NameOfDLL) == cfg->ModulesWhitelist.end() && ExportsList.size() < 2)) // Если модуль нелегальный (детект пока только на дубликаты длл (прокси)) или же у него меньше двух экспортов и он не в белом списке, вход в if
				{
					MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data;
					VirtualQueryEx(GetCurrentProcess(), it.first, &mme, it.second); // Получение подробной информации о регионе памяти модуля
					data.baseAddr = it.first; // Запись базового адреса модуля в data
					data.MemoryRights = mme.AllocationProtect; // Запись прав доступа региона в data
					data.regionSize = mme.RegionSize; // Запись размера региона в data
					data.dllName = NameOfDLL; data.dllPath = szFileName;
					data.type = DetectionType::ART_ILLEGAL_MODULE; // Выставление типа детекта на нелегальный модуль
					cfg->callback(&data); cfg->ExcludedModules.push_back(it.first); // Вызов коллбека и добавление модуля в список уже проверенных
				}
			}
		}
		Sleep(cfg->MemoryScanDelay);
	}
}