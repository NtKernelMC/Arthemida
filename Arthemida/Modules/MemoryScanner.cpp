#include "Arthemida.h"

// Сканнер памяти
void __stdcall ART_LIB::ArtemisLibrary::MemoryScanner(ArtemisConfig* cfg)
{
	if (cfg == nullptr) return;
	if (cfg->callback == nullptr) return;
	while (true)
	{
		auto WatchMemoryAllocations = [&, cfg]
		(const void* ptr, size_t length, MEMORY_BASIC_INFORMATION* info, int size)
		{
			if (ptr == nullptr || info == nullptr) return;
			const void* end = (const void*)((const char*)ptr + length);
			DWORD mask = (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ);
			while (ptr < end && VirtualQuery(ptr, &info[0], sizeof(*info)) == sizeof(*info))
			{
				MEMORY_BASIC_INFORMATION* i = &info[0];
				if ((i->State != MEM_FREE && i->State != MEM_RELEASE) && i->Type & (MEM_IMAGE | MEM_PRIVATE) && i->Protect & mask)
				{
					bool complete_sequence = false; DWORD_PTR foundIAT = 0x0;
					if (i->RegionSize > 0x1000 && i->RegionSize != 0x7D000 && i->RegionSize != 0xF000)
					{
						for (DWORD_PTR z = (DWORD_PTR)ptr; z < ((DWORD_PTR)ptr + i->RegionSize); z++)
						{
							for (DWORD x = 0; x < (10 * 6); x += 0x6)
							{
								if ((x + z) < ((DWORD_PTR)ptr + i->RegionSize) && (x + z + 0x1) < ((DWORD_PTR)ptr + i->RegionSize))
								{
									if (*(BYTE*)(z + x) == 0xFF && *(BYTE*)(x + z + 0x1) == 0x25)
									{
										foundIAT = (x + z);
										complete_sequence = true;
									}
									else complete_sequence = false;
								}
								else complete_sequence = false;
							}
							if (complete_sequence)
							{
								if (!Utils::IsMemoryInModuledRange((PVOID)z))
								{
									typedef DWORD(__stdcall* LPFN_GetMappedFileNameA)(HANDLE hProcess, LPVOID lpv, LPCSTR lpFilename, DWORD nSize);
									LPFN_GetMappedFileNameA g_GetMappedFileNameA = nullptr; HMODULE hPsapi = LoadLibraryA("psapi.dll");
									g_GetMappedFileNameA = (LPFN_GetMappedFileNameA)GetProcAddress(hPsapi, "GetMappedFileNameA");
									char MappedName[256]; memset(MappedName, 0, sizeof(MappedName));
									g_GetMappedFileNameA(GetCurrentProcess(), (PVOID)z, MappedName, sizeof(MappedName));
									if (strlen(MappedName) < 4 && !Utils::IsVecContain(cfg->ExcludedImages, i->BaseAddress))
									{
										ARTEMIS_DATA data; data.baseAddr = (PVOID)foundIAT;
										data.MemoryRights = i->Protect; data.regionSize = i->RegionSize;
										data.dllName = "unknown"; data.dllPath = "unknown";
										data.type = DetectionType::ART_MANUAL_MAP;
										cfg->callback(&data); cfg->ExcludedImages.push_back(i->BaseAddress);
									}
								}
							}
						}
					}
				}
				ptr = (const void*)((const char*)(i->BaseAddress) + i->RegionSize);
			}
		};
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		WatchMemoryAllocations(START_ADDRESS, END_ADDRESS, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		Sleep(cfg->MemoryScanDelay);
	}
}