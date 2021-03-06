#include "Arthemida.h"

// ������� �������
void __stdcall ART_LIB::ArtemisLibrary::ScanForDllThreads(ArtemisConfig* cfg)
{
	if (cfg == nullptr) return;
	if (cfg->callback == nullptr) return;
	if (cfg->ThreadScanner) return;
	cfg->ThreadScanner = true;
	typedef NTSTATUS(__stdcall* tNtQueryInformationThread)
		(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
	tNtQueryInformationThread NtQueryInformationThread =
		(tNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"); // ��������� ������� �� ntdll
	while (true) // ���� ��������
	{
		THREADENTRY32 th32; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (Thread32First(hSnapshot, &th32))
		{
			do
			{
				if (th32.th32OwnerProcessID == GetCurrentProcessId() && th32.th32ThreadID != GetCurrentThreadId()) // �������� ������ � ������� ���������, �������� ������� ����� (������ �������)
				{
					HANDLE targetThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID); // �������� ������ � ������ ��� �������
					if (targetThread)
					{
						SuspendThread(targetThread); DWORD_PTR tempBase = 0x0; // ��������� ��������� ������ ��� ��������� ����������
						NtQueryInformationThread(targetThread, (THREADINFOCLASS)9, &tempBase, sizeof(DWORD_PTR), NULL); // ��������� �������� ������ ������
						ResumeThread(targetThread); CloseHandle(targetThread); // ���������� ������ � �������� ������ � ����
						if (!Utils::IsMemoryInModuledRange((LPVOID)tempBase) && !Utils::IsVecContain(cfg->ExcludedThreads, (LPVOID)tempBase)) // �������� �� ����������� ������ (� if ������� � ������ ������������)
						{
							MEMORY_BASIC_INFORMATION mme{ 0 }; ARTEMIS_DATA data;
							VirtualQueryEx(GetCurrentProcess(), (LPCVOID)tempBase, &mme, sizeof(th32.dwSize)); // ��������� ��������� ���������� �� ������� ������ ������
							data.baseAddr = (LPVOID)tempBase; // ������ �������� ������ � data
							data.MemoryRights = mme.AllocationProtect; // ������ ���� ������� � ������� � data
							data.regionSize = mme.RegionSize; // ������ ������� ������� � data
							data.type = DetectionType::ART_ILLEGAL_THREAD; // ����������� ���� �������
							data.dllName = "unknown"; data.dllPath = "unknown"; // �������� ������ ����������, ��� �� ��������� ������, � ���������� ������� ��� ��������, � ����� ����� � ����� ������� ��� ������
							cfg->callback(&data); cfg->ExcludedThreads.push_back((LPVOID)tempBase); // ����� �������� � ���������� �������� ������ ������ � ������ ��� ����������������
							break;
						}
					}
				}
			} while (Thread32Next(hSnapshot, &th32));
			if (hSnapshot != NULL) CloseHandle(hSnapshot);
		}
		Sleep(cfg->ThreadScanDelay);
	}
}