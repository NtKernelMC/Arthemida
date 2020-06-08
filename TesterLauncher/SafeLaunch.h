#pragma once
#pragma once
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <map>
#include <winternl.h>
#include <vector>
#include <tuple>
namespace SafeLaunch
{
	std::map<DWORD_PTR, DWORD_PTR> hooks; PVOID syscall = nullptr;
	class HWBP
	{
	protected:
		static LONG __stdcall hwbpHandler(PEXCEPTION_POINTERS ExceptionInfo)
		{
			if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ||
				ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
			{
				for (const auto& it : hooks)
				{
#ifdef _WIN64
					if (it.first == ExceptionInfo->ContextRecord->Rip)
#else
					if (it.first == ExceptionInfo->ContextRecord->Eip)
#endif
					{
#ifdef _WIN64
						ExceptionInfo->ContextRecord->Rip = it.second;
#else
						ExceptionInfo->ContextRecord->Eip = it.second;
#endif
						return EXCEPTION_CONTINUE_EXECUTION;
					}
				}
			}
			return EXCEPTION_CONTINUE_SEARCH;
		}
	public:
		static int GetFreeIndex(size_t regValue)
		{
			if (!(regValue & 1)) return 0;
			else if (!(regValue & 4)) return 1;
			else if (!(regValue & 16)) return 2;
			else if (!(regValue & 64)) return 3;
			return -1;
		}
	private:
		typedef struct
		{
			DWORD_PTR target;
			DWORD_PTR interceptor;
		} PRM_THREAD, * PPRM_THREAD;
		static bool installHWBP(PPRM_THREAD prm)
		{
			if (hooks.empty()) AddVectoredExceptionHandler(0x1, hwbpHandler);
			hooks.insert(hooks.begin(), std::pair<DWORD_PTR, DWORD_PTR>(prm->target, prm->interceptor));
			THREADENTRY32 th32; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
			hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (Thread32First(hSnapshot, &th32))
			{
				do
				{
					if (th32.th32OwnerProcessID == GetCurrentProcessId() && th32.th32ThreadID != GetCurrentThreadId())
					{
						HANDLE pThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID);
						if (pThread)
						{
							SuspendThread(pThread); CONTEXT context = { 0 };
							context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
							GetThreadContext(pThread, &context);
							auto index = GetFreeIndex(context.Dr7);
							if (index < 0) continue;
							context.Dr7 |= 1 << (2 * index) | 0x100;
							if (context.Dr0 == NULL) *((DWORD_PTR*)&context.Dr0 + index) = prm->target;
							else
							{
								if (context.Dr1 == NULL) *((DWORD_PTR*)&context.Dr1 + index) = prm->target;
								else
								{
									if (context.Dr2 == NULL) *((DWORD_PTR*)&context.Dr2 + index) = prm->target;
									else
									{
										if (context.Dr3 == NULL) *((DWORD_PTR*)&context.Dr3 + index) = prm->target;
									}
								}
							}
							SetThreadContext(pThread, &context);
							ResumeThread(pThread); CloseHandle(pThread);
						}
					}
				} while (Thread32Next(hSnapshot, &th32));
			}
			return true;
		}
	public:
		static bool InstallHWBP(DWORD_PTR target, DWORD_PTR interceptor)
		{
			if (target == 0x0 || interceptor == 0x0) return false;
			if (hooks.find(target) != hooks.end()) return false;
			if (hooks.size() == 4) return false;
			static PRM_THREAD prm; prm.target = target; prm.interceptor = interceptor;
			HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)installHWBP, &prm, 0, 0);
			WaitForSingleObject(hThread, INFINITE);
			return true;
		}
	private:
		static bool deleteHWBP(PPRM_THREAD prm)
		{
			auto it = hooks.find(prm->target);
			if (it == hooks.end()) return false;
			hooks.erase(it); if (hooks.empty())
				RemoveVectoredExceptionHandler(hwbpHandler);
			THREADENTRY32 th32; HANDLE hSnapshot = NULL; th32.dwSize = sizeof(THREADENTRY32);
			hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (Thread32First(hSnapshot, &th32))
			{
				do
				{
					if (th32.th32OwnerProcessID == GetCurrentProcessId() && th32.th32ThreadID != GetCurrentThreadId())
					{
						HANDLE pThread = OpenThread(THREAD_ALL_ACCESS, FALSE, th32.th32ThreadID);
						if (pThread)
						{
							SuspendThread(pThread); CONTEXT context = { 0 };
							context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
							GetThreadContext(pThread, &context);
							context.Dr7 = 0x0;
							*(DWORD_PTR*)&context.Dr0 = 0x0;
							*(DWORD_PTR*)&context.Dr1 = 0x0;
							*(DWORD_PTR*)&context.Dr2 = 0x0;
							*(DWORD_PTR*)&context.Dr3 = 0x0;
							SetThreadContext(pThread, &context);
							ResumeThread(pThread); CloseHandle(pThread);
						}
					}
				} while (Thread32Next(hSnapshot, &th32));
			}
			return true;
		}
	public:
		static bool DeleteHWBP(DWORD_PTR target)
		{
			if (target == 0x0 || hooks.empty()) return false;
			static PRM_THREAD prm; prm.target = target;
			HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)deleteHWBP, &prm, 0, 0);
			WaitForSingleObject(hThread, INFINITE);
			return true;
		}
	};
	class ProcessGate sealed
	{
	private:
		PVOID ApiAddr = nullptr;
	public:
		explicit ProcessGate(PVOID api_address)
		{
			this->ApiAddr = api_address;
		}

		static NTSTATUS __stdcall ZwCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle,
			ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes,
			POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters,
			void* CreateInfo, void* AttributeList)
		{
			typedef NTSTATUS(__stdcall* hZwCreateUserProcess)(PHANDLE ProcessHandle, PHANDLE ThreadHandle,
				ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes,
				POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters,
				void* CreateInfo, void* AttributeList);
			hZwCreateUserProcess cZwCreateUserProcess = (hZwCreateUserProcess)syscall;
			NTSTATUS stq = cZwCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess,
				ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags,
				ThreadFlags, ProcessParameters, CreateInfo, AttributeList);
			return stq;
		}

		void ProtectFromHooking()
		{
			auto getOSver = []()
			{
				NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW); OSVERSIONINFOEXW osInfo;
				*(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");
				if (NULL != RtlGetVersion)
				{
					osInfo.dwOSVersionInfoSize = sizeof(osInfo); RtlGetVersion(&osInfo);
					return std::make_tuple(osInfo.dwMajorVersion, osInfo.dwMinorVersion);
				}
				return std::make_tuple((DWORD)0x0, (DWORD)0x0);
			};
			DWORD_PTR ZwAddr = (DWORD_PTR)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwCreateUserProcess");
#ifdef _WIN64
			if (*(BYTE*)ZwAddr != 0x4C) memcpy((void*)0xFFFFFF, (void*)0xFFFFFF, 222222);
			syscall = VirtualAlloc(0, 11, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			memcpy(syscall, (void*)ZwAddr, 8); *(BYTE*)((DWORD_PTR)syscall + 8) = 0x0F;
			*(BYTE*)((DWORD_PTR)syscall + 9) = 0x05; *(BYTE*)((DWORD_PTR)syscall + 10) = 0xC3;
#else
			if (*(BYTE*)ZwAddr != 0xB8) memcpy((void*)0xFFFFFF, (void*)0xFFFFFF, 222222);
			SYSTEM_INFO systemInfo = { 0 }; 
			GetNativeSystemInfo(&systemInfo); 
			DWORD codeSize = 15;
			if (systemInfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_INTEL)
			{
				if (std::get<0>(getOSver()) == 6 && std::get<1>(getOSver()) == 0) codeSize = 21;
				if (std::get<0>(getOSver()) == 6 && std::get<1>(getOSver()) == 1) codeSize = 24;
			}
			else
			{
				if (std::get<0>(getOSver()) == 6 && (std::get<1>(getOSver()) == 3 || std::get<1>(getOSver()) == 2)) codeSize = 18;
			}
			syscall = VirtualAlloc(0, codeSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			memcpy(syscall, (void*)ZwAddr, codeSize);
#endif      
			HWBP::InstallHWBP(ZwAddr, (DWORD_PTR)&ZwCreateUserProcess);
		}

		template<typename UnkStr, typename UnkSTARTUPINFO>
		BOOL SafeProcess(UnkStr lpApplicationName,
			UnkStr lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
			LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
			DWORD dwCreationFlags, LPVOID lpEnvironment, UnkStr lpCurrentDirectory,
			UnkSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
		{
			if (ApiAddr == nullptr) return NULL; 
			ProtectFromHooking();
			using CreateSafeProc = BOOL(*)(UnkStr lpApplicationName,
				UnkStr lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
				LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
				DWORD dwCreationFlags, LPVOID lpEnvironment, UnkStr lpCurrentDirectory,
				UnkSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
			CreateSafeProc CreateSafeProcess = (CreateSafeProc)ApiAddr;
			BOOL rslt = CreateSafeProcess(lpApplicationName, lpCommandLine,
				lpProcessAttributes, lpThreadAttributes, bInheritHandles,
				CREATE_SUSPENDED, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
			printf("lpProcessInformation:\ndwProcessId=%d\ndwThreadId=%d\nhProcess valid=%d\nhThread valid=%d\n", lpProcessInformation->dwProcessId, lpProcessInformation->dwThreadId, lpProcessInformation->hProcess?0:1, lpProcessInformation->hThread ? 0 : 1);
			if (lpProcessInformation->hProcess == NULL || rslt == NULL) return NULL;
			PVOID ctrlByte = VirtualAllocEx(lpProcessInformation->hProcess, 0,
				0x1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE); 
			if (!ctrlByte) printf("Error code: %d", GetLastError());
			BYTE nop[] = { 0x90 };
			HRESULT wrres = WriteProcessMemory(lpProcessInformation->hProcess, ctrlByte, nop, 0x1, NULL);
			if (!wrres) printf("Error code: %d", GetLastError());

			/*CONTEXT context = { 0 };
			context.ContextFlags = CONTEXT_ALL;
			GetThreadContext(lpProcessInformation->hThread, &context);
			auto index = HWBP::GetFreeIndex(context.Dr7);
			if (index < 0) return NULL;
			context.Dr7 |= 1 << (2 * index) | 0x100;
			*((DWORD_PTR*)&context.Dr2 + index) = (DWORD_PTR)ctrlByte;
			SetThreadContext(lpProcessInformation->hThread, &context);
			ResumeThread(lpProcessInformation->hThread);*/
			
			DWORD_PTR ZwAddr = (DWORD_PTR)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwCreateUserProcess");
			HWBP::DeleteHWBP(ZwAddr); 
			if (syscall != nullptr) VirtualFree(syscall, 0, MEM_RELEASE);
			if (rslt) return rslt;
			return NULL;
		}
	};
}