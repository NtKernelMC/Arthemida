#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <thread>

DWORD WINAPI TestDllThread() {
	MessageBoxA(NULL, "SetWindowsHookEx DLL injected", "cheat.dll", MB_OK);
	while (true) {}
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
    switch (ul_reason_for_call)
    {
	case DLL_PROCESS_ATTACH: {
		DisableThreadLibraryCalls(hModule);
		std::thread testThread(TestDllThread);
		testThread.detach();
		break;
	}
    default:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) int NextHook(int code, WPARAM wParam, LPARAM lParam) {
	return CallNextHookEx(NULL, code, wParam, lParam);
}