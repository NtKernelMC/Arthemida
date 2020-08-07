#include <Windows.h>
#include "resource.h"
#include <conio.h>
#pragma comment(lib, "libMinHook.x86.lib")
#include "Artemis.h"
#ifdef _DEBUG
#pragma comment(lib, "ArtemisLib_d.lib")
#else
#pragma comment(lib, "ArtemisLib.lib")
#endif
#pragma warning(disable : 4477)
#define _CRT_SECURE_NO_WARNINGS

using namespace std;
using namespace ART_LIB;
void __stdcall ArtemisCallback(ArtemisLibrary::ARTEMIS_DATA* artemis)
{
	if (artemis == nullptr) return;
	switch (artemis->type)
	{
	case ArtemisLibrary::DetectionType::ART_APC_INJECTION:
		printf("DETECTED APC! (ARGUMENT: 0x%X | CONTEXT: 0x%X | PROC: %s)\n",
			get<0>(artemis->ApcInfo), get<1>(artemis->ApcInfo), get<2>(artemis->ApcInfo));
		break;
	case ArtemisLibrary::DetectionType::ART_MANUAL_MAP:
		printf("Detected MMAP! Base: 0x%X | Size: 0x%X | Rights: 0x%X\n",
			artemis->baseAddr, artemis->regionSize, artemis->MemoryRights);
		break;
	case ArtemisLibrary::DetectionType::ART_RETURN_ADDRESS:
		printf("Detected Return to Hack Function! Address: 0x%X\n", artemis->baseAddr);
		break;
	case ArtemisLibrary::DetectionType::ART_ILLEGAL_THREAD:
		printf("Detected Anonymous thread! Base: 0x%X | Size: 0x%X\n",
			artemis->baseAddr, artemis->regionSize);
		break;
	case ArtemisLibrary::DetectionType::ART_ILLEGAL_MODULE:
		printf("Detected Illegal module! Base: 0x%X | DllName: %s | Path: %s | Size: %d\n",
			artemis->baseAddr, artemis->dllName.c_str(), artemis->dllPath.c_str(), artemis->regionSize);
		break;
	case ArtemisLibrary::DetectionType::ART_FAKE_LAUNCHER:
		printf("Detected fake launcher!\n");
		break;
	case ArtemisLibrary::DetectionType::ART_MEMORY_CHANGED:
		printf("Detected Illegal module! Base: 0x%X | Rights: 0x%X | Size: %d\n",
			artemis->baseAddr, artemis->MemoryRights, artemis->regionSize);
		break;
	}
}

#pragma region TestWindow
ATOM                RegisterWindowClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

HINSTANCE hInst;
WCHAR szTitle[100];
WCHAR szWindowClass[100];

ATOM RegisterWindowClass(HINSTANCE hInstance)
{
	WNDCLASSEXW wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = WndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_TESTER));
	wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_TESTER);
	wcex.lpszClassName = szWindowClass;
	wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_TESTER));

	return RegisterClassExW(&wcex);
}
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
	hInst = hInstance; // Store instance handle in our global variable

	HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

	if (!hWnd)
	{
		return FALSE;
	}

	ShowWindow(hWnd, nCmdShow);
	UpdateWindow(hWnd);
	SetWindowTextA(hWnd, "TESTER");

	return TRUE;
}
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_COMMAND:
	{
		int wmId = LOWORD(wParam);
		// Parse the menu selections:
		switch (wmId)
		{
		case IDM_ABOUT:
			DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
			break;
		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;
		default:
			return DefWindowProcW(hWnd, message, wParam, lParam);
		}
	}
	break;
	case WM_PAINT:
	{
		PAINTSTRUCT ps;
		HDC hdc = BeginPaint(hWnd, &ps);
		// TODO: Add any drawing code that uses hdc here...
		EndPaint(hWnd, &ps);
	}
	break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProcW(hWnd, message, wParam, lParam);
	}
	return 0;
}
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG:
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return (INT_PTR)TRUE;
		}
		break;
	}
	return (INT_PTR)FALSE;
}
#pragma endregion

ArtemisLibrary::ArtemisConfig cfg;
ArtemisLibrary* art;

// Создание консоли, загрузка dxgi.dll для теста (не имеет значения, просто у меня уже есть готовая прокси длл на dxgi), инициализация либы, ожидание
void ConsoleOutput() {
	AllocConsole();
	FILE* fDummy;
	freopen_s(&fDummy, "CONOUT$", "w", stdout);
	system("color 2F");
	SetConsoleTitleA("Tester Console");

	LoadLibraryA("dxgi.dll");

	cfg.hSelfModule = NULL;
	cfg.callback = ArtemisCallback;
	cfg.DetectThreads = true;
	cfg.DetectModules = true;

	// 2 этап
	cfg.DetectAPC = true;
	cfg.DetectFakeLaunch = true;
	cfg.DetectManualMap = true;
	
	cfg.ThreadScanDelay = 1000;
	cfg.ModuleScanDelay = 1000;
	art = alInitializeArtemis(&cfg);
	if (art == nullptr) {
		printf("Library initialization failed. Press any key to exit.\n");
		_getch();
		ExitProcess(EXIT_SUCCESS);
	}

	printf("Library initialized. Waiting for attacks. Press any key to exit.\n");
	_getch();
	ExitProcess(EXIT_SUCCESS);
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	// Создание асинхронного потока с консолью, дабы не конфликтовало с окном
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ConsoleOutput, NULL, 0, NULL);
	CloseHandle(hThread);

	// Ниже создание окна и обработка его сообщений (для уязвимости SetWindowsHookEx)
	LoadStringW(hInstance, IDS_APP_TITLE, szTitle, 100);
	LoadStringW(hInstance, IDC_TESTER, szWindowClass, 100);
	RegisterWindowClass(hInstance);
	if (!InitInstance(hInstance, nCmdShow))
	{
		return FALSE;
	}
	HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_TESTER));
	MSG msg;

	while (GetMessage(&msg, nullptr, 0, 0))
	{
		if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}

	return (int)msg.wParam;	
}