// dllmain.cpp : Defines the entry point for the DLL application.
#include "Windows.h"
#include <thread>
#include "sigscan.h"

#define uint unsigned int

HMODULE hSelf;

void Main() {
    if (!GetModuleHandleA("client.dll")) { 
        MessageBoxA(0, "client.dll not found, you must be in game for this to work.", "AttackerDLL", MB_ICONERROR | MB_OK);
        return;
    }

    typedef bool(__cdecl* ptrCheckUTF8BOMAndUpdate)(const char** pcpOutBuffer, uint* puiOutSize);

    const char pattern[] = { "\x75\x0C\x57\x8B\x7D\x08\xFF\x36\xFF\x37\xE8\x00\x00\x00\x00\x83\xC4\x08\x84\xC0\x74\x0C\x83\x07\x03\xB0\x01\x83\x06\xFD\x5F\x5E\x5D\xC3" };
    const char mask[] = { "xxxxxxxxxxx????xxxxxxxxxxxxxxxxxxx" };
    DWORD dwTemp = SigScan::FindPattern("client.dll", pattern, mask);
    if (!dwTemp) {
        MessageBoxA(0, "Signature not found.", "AttackerDLL", MB_ICONERROR | MB_OK);
        return;
    }
    DWORD dwCheckUTF8BOMAndUpdate = dwTemp - 0x5;

    ptrCheckUTF8BOMAndUpdate callCheckUTF8BOMAndUpdate = (ptrCheckUTF8BOMAndUpdate)dwCheckUTF8BOMAndUpdate;
    
    const char* buffer = "addEventHandler('dick', root)"; 
    uint size_of_dick = strlen(buffer); 
    bool res = callCheckUTF8BOMAndUpdate(&buffer, &size_of_dick);
    MessageBoxA(0, res ? "True" : "False", "AttackerDLL", MB_ICONINFORMATION | MB_OK);
    return;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        hSelf = hModule;
        Main();
    }
    default:
        break;
    }
    return TRUE;
}

