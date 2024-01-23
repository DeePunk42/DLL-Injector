#include "pch.h"
#include "Windows.h"
#include "tchar.h"
#include "stdio.h"
#include "stdint.h"

char* hookend;

void hookFunction() {
    printf("正确");
    __asm {
        mov rax, hookend
        jmp rax
    }

}

int StartHook() {
    DWORD  oldProtect;
    BYTE NewCode[12];
    HMODULE base = GetModuleHandle(L"crackme.exe");
    HMODULE dllbase = GetModuleHandle(L"EvilDll.dll");
    printf("start hook\nbase:%p\n", base);
    printf("dllbase:%p\n", dllbase);
    char* target = (char*)base + 0x192b;
    hookend = (char*)base + 0x1949;
    printf("target:%p\n", target);
    NewCode[0] = 0x48;
    NewCode[1] = 0xB8;
    uint64_t hookptr = (uint64_t)hookFunction;
    printf("hook:%p\n", hookptr);
    *(uint64_t*)&NewCode[2] = hookptr;
    NewCode[10] = 0xFF;
    NewCode[11] = 0xE0;

    VirtualProtect(target, 12, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(target, NewCode, 12);

    return 0;
}
/*
int StartHook() {
    DWORD  oldProtect;
    HMODULE base = GetModuleHandle(L"crackme.exe");
    printf("start hook\nbase:%p\n", base);
    char* target = (char*)base + 0x18e7;
    printf("target:%p\n", target);
    VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(DWORD*)(target) = 0x90909090;
    return 0;
}
*/

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugString(L"DLL Inject Success");
        MessageBox(NULL, L"DLL Injected", L"DLL Injected", MB_OK);
        StartHook();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        OutputDebugString(L"DLL free Sucess");
        MessageBox(NULL, L"DLL freed", L"DLL freed", MB_OK);
        break;
    }
    return TRUE;
}
