#include "windows.h"
#include "tchar.h"
#include "stdio.h"
#include "tlhelp32.h"
#include "cstdio"

#define targetFile "crackme.exe"
#define targetDllPATH "C:\\Users\\DeePunk\\source\\repos\\EvilDll\\x64\\Debug\\EvilDll.dll"
#define targetDll "EvilDll.dll"

DWORD FindProcess(TCHAR*  name) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            TCHAR processName[0x30];
            _tcscpy_s(processName, 0x30, entry.szExeFile);

            if (_tcscmp(name, processName)==0)
            {
                _tprintf(L"PID detected: %d\n", entry.th32ProcessID);
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);

    return -1;
}

BOOL InjectDll(LPCTSTR szDllPath)
{
    HANDLE hProcess = NULL, hThread = NULL;
    HMODULE hMod = NULL;
    LPVOID pRemoteBuf = NULL;

    DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
    LPTHREAD_START_ROUTINE pThreadProc;

    TCHAR target[] = _T(targetFile);
    if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, FindProcess(target))))
    {
        _tprintf(L"OpenProcess failed!!!\n");
        return FALSE;
    }

    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

    WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);

    _tprintf(L"Write Path Successfully:%p\n", pRemoteBuf);

    hMod = GetModuleHandle(L"kernel32.dll");
    pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");

    _tprintf(L"Get Address Successfully:%p\n", pThreadProc);


    hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}

BOOL EjectDll(LPCTSTR szDllName)
{
    BOOL bMore = FALSE, bFound = FALSE;
    HANDLE hSnapshot, hProcess, hThread;
    HMODULE hModule = NULL;
    MODULEENTRY32 me = { sizeof(me) };
    LPTHREAD_START_ROUTINE pThreadProc;

    TCHAR target[] = _T(targetFile);
    DWORD pid = FindProcess(target);
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

    bMore = Module32First(hSnapshot, &me);
    for (; bMore; bMore = Module32Next(hSnapshot, &me))
    {
        if (!_tcsicmp((LPCTSTR)me.szModule, szDllName) ||
            !_tcsicmp((LPCTSTR)me.szExePath, szDllName))
        {
            bFound = TRUE;
            break;
        }
    }

    if (!bFound)
    {
        CloseHandle(hSnapshot);
        return FALSE;
    }

    if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)))
    {
        _tprintf(L"OpenProcess(%d) failed!!! [%d]\n", pid, GetLastError());
        return FALSE;
    }

    hModule = GetModuleHandle(L"kernel32.dll");
    pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");
    hThread = CreateRemoteThread(hProcess, NULL, 0,
        pThreadProc, me.modBaseAddr,
        0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    CloseHandle(hSnapshot);

    return TRUE;
}

int _tmain(int argc, TCHAR* argv[])
{
    TCHAR DLL_PATH[] = _T(targetDllPATH);
    TCHAR DLL[] = _T(targetDll);

    if (InjectDll(DLL_PATH))
        _tprintf(L"Inject Dll success!!!\n");

    getchar();
    if (EjectDll(DLL_PATH))
        _tprintf(L"Eject Dll success!!!\n");
    getchar();
    return 0;
}
