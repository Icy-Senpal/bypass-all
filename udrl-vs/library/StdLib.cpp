#include <windows.h>

#include "Hash.h"

#pragma code_seg(".text$e")

BOOL _memcpy(void* dest, void* src, size_t size) {
    if (dest == NULL || src == NULL) {
        return FALSE;
    }
    
    unsigned char* csrc = (unsigned char*)src;
    unsigned char* cdest = (unsigned char*)dest;
    
    size_t chunks = size / 8;
    size_t remainder = size % 8;
    
    for (size_t i = 0; i < chunks; i++) {
        size_t offset = i * 8;
        cdest[offset + 0] = csrc[offset + 0];
        cdest[offset + 1] = csrc[offset + 1];
        cdest[offset + 2] = csrc[offset + 2];
        cdest[offset + 3] = csrc[offset + 3];
        cdest[offset + 4] = csrc[offset + 4];
        cdest[offset + 5] = csrc[offset + 5];
        cdest[offset + 6] = csrc[offset + 6];
        cdest[offset + 7] = csrc[offset + 7];
    }
    
    for (size_t i = chunks * 8; i < size; i++) {
        cdest[i] = csrc[i];
    }
    
    return TRUE;
}

int _memcmp(const void* ptr1, const void* ptr2, size_t size) {
    const unsigned char* p1 = (const unsigned char*)ptr1;
    const unsigned char* p2 = (const unsigned char*)ptr2;

    for (size_t i = 0; i < size; ++i) {
        if (p1[i] < p2[i]) {
            return -1;
        }
        else if (p1[i] > p2[i]) {
            return 1;
        }
    }

    return 0;
}

#pragma optimize( "", off )
void* _memset(void* dest, int ch, size_t count) {
    unsigned char* p = (unsigned char*)dest;
    unsigned char value = (unsigned char)ch;

    size_t chunks = count / 16;
    size_t i = 0;
    
    for (size_t c = 0; c < chunks; c++) {
        p[i++] = value; p[i++] = value; p[i++] = value; p[i++] = value;
        p[i++] = value; p[i++] = value; p[i++] = value; p[i++] = value;
        p[i++] = value; p[i++] = value; p[i++] = value; p[i++] = value;
        p[i++] = value; p[i++] = value; p[i++] = value; p[i++] = value;
    }
    
    for (; i < count; i++) {
        p[i] = value;
    }

    return dest;
}
#pragma optimize( "", on)

#ifdef _DEBUG
#include "FunctionResolving.h"

void _printf(const char* format, ...) {
    va_list arglist;
    va_start(arglist, format);
    char buff[1024];

    typedef int (WINAPI* VSPRINTF_S)(char*, size_t, const char*, va_list);
    typedef BOOL(WINAPI* WRITECONSOLEA)(HANDLE, const void*, DWORD, LPDWORD, LPVOID);
    typedef HANDLE(WINAPI* GETSTDHANDLE)(DWORD);

    constexpr DWORD NTDLL_HASH = CompileTimeHash("ntdll.dll");
    constexpr DWORD KERNEL32_HASH = CompileTimeHash("kernel32.dll");
    
    constexpr DWORD vsprintf_s_hash = CompileTimeHash("vsprintf_s");
    constexpr DWORD WriteConsoleA_hash = CompileTimeHash("WriteConsoleA");
    constexpr DWORD GetStdHandle_hash = CompileTimeHash("GetStdHandle");

#ifdef _WIN64
    _PPEB pebAddress = (_PPEB)__readgsqword(0x60);
#elif _WIN32
    _PPEB pebAddress = (_PPEB)__readfsdword(0x30);
#endif
    VSPRINTF_S fnVsprintf_s = (VSPRINTF_S)GetProcAddressByHash(pebAddress, NTDLL_HASH, vsprintf_s_hash);

    int len = fnVsprintf_s(buff, 1024, format, arglist);
    if (len > 0) {
        WRITECONSOLEA fnWriteConsoleA = (WRITECONSOLEA)GetProcAddressByHash(pebAddress, KERNEL32_HASH, WriteConsoleA_hash);
        GETSTDHANDLE fnGetStdHandle = (GETSTDHANDLE)GetProcAddressByHash(pebAddress, KERNEL32_HASH, GetStdHandle_hash);

        fnWriteConsoleA(fnGetStdHandle(STD_OUTPUT_HANDLE), buff, len, NULL, NULL);
    }
    va_end(arglist);
}
#endif _DEBUG
