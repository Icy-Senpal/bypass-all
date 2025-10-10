#pragma once
#include <windows.h>

#include "LoaderTypes.h"
#include "Hash.h"

constexpr DWORD KERNEL32DLL_HASH = CompileTimeHash("kernel32.dll");
constexpr DWORD NTDLLDLL_HASH = CompileTimeHash("ntdll.dll");
constexpr DWORD LOADLIBRARYA_HASH = CompileTimeHash("LoadLibraryA");
constexpr DWORD GETPROCADDRESS_HASH = CompileTimeHash("GetProcAddress");
constexpr DWORD VIRTUALALLOC_HASH = CompileTimeHash("VirtualAlloc");
constexpr DWORD NTFLUSHINSTRUCTIONCACHE_HASH = CompileTimeHash("NtFlushInstructionCache");

ULONG_PTR GetProcAddressByHash(_PPEB pebAddress, DWORD moduleHash, DWORD functionHash);
BOOL ResolveBaseLoaderFunctions(_PPEB pebAddress, PWINDOWSAPIS winApi);
