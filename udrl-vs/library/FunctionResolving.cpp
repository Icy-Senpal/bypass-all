#include "FunctionResolving.h"
#include "LoaderTypes.h"
#include "StdLib.h"

#pragma code_seg(".text$d")

ULONG_PTR GetProcAddressByHash(_PPEB pebAddress, DWORD moduleHash, DWORD functionHash) {
    volatile DWORD obfuscator = 0xDEADBEEF;
    obfuscator ^= 0xCAFEBABE;
    
    PPEB_LDR_DATA ldrData = (PPEB_LDR_DATA)(pebAddress)->pLdr;

    PLDR_DATA_TABLE_ENTRY currentLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)ldrData->InMemoryOrderModuleList.Flink;
    while (currentLdrDataTableEntry) {
        PWSTR dllName = currentLdrDataTableEntry->BaseDllName.pBuffer;

        USHORT nameLength = currentLdrDataTableEntry->BaseDllName.Length / 2;

        DWORD moduleNameHash = 0;
        do {
            moduleNameHash = _rotr(moduleNameHash, HASH_KEY);
            if (*dllName >= 'a') {
                moduleNameHash += *dllName - 0x20;
            }
            else {
                moduleNameHash += *dllName;
            }
            dllName++;
        } while (--nameLength);

        if (moduleNameHash == moduleHash) {
            ULONG_PTR moduleBaseAddress = (ULONG_PTR)currentLdrDataTableEntry->DllBase;

            PIMAGE_DOS_HEADER moduleDosHeader = (PIMAGE_DOS_HEADER)moduleBaseAddress;
            PIMAGE_NT_HEADERS modulePEHeader = (PIMAGE_NT_HEADERS)(moduleBaseAddress + moduleDosHeader->e_lfanew);

            PIMAGE_DATA_DIRECTORY exportDataDirectoryEntry = &modulePEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

            PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(moduleBaseAddress + exportDataDirectoryEntry->VirtualAddress);

            ULONG_PTR nameArray = moduleBaseAddress + exportDirectory->AddressOfNames;

            ULONG_PTR ordinalArray = moduleBaseAddress + exportDirectory->AddressOfNameOrdinals;

            while (nameArray) {
                 DWORD functionNameHash = RunTimeHash((char*)(moduleBaseAddress + DEREF_32(nameArray)));

                if (functionNameHash == functionHash) {
                    ULONG_PTR addressArray = moduleBaseAddress + exportDirectory->AddressOfFunctions;

                    addressArray += DEREF_16(ordinalArray) * sizeof(DWORD);

                    return moduleBaseAddress + DEREF_32(addressArray);
                }
                nameArray += sizeof(DWORD);

                ordinalArray += sizeof(WORD);
            }
        }
        currentLdrDataTableEntry = *(PLDR_DATA_TABLE_ENTRY*)currentLdrDataTableEntry;
    }
    return NULL;
}

BOOL ResolveBaseLoaderFunctions(_PPEB pebAddress, PWINDOWSAPIS winApi) {
    winApi->LoadLibraryA = (LOADLIBRARYA)GetProcAddressByHash(pebAddress, KERNEL32DLL_HASH, LOADLIBRARYA_HASH);
    if (winApi->LoadLibraryA == NULL) {
        PRINT("[-] Failed to find address of key loader function. Exiting..\n");
        return FALSE;
    }
    winApi->GetProcAddress = (GETPROCADDRESS)GetProcAddressByHash(pebAddress, KERNEL32DLL_HASH, GETPROCADDRESS_HASH);
    if (winApi->GetProcAddress == NULL) {
        PRINT("[-] Failed to find address of key loader function. Exiting..\n");
        return FALSE;
    }
    winApi->VirtualAlloc = (VIRTUALALLOC)GetProcAddressByHash(pebAddress, KERNEL32DLL_HASH, VIRTUALALLOC_HASH);
    if (winApi->VirtualAlloc == NULL) {
        PRINT("[-] Failed to find address of key loader function. Exiting..\n");
        return FALSE;
    }
    winApi->NtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)GetProcAddressByHash(pebAddress, NTDLLDLL_HASH, NTFLUSHINSTRUCTIONCACHE_HASH);
    if (winApi->NtFlushInstructionCache == NULL) {
        PRINT("[-] Failed to find address of key loader function. Exiting..\n");
        return FALSE;
    }
    return TRUE;
}
