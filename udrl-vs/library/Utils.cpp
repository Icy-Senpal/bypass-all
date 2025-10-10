#include <intrin.h>

#include "TrackMemory.h"
#include "End.h"
#include "Hash.h"
#include "StdLib.h"
#include "Utils.h"

#pragma code_seg(".text$c")

__declspec(noinline) void* GetLocation() {
    volatile int dummy = 0;
    dummy += 1;
    return _ReturnAddress();
}

_PPEB GetPEBAddress() {
#ifdef _WIN64
    return (_PPEB)__readgsqword(0x60);
#elif _WIN32
    return (_PPEB)__readfsdword(0x30);
#endif
}

ULONG_PTR FindBufferBaseAddress() {
#if _DEBUG
    return (ULONG_PTR)debug_dll;
#elif _WIN64
    return (ULONG_PTR)&LdrEnd + 1;
#elif _WIN32
    return (ULONG_PTR)((char*)LdrEnd() + 2);
#endif
}

ULONG_PTR FindBufferBaseAddressStephenFewer() {
#if _DEBUG
    return (ULONG_PTR)debug_dll;
#else
    ULONG_PTR imageBase = (ULONG_PTR)GetLocation();
    while (TRUE) {
        if (((PIMAGE_DOS_HEADER)imageBase)->e_magic == IMAGE_DOS_SIGNATURE) {
            ULONG_PTR ntHeader = ((PIMAGE_DOS_HEADER)imageBase)->e_lfanew;
            if (ntHeader >= sizeof(IMAGE_DOS_HEADER) && ntHeader < 1024) {
                ntHeader += imageBase;
                if (((PIMAGE_NT_HEADERS)ntHeader)->Signature == IMAGE_NT_SIGNATURE) {
                    return imageBase;
                }
            }
        }
        imageBase--;
    }
#endif
}

BOOL CopyPEHeader(ULONG_PTR srcImage, ULONG_PTR dstAddress) {
    PRINT("[+] Copying PE Header...\n");

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(srcImage + ((PIMAGE_DOS_HEADER)srcImage)->e_lfanew);
    PBYTE srcHeader = (PBYTE)srcImage;
    PBYTE dstHeader = (PBYTE)dstAddress;

    DWORD sizeOfHeaders = ntHeader->OptionalHeader.SizeOfHeaders;
    return _memcpy(dstHeader, srcHeader, sizeOfHeaders);
}

BOOL CopyPESections(ULONG_PTR srcImage, ULONG_PTR dstAddress) {
    PRINT("[+] Copying Sections...\n");

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(srcImage + ((PIMAGE_DOS_HEADER)srcImage)->e_lfanew);
    PBYTE srcHeader = (PBYTE)srcImage;
    PBYTE dstHeader = (PBYTE)dstAddress;

    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ntHeader->OptionalHeader + ntHeader->FileHeader.SizeOfOptionalHeader);

    DWORD numberOfSections = ntHeader->FileHeader.NumberOfSections;

    while (numberOfSections--) {
        PBYTE dstSection = (PBYTE)dstAddress + sectionHeader->VirtualAddress;

        PBYTE srcSection = (PBYTE)srcImage + sectionHeader->PointerToRawData;

        DWORD sizeOfData = sectionHeader->SizeOfRawData;
        if (!_memcpy(dstSection, srcSection, sizeOfData)) {
            return FALSE;
        }

        PRINT("\t[+] Copied Section: %s\n", sectionHeader->Name);
        sectionHeader++;
    }
    return TRUE;
}

BOOL CopyDllAndTrackMemory(PALLOCATED_MEMORY_REGION allocatedMemoryRegion, ULONG_PTR srcImage, ULONG_PTR dstAddress, COPY_PEHEADER copyPEHeader, DWORD memoryProtections, ALLOCATED_MEMORY_MASK_MEMORY_BOOL mask) {
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(srcImage + ((PIMAGE_DOS_HEADER)srcImage)->e_lfanew);

    if (copyPEHeader) {
        CopyPEHeaderAndTrackMemory(allocatedMemoryRegion, srcImage, ntHeader, dstAddress, memoryProtections, mask);
    }

    CopyPESectionsAndTrackMemory(allocatedMemoryRegion, srcImage, ntHeader, dstAddress, memoryProtections, mask, copyPEHeader);

    return TRUE;

}

BOOL CopyPEHeaderAndTrackMemory(PALLOCATED_MEMORY_REGION allocatedMemoryRegion, ULONG_PTR srcImage, PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress, DWORD memoryProtections, ALLOCATED_MEMORY_MASK_MEMORY_BOOL mask) {
    PRINT("[+] Copying PE Header...\n");
    PBYTE srcHeader = (PBYTE)srcImage;
    PBYTE dstHeader = (PBYTE)dstAddress;
    DWORD sizeOfHeaders = ntHeader->OptionalHeader.SizeOfHeaders;

    TrackAllocatedMemorySection(&allocatedMemoryRegion->Sections[0], ALLOCATED_MEMORY_LABEL::LABEL_PEHEADER, dstHeader, sizeOfHeaders, memoryProtections, mask);

    return _memcpy(dstHeader, srcHeader, sizeOfHeaders);
}

BOOL CopyPESectionsAndTrackMemory(PALLOCATED_MEMORY_REGION allocatedMemoryRegion, ULONG_PTR srcImage, PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress, DWORD memoryProtections, ALLOCATED_MEMORY_MASK_MEMORY_BOOL mask, COPY_PEHEADER copyPeHeader) {
    PRINT("[+] Copying Sections...\n");
    PBYTE srcHeader = (PBYTE)srcImage;
    PBYTE dstHeader = (PBYTE)dstAddress;

    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ntHeader->OptionalHeader + ntHeader->FileHeader.SizeOfOptionalHeader);

    DWORD numberOfSections = ntHeader->FileHeader.NumberOfSections;

    int sectionCount = copyPeHeader ? 1 : 0;

    while (numberOfSections--) {
        PBYTE dstSection = (PBYTE)dstAddress + sectionHeader->VirtualAddress;

        PBYTE srcSection = (PBYTE)srcImage + sectionHeader->PointerToRawData;

        DWORD sizeOfData = sectionHeader->SizeOfRawData;
        if (!_memcpy(dstSection, srcSection, sizeOfData)) {
            return FALSE;
        }
        
        TrackAllocatedMemorySection(&allocatedMemoryRegion->Sections[sectionCount], GetSectionLabelFromName(sectionHeader->Name), dstSection, sectionHeader->Misc.VirtualSize, memoryProtections, mask);

        PRINT("\t[+] Copied Section: %s\n", sectionHeader->Name);

        sectionHeader++;
        sectionCount++;
    }
    return TRUE;
}

void ResolveImports(PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress, PWINDOWSAPIS winApi) {
    PRINT("[*] Resolving Imports... \n");

    volatile DWORD obf_imp = 0xABCDEF01;
    obf_imp = ~obf_imp;
    
    PIMAGE_DATA_DIRECTORY importDataDirectoryEntry = &(ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dstAddress + importDataDirectoryEntry->VirtualAddress);

    while (importDescriptor->Name) {
        LPCSTR libraryName = (LPCSTR)(dstAddress + importDescriptor->Name);
        ULONG_PTR libraryBaseAddress = (ULONG_PTR)winApi->LoadLibraryA(libraryName);

        PRINT("[+] Loaded Module: %s\n", (char*)libraryName);

        PIMAGE_THUNK_DATA INT = (PIMAGE_THUNK_DATA)(dstAddress + importDescriptor->OriginalFirstThunk);
        PIMAGE_THUNK_DATA IAT = (PIMAGE_THUNK_DATA)(dstAddress + importDescriptor->FirstThunk);

        while (DEREF(IAT)) {
            if (INT && INT->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                PIMAGE_NT_HEADERS libraryPEHeader = (PIMAGE_NT_HEADERS)(libraryBaseAddress + ((PIMAGE_DOS_HEADER)libraryBaseAddress)->e_lfanew);

                PIMAGE_DATA_DIRECTORY exportDataDirectoryEntry = &(libraryPEHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

                PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(libraryBaseAddress + exportDataDirectoryEntry->VirtualAddress);

                ULONG_PTR addressArray = libraryBaseAddress + exportDirectory->AddressOfFunctions;

                addressArray += (IMAGE_ORDINAL(INT->u1.Ordinal) - exportDirectory->Base) * sizeof(DWORD);

                PRINT("\t[*] Ordinal: %d\tAddress: %p\n", INT->u1.Ordinal, libraryBaseAddress + DEREF_32(addressArray));
                DEREF(IAT) = libraryBaseAddress + DEREF_32(addressArray);
            }
            else {
                PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)(dstAddress + DEREF(IAT));
                LPCSTR functionName = importName->Name;

                ULONG_PTR functionAddress = (ULONG_PTR)winApi->GetProcAddress((HMODULE)libraryBaseAddress, functionName);
                PRINT("\t[*] Function: %s\tAddress: %p\n", (char*)functionName, functionAddress);
                DEREF(IAT) = functionAddress;
            }
            ++IAT;
            if (INT) {
                ++INT;
            }
        }
        importDescriptor++;
    }
    return;
}

void ProcessRelocations(PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress) {
    PRINT("[*] Processing relocations... \n");

    volatile ULONG_PTR obf_val = 0x12345678;
    obf_val ^= 0x87654321;
    
    ULONG_PTR delta = dstAddress - ntHeader->OptionalHeader.ImageBase;
    PRINT("[+] Delta: 0x%X \n", delta);

    PIMAGE_DATA_DIRECTORY relocDataDirectoryEntry = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if ((relocDataDirectoryEntry)->Size > 0) {
        PIMAGE_BASE_RELOCATION baseRelocation = (PIMAGE_BASE_RELOCATION)(dstAddress + relocDataDirectoryEntry->VirtualAddress);
        PRINT("[*] Base Relocation: %p\n", baseRelocation);

        while (baseRelocation->SizeOfBlock) {
            ULONG_PTR relocationBlock = (dstAddress + baseRelocation->VirtualAddress);
            PRINT("\t[*] Relocation Block: %p\n", relocationBlock);

            ULONG_PTR relocationCount = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

            PIMAGE_RELOC relocation = (PIMAGE_RELOC)((ULONG_PTR)baseRelocation + sizeof(IMAGE_BASE_RELOCATION));

            while (relocationCount--) {
                if ((relocation)->type == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR*)(relocationBlock + relocation->offset) += delta;
                else if (relocation->type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD*)(relocationBlock + relocation->offset) += (DWORD)delta;
                else if (relocation->type == IMAGE_REL_BASED_HIGH)
                    *(WORD*)(relocationBlock + relocation->offset) += HIWORD(delta);
                else if (relocation->type == IMAGE_REL_BASED_LOW)
                    *(WORD*)(relocationBlock + relocation->offset) += LOWORD(delta);
                relocation++;
            }
            baseRelocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)baseRelocation + baseRelocation->SizeOfBlock);
        }
    }
    return;
}

BOOL ResolveRdataSection(ULONG_PTR srcImage, ULONG_PTR dstAddress, PRDATA_SECTION rdata) {
    PRINT("[+] Resolving .rdata information...\n");

    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(srcImage + ((PIMAGE_DOS_HEADER)srcImage)->e_lfanew);
    PBYTE srcHeader = (PBYTE)srcImage;
    PBYTE dstHeader = (PBYTE)dstAddress;

    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&ntHeader->OptionalHeader + ntHeader->FileHeader.SizeOfOptionalHeader);

    DWORD numberOfSections = ntHeader->FileHeader.NumberOfSections;

    while (numberOfSections--) {
        constexpr DWORD rdataHash = CompileTimeHash(".rdata");
        if (RunTimeHash((char*)sectionHeader->Name, 6) == rdataHash) {
            PBYTE dstSection = (PBYTE)dstAddress + sectionHeader->VirtualAddress;

            rdata->start = (char*)dstSection;
            rdata->length = sectionHeader->SizeOfRawData;
            rdata->offset = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
            return TRUE;
        }

        sectionHeader++;
    }
    return FALSE;
}
