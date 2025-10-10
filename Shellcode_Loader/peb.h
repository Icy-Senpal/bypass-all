#ifndef PEB_H
#define PEB_H

#include <windows.h>
#include "custom_crt.h"

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

__forceinline PEB* GetPEB() {
#ifdef _WIN64
    return (PEB*)__readgsqword(0x60);
#else
    return (PEB*)__readfsdword(0x30);
#endif
}

PVOID GetModuleBaseByName(LPCWSTR moduleName) {
    PEB* peb = GetPEB();
    PPEB_LDR_DATA ldr = peb->Ldr;
    LIST_ENTRY* listHead = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* listCurrent = listHead->Flink;

    while (listCurrent != listHead) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(listCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        
        if (entry->BaseDllName.Buffer) {
            wchar_t dllName[256];
            my_memset(dllName, 0, sizeof(dllName));
            
            size_t copyLen = entry->BaseDllName.Length / sizeof(wchar_t);
            if (copyLen > 255) copyLen = 255;
            
            for (size_t i = 0; i < copyLen; i++) {
                wchar_t c = entry->BaseDllName.Buffer[i];
                if (c >= L'A' && c <= L'Z') {
                    c = c + 32;
                }
                dllName[i] = c;
            }
            
            wchar_t targetName[256];
            my_memset(targetName, 0, sizeof(targetName));
            my_wcscpy(targetName, moduleName);
            
            for (int i = 0; targetName[i]; i++) {
                if (targetName[i] >= L'A' && targetName[i] <= L'Z') {
                    targetName[i] = targetName[i] + 32;
                }
            }
            
            if (my_wcscmp(dllName, targetName) == 0) {
                return entry->DllBase;
            }
        }
        
        listCurrent = listCurrent->Flink;
    }
    
    return NULL;
}

PVOID GetProcAddressByName(PVOID moduleBase, LPCSTR functionName) {
    if (!moduleBase) return NULL;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)moduleBase + 
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD* nameRVAs = (DWORD*)((BYTE*)moduleBase + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)moduleBase + exportDir->AddressOfNameOrdinals);
    DWORD* functionRVAs = (DWORD*)((BYTE*)moduleBase + exportDir->AddressOfFunctions);
    
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)moduleBase + nameRVAs[i]);
        
        if (my_strcmp(name, functionName) == 0) {
            WORD ordinal = ordinals[i];
            DWORD functionRVA = functionRVAs[ordinal];
            return (PVOID)((BYTE*)moduleBase + functionRVA);
        }
    }
    
    return NULL;
}

#endif


