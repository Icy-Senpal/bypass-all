/*
 * Beacon User Data (BUD)
 * -------------------------
 * Beacon User Data is a data structure that holds values which can be
 * passed from a User Defined Reflective Loader to Beacon.
 *
 * Cobalt Strike 4.x
 * ChangeLog:
 *    5/09/2023: initial version for 4.9
 *    2/15/2024: Added new syscalls API entries for 4.10
 *                  ntReadFile, ntWriteFile and ntCreateFile
 *               Added new structure to support setting the
 *                  addresses needed for Run Time Library (RTL)
 *                  functions, which supports some system calls.
 */
#ifndef _BEACON_USER_DATA_H
#define _BEACON_USER_DATA_H

#include <Windows.h>

#define COBALT_STRIKE_VERSION 0x041000
#define BOF_MEMORY_SIZE 0x10000
#define SLEEPMASK_MEMORY_SIZE 0x10000

#define DLL_BEACON_USER_DATA 0x0d
#define BEACON_USER_DATA_CUSTOM_SIZE 32

/* Syscalls API */
typedef struct {
    PVOID fnAddr;
    PVOID jmpAddr;
    DWORD sysnum;
} SYSCALL_API_ENTRY, *PSYSCALL_API_ENTRY;

typedef struct {
    SYSCALL_API_ENTRY ntAllocateVirtualMemory;
    SYSCALL_API_ENTRY ntProtectVirtualMemory;
    SYSCALL_API_ENTRY ntFreeVirtualMemory;
    SYSCALL_API_ENTRY ntGetContextThread;
    SYSCALL_API_ENTRY ntSetContextThread;
    SYSCALL_API_ENTRY ntResumeThread;
    SYSCALL_API_ENTRY ntCreateThreadEx;
    SYSCALL_API_ENTRY ntOpenProcess;
    SYSCALL_API_ENTRY ntOpenThread;
    SYSCALL_API_ENTRY ntClose;
    SYSCALL_API_ENTRY ntCreateSection;
    SYSCALL_API_ENTRY ntMapViewOfSection;
    SYSCALL_API_ENTRY ntUnmapViewOfSection;
    SYSCALL_API_ENTRY ntQueryVirtualMemory;
    SYSCALL_API_ENTRY ntDuplicateObject;
    SYSCALL_API_ENTRY ntReadVirtualMemory;
    SYSCALL_API_ENTRY ntWriteVirtualMemory;
    SYSCALL_API_ENTRY ntReadFile;
    SYSCALL_API_ENTRY ntWriteFile;
    SYSCALL_API_ENTRY ntCreateFile;
} SYSCALL_API, *PSYSCALL_API;

/* Additional Run Time Library (RTL) addresses used to support system calls.
 * If they are not set then system calls that require them will fall back
 * to the Standard Windows API.
 *
 * Required to support the following system calls:
 *    ntCreateFile
 */
typedef struct {
   PVOID rtlDosPathNameToNtPathNameUWithStatusAddr;
   PVOID rtlFreeHeapAddr;
   PVOID rtlGetProcessHeapAddr;
} RTL_API, *PRTL_API;

// We use enums here purely to make the code examples easier to read
typedef enum {
    COPY_FALSE,
    COPY_TRUE,
} COPY_PEHEADER;

typedef enum {
    MASK_FALSE,
    MASK_TRUE,
} ALLOCATED_MEMORY_MASK_MEMORY_BOOL;

typedef enum {
    PURPOSE_EMPTY,
    PURPOSE_GENERIC_BUFFER,
    PURPOSE_BEACON_MEMORY,
    PURPOSE_SLEEPMASK_MEMORY,
    PURPOSE_BOF_MEMORY,
    PURPOSE_USER_DEFINED_MEMORY = 1000
} ALLOCATED_MEMORY_PURPOSE;

typedef enum {
    LABEL_EMPTY,
    LABEL_BUFFER,
    LABEL_PEHEADER,
    LABEL_TEXT,
    LABEL_RDATA,
    LABEL_DATA,
    LABEL_PDATA,
    LABEL_RELOC,
    LABEL_USER_DEFINED = 1000
} ALLOCATED_MEMORY_LABEL;

typedef enum {
    METHOD_UNKNOWN,
    METHOD_VIRTUALALLOC,
    METHOD_HEAPALLOC,
    METHOD_MODULESTOMP,
    METHOD_NTMAPVIEW,
    METHOD_USER_DEFINED = 1000,
} ALLOCATED_MEMORY_ALLOCATION_METHOD;

/**
* This structure allows the user to provide additional information
* about the allocated heap for cleanup. It is mandatory to provide
* the HeapHandle but the DestroyHeap Boolean can be used to indicate
* whether the clean up code should destroy the heap or simply free the pages.
* This is useful in situations where a loader allocates memory in the
* processes current heap.
*/
typedef struct _HEAPALLOC_INFO {
    PVOID HeapHandle;
    BOOL  DestroyHeap;
} HEAPALLOC_INFO, *PHEAPALLOC_INFO;

typedef struct _MODULESTOMP_INFO {
    HMODULE ModuleHandle;
} MODULESTOMP_INFO, * PMODULESTOMP_INFO;

typedef union _ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION {
    HEAPALLOC_INFO HeapAllocInfo;
    MODULESTOMP_INFO ModuleStompInfo;
    PVOID Custom;
} ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION, *PALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION;

typedef struct _ALLOCATED_MEMORY_CLEANUP_INFORMATION {
    BOOL Cleanup;
    ALLOCATED_MEMORY_ALLOCATION_METHOD AllocationMethod;
    ALLOCATED_MEMORY_ADDITIONAL_CLEANUP_INFORMATION AdditionalCleanupInformation;
} ALLOCATED_MEMORY_CLEANUP_INFORMATION, *PALLOCATED_MEMORY_CLEANUP_INFORMATION;

typedef struct _ALLOCATED_MEMORY_SECTION {
    ALLOCATED_MEMORY_LABEL Label; // A label to simplify Sleepmask development
    PVOID  BaseAddress;           // Pointer to virtual address of section
    SIZE_T VirtualSize;           // Virtual size of the section
    DWORD  CurrentProtect;        // Current memory protection of the section
    DWORD  PreviousProtect;       // The previous memory protection of the section (prior to masking/unmasking)
    BOOL   MaskSection;           // A boolean to indicate whether the section should be masked
} ALLOCATED_MEMORY_SECTION, *PALLOCATED_MEMORY_SECTION;

typedef struct _ALLOCATED_MEMORY_REGION {
    ALLOCATED_MEMORY_PURPOSE Purpose;      // A label to indicate the purpose of the allocated memory
    PVOID  AllocationBase;                 // The base address of the allocated memory block
    SIZE_T RegionSize;                     // The size of the allocated memory block 
    DWORD Type;                            // The type of memory allocated
    ALLOCATED_MEMORY_SECTION Sections[8];  // An array of section information structures
    ALLOCATED_MEMORY_CLEANUP_INFORMATION CleanupInformation; // Information required to cleanup the allocation
} ALLOCATED_MEMORY_REGION, *PALLOCATED_MEMORY_REGION;

typedef struct {
    ALLOCATED_MEMORY_REGION AllocatedMemoryRegions[6];
} ALLOCATED_MEMORY, *PALLOCATED_MEMORY;

/* Beacon User Data
 *
 * version format: 0xMMmmPP, where MM = Major, mm = Minor, and PP = Patch
 * e.g. 0x040900 -> CS 4.9
 *      0x041000 -> CS 4.10
*/
typedef struct {
    unsigned int version;
    PSYSCALL_API syscalls;
    char         custom[BEACON_USER_DATA_CUSTOM_SIZE];
    PRTL_API     rtls;
    PALLOCATED_MEMORY allocatedMemory;
} USER_DATA, *PUSER_DATA;
#endif
