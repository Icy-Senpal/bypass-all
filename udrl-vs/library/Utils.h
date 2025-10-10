#pragma once
#include <windows.h>
#include "LoaderTypes.h"
#include "TrackMemory.h"

#define PIC_STRING(NAME, STRING) constexpr char NAME[]{ STRING }
#define PIC_WSTRING(NAME, STRING) constexpr wchar_t NAME[]{ STRING }

void* GetLocation();
_PPEB GetPEBAddress();
ULONG_PTR FindBufferBaseAddress();
ULONG_PTR FindBufferBaseAddressStephenFewer();
BOOL CopyPEHeader(ULONG_PTR srcImage, ULONG_PTR dstAddress);
BOOL CopyPESections(ULONG_PTR srcImage, ULONG_PTR dstAddress);
BOOL CopyDllAndTrackMemory(PALLOCATED_MEMORY_REGION allocatedMemoryRegion, ULONG_PTR srcImage, ULONG_PTR dstAddress, COPY_PEHEADER copyPEHeader, DWORD memoryProtections, ALLOCATED_MEMORY_MASK_MEMORY_BOOL mask);
BOOL CopyPEHeaderAndTrackMemory(PALLOCATED_MEMORY_REGION allocatedMemoryRegion, ULONG_PTR srcImage, PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress, DWORD memoryProtections, ALLOCATED_MEMORY_MASK_MEMORY_BOOL mask);
BOOL CopyPESectionsAndTrackMemory(PALLOCATED_MEMORY_REGION allocatedMemoryRegion, ULONG_PTR srcImage, PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress, DWORD memoryProtections, ALLOCATED_MEMORY_MASK_MEMORY_BOOL mask, COPY_PEHEADER copyPeHeader);
void ResolveImports(PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress, PWINDOWSAPIS winApi);
void ProcessRelocations(PIMAGE_NT_HEADERS ntHeader, ULONG_PTR dstAddress);
BOOL ResolveRdataSection(ULONG_PTR srcImage, ULONG_PTR dstAddress, PRDATA_SECTION rdata);
