#pragma once
#include <windows.h>
#include "BeaconUserData.h"

void TrackAllocatedMemoryRegion(PALLOCATED_MEMORY_REGION allocatedMemoryRegion, ALLOCATED_MEMORY_PURPOSE purpose, PVOID allocationBase, SIZE_T size, DWORD memoryType, PALLOCATED_MEMORY_CLEANUP_INFORMATION memoryCleanupInformation);
void TrackAllocatedMemorySection(PALLOCATED_MEMORY_SECTION allocatedMemorySection, ALLOCATED_MEMORY_LABEL label, PVOID baseAddress, SIZE_T virtualSize, DWORD memoryProtections, ALLOCATED_MEMORY_MASK_MEMORY_BOOL mask);
void TrackAllocatedMemoryBuffer(PALLOCATED_MEMORY_REGION allocatedMemoryRegion, ALLOCATED_MEMORY_PURPOSE purpose, PVOID baseAddress, SIZE_T size, DWORD memoryType, DWORD memoryProtections, PALLOCATED_MEMORY_CLEANUP_INFORMATION memoryCleanupInformation, ALLOCATED_MEMORY_MASK_MEMORY_BOOL mask);
ALLOCATED_MEMORY_LABEL GetSectionLabelFromName(const PBYTE sectionName);
