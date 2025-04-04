#pragma once
#include <windows.h>



/*-------------------------------
   Generic windows structures
-------------------------------*/
typedef VOID(PS_POST_PROCESS_INIT_ROUTINE)(VOID);
typedef PS_POST_PROCESS_INIT_ROUTINE* PPS_POST_PROCESS_INIT_ROUTINE;


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;


typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    PVOID                         Reserved4[3];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[45];
    BYTE                          Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE                          Reserved11[128];
    PVOID                         Reserved12[1];
    ULONG                         SessionId;
} PEB, * PPEB;


typedef struct _ACTIVATION_CONTEXT {
    ULONG   cbSize;
    DWORD   dwFlags;
    LPCTSTR lpSource;
    USHORT  wProcessorArchitecture;
    LANGID  wLangId;
    LPCTSTR lpAssemblyDirectory;
    LPCTSTR lpResourceName;
    LPCTSTR lpApplicationName;

} ACTIVATION_CONTEXT, * PACTIVATION_CONTEXT;


typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PACTIVATION_CONTEXT EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _BASE_RELOCATION_ENTRY {
    WORD	Offset : 12;  
    WORD	Type : 4; 
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;



/*------------------------------------------
    Custom structs and function signatures
------------------------------------------*/
typedef LPVOID(WINAPI* Alloc_t)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
    ); // VirtualAlloc

typedef LPVOID(WINAPI* Load_t)(
    LPCSTR libName
    ); // LoadLibraryA

typedef BOOL(WINAPI* Protect_t)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
    ); // VirtualProtect

typedef FARPROC(WINAPI* Getter_t)(
    HMODULE hModule,
    LPCSTR name
    ); // GetProcAddress


typedef NTSTATUS(NTAPI* Flush_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG Length
    ); // NtFlushInstructionCache



/*-----------------------------------------
   Simple struct to hold the resolved APIs
-----------------------------------------*/
typedef struct _WINAPIS {
    Alloc_t fnAlloc;
    Load_t fnLoad;
    Protect_t fnProt;
    Getter_t Getter;
    Flush_t Flusher;

}WINAPIS, * PWINAPIS;



/*-----------------------------------------
   Simple struct to hold the PE info 
   that will be used to reflectively load it
-----------------------------------------*/
typedef struct _PEHDRS {
    LPVOID pPeBuffer;
    SIZE_T PeSize;

    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_SECTION_HEADER pSectHeader;

    PIMAGE_DATA_DIRECTORY pImportDir;
    PIMAGE_DATA_DIRECTORY pRelocDir;
}PEHDRS, * PPEHDRS;