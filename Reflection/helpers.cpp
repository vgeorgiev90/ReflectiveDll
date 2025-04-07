#include "structs.h"


// Hash seed
#define INITIAL_SEED 8


/*----------------------------------------------------------
    Simple wrapper around LdrLoadDll
----------------------------------------------------------*/
HMODULE Loader(LPSTR dllName, PWINAPIS pWinAPIs) {

    if (!dllName) {
        return NULL;
    }

    UNICODE_STRING uDll;
    WCHAR wideDllName[MAX_PATH];
    HANDLE hModule;
    DWORD dllNameLen = strlen(dllName);


    // Convert DllName to wide char
    for (size_t i = 0; i < dllNameLen; i++) {
        wideDllName[i] = (wchar_t)dllName[i];
    }

    // Null-terminate the wide string
    wideDllName[dllNameLen] = L'\0';


    // Prepare the unicode string
    uDll.Length = wcslen(wideDllName) * sizeof(WCHAR);
    uDll.MaximumLength = uDll.Length + sizeof(WCHAR);
    uDll.Buffer = wideDllName;

    // Invoke LdrLoadDll
    if (pWinAPIs->fnLoad(NULL, 0, &uDll, &hModule) == 0x00) {
        return (HMODULE)hModule;
    }
    else {
        return NULL;
    }
}


/*----------------------------------------------------------
    Simple hashing functions for ANSI and UNICODE strings
----------------------------------------------------------*/
UINT32 HashA(PCHAR String, SIZE_T Length)
{
    SIZE_T Index = 0;
    UINT32 Hash = 0;

    while (Index < Length)
    {
        Hash += String[Index++];
        Hash += Hash << INITIAL_SEED;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}


UINT32 HashW(PWCHAR String, USHORT Length)
{
    UINT32 Hash = 0;
    SIZE_T Index = 0;
    SIZE_T Count = Length / sizeof(WCHAR);

    while (Index < Count)
    {
        Hash += String[Index++];
        Hash += Hash << INITIAL_SEED;
        Hash ^= Hash >> 6;
    }

    Hash += Hash << 3;
    Hash ^= Hash >> 11;
    Hash += Hash << 15;

    return Hash;
}


/*----------------------------------------------------------
    Simple replacement for memcpy
----------------------------------------------------------*/
void MemCpy(LPVOID dst, LPVOID src, size_t size) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;

    int x;
    if (src == NULL) {
        for (x = 0; x < size; x++) {
            *d = 0x00;
            d++;
        }
    }
    else {
        for (x = 0; x < size; x++) {
            *d = *s;
            d++;
            s++;
        }
    }
}


/*----------------------------------------------------------
Replacement for GetModuleHandle that works with a UINT32 hash
----------------------------------------------------------*/
HMODULE GetHand(UINT32 hashLib) {

    // Read the PEB address from the GS register trough VS macro
#ifdef _WIN64 // if compiling as x64
    PPEB pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
    PPEB pPeb = (PEB*)(__readfsdword(0x30));
#endif

    // Get the LDR member of the PEB structure
    PPEB_LDR_DATA pLdr = pPeb->Ldr;

    // Get the InMemoryOrderModuleList member
    LIST_ENTRY ModuleList = pLdr->InMemoryOrderModuleList;

    // Get the first entry in the ModuleList
    PLDR_DATA_TABLE_ENTRY pTableEntry = (PLDR_DATA_TABLE_ENTRY)ModuleList.Flink;

    // Parse all entries until the correct lib is found
    while (pTableEntry) {

        if (pTableEntry->FullDllName.Length != NULL) {
            
            // If there is a match return a handle
            if (HashW(pTableEntry->FullDllName.Buffer, pTableEntry->FullDllName.Length) == hashLib) {
                return (HMODULE)(pTableEntry->InInitializationOrderLinks.Flink);
            }
        }
        else {
            break;
        }
        // Get next element
        pTableEntry = *(PLDR_DATA_TABLE_ENTRY*)(pTableEntry);
    }
    return NULL;
}


/*-------------------------------------------------------------------------
Simple replacement for GetProcAddress that works with hashed function name
It resolves forwarded functions and also imports by ordinal
-------------------------------------------------------------------------*/
FARPROC GetAddr(HMODULE hModule, UINT32 ApiHash, PWINAPIS pWinAPIs) {

    // Convert the handle to PBYTE for pointer arithmetic
    PBYTE peStart = (PBYTE)hModule;

    // Get the DOS header and verify it
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)peStart;
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    // Get the NT header and verify it
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(peStart + pDosHdr->e_lfanew);
    if (pNtHdr->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    // Get the optional headers
    IMAGE_OPTIONAL_HEADER pOptHdr = pNtHdr->OptionalHeader;

    // Get the image export table
    PIMAGE_EXPORT_DIRECTORY pExpTbl = (PIMAGE_EXPORT_DIRECTORY)(peStart + pOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Get the addresses of the function names, function addresses and function name ordinals arrays
    PDWORD fnNameArray = (PDWORD)(peStart + pExpTbl->AddressOfNames);
    PDWORD fnAddrArray = (PDWORD)(peStart + pExpTbl->AddressOfFunctions);
    PWORD fnNameOrdinals = (PWORD)(peStart + pExpTbl->AddressOfNameOrdinals);


    // Loop trough the exported functions, NumberOfFunctions is used as a max value
    for (DWORD i = 0; i < pExpTbl->NumberOfFunctions; i++) {
        // pointer to the function's name
        CHAR* pFuncName = (CHAR*)(peStart + fnNameArray[i]);

        // Ordinal of the function
        WORD funcOrdinal = fnNameOrdinals[i];

        // Getting the function's address trough its ordinal
        PVOID funcAddr = (PVOID)(peStart + fnAddrArray[funcOrdinal]);

        // If the required function is passed as ordinal instead of a string hash
        // just return its address
        if (ApiHash <= 0xFFFF && (WORD)ApiHash == funcOrdinal) {
            return (FARPROC)funcAddr;
        }

        // Else the function is passed by name and we need to check if its forwarded or not
        SIZE_T nameLen = strlen(pFuncName);
        if (ApiHash == HashA(pFuncName, nameLen)) {

            // Check if the function is forwarded from another dll and attempt to resolve its address
            if ((ULONG_PTR)funcAddr >= (ULONG_PTR)pExpTbl &&
                (ULONG_PTR)funcAddr < (ULONG_PTR)pExpTbl + pOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
            {
                UINT32 dot_index = 0;
                PCHAR forwardStr = (PCHAR)funcAddr;

                // Find the position of the . in the name eg. kernel32.Sleep
                for (UINT32 i = 0; i < strlen(forwardStr); i++)
                {
                    if (forwardStr[i] == '.')
                        dot_index = i;
                }

                // Extract the dll name and the function name
                CHAR dllName[MAX_PATH];
                CHAR funcName[MAX_PATH];

                MemCpy(dllName, funcAddr, dot_index);
                MemCpy(funcName, (forwardStr + dot_index + 1), strlen(forwardStr + dot_index + 1));

                // Null terminate the strings
                dllName[dot_index] = '\0';
                funcName[strlen(forwardStr + dot_index + 1)] = '\0';

                // Load the required library and try to resolve the function
                hModule = Loader(dllName, pWinAPIs);
                funcAddr = GetAddr(hModule, HashA(funcName, strlen(funcName)), pWinAPIs);

                return (FARPROC)funcAddr;
            }
            else {
                // If its not a forward just return the resolved address
                return (FARPROC)funcAddr;
            }
        }
    }
    return NULL;
}