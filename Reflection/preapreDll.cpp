#include "main.h"



/*----------------------------------------------------------
Parse the DLL's PE headers and store them for further usage
----------------------------------------------------------*/
BOOL ParsePEHeaders(PPEHDRS pPeHdrs, LPVOID dllBaseAddress) {

    pPeHdrs->pPeBuffer = dllBaseAddress;

    // Get NT headers
    pPeHdrs->pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pPeHdrs->pPeBuffer + ((PIMAGE_DOS_HEADER)pPeHdrs->pPeBuffer)->e_lfanew);
    if (pPeHdrs->pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    // Get the PE's size, RVA to section header, import directory and relocation directory
    pPeHdrs->PeSize = (SIZE_T)pPeHdrs->pNtHeaders->OptionalHeader.SizeOfImage;;
    pPeHdrs->pSectHeader = IMAGE_FIRST_SECTION(pPeHdrs->pNtHeaders);
    pPeHdrs->pImportDir = &pPeHdrs->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    pPeHdrs->pRelocDir = &pPeHdrs->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    return TRUE;
}


/*----------------------------------------------------------
Prepare new memory block for the PE's sections and copy them
----------------------------------------------------------*/
LPVOID PreparePEMemory(PPEHDRS pPeHdrs, PWINAPIS pWinAPIs) {

    // Allocate new memory block
    LPVOID pPEBase = pWinAPIs->fnAlloc(NULL, pPeHdrs->PeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pPEBase == NULL) {
        return NULL;
    }

    // Copy all the PE sections to the new block
    for (DWORD z = 0; z < pPeHdrs->pNtHeaders->FileHeader.NumberOfSections; z++) {

        // If DLL is in the form of a file PointerToRawData is to be used
        // if just testing with rundll32 the VirtualAddress is to be used
        //LPVOID src = (PBYTE)pPeHdrs->pPeBuffer + pPeHdrs->pSectHeader[z].VirtualAddress;
        LPVOID src = (PBYTE)pPeHdrs->pPeBuffer + pPeHdrs->pSectHeader[z].PointerToRawData;
        LPVOID dest = (PBYTE)pPEBase + pPeHdrs->pSectHeader[z].VirtualAddress;

        MemCpy(
            dest,
            src,
            pPeHdrs->pSectHeader[z].SizeOfRawData
        );
    }
    return pPEBase;
}


/*----------------------------------------------------------
Fix the PE's Import table and resolve all functions
----------------------------------------------------------*/
BOOL FixIAT(PPEHDRS pPeHdrs, LPVOID pPEBase, PWINAPIS pWinAPIs) {

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;
    for (SIZE_T i = 0; i < pPeHdrs->pImportDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

        // Get the current import descriptor
        pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)pPEBase + (DWORD_PTR)pPeHdrs->pImportDir->VirtualAddress + i);

        // debug validation
        if ((ULONG_PTR)pImportDesc < (ULONG_PTR)pPEBase ||
            (ULONG_PTR)pImportDesc >= (ULONG_PTR)((PBYTE)pPEBase + pPeHdrs->PeSize)) {
            return FALSE;
        }

        // if both thunks are null the end of the import table is reached
        if (pImportDesc->OriginalFirstThunk == NULL && pImportDesc->FirstThunk == NULL) {
            break;
        }


        // Extract the DLL name and attempt to load it
        LPSTR DllName = (LPSTR)((PBYTE)pPEBase + pImportDesc->Name);
        ULONG_PTR origFirstThunkRVA = pImportDesc->OriginalFirstThunk;
        ULONG_PTR firstThunkRVA = pImportDesc->FirstThunk;
        SIZE_T ThunkSize = 0x00; // Used to move to the next function (iterating through the IAT and INT)
        HMODULE hModule = NULL;

        // Load the required DLL
        hModule = (HMODULE)pWinAPIs->fnLoad(DllName);
        if (hModule == NULL) {
            return FALSE;
        }

        // Loop trough the imported functions
        while (TRUE) {
            PIMAGE_THUNK_DATA pOrigFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)pPEBase + origFirstThunkRVA + ThunkSize);
            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((PBYTE)pPEBase + firstThunkRVA + ThunkSize);
            PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
            PVOID pFuncAddress = NULL;

            if (pOrigFirstThunk->u1.Function == NULL && pFirstThunk->u1.Function == NULL) {
                break;
            }

            // if ordinal flag is set get the function's address trough its ordinal, else trough its name
            if (IMAGE_SNAP_BY_ORDINAL(pOrigFirstThunk->u1.Ordinal)) {
                pFuncAddress = pWinAPIs->Getter(hModule, (LPCSTR)(WORD)IMAGE_ORDINAL(pOrigFirstThunk->u1.Ordinal));
            }
            // else get function by name
            else {
                pImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pPEBase + pOrigFirstThunk->u1.AddressOfData);
                pFuncAddress = pWinAPIs->Getter(hModule, pImportByName->Name);
            }
            // Update the first thunk with the resolved function address
            pFirstThunk->u1.Function = (ULONGLONG)pFuncAddress;
            ThunkSize += sizeof(IMAGE_THUNK_DATA);
        }
    }
    return TRUE;
}



/*----------------------------------------------------------
Apply all relocations in the PE's relocation table
----------------------------------------------------------*/
void ApplyRelocations(PPEHDRS pPeHdrs, LPVOID pPEBase) {

    PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pPEBase + pPeHdrs->pRelocDir->VirtualAddress);
    ULONG_PTR delta = (DWORD_PTR)pPEBase - pPeHdrs->pNtHeaders->OptionalHeader.ImageBase;

    PBASE_RELOCATION_ENTRY pRelocEntry = NULL;

    while (pBaseReloc->VirtualAddress) {

        pRelocEntry = (PBASE_RELOCATION_ENTRY)(pBaseReloc + 1);

        while ((PBYTE)pRelocEntry != (PBYTE)pBaseReloc + pBaseReloc->SizeOfBlock) {

            if (pRelocEntry->Type == IMAGE_REL_BASED_DIR64) {
                *((ULONG_PTR*)((PBYTE)pPEBase + pBaseReloc->VirtualAddress + pRelocEntry->Offset)) += delta;
            }
            else if (pRelocEntry->Type == IMAGE_REL_BASED_HIGHLOW) {
                *((DWORD*)((PBYTE)pPEBase + pBaseReloc->VirtualAddress + pRelocEntry->Offset)) += (DWORD)delta;
            }
            else if (pRelocEntry->Type == IMAGE_REL_BASED_HIGH) {
                *((WORD*)((PBYTE)pPEBase + pBaseReloc->VirtualAddress + pRelocEntry->Offset)) += HIWORD(delta);
            }
            else if (pRelocEntry->Type == IMAGE_REL_BASED_LOW) {
                *((WORD*)((PBYTE)pPEBase + pBaseReloc->VirtualAddress + pRelocEntry->Offset)) += LOWORD(delta);
            }
            else if (pRelocEntry->Type == IMAGE_REL_BASED_ABSOLUTE) {
                pRelocEntry++;
                continue; // skip padding
            }

            pRelocEntry++;
        }
        pBaseReloc = (PIMAGE_BASE_RELOCATION)pRelocEntry;
    }
}


/*----------------------------------------------------------
Fix the PE's sections memory protection
----------------------------------------------------------*/
BOOL FixMemProtections(PPEHDRS pPeHdrs, LPVOID pPEBase, PWINAPIS pWinAPIs) {

    SIZE_T secSize;
    PVOID secAddr;

    for (DWORD i = 0; i < pPeHdrs->pNtHeaders->FileHeader.NumberOfSections; i++) {
        DWORD old = NULL, MemProtect = NULL;

        if (pPeHdrs->pSectHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            MemProtect = PAGE_WRITECOPY;
        }
        if (pPeHdrs->pSectHeader[i].Characteristics & IMAGE_SCN_MEM_READ) {
            MemProtect = PAGE_READONLY;
        }
        if ((pPeHdrs->pSectHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pPeHdrs->pSectHeader[i].Characteristics & IMAGE_SCN_MEM_READ)) {
            MemProtect = PAGE_READWRITE;
        }
        if (pPeHdrs->pSectHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            MemProtect = PAGE_EXECUTE;
        }
        if ((pPeHdrs->pSectHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pPeHdrs->pSectHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)) {
            MemProtect = PAGE_EXECUTE_WRITECOPY;
        }
        if ((pPeHdrs->pSectHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pPeHdrs->pSectHeader[i].Characteristics & IMAGE_SCN_MEM_READ)) {
            MemProtect = PAGE_EXECUTE_READ;
        }
        if (
            (pPeHdrs->pSectHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            && (pPeHdrs->pSectHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            && (pPeHdrs->pSectHeader[i].Characteristics & IMAGE_SCN_MEM_READ)
            ) {
            MemProtect = PAGE_EXECUTE_READWRITE;
        }

        // Apply the correct memory protection for the particular section
        secSize = pPeHdrs->pSectHeader[i].SizeOfRawData;
        secAddr = (PBYTE)pPEBase + pPeHdrs->pSectHeader[i].VirtualAddress;
        if (!pWinAPIs->fnProt(secAddr, secSize, MemProtect, &old)) {
            return FALSE;
        }
    }
    return TRUE;
}