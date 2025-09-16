// ============================================================================
// Combined Info-Stealer Deception DLL
// Techniques included:
//   [A] File System Scanning deception (FindFirst/FindNext/Create/Read hooks)
//   [B] Registry Mining deception (RegOpen/Query/Set/Create hooks)
// ============================================================================

#include "pch.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <easyhook.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <mutex>
#include <map>
#include <cstring> // for strncpy_s, strlen

#pragma comment(lib, "EasyHook32.lib") // or EasyHook64.lib

using namespace std;


// ============================================================================
// Shared logging (used by both [A] and [B])
// ============================================================================

std::mutex     logMutex;
std::ofstream  apiLog("api_log.txt", std::ios::app);

// API name logger (lightweight; no behavior change)
void LogApiCall(const std::string& apiName)
{
    std::lock_guard<std::mutex> lock(logMutex);
    if (apiLog.is_open())
    {
        apiLog << "[API Called] " << apiName << "()" << std::endl;
        apiLog.flush();
    }
}


// ============================================================================
// [A] DLL code of File System Scanning
// ============================================================================

// === Targets ===
const std::vector<std::wstring> targetKeywordsW = { L"wallet", L"api_key", L"credential", L"password", L"profile" };
const std::vector<std::wstring> targetExtensionsW = { L".json", L".conf", L".ini", L".txt" };

const std::vector<std::string> targetKeywordsA = { "wallet", "api_key", "credential", "password", "profile" };
const std::vector<std::string> targetExtensionsA = { ".json", ".conf", ".ini", ".txt" };

const std::wstring decoyWide = L"decoy_config.ini";
const std::string decoyAnsi = "decoy_config.ini";
const char* decoyContent = "FAKE_API_KEY=1234-DECOY-5678\nusername=honey\npassword=trap\n";

// === Hook Handles ===
HOOK_TRACE_INFO hHooks[8] = {};

// === Original API pointers ===
decltype(&FindFirstFileW) TrueFindFirstFileW = FindFirstFileW;
decltype(&FindNextFileW)  TrueFindNextFileW  = FindNextFileW;
decltype(&FindFirstFileA) TrueFindFirstFileA = FindFirstFileA;
decltype(&FindNextFileA)  TrueFindNextFileA  = FindNextFileA;
decltype(&CreateFileW)    TrueCreateFileW    = CreateFileW;
decltype(&CreateFileA)    TrueCreateFileA    = CreateFileA;
decltype(&ReadFile)       TrueReadFile       = ReadFile;
decltype(&ReadFileEx)     TrueReadFileEx     = ReadFileEx;

// === Sensitivity Checks ===
bool IsSensitiveW(const std::wstring& name) {
    std::wstring lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    for (const auto& k : targetKeywordsW)
        if (lower.find(k) != std::wstring::npos) return true;
    for (const auto& e : targetExtensionsW)
        if (lower.size() >= e.size() && _wcsicmp(lower.c_str() + lower.size() - e.size(), e.c_str()) == 0)
            return true;
    return false;
}

bool IsSensitiveA(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (const auto& k : targetKeywordsA)
        if (lower.find(k) != std::string::npos) return true;
    for (const auto& e : targetExtensionsA)
        if (lower.size() >= e.size() && _stricmp(lower.c_str() + lower.size() - e.size(), e.c_str()) == 0)
            return true;
    return false;
}

// === Hooked Find/Replace Functions ===
HANDLE WINAPI MyFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
    LogApiCall("FindFirstFileW");
    HANDLE hFind = TrueFindFirstFileW(lpFileName, lpFindFileData);
    if (hFind != INVALID_HANDLE_VALUE && IsSensitiveW(lpFindFileData->cFileName)) {
        wcscpy_s(lpFindFileData->cFileName, MAX_PATH, decoyWide.c_str());
        wcout << L"[Deception-W] FindFirstFileW: " << lpFileName << " → " << decoyWide << endl;
    }
    return hFind;
}

BOOL WINAPI MyFindNextFileW(HANDLE hFind, LPWIN32_FIND_DATAW lpFindFileData) {
    LogApiCall("FindNextFileW");
    BOOL result = TrueFindNextFileW(hFind, lpFindFileData);
    if (result && IsSensitiveW(lpFindFileData->cFileName)) {
        wcscpy_s(lpFindFileData->cFileName, MAX_PATH, decoyWide.c_str());
        wcout << L"[Deception-W] FindNextFileW: → " << decoyWide << endl;
    }
    return result;
}

HANDLE WINAPI MyFindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) {
    LogApiCall("FindFirstFileA");
    HANDLE hFind = TrueFindFirstFileA(lpFileName, lpFindFileData);
    if (hFind != INVALID_HANDLE_VALUE && IsSensitiveA(lpFindFileData->cFileName)) {
        strcpy_s(lpFindFileData->cFileName, MAX_PATH, decoyAnsi.c_str());
        cout << "[Deception-A] FindFirstFileA: " << lpFileName << " → " << decoyAnsi << endl;
    }
    return hFind;
}

BOOL WINAPI MyFindNextFileA(HANDLE hFind, LPWIN32_FIND_DATAA lpFindFileData) {
    LogApiCall("FindNextFileA");
    BOOL result = TrueFindNextFileA(hFind, lpFindFileData);
    if (result && IsSensitiveA(lpFindFileData->cFileName)) {
        strcpy_s(lpFindFileData->cFileName, MAX_PATH, decoyAnsi.c_str());
        cout << "[Deception-A] FindNextFileA: → " << decoyAnsi << endl;
    }
    return result;
}

// === Hooked CreateFile Functions ===
HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSec, DWORD dwCreationDisposition, DWORD dwFlags, HANDLE hTemplate) {
    LogApiCall("CreateFileW");
    if (IsSensitiveW(lpFileName)) {
        wcout << L"[Deception-W] Redirecting CreateFileW: " << lpFileName << " → " << decoyWide << endl;
        lpFileName = decoyWide.c_str();
    }
    return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSec, dwCreationDisposition, dwFlags, hTemplate);
}

HANDLE WINAPI MyCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSec, DWORD dwCreationDisposition, DWORD dwFlags, HANDLE hTemplate) {
    LogApiCall("CreateFileA");
    if (IsSensitiveA(lpFileName)) {
        cout << "[Deception-A] Redirecting CreateFileA: " << lpFileName << " → " << decoyAnsi << endl;
        lpFileName = decoyAnsi.c_str();
    }
    return TrueCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSec, dwCreationDisposition, dwFlags, hTemplate);
}

// === Hooked ReadFile: inject fake content ===
BOOL WINAPI MyReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    LogApiCall("ReadFile");
    BOOL result = TrueReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    if (result && lpBuffer && lpNumberOfBytesRead && *lpNumberOfBytesRead > 0) {
        strncpy_s((char*)lpBuffer, nNumberOfBytesToRead, decoyContent, _TRUNCATE);
        *lpNumberOfBytesRead = (DWORD)strlen(decoyContent);
        cout << "[Deception] ReadFile → Replaced content with decoy.\n";
    }
    return result;
}

// === Hooked ReadFileEx: inject fake content ===
BOOL WINAPI MyReadFileEx(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    LogApiCall("ReadFileEx");
    BOOL result = TrueReadFileEx(hFile, lpBuffer, nNumberOfBytesToRead, lpOverlapped, lpCompletionRoutine);
    if (result && lpBuffer) {
        strncpy_s((char*)lpBuffer, nNumberOfBytesToRead, decoyContent, _TRUNCATE);
        cout << "[Deception] ReadFileEx → Replaced content with decoy.\n";
    }
    return result;
}


// ============================================================================
// [B] DLL Code of Registry Mining
// ============================================================================

std::wstring gTargetKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
std::map<std::wstring, std::wstring> gDecoyRegistryData = {
    {L"DefaultUserName",      L"DecoyUser"},
    {L"DefaultPassword",      L"FakeP@ss123"},
    {L"AutoAdminLogon",       L"0"},
    {L"AltDefaultUserName",   L"AltDecoy"},
    {L"AltDefaultDomainName", L"FAKE_DOMAIN"}
};

std::map<HKEY, bool> gTrackedHandles;

// === Typedefs for original functions ===
typedef LONG(WINAPI* RegOpenKeyExW_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LONG(WINAPI* RegQueryValueExW_t)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LONG(WINAPI* RegSetValueExW_t)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
typedef LONG(WINAPI* RegCreateKeyExW_t)(
    HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);

// === Original function pointers ===
RegOpenKeyExW_t    TrueRegOpenKeyExW    = nullptr;
RegQueryValueExW_t TrueRegQueryValueExW = nullptr;
RegSetValueExW_t   TrueRegSetValueExW   = nullptr;
RegCreateKeyExW_t  TrueRegCreateKeyExW  = nullptr;

// === Hooked Functions ===

// Intercepts RegOpenKeyExW and tracks Winlogon handle
LONG WINAPI HookedRegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    LogApiCall("RegOpenKeyExW");

    LONG result = TrueRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);

    if (result == ERROR_SUCCESS && lpSubKey) {
        std::wstring subKey(lpSubKey);
        std::transform(subKey.begin(), subKey.end(), subKey.begin(), ::towlower);
        std::wstring target = gTargetKey;
        std::transform(target.begin(), target.end(), target.begin(), ::towlower);

        if (subKey == target && phkResult) {
            gTrackedHandles[*phkResult] = true;
            wcout << L"[Hook] Tracking Winlogon key handle: " << *phkResult << endl;
        }
    }

    return result;
}

// Intercepts value queries and returns decoy
LONG WINAPI HookedRegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved,
    LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    LogApiCall("RegQueryValueExW");

    if (gTrackedHandles.count(hKey) && lpValueName) {
        std::wstring valName(lpValueName);

        if (gDecoyRegistryData.count(valName)) {
            std::wstring decoy = gDecoyRegistryData[valName];
            size_t sizeInBytes = (decoy.size() + 1) * sizeof(wchar_t);

            if (lpType) *lpType = REG_SZ;
            if (lpData && lpcbData && *lpcbData >= sizeInBytes) {
                memcpy(lpData, decoy.c_str(), sizeInBytes);
                *lpcbData = (DWORD)sizeInBytes;
            }
            else if (lpcbData) {
                *lpcbData = (DWORD)sizeInBytes;
            }

            wcout << L"[Deception] Returning decoy for '" << valName << L"': " << decoy << endl;
            return ERROR_SUCCESS;
        }
    }

    return TrueRegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

// Intercepts value setting, blocks sensitive writes
LONG WINAPI HookedRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved,
    DWORD dwType, const BYTE* lpData, DWORD cbData)
{
    LogApiCall("RegSetValueExW");

    if (gTrackedHandles.count(hKey) && lpValueName) {
        std::wstring valName(lpValueName);

        if (gDecoyRegistryData.count(valName)) {
            wcout << L"[Deception] BLOCKED RegSetValueExW for key: " << valName << endl;
            return ERROR_ACCESS_DENIED; // Block write
        }
    }

    return TrueRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

// Intercepts RegCreateKeyExW, blocks creation under Winlogon
LONG WINAPI HookedRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved,
    LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult, LPDWORD lpdwDisposition)
{
    LogApiCall("RegCreateKeyExW");

    if (lpSubKey) {
        std::wstring subKey(lpSubKey);
        std::wstring fullKeyPath = subKey;
        std::transform(fullKeyPath.begin(), fullKeyPath.end(), fullKeyPath.begin(), ::towlower);

        std::wstring target = gTargetKey;
        std::transform(target.begin(), target.end(), target.begin(), ::towlower);

        if (fullKeyPath.find(target) != std::wstring::npos) {
            wcout << L"[Deception] BLOCKED RegCreateKeyExW under: " << lpSubKey << endl;
            return ERROR_ACCESS_DENIED;
        }
    }

    return TrueRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions,
        samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
}


// ============================================================================
// Unified EasyHook DLL entry — installs BOTH [A] and [B] hook sets
// ============================================================================

extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO * inRemoteInfo)
{
    // ---------------------------
    // [A] Install File System Scanning hooks
    // ---------------------------
    cout << "[*] Injection started (FS + Read deception).\n";

    struct HookDef {
        const char* name;
        FARPROC addr;
        PVOID hookFn;
        HOOK_TRACE_INFO* handle;
    } hooks[] = {
        { "FindFirstFileW", GetProcAddress(GetModuleHandleW(L"kernel32"), "FindFirstFileW"), MyFindFirstFileW, &hHooks[0] },
        { "FindNextFileW",  GetProcAddress(GetModuleHandleW(L"kernel32"), "FindNextFileW"),  MyFindNextFileW,  &hHooks[1] },
        { "FindFirstFileA", GetProcAddress(GetModuleHandleW(L"kernel32"), "FindFirstFileA"), MyFindFirstFileA, &hHooks[2] },
        { "FindNextFileA",  GetProcAddress(GetModuleHandleW(L"kernel32"), "FindNextFileA"),  MyFindNextFileA,  &hHooks[3] },
        { "CreateFileW",    GetProcAddress(GetModuleHandleW(L"kernel32"), "CreateFileW"),    MyCreateFileW,    &hHooks[4] },
        { "CreateFileA",    GetProcAddress(GetModuleHandleW(L"kernel32"), "CreateFileA"),    MyCreateFileA,    &hHooks[5] },
        { "ReadFile",       GetProcAddress(GetModuleHandleW(L"kernel32"), "ReadFile"),       MyReadFile,       &hHooks[6] },
        { "ReadFileEx",     GetProcAddress(GetModuleHandleW(L"kernel32"), "ReadFileEx"),     MyReadFileEx,     &hHooks[7] },
    };

    ULONG acl[1] = { 0 };
    for (const auto& h : hooks) {
        if (LhInstallHook(h.addr, h.hookFn, nullptr, h.handle) == 0) {
            LhSetExclusiveACL(acl, 1, h.handle);
            cout << "[+] Hooked " << h.name << "\n";
        }
        else {
            cerr << "[-] Failed to hook " << h.name << "\n";
        }
    }

    cout << "[*] All FS hooks installed.\n";

    // ---------------------------
    // [B] Install Registry Mining hooks
    // ---------------------------
    cout << "[*] Registry deception injection started.\n";

    HOOK_TRACE_INFO hOpenHook   = { NULL };
    HOOK_TRACE_INFO hQueryHook  = { NULL };
    HOOK_TRACE_INFO hSetHook    = { NULL };
    HOOK_TRACE_INFO hCreateHook = { NULL };

    HMODULE advapi = GetModuleHandleW(L"advapi32.dll");

    if (!advapi) {
        wcerr << L"[!] Failed to load advapi32.dll\n";
        return;
    }

    TrueRegOpenKeyExW    = (RegOpenKeyExW_t)   GetProcAddress(advapi, "RegOpenKeyExW");
    TrueRegQueryValueExW = (RegQueryValueExW_t)GetProcAddress(advapi, "RegQueryValueExW");
    TrueRegSetValueExW   = (RegSetValueExW_t)  GetProcAddress(advapi, "RegSetValueExW");
    TrueRegCreateKeyExW  = (RegCreateKeyExW_t) GetProcAddress(advapi, "RegCreateKeyExW");

    if (!TrueRegOpenKeyExW || !TrueRegQueryValueExW || !TrueRegSetValueExW || !TrueRegCreateKeyExW) {
        wcerr << L"[!] Failed to resolve one or more registry API addresses.\n";
        return;
    }

    // Install Hooks
    LhInstallHook((LPVOID)TrueRegOpenKeyExW,    HookedRegOpenKeyExW,   nullptr, &hOpenHook);
    LhInstallHook((LPVOID)TrueRegQueryValueExW, HookedRegQueryValueExW, nullptr, &hQueryHook);
    LhInstallHook((LPVOID)TrueRegSetValueExW,   HookedRegSetValueExW,  nullptr, &hSetHook);
    LhInstallHook((LPVOID)TrueRegCreateKeyExW,  HookedRegCreateKeyExW, nullptr, &hCreateHook);

    ULONG ACLEntries[1] = { 0 };
    LhSetExclusiveACL(ACLEntries, 1, &hOpenHook);
    LhSetExclusiveACL(ACLEntries, 1, &hQueryHook);
    LhSetExclusiveACL(ACLEntries, 1, &hSetHook);
    LhSetExclusiveACL(ACLEntries, 1, &hCreateHook);

    cout << "[*] Registry API deception hooks installed.\n";
}
