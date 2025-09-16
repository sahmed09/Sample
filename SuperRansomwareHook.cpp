// ============================================================================
// Combined Anti-Ransomware DLL
// Techniques included (logic UNCHANGED; original comments preserved):
//   [A] File-Based Encryption blocking (CreateFileW / WriteFile / SetFilePointer / FlushFileBuffers)
//   [B] File Renaming or Extension Change blocking (MoveFileW / MoveFileExW)
// ============================================================================

#include "pch.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <easyhook.h>
#include <string>
#include <set>
#include <iostream>
#include <unordered_map>
#include <fstream>
#include <ctime>
#include <vector>
#include <algorithm>
#include <sstream>
#include <map>
#include <cstring>
#include <cstdint>

#ifdef _WIN64
#pragma comment(lib, "EasyHook64.lib")
#else
#pragma comment(lib, "EasyHook32.lib") // or EasyHook64.lib depending on your target
#endif

using namespace std;


// ============================================================================
// [A] DLL Code of File-Based Encryption (ORIGINAL CONTENT PRESERVED)
// ============================================================================

// Target extensions
const set<wstring> BLOCKED_EXTENSIONS = { L".docx", L".xlsx", L".db", L".txt" };

// Map to track ransomware file handles
unordered_map<HANDLE, bool> ransomwareHandles;
CRITICAL_SECTION handleMapLock;
CRITICAL_SECTION logLock;

// Utility: get file extension
wstring GetFileExtension(const wstring& filePath)
{
    size_t pos = filePath.find_last_of(L'.');
    if (pos == wstring::npos) return L"";
    return filePath.substr(pos);
}

// Fake failure for ransomware targets
bool IsRansomwareTarget(LPCWSTR lpFileName)
{
    wstring path(lpFileName);
    wstring ext = GetFileExtension(path);

    for (const auto& blocked : BLOCKED_EXTENSIONS)
    {
        if (_wcsicmp(ext.c_str(), blocked.c_str()) == 0)
            return true;
    }
    return false;
}

void LogAPIUsage(const string& apiName, const wstring& info)
{
    EnterCriticalSection(&logLock);

    ofstream log("api_log.txt", ios::app);
    if (log.is_open())
    {
        // Timestamp
        time_t now = time(nullptr);
        char timebuf[32];
        ctime_s(timebuf, sizeof(timebuf), &now);
        timebuf[strcspn(timebuf, "\n")] = 0; // Strip newline

        log << "[" << timebuf << "] " << apiName << ": ";
        log << string(info.begin(), info.end()) << endl;

        log.close();
    }

    LeaveCriticalSection(&logLock);
}

/////////////////////////////////////////////////
// Original function pointers
/////////////////////////////////////////////////

static HANDLE(WINAPI* TrueCreateFileW)(
    LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;

static BOOL(WINAPI* TrueWriteFile)(
    HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;

static DWORD(WINAPI* TrueSetFilePointer)(
    HANDLE, LONG, PLONG, DWORD) = SetFilePointer;

static BOOL(WINAPI* TrueFlushFileBuffers)(HANDLE) = FlushFileBuffers;

/////////////////////////////////////////////////
// Hooked Functions
/////////////////////////////////////////////////

HANDLE WINAPI MyCreateFileWHook(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    HANDLE hFile = TrueCreateFileW(lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile);

    // LogAPIUsage("CreateFileW", lpFileName);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        if (IsRansomwareTarget(lpFileName))
        {
            EnterCriticalSection(&handleMapLock);
            ransomwareHandles[hFile] = true;
            LeaveCriticalSection(&handleMapLock);

            wcout << L"[!] Blocked ransomware handle created for: " << lpFileName << endl;
        }
    }
    return hFile;
}

BOOL WINAPI MyWriteFileHook(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped)
{
    // LogAPIUsage("WriteFile", L"HANDLE=" + to_wstring((uintptr_t)hFile));

    EnterCriticalSection(&handleMapLock);
    bool isBlocked = (ransomwareHandles.find(hFile) != ransomwareHandles.end());
    LeaveCriticalSection(&handleMapLock);

    if (isBlocked)
    {
        wcout << L"[!] FakeFailure: WriteFile blocked for ransomware handle." << endl;
        SetLastError(ERROR_ACCESS_DENIED);
        if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = 0;
        return FALSE;
    }

    return TrueWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

DWORD WINAPI MySetFilePointerHook(
    HANDLE hFile,
    LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh,
    DWORD dwMoveMethod)
{
    // LogAPIUsage("SetFilePointer", L"HANDLE=" + to_wstring((uintptr_t)hFile));

    EnterCriticalSection(&handleMapLock);
    bool isBlocked = (ransomwareHandles.find(hFile) != ransomwareHandles.end());
    LeaveCriticalSection(&handleMapLock);

    if (isBlocked)
    {
        wcout << L"[!] FakeFailure: SetFilePointer blocked for ransomware handle." << endl;
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_SET_FILE_POINTER;
    }

    return TrueSetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
}

BOOL WINAPI MyFlushFileBuffersHook(HANDLE hFile)
{
    // LogAPIUsage("FlushFileBuffers", L"HANDLE=" + to_wstring((uintptr_t)hFile));

    EnterCriticalSection(&handleMapLock);
    bool isBlocked = (ransomwareHandles.find(hFile) != ransomwareHandles.end());
    LeaveCriticalSection(&handleMapLock);

    if (isBlocked)
    {
        wcout << L"[!] FakeFailure: FlushFileBuffers blocked for ransomware handle." << endl;
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    return TrueFlushFileBuffers(hFile);
}


// ============================================================================
// [B] DLL Code of File Renaming or Extension Change (ORIGINAL CONTENT PRESERVED)
// ============================================================================

HOOK_TRACE_INFO hMoveFileHook = { NULL };
HOOK_TRACE_INFO hMoveFileExHook = { NULL };

const std::vector<std::wstring> suspiciousExtensions = {
    L".encrypted", L".locked", L".enc", L".REvil"
};

// Utility: Check if extension is suspicious
bool HasSuspiciousExtension(const std::wstring& path)
{
    std::wstring lowered = path;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::towlower);
    for (const auto& ext : suspiciousExtensions)
    {
        if (lowered.size() >= ext.size() &&
            lowered.compare(lowered.size() - ext.size(), ext.size(), ext) == 0)
        {
            return true;
        }
    }
    return false;
}

// Utility: Log message to api_log.txt in current directory
void LogApiUsage(const std::wstring& message)
{
    std::wstring logFile = L"api_log.txt";

    HANDLE hLog = CreateFileW(
        logFile.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hLog != INVALID_HANDLE_VALUE)
    {
        std::wstring logLine = message + L"\r\n";
        DWORD bytesWritten;
        WriteFile(hLog, logLine.c_str(), static_cast<DWORD>(logLine.length() * sizeof(wchar_t)), &bytesWritten, NULL);
        CloseHandle(hLog);
    }
}

// Hooked MoveFileW
BOOL WINAPI myMoveFileWHook(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName)
{
    std::wstringstream ss;
    ss << L"[MoveFileW] " << lpExistingFileName << L" -> " << lpNewFileName;
    LogApiUsage(ss.str());

    std::wcout << L"[Hook] MoveFileW: " << lpExistingFileName << L" -> " << lpNewFileName << std::endl;

    if (HasSuspiciousExtension(lpNewFileName))
    {
        std::wstringstream bs;
        bs << L"[BLOCKED] Suspicious rename: " << lpNewFileName;
        LogApiUsage(bs.str());
        std::wcout << L"[!] BLOCKED: Suspicious file rename attempt detected!" << std::endl;
        return TRUE; // Fake success
    }

    return MoveFileW(lpExistingFileName, lpNewFileName);
}

// Hooked MoveFileExW
BOOL WINAPI myMoveFileExWHook(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, DWORD dwFlags)
{
    std::wstringstream ss;
    ss << L"[MoveFileExW] " << lpExistingFileName << L" -> " << lpNewFileName;
    LogApiUsage(ss.str());

    std::wcout << L"[Hook] MoveFileExW: " << lpExistingFileName << L" -> " << lpNewFileName << std::endl;

    if (HasSuspiciousExtension(lpNewFileName))
    {
        std::wstringstream bs;
        bs << L"[BLOCKED] Suspicious rename: " << lpNewFileName;
        LogApiUsage(bs.str());
        std::wcout << L"[!] BLOCKED: Suspicious file rename attempt detected!" << std::endl;
        return TRUE; // Fake success
    }

    return MoveFileExW(lpExistingFileName, lpNewFileName, dwFlags);
}


// ============================================================================
// Unified EasyHook DLL entry — installs BOTH [A] and [B] hook sets
// ============================================================================

extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO * inRemoteInfo)
{
    // ---------------------------
    // [A] Install File-Based Encryption hooks
    // ---------------------------
    cout << "[*] Anti-Ransomware File-Based Encryption Hook injected." << endl;

    InitializeCriticalSection(&handleMapLock);
    // Note: original code uses LogAPIUsage with logLock but never calls; we keep logic unchanged.

    HOOK_TRACE_INFO h1 = { NULL }, h2 = { NULL }, h3 = { NULL }, h4 = { NULL };

    LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "CreateFileW"),
        MyCreateFileWHook, nullptr, &h1);

    LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "WriteFile"),
        MyWriteFileHook, nullptr, &h2);

    LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "SetFilePointer"),
        MySetFilePointerHook, nullptr, &h3);

    LhInstallHook(GetProcAddress(GetModuleHandle(TEXT("kernel32")), "FlushFileBuffers"),
        MyFlushFileBuffersHook, nullptr, &h4);

    ULONG ACLEntries[1] = { 0 };
    LhSetExclusiveACL(ACLEntries, 1, &h1);
    LhSetExclusiveACL(ACLEntries, 1, &h2);
    LhSetExclusiveACL(ACLEntries, 1, &h3);
    LhSetExclusiveACL(ACLEntries, 1, &h4);

    // ---------------------------
    // [B] Install File Renaming/Extension Change hooks
    // ---------------------------
	cout << "[*] Anti-Ransomware File Renaming Hook injected." << endl;
    LogApiUsage(L"[*] DLL Injected: AntiRansomRenameHook");

    // Hook MoveFileW
    FARPROC moveFileAddr = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "MoveFileW");
    if (SUCCEEDED(LhInstallHook(moveFileAddr, myMoveFileWHook, nullptr, &hMoveFileHook)))
    {
        LogApiUsage(L"[+] MoveFileW hook installed.");
        ULONG ACL[1] = { 0 };
        LhSetExclusiveACL(ACL, 1, &hMoveFileHook);
    }
    else
    {
        LogApiUsage(L"[-] Failed to install MoveFileW hook.");
    }

    // Hook MoveFileExW
    FARPROC moveFileExAddr = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "MoveFileExW");
    if (SUCCEEDED(LhInstallHook(moveFileExAddr, myMoveFileExWHook, nullptr, &hMoveFileExHook)))
    {
        LogApiUsage(L"[+] MoveFileExW hook installed.");
        ULONG ACL[1] = { 0 };
        LhSetExclusiveACL(ACL, 1, &hMoveFileExHook);
    }
    else
    {
        LogApiUsage(L"[-] Failed to install MoveFileExW hook.");
    }
}
