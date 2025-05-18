#include "pch.h"
#include <stdio.h>
#include <Windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <DbgHelp.h>
#include "detours.h"
#include <vector>
#include <string>
#include <map>
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <urlmon.h>  
#include <wininet.h>  
#include <winhttp.h>  
#include <shellapi.h>
#include <psapi.h>         
#include <tlhelp32.h>     
#include <winternl.h>
#pragma comment(lib, "psapi.lib")   
#pragma comment(lib, "advapi32.lib") 
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "urlmon.lib")  
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "shell32.lib")
// Link with ntdll.dll
#pragma comment(lib, "ntdll.lib")
#define ObjectNameInformation 1 // Undocumented
typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;


const wchar_t* PIPE_NAME = TEXT("\\\\.\\pipe\\RATMonitorPipe");
HANDLE hPipe = INVALID_HANDLE_VALUE;
HMODULE hKernelBaseMod = LoadLibrary(L"kernelbase.dll");
typedef BOOL(WINAPI* PFN_CopyFileExW)(
    LPCWSTR lpExistingFileName,
    LPCWSTR lpNewFileName,
    LPPROGRESS_ROUTINE lpProgressRoutine,
    LPVOID lpData,
    LPBOOL pbCancel,
    DWORD dwCopyFlags
);
//typedef enum _PROCESSINFOCLASS {
//    ProcessBasicInformation = 0,
//    ProcessDebugPort = 7,
//    ProcessWow64Information = 26,
//    ProcessImageFileName = 27,
//    ProcessBreakOnTermination = 29
//} PROCESSINFOCLASS;
//typedef enum _THREADINFOCLASS {
//    ThreadBasicInformation = 0,
//    ThreadQuerySetWin32StartAddress = 9,
//    ThreadQuerySetWin32StartAddressEx = 10
//} THREADINFOCLASS;
//
//typedef NTSTATUS(NTAPI* NtQueryInformationThread_t)(
//    HANDLE ThreadHandle,
//    THREADINFOCLASS ThreadInformationClass,
//    PVOID ThreadInformation,
//    ULONG ThreadInformationLength,
//    PULONG ReturnLength
//    );
//
//typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
//    HANDLE ProcessHandle,
//    PROCESSINFOCLASS ProcessInformationClass,
//    PVOID ProcessInformation,
//    ULONG ProcessInformationLength,
//    PULONG ReturnLength
//    );
//
//typedef NTSTATUS(WINAPI* NtQueryObjectFunc)(
//    HANDLE Handle,
//    OBJECT_INFORMATION_CLASS ObjectInformationClass,
//    PVOID ObjectInformation,
//    ULONG ObjectInformationLength,
//    PULONG ReturnLength
//    );
//
//NtQueryObjectFunc NtQueryObject = reinterpret_cast<NtQueryObjectFunc>(
//    GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject"));
//
//NtQueryInformationProcess_t NtQueryInformationProcess =
//reinterpret_cast<NtQueryInformationProcess_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
//
//NtQueryInformationThread_t NtQueryInformationThread =
//reinterpret_cast<NtQueryInformationThread_t>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"));

std::string wideToUtf8(LPCWSTR wstr) {
    if (!wstr) return "null";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (size == 0) return "";
    std::string result(size - 1, 0); // Exclude null terminator from length
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size, nullptr, nullptr);
    return result;
}

std::string GetRequestUrl(HINTERNET hRequest) {
    DWORD dwSize = 0;
    LPWSTR lpUrl = NULL;
    std::string urlUtf8;
    // Determine the size of the URL
    if (!WinHttpQueryOption(hRequest, WINHTTP_OPTION_URL, NULL, &dwSize)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            // Allocate memory for the URL
            lpUrl = (LPWSTR)malloc(dwSize);
            if (lpUrl) {
                // Retrieve the full URL
                if (WinHttpQueryOption(hRequest, WINHTTP_OPTION_URL, lpUrl, &dwSize)) {
                    urlUtf8 = wideToUtf8(lpUrl); // Convert wide string to UTF-8
                }
                else {
                    urlUtf8 = "null";
                }
                free(lpUrl); // Free allocated memory
            }
            else {
                urlUtf8 = "null";
            }
        }
        else {
            urlUtf8 = "null";
        }
    }
    else {
        urlUtf8 = "null";
    }
    return urlUtf8;
}

std::string getUrlFromHandle(HINTERNET hInternet) {
    char url[2048];
    DWORD urlLength = sizeof(url);
    if (InternetQueryOptionA(hInternet, INTERNET_OPTION_URL, url, &urlLength)) {
        return std::string(url, urlLength);
    }
    return "null";
}

std::string getPeerInfo(SOCKET s) {
    struct sockaddr_storage peer_addr;
    int addrlen = sizeof(peer_addr);
    if (getpeername(s, (struct sockaddr*)&peer_addr, &addrlen) == 0) {
        char ip_buf[INET6_ADDRSTRLEN];
        int port = 0;
        if (peer_addr.ss_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)&peer_addr;
            inet_ntop(AF_INET, &ipv4->sin_addr, ip_buf, sizeof(ip_buf));
            port = ntohs(ipv4->sin_port);
        }
        else if (peer_addr.ss_family == AF_INET6) {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)&peer_addr;
            inet_ntop(AF_INET6, &ipv6->sin6_addr, ip_buf, sizeof(ip_buf));
            port = ntohs(ipv6->sin6_port);
        }
        else {
            return "addr=null";
        }
        return "addr=" + std::string(ip_buf) + ":" + std::to_string(port);
    }
    else {
        return "addr=null";
    }
}

// Helper to get the full file path from a HANDLE
std::wstring GetFullPathFromHFILE(HANDLE hFile) {
    std::wstring path;
    DWORD size = MAX_PATH;
    std::unique_ptr<WCHAR[]> buffer(new WCHAR[size]);

    DWORD length = GetFinalPathNameByHandleW(hFile, buffer.get(), size, FILE_NAME_NORMALIZED);
    if (length > 0 && length <= size) {
        path.assign(buffer.get(), length);
    }
    else if (length > size) {
        buffer.reset(new WCHAR[length]);
        if (GetFinalPathNameByHandleW(hFile, buffer.get(), length, FILE_NAME_NORMALIZED)) {
            path.assign(buffer.get(), length);
        }
    }
    if (path.empty()) {
        //std::wcerr << L"Failed to get file path." << std::endl;
        return L"null";
    }

    // Remove the \\?\ prefix if present
    if (path.rfind(L"\\\\?\\", 0) == 0) {
        path.erase(0, 4);
    }

    return path;
}

// Helper to get the full object name of a registry key handle
std::wstring GetObjectNameFromHandle(HANDLE handle) {

    if (!NtQueryObject) {
        std::wcerr << L"NtQueryObject not found." << std::endl;
        return L"null";
    }

    ULONG len = 0;
    NTSTATUS status = NtQueryObject(handle, (OBJECT_INFORMATION_CLASS)ObjectNameInformation, nullptr, 0, &len);
    if (!len) return L"null";

    auto buffer = reinterpret_cast<BYTE*>(malloc(len));
    if (!buffer) return L"null";

    status = NtQueryObject(handle, (OBJECT_INFORMATION_CLASS)ObjectNameInformation, buffer, len, &len);
    if (!NT_SUCCESS(status)) {
        free(buffer);
        return L"null";
    }

    auto objName = reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer);
    std::wstring result(objName->Name.Buffer, objName->Name.Length / sizeof(WCHAR));

    free(buffer);
    return result;
}


std::string getCurrentTimestamp() {
    // Get current system time for the date & wall-clock part
    SYSTEMTIME st;
    GetSystemTime(&st);

    // High-precision counter part
    LARGE_INTEGER frequency, counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);

    // Convert counter to microseconds
    double timeInMicro = (counter.QuadPart % frequency.QuadPart) * 1'000'000.0 / frequency.QuadPart;
    int microseconds = static_cast<int>(timeInMicro);

    char buffer[40];
    sprintf_s(buffer, sizeof(buffer),
        "%04d-%02d-%02d %02d:%02d:%02d.%03d%03d",  // Shows up to microseconds
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond,
        st.wMilliseconds,
        microseconds % 1000); // last 3 digits = microseconds remainder

    return std::string(buffer);
}


std::string sockaddr_to_string(const sockaddr* sa, int salen) {
    char ip[INET6_ADDRSTRLEN] = { 0 };
    int port = 0;
    if (sa->sa_family == AF_INET && salen >= sizeof(sockaddr_in)) {
        const sockaddr_in* sin = reinterpret_cast<const sockaddr_in*>(sa);
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        port = ntohs(sin->sin_port);
    }
    else if (sa->sa_family == AF_INET6 && salen >= sizeof(sockaddr_in6)) {
        const sockaddr_in6* sin6 = reinterpret_cast<const sockaddr_in6*>(sa);
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        port = ntohs(sin6->sin6_port);
    }
    else {
        return "null";
    }
    return std::string(ip) + ":" + std::to_string(port);
}

std::string acceptTypesToString(LPCWSTR* ppwszAcceptTypes) {
    if (!ppwszAcceptTypes) return "null";
    std::string result;
    LPCWSTR* current = ppwszAcceptTypes;
    while (*current) {
        if (!result.empty()) result += ", ";
        result += wideToUtf8(*current);
        current++;
    }
    return result;
}

std::string acceptTypesToStringA(LPCSTR* lplpszAcceptTypes) {
    if (!lplpszAcceptTypes) return "null";
    std::string result;
    LPCSTR* current = lplpszAcceptTypes;
    while (*current) {
        if (!result.empty()) result += ", ";
        result += *current;
        current++;
    }
    return result;
}

std::string logInternetBuffersA(const INTERNET_BUFFERSA* pBuffer) {
    std::string log;
    while (pBuffer) {
        log += "dwStructSize=" + std::to_string(pBuffer->dwStructSize) + ", ";
        log += "lpcszHeader=" + (pBuffer->lpcszHeader ? std::string(pBuffer->lpcszHeader) : "null") + ", ";
        log += "dwHeadersLength=" + std::to_string(pBuffer->dwHeadersLength) + ", ";
        log += "dwHeadersTotal=" + std::to_string(pBuffer->dwHeadersTotal) + ", ";
        log += "dwBufferLength=" + std::to_string(pBuffer->dwBufferLength) + ", ";
        log += "dwBufferTotal=" + std::to_string(pBuffer->dwBufferTotal) + ", ";
        log += "dwOffsetLow=" + std::to_string(pBuffer->dwOffsetLow) + ", ";
        log += "dwOffsetHigh=" + std::to_string(pBuffer->dwOffsetHigh);
        if (pBuffer->lpvBuffer && pBuffer->dwBufferLength > 0) {
            DWORD base64Len = 0;
            CryptBinaryToStringA((const BYTE*)pBuffer->lpvBuffer, pBuffer->dwBufferLength, CRYPT_STRING_BASE64, nullptr, &base64Len);
            std::string base64Data(base64Len, '\0');
            CryptBinaryToStringA((const BYTE*)pBuffer->lpvBuffer, pBuffer->dwBufferLength, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
            log += ", lpvBuffer=" + base64Data;
        }
        pBuffer = pBuffer->Next;
        if (pBuffer) log += "; ";
    }
    return log;
}

std::string logInternetBuffersW(const INTERNET_BUFFERSW* pBuffer) {
    std::string log;
    while (pBuffer) {
        log += "dwStructSize=" + std::to_string(pBuffer->dwStructSize) + ", ";
        log += "lpcszHeader=" + wideToUtf8(pBuffer->lpcszHeader) + ", ";
        log += "dwHeadersLength=" + std::to_string(pBuffer->dwHeadersLength) + ", ";
        log += "dwHeadersTotal=" + std::to_string(pBuffer->dwHeadersTotal) + ", ";
        log += "dwBufferLength=" + std::to_string(pBuffer->dwBufferLength) + ", ";
        log += "dwBufferTotal=" + std::to_string(pBuffer->dwBufferTotal) + ", ";
        log += "dwOffsetLow=" + std::to_string(pBuffer->dwOffsetLow) + ", ";
        log += "dwOffsetHigh=" + std::to_string(pBuffer->dwOffsetHigh);
        if (pBuffer->lpvBuffer && pBuffer->dwBufferLength > 0) {
            DWORD base64Len = 0;
            CryptBinaryToStringA((const BYTE*)pBuffer->lpvBuffer, pBuffer->dwBufferLength, CRYPT_STRING_BASE64, nullptr, &base64Len);
            std::string base64Data(base64Len, '\0');
            CryptBinaryToStringA((const BYTE*)pBuffer->lpvBuffer, pBuffer->dwBufferLength, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
            log += ", lpvBuffer=" + base64Data;
        }
        pBuffer = pBuffer->Next;
        if (pBuffer) log += "; ";
    }
    return log;
}

// Get process name from a handle
std::string getProcessName(HANDLE hProcess) {
    WCHAR processName[MAX_PATH] = L"null";
    HANDLE hProc = hProcess;
    if (hProc == GetCurrentProcess()) {
        GetModuleFileNameW(NULL, processName, MAX_PATH);
    }
    else {
        DWORD pid = GetProcessId(hProcess);
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(hSnapshot, &pe)) {
                do {
                    if (pe.th32ProcessID == pid) {
                        wcsncpy_s(processName, pe.szExeFile, MAX_PATH);
                        break;
                    }
                } while (Process32NextW(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);
        }
    }
    return wideToUtf8(processName);
}

// Get module name and offset from an address in a process
std::pair<std::string, uintptr_t> getModuleAndOffset(HANDLE hProcess, LPVOID address) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    std::string moduleName = "unknown";
    uintptr_t offset = reinterpret_cast<uintptr_t>(address);

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                uintptr_t base = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                uintptr_t end = base + modInfo.SizeOfImage;
                if (offset >= base && offset < end) {
                    WCHAR modPath[MAX_PATH];
                    if (GetModuleFileNameExW(hProcess, hMods[i], modPath, MAX_PATH)) {
                        moduleName = wideToUtf8(modPath);
                    }
                    offset -= base;
                    break;
                }
            }
        }
    }
    return { moduleName, offset };
}

// Get thread start address and its module info
std::pair<std::string, uintptr_t> getThreadStartAddressInfo(HANDLE hProc, HANDLE hThread) {
    NTSTATUS status;
    PVOID startAddress = NULL;
    status = NtQueryInformationThread(
        hThread, (THREADINFOCLASS)9, // ThreadQuerySetWin32StartAddress
        &startAddress, sizeof(PVOID), NULL
    );
    if (status) {
        return getModuleAndOffset(hProc, startAddress);
    }
    return { "unknown", 0 };
}

// Convert service handle to service name
std::string getServiceName(SC_HANDLE hService) {
    QUERY_SERVICE_CONFIGA serviceConfig;
    DWORD bytesNeeded;

    // Query the service configuration
    if (QueryServiceConfigA(hService, &serviceConfig, sizeof(serviceConfig), &bytesNeeded)) {
        std::string serviceName = serviceConfig.lpServiceStartName;
        return serviceName;
    }
    return "null";
}

// Original function pointers
HANDLE(WINAPI* OriginalCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
HANDLE(WINAPI* OriginalCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileA;
SOCKET(WSAAPI* OriginalSocket)(int, int, int) = socket;
int(WSAAPI* OriginalConnect)(SOCKET, const sockaddr*, int) = connect;
int(WSAAPI* OriginalSend)(SOCKET, const char*, int, int) = send;
int(WSAAPI* OriginalRecv)(SOCKET, char*, int, int) = recv;
int(WSAAPI* OriginalGetaddrinfo)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*) = getaddrinfo;
int(WSAAPI* OriginalGetAddrInfoW)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*) = GetAddrInfoW;
BOOL(WINAPI* OriginalReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = ReadFile;
BOOL(WINAPI* OriginalWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
BOOL(WINAPI* OriginalDeleteFileW)(LPCWSTR) = DeleteFileW;
LONG(WINAPI* OriginalRegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD) = RegSetValueExA;
LONG(WINAPI* OriginalRegDeleteKeyW)(HKEY, LPCWSTR) = RegDeleteKeyW;
LONG(WINAPI* OriginalRegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD) = RegCreateKeyExA;
HRESULT(WINAPI* OriginalURLDownloadToFileW)(LPUNKNOWN, LPCWSTR, LPCWSTR, DWORD, LPBINDSTATUSCALLBACK) = URLDownloadToFileW;
BOOL(WINAPI* OriginalInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD) = InternetReadFile;
BOOL(WINAPI* OriginalInternetWriteFile)(HINTERNET, LPCVOID, DWORD, LPDWORD) = InternetWriteFile;
HRESULT(WINAPI* OriginalURLDownloadToFileA)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK) = URLDownloadToFileA;
HRESULT(WINAPI* OriginalURLDownloadToCacheFileA)(LPUNKNOWN, LPCSTR, LPSTR, DWORD, DWORD, LPBINDSTATUSCALLBACK) = URLDownloadToCacheFileA;
HRESULT(WINAPI* OriginalURLOpenBlockingStreamA)(LPUNKNOWN, LPCSTR, LPSTREAM*, DWORD, LPBINDSTATUSCALLBACK) = URLOpenBlockingStreamA;
HRESULT(WINAPI* OriginalURLOpenStreamA)(LPUNKNOWN, LPCSTR, DWORD, LPBINDSTATUSCALLBACK) = URLOpenStreamA;
HINTERNET(WINAPI* OriginalInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD) = InternetOpenA;
HINTERNET(WINAPI* OriginalInternetOpenW)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) = InternetOpenW;
HINTERNET(WINAPI* OriginalInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR) = InternetOpenUrlA;
BOOL(WINAPI* OriginalInternetReadFileExA)(HINTERNET, LPINTERNET_BUFFERSA, DWORD, DWORD_PTR) = InternetReadFileExA;
HINTERNET(WINAPI* OriginalHttpOpenRequestA)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR) = HttpOpenRequestA;
HINTERNET(WINAPI* OriginalHttpOpenRequestW)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD, DWORD_PTR) = HttpOpenRequestW;
BOOL(WINAPI* OriginalHttpSendRequestA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD) = HttpSendRequestA;
BOOL(WINAPI* OriginalHttpSendRequestW)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD) = HttpSendRequestW;
BOOL(WINAPI* OriginalHttpSendRequestExA)(HINTERNET, LPINTERNET_BUFFERSA, LPINTERNET_BUFFERSA, DWORD, DWORD_PTR) = HttpSendRequestExA;
BOOL(WINAPI* OriginalHttpSendRequestExW)(HINTERNET, LPINTERNET_BUFFERSW, LPINTERNET_BUFFERSW, DWORD, DWORD_PTR) = HttpSendRequestExW;
BOOL(WINAPI* OriginalFtpPutFileA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD_PTR) = FtpPutFileA;
BOOL(WINAPI* OriginalFtpPutFileW)(HINTERNET, LPCWSTR, LPCWSTR, DWORD, DWORD_PTR) = FtpPutFileW;
HINTERNET(WINAPI* OriginalWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD) = WinHttpOpen;
HINTERNET(WINAPI* OriginalWinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD) = WinHttpConnect;
HINTERNET(WINAPI* OriginalWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD) = WinHttpOpenRequest;
BOOL(WINAPI* OriginalShellExecuteExW)(SHELLEXECUTEINFOW*) = ShellExecuteExW;
BOOL(WINAPI* OriginalMoveFileW)(LPCWSTR, LPCWSTR) = MoveFileW;
BOOL(WINAPI* OriginalCopyFileExW)(LPCWSTR, LPCWSTR, LPPROGRESS_ROUTINE, LPVOID, LPBOOL, DWORD) = (PFN_CopyFileExW) GetProcAddress(hKernelBaseMod, "CopyFileExW");
LONG(WINAPI* OriginalRegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD) = RegSetValueExW;
LONG(WINAPI* OriginalRegDeleteKeyExA)(HKEY, LPCSTR, REGSAM, DWORD) = RegDeleteKeyExA;
LONG(WINAPI* OriginalRegDeleteKeyExW)(HKEY, LPCWSTR, REGSAM, DWORD) = RegDeleteKeyExW;
LONG(WINAPI* OriginalRegCreateKeyExW)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD) = RegCreateKeyExW;
BOOL(WINAPI* OriginalCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;
BOOL(WINAPI* OriginalCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION) = CreateProcessA;
HANDLE(WINAPI* OriginalOpenProcess)(DWORD, BOOL, DWORD) = OpenProcess;
BOOL(WINAPI* OriginalWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = WriteProcessMemory;
BOOL(WINAPI* OriginalReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*) = ReadProcessMemory;
HANDLE(WINAPI* OriginalCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateRemoteThread;
LPVOID(WINAPI* OriginalVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = VirtualAllocEx;
BOOL(WINAPI* OriginalVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD) = VirtualProtectEx;
DWORD(WINAPI* OriginalResumeThread)(HANDLE) = ResumeThread;
DWORD(WINAPI* OriginalSuspendThread)(HANDLE) = SuspendThread;
HHOOK(WINAPI* OriginalSetWindowsHookExA)(int, HOOKPROC, HINSTANCE, DWORD) = SetWindowsHookExA;
HHOOK(WINAPI* OriginalSetWindowsHookExW)(int, HOOKPROC, HINSTANCE, DWORD) = SetWindowsHookExW;
SHORT(WINAPI* OriginalGetAsyncKeyState)(int) = GetAsyncKeyState;
BOOL(WINAPI* OriginalGetComputerNameW)(LPWSTR, LPDWORD) = GetComputerNameW;
VOID(WINAPI* OriginalGetSystemInfo)(LPSYSTEM_INFO) = GetSystemInfo;
BOOL(WINAPI* OriginalGetUserNameA)(LPSTR, LPDWORD) = GetUserNameA;
BOOL(WINAPI* OriginalGetUserNameW)(LPWSTR, LPDWORD) = GetUserNameW;
BOOL(WINAPI* OriginalIsDebuggerPresent)(VOID) = IsDebuggerPresent;
//NTSTATUS(NTAPI* OriginalNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG) = NtQueryInformationProcess;
HWND(WINAPI* OriginalFindWindowA)(LPCSTR, LPCSTR) = FindWindowA;
HWND(WINAPI* OriginalFindWindowW)(LPCWSTR, LPCWSTR) = FindWindowW;
HMODULE(WINAPI* OriginalLoadLibraryA)(LPCSTR) = LoadLibraryA;
HMODULE(WINAPI* OriginalLoadLibraryW)(LPCWSTR) = LoadLibraryW;
FARPROC(WINAPI* OriginalGetProcAddress)(HMODULE, LPCSTR) = GetProcAddress;
BOOL(WINAPI* OriginalAdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD) = AdjustTokenPrivileges;
SC_HANDLE(WINAPI* OriginalCreateServiceA)(SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD, DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR) = CreateServiceA;
SC_HANDLE(WINAPI* OriginalCreateServiceW)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR) = CreateServiceW;
BOOL(WINAPI* OriginalStartServiceA)(SC_HANDLE, DWORD, LPCSTR*) = StartServiceA;
BOOL(WINAPI* OriginalStartServiceW)(SC_HANDLE, DWORD, LPCWSTR*) = StartServiceW;
HANDLE(WINAPI* OriginalCreateMutexW)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR) = CreateMutexW;
BOOL(WINAPI* OriginalCheckRemoteDebuggerPresent)(HANDLE, PBOOL) = CheckRemoteDebuggerPresent;
int (WINAPI* OriginalGetLocaleInfoW)(LCID, LCTYPE, LPWSTR, int) = GetLocaleInfoW;
BOOL (WINAPI* OriginalCloseHandle)(HANDLE) = CloseHandle;
int (WSAAPI* OriginalWSAConnect)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS) = WSAConnect;

void SendLog(const std::string& log) {
    DWORD bytesWritten;
    BOOL res = OriginalWriteFile(hPipe, log.c_str(), log.size(), &bytesWritten, NULL);
    if (res == 0) {
        hPipe = OriginalCreateFileW(PIPE_NAME, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (!WaitNamedPipe(PIPE_NAME, 5000)) {
            printf("WaitNamedPipe timed out.\n");
            return;
        }
        OriginalWriteFile(hPipe, log.c_str(), log.size(), &bytesWritten, NULL);
    }
    
}

// Hooking functions

int WSAAPI Hooking_WSAConnect(SOCKET s, const sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
    int result = OriginalWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "WSAConnect";
    std::string addr_str = sockaddr_to_string(name, namelen);
    std::string log_message = "addr=" + addr_str +
        ", return=" + std::to_string(result);
    if (result == SOCKET_ERROR) {
        log_message += ", error=" + std::to_string(WSAGetLastError());
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_CloseHandle(HANDLE hObject) {
    BOOL result = 3;
	if (hObject == hPipe) {
        std::string timestamp = getCurrentTimestamp();
        std::string api_name = "CloseHandle";
        std::string log_message = "hObject=" + std::to_string((uintptr_t)hObject);
        SendLog(timestamp + "|" + api_name + "|" + log_message);
	}
    else {
         result = OriginalCloseHandle(hObject);
    }
	return result;
}

int WINAPI Hooking_GetLocaleInfoW(LCID Locale, LCTYPE LCType, LPWSTR lpLCData, int cchData) {
    int result = OriginalGetLocaleInfoW(Locale, LCType, lpLCData, cchData);
    std::string timestamp = getCurrentTimestamp(); 
    std::string api_name = "GetLocaleInfoW";
    std::string log_message = "Locale=" + std::to_string(Locale) +
        ", LCType=" + std::to_string(LCType) +
        ", cchData=" + std::to_string(cchData) +
        ", return=" + std::to_string(result);
    if (result == 0) {
        log_message += ", error=" + std::to_string(GetLastError());
    }
    else if (cchData > 0 && lpLCData) {
        std::wstring wideStr(lpLCData, result - 1); // Exclude null terminator
        log_message += ", lpLCData=" + wideToUtf8(wideStr.c_str());
    }
    else if (cchData == 0) {
        log_message += ", required_size=" + std::to_string(result);
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent) {
    BOOL result = OriginalCheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "CheckRemoteDebuggerPresent";
    std::string procName = getProcessName(hProcess);
    std::string log_message = "hProcess=" + procName +
        ", original_pbDebuggerPresent=" + std::to_string(*pbDebuggerPresent) + 
        ", original_return=" + std::to_string(result);
    if (pbDebuggerPresent) {
        *pbDebuggerPresent = FALSE; // Force FALSE to hide debugger
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HANDLE WINAPI Hooking_CreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName) {
    HANDLE result = OriginalCreateMutexW(lpMutexAttributes, bInitialOwner, lpName);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "CreateMutexW";
    std::string log_message = "bInitialOwner=" + std::to_string(bInitialOwner) +
        ", lpName=" + wideToUtf8(lpName) +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_StartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR* lpServiceArgVectors) {
    BOOL result = OriginalStartServiceA(hService, dwNumServiceArgs, lpServiceArgVectors);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "StartServiceA";
    std::string svcName = getServiceName(hService);
    std::string log_message = "hService=" + svcName +
        ", dwNumServiceArgs=" + std::to_string(dwNumServiceArgs) +
        ", return=" + std::to_string(result);
    if (lpServiceArgVectors && dwNumServiceArgs > 0) {
        std::string args;
        for (DWORD i = 0; i < dwNumServiceArgs; i++) {
            if (lpServiceArgVectors[i]) {
                if (!args.empty()) args += ", ";
                args += lpServiceArgVectors[i];
            }
        }
        log_message += ", lpServiceArgVectors=[" + args + "]";
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_StartServiceW(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors) {
    BOOL result = OriginalStartServiceW(hService, dwNumServiceArgs, lpServiceArgVectors);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "StartServiceW";
    std::string svcName = getServiceName(hService);
    std::string log_message = "hService=" + svcName +
        ", dwNumServiceArgs=" + std::to_string(dwNumServiceArgs) +
        ", return=" + std::to_string(result);
    if (lpServiceArgVectors && dwNumServiceArgs > 0) {
        std::string args;
        for (DWORD i = 0; i < dwNumServiceArgs; i++) {
            if (lpServiceArgVectors[i]) {
                if (!args.empty()) args += ", ";
                args += wideToUtf8(lpServiceArgVectors[i]);
            }
        }
        log_message += ", lpServiceArgVectors=[" + args + "]";
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

SC_HANDLE WINAPI Hooking_CreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword) {
    SC_HANDLE result = OriginalCreateServiceA(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "CreateServiceA";
    std::string log_message = "lpServiceName=" + (lpServiceName ? std::string(lpServiceName) : "null") +
        ", lpDisplayName=" + (lpDisplayName ? std::string(lpDisplayName) : "null") +
        ", dwDesiredAccess=" + std::to_string(dwDesiredAccess) +
        ", dwServiceType=" + std::to_string(dwServiceType) +
        ", dwStartType=" + std::to_string(dwStartType) +
        ", dwErrorControl=" + std::to_string(dwErrorControl) +
        ", lpBinaryPathName=" + (lpBinaryPathName ? std::string(lpBinaryPathName) : "null") +
        ", lpLoadOrderGroup=" + (lpLoadOrderGroup ? std::string(lpLoadOrderGroup) : "null") +
        ", lpDependencies=" + (lpDependencies ? std::string(lpDependencies) : "null") +
        ", lpServiceStartName=" + (lpServiceStartName ? std::string(lpServiceStartName) : "null") +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

SC_HANDLE WINAPI Hooking_CreateServiceW(SC_HANDLE hSCManager, LPCWSTR lpServiceName, LPCWSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCWSTR lpBinaryPathName, LPCWSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCWSTR lpDependencies, LPCWSTR lpServiceStartName, LPCWSTR lpPassword) {
    SC_HANDLE result = OriginalCreateServiceW(hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess, dwServiceType, dwStartType, dwErrorControl, lpBinaryPathName, lpLoadOrderGroup, lpdwTagId, lpDependencies, lpServiceStartName, lpPassword);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "CreateServiceW";
    std::string log_message = "lpServiceName=" + wideToUtf8(lpServiceName) +
        ", lpDisplayName=" + wideToUtf8(lpDisplayName) +
        ", dwDesiredAccess=" + std::to_string(dwDesiredAccess) +
        ", dwServiceType=" + std::to_string(dwServiceType) +
        ", dwStartType=" + std::to_string(dwStartType) +
        ", dwErrorControl=" + std::to_string(dwErrorControl) +
        ", lpBinaryPathName=" + wideToUtf8(lpBinaryPathName) +
        ", lpLoadOrderGroup=" + wideToUtf8(lpLoadOrderGroup) +
        ", lpDependencies=" + wideToUtf8(lpDependencies) +
        ", lpServiceStartName=" + wideToUtf8(lpServiceStartName) +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength) {
    BOOL result = OriginalAdjustTokenPrivileges(TokenHandle, DisableAllPrivileges, NewState, BufferLength, PreviousState, ReturnLength);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "AdjustTokenPrivileges";
    std::string log_message = "DisableAllPrivileges=" + std::to_string(DisableAllPrivileges) +
        ", return=" + std::to_string(result);
    if (NewState) {
        log_message += ", PrivilegeCount=" + std::to_string(NewState->PrivilegeCount);
        for (DWORD i = 0; i < NewState->PrivilegeCount; i++) {
            WCHAR privName[256];
            DWORD nameLen = 256;
            if (LookupPrivilegeNameW(NULL, &NewState->Privileges[i].Luid, privName, &nameLen)) {
                log_message += ", Privilege[" + std::to_string(i) + "]=" + wideToUtf8(privName) +
                    " (Attributes=" + std::to_string(NewState->Privileges[i].Attributes) + ")";
            }
        }
    }
    else {
		log_message += ", NewState=null";
	}
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

FARPROC WINAPI Hooking_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "GetProcAddress";
    WCHAR modPath[MAX_PATH];
    std::string modName = GetModuleFileNameW(hModule, modPath, MAX_PATH) ? wideToUtf8(modPath) : "unknown";
    // Handle lpProcName (string or ordinal)
    std::string procName;
    if (lpProcName == NULL) {
        procName = "null";
    }
    else if (((ULONG_PTR)lpProcName >> 16) == 0) {
        // Ordinal case: lpProcName is an ordinal number
        WORD ordinal = (WORD)(ULONG_PTR)lpProcName;
        procName = "ordinal(" + std::to_string(ordinal) + ")";
    }
    else {
        // String case: lpProcName is a function name
        procName = std::string(lpProcName);
    }
    std::string log_message = "hModule=" + modName +
        ", lpProcName=" + procName;
    FARPROC result = OriginalGetProcAddress(hModule, lpProcName);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HMODULE WINAPI Hooking_LoadLibraryA(LPCSTR lpLibFileName) {
    HMODULE result = OriginalLoadLibraryA(lpLibFileName);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "LoadLibraryA";
    std::string log_message = "lpLibFileName=" + (lpLibFileName ? std::string(lpLibFileName) : "null") +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HMODULE WINAPI Hooking_LoadLibraryW(LPCWSTR lpLibFileName) {
    HMODULE result = OriginalLoadLibraryW(lpLibFileName);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "LoadLibraryW";
    std::string log_message = "lpLibFileName=" + wideToUtf8(lpLibFileName) +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HWND WINAPI Hooking_FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName) {
    HWND result = OriginalFindWindowA(lpClassName, lpWindowName);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "FindWindowA";
    std::string log_message = "lpClassName=" + (lpClassName ? std::string(lpClassName) : "null") +
        ", lpWindowName=" + (lpWindowName ? std::string(lpWindowName) : "null") +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HWND WINAPI Hooking_FindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName) {
    HWND result = OriginalFindWindowW(lpClassName, lpWindowName);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "FindWindowW";
    std::string log_message = "lpClassName=" + wideToUtf8(lpClassName) +
        ", lpWindowName=" + wideToUtf8(lpWindowName) +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}


//NTSTATUS NTAPI Hooking_NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
//    NTSTATUS result = OriginalNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
//    std::string timestamp = getCurrentTimestamp();
//    std::string api_name = "NtQueryInformationProcess";
//    std::string procName = getProcessName(ProcessHandle);
//    std::string log_message = "ProcessHandle=" + procName +
//        ", ProcessInformationClass=" + std::to_string(ProcessInformationClass) +
//        ", return=" + std::to_string(result);
//    SendLog(timestamp + "|" + api_name + "|" + log_message);
//
//    // Modify return values to hide debugger/VM
//    if (ProcessInformationClass == ProcessDebugPort) {
//        if (ProcessInformation && ProcessInformationLength >= sizeof(DWORD_PTR)) {
//            *(DWORD_PTR*)ProcessInformation = 0; // No debugger
//        }
//        if (ReturnLength) *ReturnLength = sizeof(DWORD_PTR);
//	}
//	else if (ProcessInformationClass == ProcessBasicInformation) {
//		if (ProcessInformation && ProcessInformationLength >= sizeof(PVOID)) {
//			*(PVOID*)ProcessInformation = NULL; // No debugger
//		}
//		if (ReturnLength) *ReturnLength = sizeof(PVOID);
//	}
//    result = 0;
//    return result;
//}


BOOL WINAPI Hooking_IsDebuggerPresent(VOID) {
    BOOL result = OriginalIsDebuggerPresent();
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "IsDebuggerPresent";
    std::string log_message = "original_return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return FALSE; // Always return FALSE to hide debugger presence
}

BOOL WINAPI Hooking_GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer) {
    BOOL result = OriginalGetUserNameA(lpBuffer, pcbBuffer);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "GetUserNameA";
    std::string log_message = "return=" + std::to_string(result);
    if (result && lpBuffer && pcbBuffer && *pcbBuffer > 0) {
        log_message += ", lpBuffer=" + std::string(lpBuffer);
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_GetUserNameW(LPWSTR lpBuffer, LPDWORD pcbBuffer) {
    BOOL result = OriginalGetUserNameW(lpBuffer, pcbBuffer);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "GetUserNameW";
    std::string log_message = "return=" + std::to_string(result);
    if (result && lpBuffer && pcbBuffer && *pcbBuffer > 0) {
        log_message += ", lpBuffer=" + wideToUtf8(lpBuffer);
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}


VOID WINAPI Hooking_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo) {
    OriginalGetSystemInfo(lpSystemInfo);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "GetSystemInfo";
    std::string log_message;
    if (lpSystemInfo) {
        log_message = "wProcessorArchitecture=" + std::to_string(lpSystemInfo->wProcessorArchitecture) +
            ", dwProcessorType=" + std::to_string(lpSystemInfo->dwProcessorType);
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
}

BOOL WINAPI Hooking_GetComputerNameW(LPWSTR lpBuffer, LPDWORD nSize) {
    BOOL result = OriginalGetComputerNameW(lpBuffer, nSize);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "GetComputerNameW";
    std::string log_message = "nSize=" + std::to_string(*nSize);
    if (result && lpBuffer && nSize && *nSize > 0) {
        log_message += ", lpBuffer=" + wideToUtf8(lpBuffer);
    }
    log_message += ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

SHORT WINAPI Hooking_GetAsyncKeyState(int vKey) {
    SHORT result = OriginalGetAsyncKeyState(vKey);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "GetAsyncKeyState";
    std::string log_message = "vKey=" + std::to_string(vKey) +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HHOOK WINAPI Hooking_SetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId) {
    HHOOK result = OriginalSetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "SetWindowsHookExA";
    WCHAR modPath[MAX_PATH];
    std::string modName = GetModuleFileNameW(hmod, modPath, MAX_PATH) ? wideToUtf8(modPath) : "unknown";
    uintptr_t offset = reinterpret_cast<uintptr_t>(lpfn) - reinterpret_cast<uintptr_t>(hmod);
    std::string log_message = "idHook=" + std::to_string(idHook) +
        ", lpfn=" + modName + "+0x" + std::to_string(offset) +
        ", hmod=" + modName +
        ", dwThreadId=" + std::to_string(dwThreadId) +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HHOOK WINAPI Hooking_SetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId) {
    HHOOK result = OriginalSetWindowsHookExW(idHook, lpfn, hmod, dwThreadId);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "SetWindowsHookExW";
    WCHAR modPath[MAX_PATH];
    std::string modName = GetModuleFileNameW(hmod, modPath, MAX_PATH) ? wideToUtf8(modPath) : "unknown";
    uintptr_t offset = reinterpret_cast<uintptr_t>(lpfn) - reinterpret_cast<uintptr_t>(hmod);
    std::string log_message = "idHook=" + std::to_string(idHook) +
        ", lpfn=" + modName + "+0x" + std::to_string(offset) +
        ", hmod=" + modName +
        ", dwThreadId=" + std::to_string(dwThreadId) +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}


DWORD WINAPI Hooking_SuspendThread(HANDLE hThread) {
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "SuspendThread";
    DWORD pid = GetProcessIdOfThread(hThread);
    std::string procName = "null";
    auto pair_res = std::pair<std::string, uintptr_t>{ "null", 0 };
    if (pid != 0) {
        HANDLE hProc = OriginalOpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc != NULL) {
            procName = getProcessName(hProc);
            pair_res = getThreadStartAddressInfo(hProc, hThread);
            CloseHandle(hProc);
        }
    }
    DWORD result = OriginalSuspendThread(hThread);

    std::string log_message = "hThread=" + std::to_string(reinterpret_cast<uintptr_t>(hThread)) +
        ", processName=" + procName +
        ", startAddress=" + pair_res.first + "+0x" + std::to_string(pair_res.second) +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);

    return result;
}


DWORD WINAPI Hooking_ResumeThread(HANDLE hThread) {
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "ResumeThread";
    DWORD pid = GetProcessIdOfThread(hThread);
    std::string procName = "null";
	auto pair_res = std::pair<std::string, uintptr_t>{ "null", 0 };
    if (pid != 0) {
        HANDLE hProc = OriginalOpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc != NULL) {
            procName = getProcessName(hProc); 
            pair_res = getThreadStartAddressInfo(hProc, hThread);
            CloseHandle(hProc);
        }
    }
    DWORD result = OriginalResumeThread(hThread);

    std::string log_message = "hThread=" + std::to_string(reinterpret_cast<uintptr_t>(hThread)) +
        ", processName=" + procName +
        ", startAddress=" + pair_res.first + "+0x" + std::to_string(pair_res.second) +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);

    return result;
}

BOOL WINAPI Hooking_VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    BOOL result = OriginalVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "VirtualProtectEx";
    std::string procName = getProcessName(hProcess);
    auto pair_res = getModuleAndOffset(hProcess, lpAddress);
    std::string log_message = "hProcess=" + procName +
        ", lpAddress=" + pair_res.first + "+0x" + std::to_string(pair_res.second) +
        ", dwSize=" + std::to_string(dwSize) +
        ", flNewProtect=" + std::to_string(flNewProtect) +
        ", return=" + std::to_string(result);
    if (lpflOldProtect) log_message += ", lpflOldProtect=" + std::to_string(*lpflOldProtect);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

LPVOID WINAPI Hooking_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    LPVOID result = OriginalVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "VirtualAllocEx";
    std::string procName = getProcessName(hProcess);
    auto pair_res = lpAddress ? getModuleAndOffset(hProcess, lpAddress) : std::pair<std::string, uintptr_t>{ "null", 0 };
    std::string log_message = "hProcess=" + procName +
        ", lpAddress=" + (lpAddress ? pair_res.first + "+0x" + std::to_string(pair_res.second) : "null") +
        ", dwSize=" + std::to_string(dwSize) +
        ", flAllocationType=" + std::to_string(flAllocationType) +
        ", flProtect=" + std::to_string(flProtect) +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HANDLE WINAPI Hooking_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HANDLE result = OriginalCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "CreateRemoteThread";
    std::string procName = getProcessName(hProcess);
    auto pair_res = getModuleAndOffset(hProcess, lpStartAddress);
    std::string log_message = "hProcess=" + procName +
        ", lpStartAddress=" + pair_res.first + "+0x" + std::to_string(pair_res.second) +
        ", return=" + std::to_string((uintptr_t)result);
    if (lpParameter) {
        BYTE buffer[512];
        SIZE_T bytesRead;
        if (OriginalReadProcessMemory(hProcess, lpParameter, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
            DWORD base64Len = 0;
            CryptBinaryToStringA(buffer, bytesRead, CRYPT_STRING_BASE64, nullptr, &base64Len);
            std::string base64Data(base64Len, '\0');
            CryptBinaryToStringA(buffer, bytesRead, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
            log_message += ", lpParameter=" + base64Data;
        }
    }
    else {
                log_message += ", lpParameter=null";
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}


BOOL WINAPI Hooking_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
    BOOL result = OriginalReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "ReadProcessMemory";
    std::string procName = getProcessName(hProcess);
    std::string log_message = "hProcess=" + procName +
        ", lpBaseAddress=" + std::to_string((uintptr_t)lpBaseAddress) +
        ", nSize=" + std::to_string(nSize) +
        ", return=" + std::to_string(result);
    if (result && lpNumberOfBytesRead && lpBuffer && *lpNumberOfBytesRead > 0) {
        DWORD base64Len = 0;
        CryptBinaryToStringA((const BYTE*)lpBuffer, *lpNumberOfBytesRead, CRYPT_STRING_BASE64, nullptr, &base64Len);
        std::string base64Data(base64Len, '\0');
        CryptBinaryToStringA((const BYTE*)lpBuffer, *lpNumberOfBytesRead, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
        log_message += ", lpBuffer=" + base64Data;
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}


BOOL WINAPI Hooking_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    BOOL result = OriginalWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "WriteProcessMemory";
    std::string procName = getProcessName(hProcess);
    std::string log_message = "hProcess=" + procName +
        ", lpBaseAddress=" + std::to_string((uintptr_t)lpBaseAddress) +
        ", nSize=" + std::to_string(nSize) +
        ", return=" + std::to_string(result);
    if (result && lpNumberOfBytesWritten && lpBuffer && *lpNumberOfBytesWritten > 0) {
        DWORD base64Len = 0;
        CryptBinaryToStringA((const BYTE*)lpBuffer, *lpNumberOfBytesWritten, CRYPT_STRING_BASE64, nullptr, &base64Len);
        std::string base64Data(base64Len, '\0');
        CryptBinaryToStringA((const BYTE*)lpBuffer, *lpNumberOfBytesWritten, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
        log_message += ", lpBuffer=" + base64Data;
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HANDLE WINAPI Hooking_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    HANDLE result = OriginalOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "OpenProcess";
    std::string procName = result ? getProcessName(result) : "null";
    std::string log_message = "dwProcessId=" + std::to_string(dwProcessId) +
        ", dwDesiredAccess=" + std::to_string(dwDesiredAccess) +
        ", bInheritHandle=" + std::to_string(bInheritHandle) +
        ", processName=" + procName +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}


BOOL WINAPI Hooking_CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    BOOL result = OriginalCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "CreateProcessW";
    std::string log_message = "lpApplicationName=" + wideToUtf8(lpApplicationName) +
        ", lpCommandLine=" + wideToUtf8(lpCommandLine) +
        ", lpCurrentDirectory=" + wideToUtf8(lpCurrentDirectory) +
        ", return=" + std::to_string(result);
    if (result && lpProcessInformation) {
        log_message += ", dwProcessId=" + std::to_string(lpProcessInformation->dwProcessId);
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
    BOOL result = OriginalCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "CreateProcessA";
    std::string log_message = "lpApplicationName=" + (lpApplicationName ? std::string(lpApplicationName) : "null") +
        ", lpCommandLine=" + (lpCommandLine ? std::string(lpCommandLine) : "null") +
        ", lpCurrentDirectory=" + (lpCurrentDirectory ? std::string(lpCurrentDirectory) : "null") +
        ", return=" + std::to_string(result);
    if (result && lpProcessInformation) {
        log_message += ", dwProcessId=" + std::to_string(lpProcessInformation->dwProcessId);
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}


LONG WINAPI Hooking_RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition) {
    LONG result = OriginalRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "RegCreateKeyExW";
    std::string log_message = "hKey=" + std::to_string((uintptr_t)hKey) +
        ", lpSubKey=" + wideToUtf8(lpSubKey) +
        ", dwOptions=" + std::to_string(dwOptions) +
        ", samDesired=" + std::to_string(samDesired) +
        ", return=" + std::to_string(result);
    if (phkResult) {
        log_message += ", phkResult=" + wideToUtf8(GetObjectNameFromHandle(*phkResult).c_str());
    }
    if (lpdwDisposition) {
        log_message += ", lpdwDisposition=" + std::to_string(*lpdwDisposition);
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

LONG WINAPI Hooking_RegDeleteKeyExW(HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, DWORD Reserved) {
    LONG result = OriginalRegDeleteKeyExW(hKey, lpSubKey, samDesired, Reserved);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "RegDeleteKeyExW";
    std::string log_message = "hKey=" + wideToUtf8(GetObjectNameFromHandle(hKey).c_str()) +
        ", lpSubKey=" + wideToUtf8(lpSubKey) +
        ", samDesired=" + std::to_string(samDesired) +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

LONG WINAPI Hooking_RegDeleteKeyExA(HKEY hKey, LPCSTR lpSubKey, REGSAM samDesired, DWORD Reserved) {
    LONG result = OriginalRegDeleteKeyExA(hKey, lpSubKey, samDesired, Reserved);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "RegDeleteKeyExA";
    std::string log_message = "hKey=" + wideToUtf8(GetObjectNameFromHandle(hKey).c_str()) +
        ", lpSubKey=" + (lpSubKey ? std::string(lpSubKey) : "null") +
        ", samDesired=" + std::to_string(samDesired) +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}


LONG WINAPI Hooking_RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved,
    DWORD dwType, const BYTE* lpData, DWORD cbData) {
    LONG result = OriginalRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "RegSetValueExW";
    std::string log_message = "hKey=" + wideToUtf8(GetObjectNameFromHandle(hKey).c_str()) +
        ", lpValueName=" + wideToUtf8(lpValueName) +
        ", dwType=" + std::to_string(dwType) +
        ", cbData=" + std::to_string(cbData) +
        ", return=" + std::to_string(result);
    if (lpData && cbData > 0) {
        DWORD base64Len = 0;
        CryptBinaryToStringA(lpData, cbData, CRYPT_STRING_BASE64, nullptr, &base64Len);
        std::string base64Data(base64Len, '\0');
        CryptBinaryToStringA(lpData, cbData, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
        log_message += ", lpData=" + base64Data;
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_CopyFileExW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName,
    LPPROGRESS_ROUTINE lpProgressRoutine, LPVOID lpData,
    LPBOOL pbCancel, DWORD dwCopyFlags) {
    BOOL result = OriginalCopyFileExW(lpExistingFileName, lpNewFileName, lpProgressRoutine,
        lpData, pbCancel, dwCopyFlags);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "CopyFileExW";
    std::string log_message = "lpExistingFileName=" + wideToUtf8(lpExistingFileName) +
        ", lpNewFileName=" + wideToUtf8(lpNewFileName) +
        ", dwCopyFlags=" + std::to_string(dwCopyFlags) +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}


BOOL WINAPI Hooking_MoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName) {
    BOOL result = OriginalMoveFileW(lpExistingFileName, lpNewFileName);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "MoveFileW";
    std::string log_message = "lpExistingFileName=" + wideToUtf8(lpExistingFileName) +
        ", lpNewFileName=" + wideToUtf8(lpNewFileName) +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_ShellExecuteExW(SHELLEXECUTEINFOW* pExecInfo) {
    BOOL result = OriginalShellExecuteExW(pExecInfo);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "ShellExecuteExW";
    std::string log_message = "return=" + std::to_string(result);
    if (pExecInfo) {
        log_message +=", fMask=" + std::to_string(pExecInfo->fMask) +
            ", lpVerb=" + wideToUtf8(pExecInfo->lpVerb) +
            ", lpFile=" + wideToUtf8(pExecInfo->lpFile) +
            ", lpParameters=" + wideToUtf8(pExecInfo->lpParameters) +
            ", lpDirectory=" + wideToUtf8(pExecInfo->lpDirectory) +
            ", lpClass=" + wideToUtf8(pExecInfo->lpClass);
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_HttpSendRequestExW(HINTERNET hRequest, LPINTERNET_BUFFERSW lpBuffersIn, LPINTERNET_BUFFERSW lpBuffersOut, DWORD dwFlags, DWORD_PTR dwContext) {
    BOOL result = OriginalHttpSendRequestExW(hRequest, lpBuffersIn, lpBuffersOut, dwFlags, dwContext);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "HttpSendRequestExW";
    std::string log_message = "hRequest=" + GetRequestUrl(hRequest) +
        ", return=" + std::to_string(result);
    if (lpBuffersIn) {
        log_message += ", lpBuffersIn=" + logInternetBuffersW(lpBuffersIn);
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_HttpSendRequestExA(HINTERNET hRequest, LPINTERNET_BUFFERSA lpBuffersIn, LPINTERNET_BUFFERSA lpBuffersOut, DWORD dwFlags, DWORD_PTR dwContext) {
    BOOL result = OriginalHttpSendRequestExA(hRequest, lpBuffersIn, lpBuffersOut, dwFlags, dwContext);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "HttpSendRequestExA";
    std::string log_message = "hRequest=" + GetRequestUrl(hRequest) +
        ", return=" + std::to_string(result);
    if (lpBuffersIn) {
        log_message += ", lpBuffersIn=" + logInternetBuffersA(lpBuffersIn);
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_InternetReadFileExA(HINTERNET hFile, LPINTERNET_BUFFERSA lpBuffersOut, DWORD dwFlags, DWORD_PTR dwContext) {
    BOOL result = OriginalInternetReadFileExA(hFile, lpBuffersOut, dwFlags, dwContext);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "InternetReadFileExA";
    std::string log_message = "hFile=" + getUrlFromHandle(hFile) +
        ", return=" + std::to_string(result);
    if (lpBuffersOut) {
        log_message += ", lpBuffersOut=" + logInternetBuffersA(lpBuffersOut);
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HINTERNET WINAPI Hooking_InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext) {
    HINTERNET result = OriginalInternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "InternetOpenUrlA";
    std::string log_message = "hInternet=" + std::to_string((uintptr_t)hInternet) +
        ", lpszUrl=" + (lpszUrl ? std::string(lpszUrl) : "null") +
        ", dwHeadersLength=" + std::to_string(dwHeadersLength) +
        ", dwFlags=" + std::to_string(dwFlags) +
        ", return=" + std::to_string((uintptr_t)result);
    if (lpszHeaders && dwHeadersLength > 0) {
        std::string headers(lpszHeaders, dwHeadersLength);
        log_message += ", lpszHeaders=" + headers;
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HINTERNET WINAPI Hooking_InternetOpenW(LPCWSTR lpszAgent, DWORD dwAccessType, LPCWSTR lpszProxy, LPCWSTR lpszProxyBypass, DWORD dwFlags) {
    HINTERNET result = OriginalInternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "InternetOpenW";
    std::string log_message = "lpszAgent=" + wideToUtf8(lpszAgent) +
        ", dwAccessType=" + std::to_string(dwAccessType) +
        ", lpszProxy=" + wideToUtf8(lpszProxy) +
        ", lpszProxyBypass=" + wideToUtf8(lpszProxyBypass) +
        ", dwFlags=" + std::to_string(dwFlags) +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HINTERNET WINAPI Hooking_InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags) {
    HINTERNET result = OriginalInternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "InternetOpenA";
    std::string log_message = "lpszAgent=" + (lpszAgent ? std::string(lpszAgent) : "null") +
        ", dwAccessType=" + std::to_string(dwAccessType) +
        ", lpszProxy=" + (lpszProxy ? std::string(lpszProxy) : "null") +
        ", lpszProxyBypass=" + (lpszProxyBypass ? std::string(lpszProxyBypass) : "null") +
        ", dwFlags=" + std::to_string(dwFlags) +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_HttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) {
    BOOL result = OriginalHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "HttpSendRequestW";
    std::string log_message = "hRequest=" + GetRequestUrl(hRequest) +
        ", dwHeadersLength=" + std::to_string(dwHeadersLength) +
        ", dwOptionalLength=" + std::to_string(dwOptionalLength) +
        ", return=" + std::to_string(result);
    if (lpszHeaders && dwHeadersLength > 0) {
        std::wstring headersW(lpszHeaders, dwHeadersLength);
        log_message += ", lpszHeaders=" + wideToUtf8(headersW.c_str());
    }
    if (lpOptional && dwOptionalLength > 0) {
        DWORD base64Len = 0;
        CryptBinaryToStringA((const BYTE*)lpOptional, dwOptionalLength, CRYPT_STRING_BASE64, nullptr, &base64Len);
        std::string base64Data(base64Len, '\0');
        CryptBinaryToStringA((const BYTE*)lpOptional, dwOptionalLength, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
        log_message += ", lpOptional=" + base64Data;
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength) {
    BOOL result = OriginalHttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "HttpSendRequestA";
    std::string log_message = "hRequest=" + GetRequestUrl(hRequest) +
        ", dwHeadersLength=" + std::to_string(dwHeadersLength) +
        ", dwOptionalLength=" + std::to_string(dwOptionalLength) +
        ", return=" + std::to_string(result);
    if (lpszHeaders && dwHeadersLength > 0) {
        std::string headers(lpszHeaders, dwHeadersLength);
        log_message += ", lpszHeaders=" + headers;
    }
    if (lpOptional && dwOptionalLength > 0) {
        DWORD base64Len = 0;
        CryptBinaryToStringA((const BYTE*)lpOptional, dwOptionalLength, CRYPT_STRING_BASE64, nullptr, &base64Len);
        std::string base64Data(base64Len, '\0');
        CryptBinaryToStringA((const BYTE*)lpOptional, dwOptionalLength, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
        log_message += ", lpOptional=" + base64Data;
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HINTERNET WINAPI Hooking_HttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) {
    HINTERNET result = OriginalHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "HttpOpenRequestW";
    std::string log_message = "hConnect=" + std::to_string((uintptr_t)hConnect) +
        ", lpszVerb=" + wideToUtf8(lpszVerb) +
        ", lpszObjectName=" + wideToUtf8(lpszObjectName) +
        ", lpszVersion=" + wideToUtf8(lpszVersion) +
        ", lpszReferrer=" + wideToUtf8(lpszReferrer) +
        ", lplpszAcceptTypes=[" + acceptTypesToString(lplpszAcceptTypes) + "]" +
        ", dwFlags=" + std::to_string(dwFlags) +
        ", return=" + std::to_string((uintptr_t)result) +
        ", url=" + GetRequestUrl(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HINTERNET WINAPI Hooking_HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext) {
    HINTERNET result = OriginalHttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "HttpOpenRequestA";
    std::string log_message = "hConnect=" + std::to_string((uintptr_t)hConnect) +
        ", lpszVerb=" + (lpszVerb ? std::string(lpszVerb) : "null") +
        ", lpszObjectName=" + (lpszObjectName ? std::string(lpszObjectName) : "null") +
        ", lpszVersion=" + (lpszVersion ? std::string(lpszVersion) : "null") +
        ", lpszReferrer=" + (lpszReferrer ? std::string(lpszReferrer) : "null") +
        ", lplpszAcceptTypes=[" + acceptTypesToStringA(lplpszAcceptTypes) + "]" +
        ", dwFlags=" + std::to_string(dwFlags) +
        ", return=" + std::to_string((uintptr_t)result) +
        ", url=" + GetRequestUrl(result); 
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}


BOOL WINAPI Hooking_FtpPutFileW(HINTERNET hConnect, LPCWSTR lpszLocalFile, LPCWSTR lpszNewRemoteFile, DWORD dwFlags, DWORD_PTR dwContext) {
    BOOL result = OriginalFtpPutFileW(hConnect, lpszLocalFile, lpszNewRemoteFile, dwFlags, dwContext);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "FtpPutFileW";
    std::string log_message = "hConnect=" + std::to_string((uintptr_t)hConnect) +
        ", lpszLocalFile=" + wideToUtf8(lpszLocalFile) +
        ", lpszNewRemoteFile=" + wideToUtf8(lpszNewRemoteFile) +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_FtpPutFileA(HINTERNET hConnect, LPCSTR lpszLocalFile, LPCSTR lpszNewRemoteFile, DWORD dwFlags, DWORD_PTR dwContext) {
    BOOL result = OriginalFtpPutFileA(hConnect, lpszLocalFile, lpszNewRemoteFile, dwFlags, dwContext);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "FtpPutFileA";
    std::string log_message = "hConnect=" + std::to_string((uintptr_t)hConnect) +
        ", lpszLocalFile=" + (lpszLocalFile ? std::string(lpszLocalFile) : "null") +
        ", lpszNewRemoteFile=" + (lpszNewRemoteFile ? std::string(lpszNewRemoteFile) : "null") +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HINTERNET WINAPI Hooking_WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags) {
    HINTERNET result = OriginalWinHttpOpen(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "WinHttpOpen";
    std::string log_message = "pszAgentW=" + wideToUtf8(pszAgentW) +
        ", dwAccessType=" + std::to_string(dwAccessType) +
        ", pszProxyW=" + wideToUtf8(pszProxyW) +
        ", pszProxyBypassW=" + wideToUtf8(pszProxyBypassW) +
        ", dwFlags=" + std::to_string(dwFlags) +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HINTERNET WINAPI Hooking_WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags) {
    HINTERNET result = OriginalWinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, dwFlags);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "WinHttpOpenRequest";
    std::string log_message = "hConnect=" + std::to_string((uintptr_t)hConnect) +
        ", pwszVerb=" + wideToUtf8(pwszVerb) +
        ", pwszObjectName=" + wideToUtf8(pwszObjectName) +
        ", pwszVersion=" + wideToUtf8(pwszVersion) +
        ", pwszReferrer=" + wideToUtf8(pwszReferrer) +
        ", ppwszAcceptTypes=[" + acceptTypesToString(ppwszAcceptTypes) + "]" +
        ", dwFlags=" + std::to_string(dwFlags) +
        ", return=" + std::to_string((uintptr_t)result) +
        ", url=" + GetRequestUrl(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HINTERNET WINAPI Hooking_WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved) {
    HINTERNET result = OriginalWinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "WinHttpConnect";
    std::string log_message = "hSession=" + std::to_string((uintptr_t)hSession) +
        ", pswzServerName=" + wideToUtf8(pswzServerName) +
        ", nServerPort=" + std::to_string(nServerPort) +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HRESULT WINAPI Hooking_URLOpenStreamA(LPUNKNOWN pCaller, LPCSTR szURL, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB) {
    HRESULT result = OriginalURLOpenStreamA(pCaller, szURL, dwReserved, lpfnCB);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "URLOpenStreamA";
    std::string log_message = "szURL=" + (szURL ? std::string(szURL) : "null") +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HRESULT WINAPI Hooking_URLOpenBlockingStreamA(LPUNKNOWN pCaller, LPCSTR szURL, LPSTREAM* ppStream, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB) {
    HRESULT result = OriginalURLOpenBlockingStreamA(pCaller, szURL, ppStream, dwReserved, lpfnCB);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "URLOpenBlockingStreamA";
    std::string log_message = "szURL=" + (szURL ? std::string(szURL) : "null") +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HRESULT WINAPI Hooking_URLDownloadToCacheFileA(LPUNKNOWN pCaller, LPCSTR szURL, LPSTR szFileName, DWORD cchFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB) {
    HRESULT result = OriginalURLDownloadToCacheFileA(pCaller, szURL, szFileName, cchFileName, dwReserved, lpfnCB);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "URLDownloadToCacheFileA";
    std::string log_message = "szURL=" + (szURL ? std::string(szURL) : "null") +
        ", szFileName=" + (szFileName ? std::string(szFileName) : "null") +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HRESULT WINAPI Hooking_URLDownloadToFileA(LPUNKNOWN pCaller, LPCSTR szURL, LPCSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB) {
    HRESULT result = OriginalURLDownloadToFileA(pCaller, szURL, szFileName, dwReserved, lpfnCB);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "URLDownloadToFileA";
    std::string log_message = "szURL=" + (szURL ? std::string(szURL) : "null") +
        ", szFileName=" + (szFileName ? std::string(szFileName) : "null") +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_InternetWriteFile(HINTERNET hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten) {
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "InternetWriteFile";
    std::string log_message = "hFile=" + getUrlFromHandle(hFile) +
        ", dwNumberOfBytesToWrite=" + std::to_string(dwNumberOfBytesToWrite);
    if (lpBuffer != NULL && dwNumberOfBytesToWrite > 0) {
        DWORD base64Len = 0;
        CryptBinaryToStringA((const BYTE*)lpBuffer, dwNumberOfBytesToWrite, CRYPT_STRING_BASE64, nullptr, &base64Len);
        std::string base64Data(base64Len, '\0');
        CryptBinaryToStringA((const BYTE*)lpBuffer, dwNumberOfBytesToWrite, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
        log_message += ", lpBuffer=" + base64Data;
    }
    BOOL result = OriginalInternetWriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
    log_message += ", return=" + std::to_string(result);
    if (result && lpdwNumberOfBytesWritten != NULL) {
        log_message += ", bytes_written=" + std::to_string(*lpdwNumberOfBytesWritten);
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    BOOL result = OriginalInternetReadFile(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "InternetReadFile";
    std::string log_message = "hFile=" + getUrlFromHandle(hFile) +
        ", dwNumberOfBytesToRead=" + std::to_string(dwNumberOfBytesToRead) +
        ", return=" + std::to_string(result);
    if (result && lpdwNumberOfBytesRead != NULL && lpBuffer != NULL) {
        DWORD bytesRead = *lpdwNumberOfBytesRead;
        if (bytesRead > 0) {
            DWORD base64Len = 0;
            CryptBinaryToStringA((const BYTE*)lpBuffer, bytesRead, CRYPT_STRING_BASE64, nullptr, &base64Len);
            std::string base64Data(base64Len, '\0');
            CryptBinaryToStringA((const BYTE*)lpBuffer, bytesRead, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
            log_message += ", lpBuffer=" + base64Data;
        }
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HANDLE Hooking_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HANDLE result = OriginalCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "CreateFileA";
    std::string log_message = "lpFileName=" + std::string(lpFileName) +
        ", dwDesiredAccess=" + std::to_string(dwDesiredAccess) +
        ", dwCreationDisposition=" + std::to_string(dwCreationDisposition) +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HANDLE Hooking_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    HANDLE result = OriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "CreateFileW";
    std::string log_message = "lpFileName=" + wideToUtf8(lpFileName) +
        ", dwDesiredAccess=" + std::to_string(dwDesiredAccess) +
        ", dwCreationDisposition=" + std::to_string(dwCreationDisposition) +
        ", return=" + std::to_string((uintptr_t)result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

SOCKET WSAAPI Hooking_socket(int af, int type, int protocol) {
    SOCKET result = OriginalSocket(af, type, protocol);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "socket";
    std::string log_message = "af=" + std::to_string(af) +
        ", type=" + std::to_string(type) +
        ", protocol=" + std::to_string(protocol);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

int WSAAPI Hooking_connect(SOCKET s, const sockaddr* name, int namelen) {
    int result = OriginalConnect(s, name, namelen);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "connect";
    std::string addr_str = sockaddr_to_string(name, namelen);
    std::string log_message = "addr=" + addr_str +
        ", return=" + std::to_string(result);
    if (result == SOCKET_ERROR) {
        log_message += ", error=" + std::to_string(WSAGetLastError());
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

int WSAAPI Hooking_send(SOCKET s, const char* buf, int len, int flags) {
    int result = OriginalSend(s, buf, len, flags);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "send";
    std::string log_message = getPeerInfo(s) + ", len=" + std::to_string(len) +
        ", flags=" + std::to_string(flags);
    if (result == SOCKET_ERROR) {
        log_message += ", error=" + std::to_string(WSAGetLastError());
    }
    else {
        log_message += ", bytes_sent=" + std::to_string(result);
        if (buf && len > 0) {
            DWORD base64Len = 0;
            CryptBinaryToStringA((const BYTE*)buf, len, CRYPT_STRING_BASE64, nullptr, &base64Len);
            std::string base64Data(base64Len, '\0');
            CryptBinaryToStringA((const BYTE*)buf, len, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
            log_message += ", buf=" + base64Data;
        }
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

int WSAAPI Hooking_recv(SOCKET s, char* buf, int len, int flags) {
    int result = OriginalRecv(s, buf, len, flags);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "recv";
    std::string log_message = getPeerInfo(s) + ", len=" + std::to_string(len) +
        ", flags=" + std::to_string(flags);
    if (result == SOCKET_ERROR) {
        log_message += ", error=" + std::to_string(WSAGetLastError());
    }
    else if (result == 0) {
        log_message += ", connection_closed";
    }
    else {
        log_message += ", bytes_received=" + std::to_string(result);
        if (buf && result > 0) {
            DWORD base64Len = 0;
            CryptBinaryToStringA((const BYTE*)buf, result, CRYPT_STRING_BASE64, nullptr, &base64Len);
            std::string base64Data(base64Len, '\0');
            CryptBinaryToStringA((const BYTE*)buf, result, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
            log_message += ", buf=" + base64Data;
        }
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

int WSAAPI Hooking_getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, ADDRINFOA** ppResult) {
    int result = OriginalGetaddrinfo(pNodeName, pServiceName, pHints, ppResult);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "getaddrinfo";
    std::string log_message = "nodeName=" + (pNodeName ? std::string(pNodeName) : "null") +
        ", serviceName=" + (pServiceName ? std::string(pServiceName) : "null") +
        ", return=" + std::to_string(result);
    if (result != 0) {
        log_message += ", error=" + std::to_string(WSAGetLastError());
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

int WSAAPI Hooking_GetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW* pHints, PADDRINFOW* ppResult) {
    int result = OriginalGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "GetAddrInfoW";
    std::string log_message = "nodeName=" + wideToUtf8(pNodeName) +
        ", serviceName=" + wideToUtf8(pServiceName) +
        ", return=" + std::to_string(result);
    if (result != 0) {
        log_message += ", error=" + std::to_string(WSAGetLastError());
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    BOOL result = OriginalReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "ReadFile";
    std::string log_message = "hFile=" + wideToUtf8(GetFullPathFromHFILE(hFile).c_str()) +
        ", nNumberOfBytesToRead=" + std::to_string(nNumberOfBytesToRead) +
        ", return=" + std::to_string(result);
    if (result && lpNumberOfBytesRead != NULL) {
        DWORD bytesRead = *lpNumberOfBytesRead;
        if (bytesRead > 0 && lpBuffer != NULL) {
            DWORD base64Len = 0;
            CryptBinaryToStringA((const BYTE*)lpBuffer, bytesRead, CRYPT_STRING_BASE64, nullptr, &base64Len);
            std::string base64Data(base64Len, '\0');
            CryptBinaryToStringA((const BYTE*)lpBuffer, bytesRead, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
            log_message += ", lpBuffer=" + base64Data;
        }
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "WriteFile";
    std::string log_message = "hFile=" + wideToUtf8(GetFullPathFromHFILE(hFile).c_str()) +
        ", nNumberOfBytesToWrite=" + std::to_string(nNumberOfBytesToWrite);
    if (lpBuffer != NULL && nNumberOfBytesToWrite > 0) {
        DWORD base64Len = 0;
        CryptBinaryToStringA((const BYTE*)lpBuffer, nNumberOfBytesToWrite, CRYPT_STRING_BASE64, nullptr, &base64Len);
        std::string base64Data(base64Len, '\0');
        CryptBinaryToStringA((const BYTE*)lpBuffer, nNumberOfBytesToWrite, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
        log_message += ", lpBuffer=" + base64Data;
    }
    BOOL result = OriginalWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    log_message += ", return=" + std::to_string(result);
    if (result && lpNumberOfBytesWritten != NULL) {
        log_message += ", bytes_written=" + std::to_string(*lpNumberOfBytesWritten);
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

BOOL WINAPI Hooking_DeleteFileW(LPCWSTR lpFileName) {
    BOOL result = OriginalDeleteFileW(lpFileName);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "DeleteFileW";
    std::string log_message = "lpFileName=" + wideToUtf8(lpFileName) +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

LONG WINAPI Hooking_RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData) {
    LONG result = OriginalRegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "RegSetValueExA";
    std::string log_message = "hKey=" + wideToUtf8(GetObjectNameFromHandle(hKey).c_str()) +
        ", lpValueName=" + (lpValueName ? std::string(lpValueName) : "null") +
        ", dwType=" + std::to_string(dwType) +
        ", cbData=" + std::to_string(cbData) +
        ", return=" + std::to_string(result);
    if (lpData && cbData > 0) {
        DWORD base64Len = 0;
        CryptBinaryToStringA(lpData, cbData, CRYPT_STRING_BASE64, nullptr, &base64Len);
        std::string base64Data(base64Len, '\0');
        CryptBinaryToStringA(lpData, cbData, CRYPT_STRING_BASE64, &base64Data[0], &base64Len);
        log_message += ", lpData=" + base64Data;
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

LONG WINAPI Hooking_RegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey) {
    LONG result = OriginalRegDeleteKeyW(hKey, lpSubKey);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "RegDeleteKeyW";
    std::string log_message = "hKey=" + wideToUtf8(GetObjectNameFromHandle(hKey).c_str()) +
        ", lpSubKey=" + (lpSubKey ? wideToUtf8(lpSubKey) : "null") +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

LONG WINAPI Hooking_RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition) {
    LONG result = OriginalRegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "RegCreateKeyExA";
    std::string log_message = "hKey=" + std::to_string((uintptr_t)hKey) +
        ", lpSubKey=" + (lpSubKey ? std::string(lpSubKey) : "null") +
        ", dwOptions=" + std::to_string(dwOptions) +
        ", samDesired=" + std::to_string(samDesired) +
        ", return=" + std::to_string(result);
    if (phkResult) {
        log_message += ", phkResult=" + wideToUtf8(GetObjectNameFromHandle(*phkResult).c_str());
    }
    if (lpdwDisposition) {
        log_message += ", lpdwDisposition=" + std::to_string(*lpdwDisposition);
    }
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

HRESULT WINAPI Hooking_URLDownloadToFileW(LPUNKNOWN pCaller, LPCWSTR szURL, LPCWSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB) {
    HRESULT result = OriginalURLDownloadToFileW(pCaller, szURL, szFileName, dwReserved, lpfnCB);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "URLDownloadToFileW";
    std::string log_message = "szURL=" + (szURL ? wideToUtf8(szURL) : "null") +
        ", szFileName=" + (szFileName ? wideToUtf8(szFileName) : "null") +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}


// Define originals and hooks based on architecture
#ifdef _WIN64
std::vector<PVOID*> originals = {
    //(PVOID*)&OriginalCreateFileA,
    //(PVOID*)&OriginalCreateFileW,
    //(PVOID*)&OriginalSocket,
    (PVOID*)&OriginalConnect,
    (PVOID*)&OriginalSend,
    (PVOID*)&OriginalRecv,
    (PVOID*)&OriginalGetaddrinfo,
    (PVOID*)&OriginalGetAddrInfoW,
    (PVOID*)&OriginalReadFile,
    (PVOID*)&OriginalWriteFile,
    (PVOID*)&OriginalDeleteFileW,
    (PVOID*)&OriginalRegSetValueExA,
    (PVOID*)&OriginalRegDeleteKeyW,
    (PVOID*)&OriginalRegCreateKeyExA,
    (PVOID*)&OriginalURLDownloadToFileW,
    (PVOID*)&OriginalInternetReadFile,
    (PVOID*)&OriginalInternetWriteFile,
    (PVOID*)&OriginalURLDownloadToFileA,
    (PVOID*)&OriginalURLDownloadToCacheFileA,
    (PVOID*)&OriginalURLOpenBlockingStreamA,
    (PVOID*)&OriginalURLOpenStreamA,
    (PVOID*)&OriginalInternetOpenA,
    (PVOID*)&OriginalInternetOpenW,
    (PVOID*)&OriginalInternetOpenUrlA,
    (PVOID*)&OriginalInternetReadFileExA,
    (PVOID*)&OriginalHttpOpenRequestA,
    (PVOID*)&OriginalHttpOpenRequestW,
    (PVOID*)&OriginalHttpSendRequestA,
    (PVOID*)&OriginalHttpSendRequestW,
    (PVOID*)&OriginalHttpSendRequestExA,
    (PVOID*)&OriginalHttpSendRequestExW,
    (PVOID*)&OriginalFtpPutFileA,
    (PVOID*)&OriginalFtpPutFileW,
    (PVOID*)&OriginalWinHttpOpen,
    (PVOID*)&OriginalWinHttpConnect,
    (PVOID*)&OriginalWinHttpOpenRequest,
    (PVOID*)&OriginalShellExecuteExW,
    (PVOID*)&OriginalMoveFileW,
    (PVOID*)&OriginalCopyFileExW,
    (PVOID*)&OriginalRegSetValueExW,
    (PVOID*)&OriginalRegDeleteKeyExA,
    (PVOID*)&OriginalRegDeleteKeyExW,
    (PVOID*)&OriginalRegCreateKeyExW,
    (PVOID*)&OriginalCreateProcessW,
    (PVOID*)&OriginalCreateProcessA,
    (PVOID*)&OriginalOpenProcess,
    (PVOID*)&OriginalWriteProcessMemory,
    (PVOID*)&OriginalReadProcessMemory,
    (PVOID*)&OriginalCreateRemoteThread,
    (PVOID*)&OriginalVirtualAllocEx,
    (PVOID*)&OriginalVirtualProtectEx,
    (PVOID*)&OriginalResumeThread,
    (PVOID*)&OriginalSuspendThread,
    (PVOID*)&OriginalSetWindowsHookExA,
    (PVOID*)&OriginalSetWindowsHookExW,
    (PVOID*)&OriginalGetAsyncKeyState,
    (PVOID*)&OriginalGetComputerNameW,
    (PVOID*)&OriginalGetSystemInfo,
    (PVOID*)&OriginalGetUserNameA,
    (PVOID*)&OriginalGetUserNameW,
    (PVOID*)&OriginalIsDebuggerPresent,
    //(PVOID*)&OriginalNtQueryInformationProcess,
    (PVOID*)&OriginalFindWindowA,
    (PVOID*)&OriginalFindWindowW,
    (PVOID*)&OriginalLoadLibraryA,
    (PVOID*)&OriginalLoadLibraryW,
    (PVOID*)&OriginalGetProcAddress,
    (PVOID*)&OriginalAdjustTokenPrivileges,
    (PVOID*)&OriginalCreateServiceA,
    (PVOID*)&OriginalCreateServiceW,
    (PVOID*)&OriginalStartServiceA,
    (PVOID*)&OriginalStartServiceW,
    (PVOID*)&OriginalCreateMutexW,
    (PVOID*)&OriginalCheckRemoteDebuggerPresent,
    (PVOID*)&OriginalGetLocaleInfoW,
    (PVOID*)&OriginalCloseHandle,
    (PVOID*)&OriginalWSAConnect
};
std::vector<PVOID> hooks = {
    //Hooking_CreateFileA,
    //Hooking_CreateFileW,
    //Hooking_socket,
    Hooking_connect,
    Hooking_send,
    Hooking_recv,
    Hooking_getaddrinfo,
    Hooking_GetAddrInfoW,
    Hooking_ReadFile,
    Hooking_WriteFile,
    Hooking_DeleteFileW,
    Hooking_RegSetValueExA,
    Hooking_RegDeleteKeyW,
    Hooking_RegCreateKeyExA,
    Hooking_URLDownloadToFileW,
    Hooking_InternetReadFile,
    Hooking_InternetWriteFile,
    Hooking_URLDownloadToFileA,
    Hooking_URLDownloadToCacheFileA,
    Hooking_URLOpenBlockingStreamA,
    Hooking_URLOpenStreamA,
    Hooking_InternetOpenA,
    Hooking_InternetOpenW,
    Hooking_InternetOpenUrlA,
    Hooking_InternetReadFileExA,
    Hooking_HttpOpenRequestA,
    Hooking_HttpOpenRequestW,
    Hooking_HttpSendRequestA,
    Hooking_HttpSendRequestW,
    Hooking_HttpSendRequestExA,
    Hooking_HttpSendRequestExW,
    Hooking_FtpPutFileA,
    Hooking_FtpPutFileW,
    Hooking_WinHttpOpen,
    Hooking_WinHttpConnect,
    Hooking_WinHttpOpenRequest,
    Hooking_ShellExecuteExW,
    Hooking_MoveFileW,
    Hooking_CopyFileExW,
    Hooking_RegSetValueExW,
    Hooking_RegDeleteKeyExA,
    Hooking_RegDeleteKeyExW,
    Hooking_RegCreateKeyExW,
    Hooking_CreateProcessW,
    Hooking_CreateProcessA,
    Hooking_OpenProcess,
    Hooking_WriteProcessMemory,
    Hooking_ReadProcessMemory,
    Hooking_CreateRemoteThread,
    Hooking_VirtualAllocEx,
    Hooking_VirtualProtectEx,
    Hooking_ResumeThread,
    Hooking_SuspendThread,
    Hooking_SetWindowsHookExA,
    Hooking_SetWindowsHookExW,
    Hooking_GetAsyncKeyState,
    Hooking_GetComputerNameW,
    Hooking_GetSystemInfo,
    Hooking_GetUserNameA,
    Hooking_GetUserNameW,
    Hooking_IsDebuggerPresent,
    //Hooking_NtQueryInformationProcess,
    Hooking_FindWindowA,
    Hooking_FindWindowW,
    Hooking_LoadLibraryA,
    Hooking_LoadLibraryW,
    Hooking_GetProcAddress,
    Hooking_AdjustTokenPrivileges,
    Hooking_CreateServiceA,
    Hooking_CreateServiceW,
    Hooking_StartServiceA,
    Hooking_StartServiceW,
    Hooking_CreateMutexW,
    Hooking_CheckRemoteDebuggerPresent,
    Hooking_GetLocaleInfoW,
    Hooking_CloseHandle,
    Hooking_WSAConnect
};
#else
std::vector<PVOID*> originals = {
    //(PVOID*)&OriginalCreateFileW,
    //(PVOID*)&OriginalSocket,
    (PVOID*)&OriginalConnect,
    (PVOID*)&OriginalSend,
    (PVOID*)&OriginalRecv,
    (PVOID*)&OriginalGetaddrinfo,
    (PVOID*)&OriginalGetAddrInfoW,
    (PVOID*)&OriginalReadFile,
    (PVOID*)&OriginalWriteFile,
    (PVOID*)&OriginalDeleteFileW,
    (PVOID*)&OriginalRegSetValueExA,
    (PVOID*)&OriginalRegDeleteKeyW,
    (PVOID*)&OriginalRegCreateKeyExA,
    (PVOID*)&OriginalURLDownloadToFileW,
    (PVOID*)&OriginalInternetReadFile,
    (PVOID*)&OriginalInternetWriteFile,
    (PVOID*)&OriginalURLDownloadToFileA,
    (PVOID*)&OriginalURLDownloadToCacheFileA,
    (PVOID*)&OriginalURLOpenBlockingStreamA,
    (PVOID*)&OriginalURLOpenStreamA,
    (PVOID*)&OriginalInternetOpenA,
    (PVOID*)&OriginalInternetOpenW,
    (PVOID*)&OriginalInternetOpenUrlA,
    (PVOID*)&OriginalInternetReadFileExA,
    (PVOID*)&OriginalHttpOpenRequestA,
    (PVOID*)&OriginalHttpOpenRequestW,
    (PVOID*)&OriginalHttpSendRequestA,
    (PVOID*)&OriginalHttpSendRequestW,
    (PVOID*)&OriginalHttpSendRequestExA,
    (PVOID*)&OriginalHttpSendRequestExW,
    (PVOID*)&OriginalFtpPutFileA,
    (PVOID*)&OriginalFtpPutFileW,
    (PVOID*)&OriginalWinHttpOpen,
    (PVOID*)&OriginalWinHttpConnect,
    (PVOID*)&OriginalWinHttpOpenRequest,
    (PVOID*)&OriginalShellExecuteExW,
    (PVOID*)&OriginalMoveFileW,
    (PVOID*)&OriginalCopyFileExW,
    (PVOID*)&OriginalRegSetValueExW,
    (PVOID*)&OriginalRegDeleteKeyExA,
    (PVOID*)&OriginalRegDeleteKeyExW,
    (PVOID*)&OriginalRegCreateKeyExW,
    (PVOID*)&OriginalCreateProcessW,
    (PVOID*)&OriginalCreateProcessA,
    (PVOID*)&OriginalOpenProcess,
    (PVOID*)&OriginalWriteProcessMemory,
    (PVOID*)&OriginalReadProcessMemory,
    (PVOID*)&OriginalCreateRemoteThread,
    (PVOID*)&OriginalVirtualAllocEx,
    (PVOID*)&OriginalVirtualProtectEx,
    (PVOID*)&OriginalResumeThread,
    (PVOID*)&OriginalSuspendThread,
    (PVOID*)&OriginalSetWindowsHookExA,
    (PVOID*)&OriginalSetWindowsHookExW,
    (PVOID*)&OriginalGetAsyncKeyState,
    (PVOID*)&OriginalGetComputerNameW,
    (PVOID*)&OriginalGetSystemInfo,
    (PVOID*)&OriginalGetUserNameA,
    (PVOID*)&OriginalGetUserNameW,
    (PVOID*)&OriginalIsDebuggerPresent,
    //(PVOID*)&OriginalNtQueryInformationProcess,
    (PVOID*)&OriginalFindWindowA,
    (PVOID*)&OriginalFindWindowW,
    (PVOID*)&OriginalLoadLibraryA,
    (PVOID*)&OriginalLoadLibraryW,
    (PVOID*)&OriginalGetProcAddress,
    (PVOID*)&OriginalAdjustTokenPrivileges,
    (PVOID*)&OriginalCreateServiceA,
    (PVOID*)&OriginalCreateServiceW,
    (PVOID*)&OriginalStartServiceA,
    (PVOID*)&OriginalStartServiceW,
    (PVOID*)&OriginalCreateMutexW,
    (PVOID*)&OriginalCheckRemoteDebuggerPresent,
	(PVOID*)&OriginalGetLocaleInfoW,
	(PVOID*)&OriginalCloseHandle,
	(PVOID*)&OriginalWSAConnect
};
std::vector<PVOID> hooks = {
    //Hooking_CreateFileW,
    //Hooking_socket,
    Hooking_connect,
    Hooking_send,
    Hooking_recv,
    Hooking_getaddrinfo,
    Hooking_GetAddrInfoW,
    Hooking_ReadFile,
    Hooking_WriteFile,
    Hooking_DeleteFileW,
    Hooking_RegSetValueExA,
    Hooking_RegDeleteKeyW,
    Hooking_RegCreateKeyExA,
    Hooking_URLDownloadToFileW,
    Hooking_InternetReadFile,
    Hooking_InternetWriteFile,
    Hooking_URLDownloadToFileA,
    Hooking_URLDownloadToCacheFileA,
    Hooking_URLOpenBlockingStreamA,
    Hooking_URLOpenStreamA,
    Hooking_InternetOpenA,
    Hooking_InternetOpenW,
    Hooking_InternetOpenUrlA,
    Hooking_InternetReadFileExA,
    Hooking_HttpOpenRequestA,
    Hooking_HttpOpenRequestW,
    Hooking_HttpSendRequestA,
    Hooking_HttpSendRequestW,
    Hooking_HttpSendRequestExA,
    Hooking_HttpSendRequestExW,
    Hooking_FtpPutFileA,
    Hooking_FtpPutFileW,
    Hooking_WinHttpOpen,
    Hooking_WinHttpConnect,
    Hooking_WinHttpOpenRequest,
    Hooking_ShellExecuteExW,
    Hooking_MoveFileW,
    Hooking_CopyFileExW,
    Hooking_RegSetValueExW,
    Hooking_RegDeleteKeyExA,
    Hooking_RegDeleteKeyExW,
    Hooking_RegCreateKeyExW,
    Hooking_CreateProcessW,
    Hooking_CreateProcessA,
    Hooking_OpenProcess,
    Hooking_WriteProcessMemory,
    Hooking_ReadProcessMemory,
    Hooking_CreateRemoteThread,
    Hooking_VirtualAllocEx,
    Hooking_VirtualProtectEx,
    Hooking_ResumeThread,
    Hooking_SuspendThread,
    Hooking_SetWindowsHookExA,
    Hooking_SetWindowsHookExW,
    Hooking_GetAsyncKeyState,
    Hooking_GetComputerNameW,
    Hooking_GetSystemInfo,
    Hooking_GetUserNameA,
    Hooking_GetUserNameW,
    Hooking_IsDebuggerPresent,
    //Hooking_NtQueryInformationProcess,
    Hooking_FindWindowA,
    Hooking_FindWindowW,
    Hooking_LoadLibraryA,
    Hooking_LoadLibraryW,
    Hooking_GetProcAddress,
    Hooking_AdjustTokenPrivileges,
    Hooking_CreateServiceA,
    Hooking_CreateServiceW,
    Hooking_StartServiceA,
    Hooking_StartServiceW,
    Hooking_CreateMutexW,
    Hooking_CheckRemoteDebuggerPresent,
	Hooking_GetLocaleInfoW,
	Hooking_CloseHandle,
	Hooking_WSAConnect
};
#endif

BOOL InstallHooks() {
    DWORD error = DetourTransactionBegin();
    if (error != NO_ERROR) return FALSE;
    error = DetourUpdateThread(GetCurrentThread());
    if (error != NO_ERROR) return FALSE;
    for (size_t i = 0; i < originals.size(); i++) {
        error = DetourAttach(originals[i], hooks[i]);
        if (error != NO_ERROR) return FALSE;
    }
    error = DetourTransactionCommit();
    return (error == NO_ERROR);
}

BOOL UninstallHooks() {
    DWORD error = DetourTransactionBegin();
    if (error != NO_ERROR) return FALSE;
    error = DetourUpdateThread(GetCurrentThread());
    if (error != NO_ERROR) return FALSE;
    for (size_t i = 0; i < originals.size(); i++) {
        error = DetourDetach(originals[i], hooks[i]);
        if (error != NO_ERROR) return FALSE;
    }
    error = DetourTransactionCommit();
    return (error == NO_ERROR);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Connect to the named pipe
        hPipe = OriginalCreateFileW(PIPE_NAME, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe == INVALID_HANDLE_VALUE) {
            printf("Failed to connect to pipe: %d\n", GetLastError());
            return FALSE;
        }

        InstallHooks();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}