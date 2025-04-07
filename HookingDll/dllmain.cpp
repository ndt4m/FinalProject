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
#include <urlmon.h>  // For URLDownloadToFileA
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "urlmon.lib")  // Link with urlmon.lib for URLDownloadToFileA

const wchar_t* PIPE_NAME = TEXT("\\\\.\\pipe\\RATMonitorPipe");
HANDLE hPipe = INVALID_HANDLE_VALUE;

// Helper function to get the current timestamp as a string
std::string getCurrentTimestamp() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buffer[20];
    sprintf_s(buffer, "%04d-%02d-%02d %02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(buffer);
}

std::string wideToUtf8(LPCWSTR wstr) {
    if (!wstr) return "null";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (size == 0) return "";
    std::string result(size - 1, 0); // Exclude null terminator from length
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size, nullptr, nullptr);
    return result;
}

// Helper function to convert sockaddr to a readable string
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
        return "unknown family";
    }
    return std::string(ip) + ":" + std::to_string(port);
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
BOOL(WINAPI* OriginalDeleteFileA)(LPCSTR) = DeleteFileA;
LONG(WINAPI* OriginalRegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD) = RegSetValueExA;
LONG(WINAPI* OriginalRegDeleteKeyW)(HKEY, LPCWSTR) = RegDeleteKeyW;
LONG(WINAPI* OriginalRegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD) = RegCreateKeyExA;
HRESULT(WINAPI* OriginalURLDownloadToFileA)(LPUNKNOWN, LPCSTR, LPCSTR, DWORD, LPBINDSTATUSCALLBACK) = URLDownloadToFileA;

void SendLog(const std::string& log) {
    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        OriginalWriteFile(hPipe, log.c_str(), log.size(), &bytesWritten, NULL);
    }
}

// Hooking functions
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
    std::string log_message = "len=" + std::to_string(len) +
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
    std::string log_message = "len=" + std::to_string(len) +
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
    std::string log_message = "hFile=" + std::to_string((uintptr_t)hFile) +
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
    std::string log_message = "hFile=" + std::to_string((uintptr_t)hFile) +
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

BOOL WINAPI Hooking_DeleteFileA(LPCSTR lpFileName) {
    BOOL result = OriginalDeleteFileA(lpFileName);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "DeleteFileA";
    std::string log_message = "lpFileName=" + std::string(lpFileName) +
        ", return=" + std::to_string(result);
    SendLog(timestamp + "|" + api_name + "|" + log_message);
    return result;
}

LONG WINAPI Hooking_RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData) {
    LONG result = OriginalRegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    std::string timestamp = getCurrentTimestamp();
    std::string api_name = "RegSetValueExA";
    std::string log_message = "hKey=" + std::to_string((uintptr_t)hKey) +
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
    std::string api_name = "RegDeleteKeyA";
    std::string log_message = "hKey=" + std::to_string((uintptr_t)hKey) +
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
        log_message += ", phkResult=" + std::to_string((uintptr_t)*phkResult);
    }
    if (lpdwDisposition) {
        log_message += ", lpdwDisposition=" + std::to_string(*lpdwDisposition);
    }
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

// Define originals and hooks based on architecture
#ifdef _WIN64
std::vector<PVOID*> originals = {
    (PVOID*)&OriginalCreateFileA,
    (PVOID*)&OriginalCreateFileW,
    (PVOID*)&OriginalSocket,
    (PVOID*)&OriginalConnect,
    (PVOID*)&OriginalSend,
    (PVOID*)&OriginalRecv,
    (PVOID*)&OriginalGetaddrinfo,
    (PVOID*)&OriginalGetAddrInfoW,
    (PVOID*)&OriginalReadFile,
    (PVOID*)&OriginalWriteFile,
    (PVOID*)&OriginalDeleteFileA,
    (PVOID*)&OriginalRegSetValueExA,
    (PVOID*)&OriginalRegDeleteKeyW,
    (PVOID*)&OriginalRegCreateKeyExA,
    (PVOID*)&OriginalURLDownloadToFileA
};
std::vector<PVOID> hooks = {
    Hooking_CreateFileA,
    Hooking_CreateFileW,
    Hooking_socket,
    Hooking_connect,
    Hooking_send,
    Hooking_recv,
    Hooking_getaddrinfo,
    Hooking_GetAddrInfoW,
    Hooking_ReadFile,
    Hooking_WriteFile,
    Hooking_DeleteFileA,
    Hooking_RegSetValueExA,
    Hooking_RegDeleteKeyW,
    Hooking_RegCreateKeyExA,
    Hooking_URLDownloadToFileA
};
#else
std::vector<PVOID*> originals = {
    (PVOID*)&OriginalCreateFileW,
    (PVOID*)&OriginalSocket,
    (PVOID*)&OriginalConnect,
    (PVOID*)&OriginalSend,
    (PVOID*)&OriginalRecv,
    (PVOID*)&OriginalGetaddrinfo,
    (PVOID*)&OriginalGetAddrInfoW,
    (PVOID*)&OriginalReadFile,
    (PVOID*)&OriginalWriteFile,
    (PVOID*)&OriginalDeleteFileA,
    (PVOID*)&OriginalRegSetValueExA,
    (PVOID*)&OriginalRegDeleteKeyW,
    (PVOID*)&OriginalRegCreateKeyExA,
    (PVOID*)&OriginalURLDownloadToFileA
};
std::vector<PVOID> hooks = {
    Hooking_CreateFileW,
    Hooking_socket,
    Hooking_connect,
    Hooking_send,
    Hooking_recv,
    Hooking_getaddrinfo,
    Hooking_GetAddrInfoW,
    Hooking_ReadFile,
    Hooking_WriteFile,
    Hooking_DeleteFileA,
    Hooking_RegSetValueExA,
    Hooking_RegDeleteKeyW,
    Hooking_RegCreateKeyExA,
    Hooking_URLDownloadToFileA
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