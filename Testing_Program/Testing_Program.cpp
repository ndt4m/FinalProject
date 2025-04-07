#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <winbase.h>
#include <Winhttp.h>
#include <Urlmon.h>
#include <wininet.h>
#include <shellapi.h>
#include <winternl.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ntdll.lib")
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 // Windows Vista or later
#endif


int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return 1;
    }
    std::cout << "Creating socket..." << std::endl;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "socket failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }
    std::cout << "Socket created: " << sock << std::endl;
    struct addrinfo hints, * res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; 
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (getaddrinfo("example.com", "80", &hints, &res) != 0) {
        std::cerr << "getaddrinfo failed: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }
   /* struct addrinfoW hintsW, * resW;
    memset(&hintsW, 0, sizeof(hintsW));
    hintsW.ai_family = AF_INET;
    hintsW.ai_socktype = SOCK_STREAM;
    hintsW.ai_protocol = IPPROTO_TCP;
    if (GetAddrInfoW(L"example.com", L"80", &hintsW, &resW) != 0) {
        std::cerr << "GetAddrInfoW failed: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        WSACleanup();
    }*/
    std::cout << "Connecting to server..." << std::endl;
    if (connect(sock, res->ai_addr, (int)res->ai_addrlen) == SOCKET_ERROR) {
        std::cerr << "connect failed: " << WSAGetLastError() << std::endl;
        freeaddrinfo(res);
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    freeaddrinfo(res); 
    std::cout << "Connected to server" << std::endl;
    const char* request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    std::cout << "Sending request..." << std::endl;
    if (send(sock, request, (int)strlen(request), 0) == SOCKET_ERROR) {
        std::cerr << "send failed: " << WSAGetLastError() << std::endl;
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    std::cout << "Request sent" << std::endl;
    char buffer[4096];
    std::cout << "Receiving response..." << std::endl;
    int bytesReceived = recv(sock, buffer, sizeof(buffer), 0);
    if (bytesReceived == SOCKET_ERROR) {
        std::cerr << "recv failed: " << WSAGetLastError() << std::endl;
    }
    else if (bytesReceived == 0) {
        std::cout << "Connection closed by server" << std::endl;
    }
    else {
        std::cout << "Received " << bytesReceived << " bytes" << std::endl;
        // Uncomment the line below to print the received data
        // std::cout << std::string(buffer, bytesReceived) << std::endl;
    }
    closesocket(sock);
    WSACleanup();
    const wchar_t* filename = L"C:\\Users\\HP\\Downloads\\Project3\\Testing_Program\\testFile.txt";
    const char* filenameA = "C:\\Users\\HP\\Downloads\\Project3\\Testing_Program\\testFiele.txt";
    const char* filenameB = "C:\\Users\\HP\\Downloads\\Project3\\Testing_Program\\testFieldddddde.txt";
    HANDLE hFile;
    std::cout << "start here " << std::endl;
    _lopen(filenameA, 0);
    std::cout << "stop here " << std::endl;
    CreateFileA(filenameB, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    hFile = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    std::cout << "end here " << std::endl;
	WinHttpOpenRequest(hFile, L"GET", NULL, NULL, NULL, NULL, WINHTTP_FLAG_REFRESH);
	URLOpenStreamW(NULL, L"http://example.com", NULL, 0);
	InternetOpenA(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	ShellExecuteA(NULL, "open", "http://example.com", NULL, NULL, SW_SHOWNORMAL);
    return 0;
}

    

