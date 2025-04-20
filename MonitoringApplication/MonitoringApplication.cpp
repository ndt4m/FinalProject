#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <fstream>
#include <nlohmann/json.hpp> 

const wchar_t* PIPE_NAME = TEXT("\\\\.\\pipe\\RATMonitorPipe");

std::string getCurrentTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st); // Use GetSystemTime if you prefer UTC

    char buffer[32];
    sprintf_s(buffer, sizeof(buffer),
        "%04d-%02d-%02d_%02d-%02d-%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    return std::string(buffer);
}


// Function to inject the DLL into the RAT process (unchanged)
void InjectDLL(DWORD processId, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cerr << "Failed to open process: " << GetLastError() << std::endl;
        return;
    }

    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMemory) {
        std::cerr << "Failed to allocate memory in process: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return;
    }

    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "Failed to write memory: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    HMODULE hKernel32 = GetModuleHandle(TEXT("kernel32.dll"));
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteMemory, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create remote thread: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);
}

// Logging thread to read from the pipe and write to a JSON file
void LoggingThread(HANDLE hPipe, std::atomic<bool>* stopLogging) {

    std::ofstream log_file("api_logs_" + getCurrentTimestamp() + ".jsonl"); // Open the JSON Lines file
    if (!log_file.is_open()) {
        std::cerr << "Failed to open log file" << std::endl;
        return;
    }

    char buffer[4096];
    DWORD bytesRead;

    while (!stopLogging->load()) {
        if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            while (true) {
                DWORD bytesAvailable;
                if (PeekNamedPipe(hPipe, NULL, 0, NULL, &bytesAvailable, NULL)) {
                    if (bytesAvailable > 0) {
                        if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
                            buffer[bytesRead] = '\0';
                            std::string logMsg(buffer);

                            // Parse the log message: "timestamp|api_name|log_message"
                            size_t pos1 = logMsg.find('|');
                            if (pos1 != std::string::npos) {
                                size_t pos2 = logMsg.find('|', pos1 + 1);
                                if (pos2 != std::string::npos) {
                                    std::string timestamp = logMsg.substr(0, pos1);
                                    std::string api_name = logMsg.substr(pos1 + 1, pos2 - pos1 - 1);
                                    std::string log_message = logMsg.substr(pos2 + 1);

                                    // Create a JSON object
                                    nlohmann::json log_entry = {
                                        {"timestamp", timestamp},
                                        {"api_name", api_name},
                                        {"log_message", log_message}
                                    };

                                    // Write the JSON object to the file
                                    log_file << log_entry.dump() << std::endl;
                                }
                            }
                        }
                        else {
                            break; // Pipe disconnected or error
                        }
                    }
                    else {
                        Sleep(100); // No data available
                    }
                }
                else {
                    break; // Peek failed
                }
            }
            DisconnectNamedPipe(hPipe);
        }
        else {
            std::cerr << "Failed to connect to pipe: " << GetLastError() << std::endl;
            break;
        }
    }
    // File is automatically closed when log_file goes out of scope
}

int main(int argc, char* argv[]) {
     if (argc != 3) {
         std::cerr << "Usage: monitor.exe <path_to_rat.exe> <path_to_hooking_dll.dll>" << std::endl;
         return 1;
     }

    HANDLE hPipe = CreateNamedPipe(
        PIPE_NAME,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        4096*5,
        4096*5,
        10000,
        NULL
    );
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create named pipe: " << GetLastError() << std::endl;
        return 1;
    }
    std::atomic<bool> stopLogging(false);
    std::thread loggingThread(LoggingThread, hPipe, &stopLogging);

    const char* ratPath = argv[1];
    const char* dllPath = argv[2];
    /*const char* ratPath = "C:\\Users\\HP\\Documents\\FinalProject\\MonitoringApplication\\x64\\Release\\Testing_Program.exe";
    const char* dllPath = "C:\\Users\\HP\\Documents\\FinalProject\\MonitoringApplication\\x64\\Release\\HookingDll.dll";*/
	//const char* dllPath = "C:\\Users\\HP\\Documents\\FinalProject\\MonitoringApplication\\x64\\Release\\Monitor.dll";
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(ratPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        std::cerr << "Failed to create process: " << GetLastError() << std::endl;
        CloseHandle(hPipe);
        return 1;
    }

    InjectDLL(pi.dwProcessId, dllPath);
    ResumeThread(pi.hThread);


    WaitForSingleObject(pi.hProcess, INFINITE);
    //exit(0);
    stopLogging = true;
 //   CancelIoEx(hPipe, nullptr);
    loggingThread.join();
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
	////exit(0);
    std::cout << "Monitoring completed" << std::endl;
    return 0;
}