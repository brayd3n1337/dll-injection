#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <TlHelp32.h>

#define INFO(format, ...) printf("[INFO] " format "\n", ##__VA_ARGS__)
#define ERROR(format, ...) printf("[ERROR] " format "\n", ##__VA_ARGS__)

DWORD GetProcessId(const char* processName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        ERROR("failed 2 create snapshot of processes. Error: %lu", GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32))
    {
        ERROR("failed 2 get first process in snapshot. Error: %lu", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }

    do
    {
        if (strcmp(pe32.szExeFile, processName) == 0)
        {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    return 0;
}

int main()
{
    // C STYLE STRINGS ARENT THEY AMAZING?
    const char* dllPath = R"(C:\Users\creid\CLionProjects\mapping-injection\testttt.dll)";
    const char* processName = "java.exe";

    // Get process ID of the target process
    DWORD pid = 11180;

    if (pid == 0)
    {
        ERROR("failed 2 get PID for %s. process not found or access denied. Error: %lu", processName, GetLastError());
        ERROR("failed 2 create handle opening da process (invalid pid?). %lu", GetLastError());
        return 1;
    }

    INFO("Found process %s with PID %lu", processName, pid);

    // open the target process
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (processHandle == nullptr)
    {
        ERROR("failed to open process. %lu", GetLastError());
        return 1;
    }

    INFO("successfully opened process with handle 0x%p", processHandle);

    // allocate memory in the target process for the dll path
    LPVOID baseAddr = VirtualAllocEx(processHandle, nullptr, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);

    if (baseAddr == nullptr)
    {
        ERROR("failed to allocate memory into the target process. %lu", GetLastError());
        CloseHandle(processHandle);
        return 1;
    }

    // write the DLL path into the allocated memory in the target process
    if (!WriteProcessMemory(processHandle, baseAddr, dllPath, strlen(dllPath) + 1, nullptr))
    {
        ERROR("failed to write DLL path to target process memory. %lu", GetLastError());
        VirtualFreeEx(processHandle, baseAddr, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    INFO("wrote DLL path %s to target process memory", dllPath);

    // get the handle to kernel32.dll
    HMODULE kernelHandle = GetModuleHandleA("kernel32.dll");

    // check if null
    if (kernelHandle == nullptr)
    {
        ERROR("Failed to get handle to kernel32.dll. Error: %lu", GetLastError());
        VirtualFreeEx(processHandle, baseAddr, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    INFO("got handle to kernel32.dll at address yayyyy :3 0x%p", kernelHandle);

    // get address of LoadLibraryA function from the kernel handle
    // GetProcAddress function retrieves the address of an exported function or variable from the specified DLL.
    auto kernelLLAAddress = (LPTHREAD_START_ROUTINE) GetProcAddress(kernelHandle, "LoadLibraryA");

    if (kernelLLAAddress == nullptr)
    {
        ERROR("failed 2 get address of LLA function. Error: %lu", GetLastError());
        VirtualFreeEx(processHandle, baseAddr, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    INFO("got address of LLA function at 0x%p", kernelLLAAddress);

    // create remote thread in the target process to load the DLL
    // the create remote thread function creates a thread in the address space of another process
    HANDLE hRemoteThread = CreateRemoteThread(processHandle, nullptr, 0, kernelLLAAddress, baseAddr, 0, nullptr);

    if (hRemoteThread == nullptr)
    {
        ERROR("failed to create remote thread in target process. Error: %lu", GetLastError());
        VirtualFreeEx(processHandle, baseAddr, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    INFO("created da remote thread in target process. thread handle: 0x%p", hRemoteThread);

    // Wait for the remote thread to finish
    WaitForSingleObject(hRemoteThread, INFINITE);

    INFO("cleaning up ^_^ yipeeeee");

    // Clean up
    VirtualFreeEx(processHandle, baseAddr, 0, MEM_RELEASE);
    CloseHandle(hRemoteThread);
    CloseHandle(processHandle);

    return 0;
}
