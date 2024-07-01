#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>

// debugging :3
#define INFO(format, ...) printf("[INFO] " format "\n", ##__VA_ARGS__)

#define ERROR(format, ...) printf("[ERROR] " format "\n", ##__VA_ARGS__)

// this should work fine for processes with only 1 fucking instance but im injecting into a java
// program and im too lazy to check for the highest cpu usage :3
DWORD GetProcessId(const char* processName)
{
    // create a snapshot of all processes running on the system
    auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        ERROR("failed to create snapshot of processes. %lu", GetLastError());
        return 0;
    }

    // create a PROCESSENTRY32 structure to store information about the process
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // get the first process in the snapshot
    if (!Process32First(hSnapshot, &pe32))
    {
        ERROR("failed to get first process in snapshot. %lu", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }

    while (Process32Next(hSnapshot, &pe32))
    {
        if (strcmp(pe32.szExeFile, processName) == 0)
        {
            // close the snapshot handle and return the process id
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    }

    // close the snapshot handle
    CloseHandle(hSnapshot);

    // return 0 if the process was not found
    return 0;
}



int main() {
    const char* dllPath = R"(C:\Users\creid\RustroverProjects\file-injection\testttt.dll)";

    // create a handle to the target process
    auto hProcess = OpenProcess(
            PROCESS_ALL_ACCESS,
            FALSE,
            26664);

    if (hProcess == nullptr)
    {
        ERROR("failed 2 create handle opening da process (invalid pid?). %lu", GetLastError());
        return 1;
    }

    INFO("Successfully opened process! 0x%p", hProcess);

    // virtual alloc memory in the target process to store the path to the DLL
    auto dllPathAddr = VirtualAllocEx(hProcess,
                                      nullptr,
                                      strlen(dllPath) + 1,
                                      MEM_COMMIT,
                                      PAGE_READWRITE);

    if (dllPathAddr == nullptr)
    {
        ERROR("failed to allocate memory in da process. %lu", GetLastError());

        // close the handle to the target process
        CloseHandle(hProcess);
        return 1;
    }

    // Write the DLL path to the allocated memory in the target process
    if (!WriteProcessMemory(hProcess,
                            dllPathAddr,
                            dllPath,
                            strlen(dllPath) + 1,
                            nullptr))
    {
        ERROR("failed to write dll path to target process memory (what the fuck). %lu", GetLastError());

        // clean up the memory we allocated in the target process and close the handle
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // find the kernel32 dll module handle.
    auto hKernel32 = GetModuleHandleA("kernel32.dll");

    // if we failed to get the handle to kernel32.dll most processes from windows have this? i think?
    if (hKernel32 == nullptr)
    {
        ERROR("wtf man couldn't get the kernel 32 handle :(. error code: %lu", GetLastError());

        // clean up the memory we allocated in the target process and close the handle
        VirtualFreeEx(hProcess,
                      dllPathAddr,
                      0,
                      MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    INFO("got the kernel 32 handle 0x%p", hKernel32);

    // get the address of the kernel32 LoadLibraryA function
    auto pfnThreadRtn = (LPTHREAD_START_ROUTINE) GetProcAddress(
            hKernel32,
            "LoadLibraryA");


    if (pfnThreadRtn == nullptr)
    {
        ERROR("failed to get address of LoadLibraryA. %lu", GetLastError());

        // clean up the memory we allocated in the target process and close the handle

        VirtualFreeEx(hProcess,
                      dllPathAddr,
                      0,
                      MEM_RELEASE);

        CloseHandle(hProcess);
        return 1;
    }

    INFO("got the address of LoadLibraryA from the kernel32 dll handle 0x%p", pfnThreadRtn);

    // create a new remote thread in the target process to load the dll
    auto hRemoteThread = CreateRemoteThread(hProcess,
                                            nullptr,
                                            0,
                                            pfnThreadRtn,
                                            dllPathAddr,
                                            0,
                                            nullptr);

    INFO("creating remote thread in target process...");

    // IF FUK FAIL
    if (hRemoteThread == nullptr)
    {
        ERROR("failed to create remote thread. %lu", GetLastError());

        // free the memory we allocated in the target process due to failure
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);

        // close the handle cuz it failed lol
        CloseHandle(hProcess);
        return 1;
    }

    INFO("successfully created remote thread! yipeeee! 0x%p", hRemoteThread);


    INFO("injected dll with no issues.");

    INFO("cleaning up!");

    // Clean up
    WaitForSingleObject(hRemoteThread, INFINITE);

    // free the memory we allocated in the target process
    VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);

    // close the handles when we are done
    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);

    return 0;
}
