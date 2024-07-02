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
    const char* processName = "javaw.exe";

    // replace with your own
    const char* dllPath = R"(C:\Users\creid\OneDrive\Documents\GitHub\plaguemc\x64\Release\plague-nextgen.dll)";

    const DWORD processId = GetProcessId(processName);

    if (processId == 0)
    {
        ERROR("failed 2 get process id of %s", processName);
        return 1;
    }

    // create a handle to the process
    // this handle is responsible for all operations on the process
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    // check if the handle is valid
    if (processHandle == nullptr)
    {
        ERROR("failed 2 open process %lu. error: %lu", processId, GetLastError());
        return 1;
    }

    // allocate the memory into the target process
    // we use the length of the dll path + 1 to include the null terminator
    // VirtualAllocEx allocates memory into a target process, hence why we aren't using malloc or new (obviously)
    LPVOID dllPathAddress = VirtualAllocEx(processHandle, nullptr, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // check if its null
    if (dllPathAddress == nullptr)
    {
        ERROR("failed 2 allocate memory in process %lu. error: %lu", processId, GetLastError());
        CloseHandle(processHandle);
        return 1;
    }


    if (!WriteProcessMemory(processHandle, dllPathAddress, dllPath, strlen(dllPath) + 1, nullptr))
    {
        ERROR("failed 2 write memory in process %lu. Error: %lu", processId, GetLastError());

        // cleanup
        VirtualFreeEx(processHandle, dllPathAddress, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    // we cant do anything if we dont have this handle
    // the kernel 32 handle is responsible for loading the dll into the process
    // each windows process has a kernel32.dll loaded into it
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");

    if (kernel32 == nullptr)
    {
        ERROR("failed 2 get handle to kernel32.dll. Error: %lu", GetLastError());

        // cleanup
        VirtualFreeEx(processHandle, dllPathAddress, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    // get the address of LoadLibraryA
    FARPROC LLAAddress = GetProcAddress(kernel32, "LoadLibraryA");

    // if we cant get the address of LoadLibraryA, we cant load the dll
    if (LLAAddress == nullptr)
    {
        ERROR("failed 2 get LLA address. Error: %lu", GetLastError());
        VirtualFreeEx(processHandle, dllPathAddress, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    // create a remote thread in the target process
    // this thread is responsible for actually loading it
    HANDLE remoteThreadHandle = CreateRemoteThread(processHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)LLAAddress, dllPathAddress, 0, nullptr);

    INFO("creating remote thread handle...");

    if (remoteThreadHandle == nullptr)
    {
        ERROR("failed 2 create remote thread in process %lu. error: %lu", processId, GetLastError());

        // cleanup

        VirtualFreeEx(processHandle, dllPathAddress, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return 1;
    }

    INFO("Successfully created remote thread handle!");


    INFO("we are so fucking gucci it injected ;3 %s", processName);


    INFO("Waiting for the thread to finish...");
    WaitForSingleObject(remoteThreadHandle, INFINITE);

    INFO("Thread finished!");

    INFO("Cleaning up...");


    VirtualFreeEx(processHandle, dllPathAddress, 0, MEM_RELEASE);
    CloseHandle(remoteThreadHandle);
    CloseHandle(processHandle);



    return 0;
}
