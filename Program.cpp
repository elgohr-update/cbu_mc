#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <memory>
#include <vector>

//
// Author: moh@yutsuku.net
// Revision: 2021-04-27
// Description: This program allows to run multiple instances of Stage Editor and/or Game at same time for Cosmic Break Universal
// 
// This work is heavly based on work published by Pavel Yosifovich
// at https://scorpiosoftware.net/2020/03/15/how-can-i-close-a-handle-in-another-process/
//

#pragma comment(lib, "ntdll")
#define NT_SUCCESS(status) (status >= 0)
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)

enum PROCESSINFOCLASS {
    ProcessHandleInformation = 51
};

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

// private
typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectNameInformation = 1
} OBJECT_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

extern "C" NTSTATUS NTAPI NtQueryObject(
    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength);

std::vector<DWORD> FindProcesses() {
    std::vector<DWORD> pid;
    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return pid;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    // skip the idle process
    ::Process32First(hSnapshot, &pe);

    //DWORD pid = 0;
    while (::Process32Next(hSnapshot, &pe)) {
        if (::_wcsicmp(pe.szExeFile, L"cosmic_x64.exe") == 0) {
            // found it!
            //pid = pe.th32ProcessID;
            //break;
            pid.push_back(pe.th32ProcessID);
        }
    }
    ::CloseHandle(hSnapshot);
    return pid;
}

int CloseCBUMutex(DWORD pid) {
    printf("Located process: PID=%u\n", pid);

    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE,
        FALSE, pid);
    if (!hProcess) {
        printf("Failed to open process handle (error=%u)\n",
            ::GetLastError());
        return 1;
    }

    ULONG size = 1 << 10;
    std::unique_ptr<BYTE[]> buffer;
    for (;;) {
        buffer = std::make_unique<BYTE[]>(size);
        auto status = ::NtQueryInformationProcess(hProcess, ProcessHandleInformation,
            buffer.get(), size, &size);
        if (NT_SUCCESS(status))
            break;
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            size += 1 << 10;
            continue;
        }
        printf("Error enumerating handles\n");
        return 1;
    }

    auto info = reinterpret_cast<PROCESS_HANDLE_SNAPSHOT_INFORMATION*>(buffer.get());
    for (ULONG i = 0; i < info->NumberOfHandles; i++) {
        HANDLE h = info->Handles[i].HandleValue;
        HANDLE hTarget;
        if (!::DuplicateHandle(hProcess, h, ::GetCurrentProcess(), &hTarget,
            0, FALSE, DUPLICATE_SAME_ACCESS))
            continue;   // move to next handle

        BYTE nameBuffer[1 << 10];
        auto status = ::NtQueryObject(hTarget, ObjectNameInformation,
            nameBuffer, sizeof(nameBuffer), nullptr);
        ::CloseHandle(hTarget);
        if (!NT_SUCCESS(status))
            continue;

        WCHAR targetName[256];
        DWORD sessionId;
        ::ProcessIdToSessionId(pid, &sessionId);
        ::swprintf_s(targetName,
            L"\\Sessions\\%u\\BaseNamedObjects\\COSMICBREAK_NIJUUKIDOUBOUSHI_MUTEX_080725",
            sessionId);
        auto len = ::wcslen(targetName);

        auto name = reinterpret_cast<UNICODE_STRING*>(nameBuffer);
        if (name->Buffer &&
            ::_wcsnicmp(name->Buffer, targetName, len) == 0) {
            // found it!
            ::DuplicateHandle(hProcess, h, ::GetCurrentProcess(), &hTarget,
                0, FALSE, DUPLICATE_CLOSE_SOURCE);
            ::CloseHandle(hTarget);
            printf("Found it! and closed it!\n");
            return 0;
        }
    }
}

int main() {
    std::vector<DWORD> pids = FindProcesses();

    for (std::size_t i = 0; i < pids.size(); ++i) {
        CloseCBUMutex(pids[i]);
    }

    return 0;
}