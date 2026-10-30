#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

int GetProcessName(DWORD pid, char name[])
{
    HMODULE hMod;
    DWORD bytesNeeded;
    int success = 0;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (hProcess == NULL)
        return 0;

    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &bytesNeeded))
    {
        if (bytesNeeded >= sizeof(hMod))
        {
            if (GetModuleBaseNameA(hProcess, hMod, name, MAX_PATH) > 0)
                success = 1;
        }
    }

    CloseHandle(hProcess);
    return success;
}

void scanSpecificAddr(DWORD processId, uintptr_t targetAddress, SIZE_T length)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, processId);

    if (hProcess == NULL)
        return;

    char buffer[4096] = {0};
    SIZE_T bytesRead = 0;

    if (length == 0 || length >= sizeof(buffer))
    {
        CloseHandle(hProcess);
        return;
    }

    if (ReadProcessMemory(hProcess,(LPCVOID)targetAddress, buffer, length, &bytesRead)) {
        printf("\nAddress: %p | Value: %s\n", (void *)targetAddress, buffer);
    } else {
        printf("ReadProcessMemory failed. Error: %lu\n", GetLastError());
    }

    CloseHandle(hProcess);
}

void ShowMemoryRegion(DWORD pid, uintptr_t address)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

    if (hProcess == NULL)
    {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return;
    }

    MEMORY_BASIC_INFORMATION mbi;

    if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == 0)
    {
        printf("VirtualQueryEx failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    printf("\nAddress: %p\n", (void *)address);
    printf("Base Address: %p\n", mbi.BaseAddress);
    printf("Region Size: %zu bytes\n", mbi.RegionSize);
    printf("State: 0x%lX\n", (unsigned long)mbi.State);
    printf("Protect: 0x%lX\n", (unsigned long)mbi.Protect);
    printf("Type: 0x%lX\n", (unsigned long)mbi.Type);
    printf("Base Address: %p\n", mbi.BaseAddress);
    printf("Allocation Base: %p\n", mbi.AllocationBase);

    CloseHandle(hProcess);
}


bool ScanMemoryForStr(DWORD pid, const char *target, uintptr_t addresses[], SIZE_T *matchCount)
{
    SYSTEM_INFO sysInfo;
    MEMORY_BASIC_INFORMATION mbi;

    *matchCount = 0;

    bool found = FALSE;

    SIZE_T targetLen = strlen(target);

    if (targetLen == 0)
        return false;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (hProcess == NULL)
        return false;

    GetSystemInfo(&sysInfo);
    uintptr_t address = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t end = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

    unsigned char buffer[65536];

    printf("\nSearching for string: %s\n", target);
    for (SIZE_T x=0;x < strlen(target)+22;x++){printf("-");}

    ULONGLONG startTime = GetTickCount64();

    while (address < end)
    {
        if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == 0)
            break;

        DWORD protect = mbi.Protect & 0xFF;

        int readable =  protect == PAGE_READONLY ||
                        protect == PAGE_READWRITE ||
                        protect == PAGE_WRITECOPY ||
                        protect == PAGE_EXECUTE_READ ||
                        protect == PAGE_EXECUTE_READWRITE ||
                        protect == PAGE_EXECUTE_WRITECOPY;

        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && readable)
        {
            uintptr_t current = (uintptr_t)mbi.BaseAddress;
            uintptr_t regionEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

            while (current < regionEnd)
            {

                SIZE_T bytesRead = 0;
                SIZE_T readSize = regionEnd - current;

                if (readSize > sizeof(buffer))
                    readSize = sizeof(buffer);

                if (ReadProcessMemory(hProcess, (LPCVOID)current, buffer, readSize, &bytesRead))
                    {
                        if (bytesRead >= targetLen)
                        {
                            for (SIZE_T i = 0; i <= bytesRead - targetLen; i++)
                            {
                                if (memcmp(buffer + i, target, targetLen) == 0)
                                {
                                    printf("\n[+] Address: %p | Value: %s\n", (void *)current + i, target);
                                    //scanSpecificAddr(pid, current+i, targetLen);
                                    found = TRUE;

                                    if (*matchCount < 100)
                                    {
                                        addresses[*matchCount] = current + i;
                                        (*matchCount)++;
                                    }
                                }
                            }
                        }
                    }   

                current += readSize;
            }
        }

        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;

        if (next <= address)
            break;

        address = next;
    }

    CloseHandle(hProcess);
    ULONGLONG elapsed = GetTickCount64() - startTime;

    printf("\nScan completed in %llu ms\n", (unsigned long long)elapsed);

    return found;
}

void NextScan(DWORD pid, const char *target, uintptr_t addresses[], SIZE_T *addressCount)
{
    SIZE_T targetLen = strlen(target);

    if (targetLen == 0 || targetLen > 4096 || *addressCount == 0)
        return;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL)
        return;

    unsigned char buffer[4096];
    SIZE_T newCount = 0;

    printf("\nNext Scan: %s", target);

    for (SIZE_T i = 0; i < *addressCount; i++)
    {
        SIZE_T bytesRead = 0;

        if (ReadProcessMemory(hProcess, (LPCVOID)addresses[i], buffer, targetLen, &bytesRead) &&  bytesRead == targetLen)
        {
            if (memcmp(buffer, target, targetLen) == 0)
            {
                printf("\n[+] Address: %p | Value: %s\n", (void *)addresses[i], target);

                addresses[newCount] = addresses[i];
                newCount++;
            }
        }
    }

    *addressCount = newCount;
    printf("\nRemaining addresses: %zu\n", *addressCount);

    CloseHandle(hProcess);
}

bool WriteMemory(DWORD pid, uintptr_t address, const char *oldValue, const char *newValue)
{
    SIZE_T length = strlen(oldValue);

    if (length == 0 || length >= MAX_PATH || strlen(newValue) != length)
        return false;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);

    if (hProcess == NULL)
    {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return false;
    }

    char buffer[MAX_PATH] = {0};
    SIZE_T bytesRead = 0;
    SIZE_T bytesWritten = 0;
    bool success = false;

    if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer, length, &bytesRead) && bytesRead == length && memcmp(buffer, oldValue, length) == 0)
    {
        if (WriteProcessMemory(hProcess, (LPVOID)address, newValue, length, &bytesWritten) && bytesWritten == length)
        {
            bytesRead = 0;

            if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer, length, &bytesRead) && bytesRead == length && memcmp(buffer, newValue, length) == 0)
            {
                success = true;
            }
        }
    }

    if (success == true){
        printf("\n[+] Address: %p\nWrite verified.", (void *)address);
    }
    else if (success == false){
        printf("\n[-] Address: %p\nWrite skipped or not verified", (void *)address);
    }

    CloseHandle(hProcess);

    return success;
}

int FindProcess(char target[])
{
    DWORD pids[1024];
    DWORD bytesNeeded;
    char name[MAX_PATH];
    char search_for_str[MAX_PATH];

    DWORD matchedPids[1024];
    DWORD matchCount = 0;

    if (!EnumProcesses(pids, sizeof(pids), &bytesNeeded))
        return 0;

    DWORD count = bytesNeeded / sizeof(DWORD);

    for (DWORD i = 0; i < count; i++)
    {
        if (pids[i] == 0)
            continue;

        if (GetProcessName(pids[i], name))
        {
            if (_stricmp(target, name) == 0)
            {
                matchedPids[matchCount] = pids[i];
                matchCount++;
            }
        }
    }

    if (matchCount == 0)
        return 0;

    DWORD selectedPid = matchedPids[0];

    if (matchCount > 1)
    {
        printf("[+] Multiple processes found:\n");

        for (DWORD i = 0; i < matchCount; i++)
            printf("[%lu] PID: %lu\n", i + 1, matchedPids[i]);


        DWORD choice;

        printf("\nSelect process: ");

        if (scanf("%lu", &choice) != 1)
            return 0;

        getchar();

        if (choice == 0 || choice > matchCount)
        {
            printf("Invalid selection!\n");
            return 0;
        }

        selectedPid = matchedPids[choice - 1];
    }

    printf("[+] Found: %s (PID: %lu)\n", target, selectedPid);

    uintptr_t addresses[100];
    SIZE_T addressCount = 0;
    SIZE_T trackedLen = 0;
    char trackedValue[MAX_PATH] = "";

    while (1)
    {
        printf("\nSearch for string (n: next, r: reread, m: region, w: write, q: quit): ");

        if (fgets(search_for_str, sizeof(search_for_str), stdin) == NULL)
            break;

        search_for_str[strcspn(search_for_str, "\r\n")] = '\0';

        if (strcmp(search_for_str, "q") == 0)
        {
            printf("Exiting...\n\n");
            return 1;
        }

        if (strcmp(search_for_str, "w") == 0)
        {
            if (addressCount == 0)
            {
                printf("No saved addresses!\n");
                continue;
            }

            char newValue[MAX_PATH];
            char confirm[8];

            printf("Enter new string: ");

            if (fgets(newValue, sizeof(newValue), stdin) == NULL)
                break;

            newValue[strcspn(newValue, "\r\n")] = '\0';

            if (strlen(newValue) > trackedLen)
            {
                printf("New string should not exceed %zu bytes!\n", trackedLen);
                continue;
            }

            char paddedValue[MAX_PATH];

            memset(paddedValue, ' ', trackedLen);
            memcpy(paddedValue, newValue, strlen(newValue));
            paddedValue[trackedLen] = '\0';

            printf("Write to %zu addresses? (y/n): ", addressCount);

            if (fgets(confirm, sizeof(confirm), stdin) == NULL)
                break;

            if (confirm[0] != 'y')
                continue;

            SIZE_T successCount = 0;

            for (SIZE_T i = 0; i < addressCount; i++)
            {
                if (WriteMemory(selectedPid, addresses[i], trackedValue, paddedValue))
                {
                    successCount++;
                }
            }

            printf("\nVerified writes: %zu/%zu\n",
                successCount, addressCount);

            if (successCount == addressCount)
                strcpy(trackedValue, paddedValue);

            continue;
        }

        if (strcmp(search_for_str, "m") == 0)
        {
            if (addressCount == 0)
            {
                printf("No saved addresses!\n");
                continue;
            }

            for (SIZE_T i = 0; i < addressCount; i++)
            {
                ShowMemoryRegion(selectedPid, addresses[i]);
            }

            continue;
        }       

        if (strcmp(search_for_str, "n") == 0)
        {
            if (addressCount == 0)
            {
                printf("No saved addresses! Run First Scan.\n");
                continue;
            }

            printf("Next scan string:");

            if (fgets(search_for_str, sizeof(search_for_str), stdin) == NULL)
                break;

            search_for_str[strcspn(search_for_str, "\r\n")] = '\0';

            NextScan(selectedPid, search_for_str, addresses, &addressCount);
            trackedLen = strlen(search_for_str);
            strcpy(trackedValue, search_for_str);

            continue;
        }

        if (strcmp(search_for_str, "r") == 0)
        {
            if (addressCount == 0)
            {
                printf("No saved addresses!\n");
                continue;
            }

            printf("\nRe-reading %zu addresses:\n", addressCount);

            for (SIZE_T i = 0; i < addressCount; i++)
            {
                scanSpecificAddr(selectedPid, addresses[i], trackedLen);
            }

            continue;
        }       
            
        if (search_for_str[0] == '\0')
            continue;

        trackedLen = strlen(search_for_str);

        if (ScanMemoryForStr(selectedPid, search_for_str, addresses, &addressCount) == FALSE)
            printf("\n[-] String not found!\n");

        strcpy(trackedValue, search_for_str);

        printf("\n");                  
    }

    return 0;
}

int main(void)
{
    char name[MAX_PATH];

    printf("\nEnter process name: ");

    if (fgets(name, sizeof(name), stdin) == NULL)
        return 1;

    name[strcspn(name, "\r\n")] = '\0'; //remove \n and \r, write \0

    if (!FindProcess(name))
        printf("Process not found!\n");

    return 0;
}