#include "proc.h"
#include <process.h>

// create object to struct
proc procInfo;



std::wstring GetProcName(DWORD aPid)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);
    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE)
    {
        std::wcout << "can't get a process snapshot ";
        return 0;
    }

    for (BOOL bok = Process32First(processesSnapshot, &processInfo);bok; bok = Process32Next(processesSnapshot, &processInfo))
    {
        if (aPid == processInfo.th32ProcessID)
        {
            CloseHandle(processesSnapshot);
            return processInfo.szExeFile;
        }

    }
    std::wcout << "no process with given pid (" << aPid << ")" << std::endl;
    CloseHandle(processesSnapshot);
    return std::wstring();
}

DWORD getParentPID(DWORD pid)
{
    HANDLE h = NULL;
    PROCESSENTRY32 pe = { 0 };
    DWORD ppid = 0;
    pe.dwSize = sizeof(PROCESSENTRY32);
    h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(h, &pe))
    {
        do
        {
            if (pe.th32ProcessID == pid)
            {
                ppid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(h, &pe));
    }
    CloseHandle(h);
    return (ppid);
}

void procManager::findProc(uint32_t processID)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

    // Get a handle to the process.

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);

    // Get the process name.

    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
            &cbNeeded))
        {
            GetModuleBaseName(hProcess, hMod, szProcessName,
                sizeof(szProcessName) / sizeof(TCHAR));
        }
    }
    // Print the process name and identifier.
    if (std::find(versions.begin(), versions.end(), szProcessName) != versions.end()) {
        DWORD parentPID = getParentPID(processID);
        std::wstring parent = GetProcName(parentPID);
        LPWSTR fname[MAX_PATH] = { 0 };

        // filter wrong proc
        // parent shares the same memory as all child processes so we want that
        if (parent == L"explorer.exe") {
            _tprintf(TEXT("[+] Found process: %s (PID: %u) \n"), szProcessName, processID);


            // convert TCHAR to string
            std::string procName(&szProcessName[0], &szProcessName[260]);

            // set values to struct procInfo defined in proc.h
            procInfo.name = procName;
            procInfo.pid = processID;
        }
        else {
            count++;
        }
    }
    else {
        return;
    }


    // Release the handle to the process.

    CloseHandle(hProcess);

    return;

}

uint32_t GetProcessBaseAddress(DWORD processID)
{
    uint32_t   baseAddress = 0;
    HANDLE      processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    HMODULE* moduleArray;
    LPBYTE      moduleArrayBytes;
    DWORD       bytesRequired;

    if (processHandle)
    {
        if (EnumProcessModules(processHandle, NULL, 0, &bytesRequired))
        {
            if (bytesRequired)
            {
                moduleArrayBytes = (LPBYTE)LocalAlloc(LPTR, bytesRequired);

                if (moduleArrayBytes)
                {
                    unsigned int moduleCount;
                    moduleCount = bytesRequired / sizeof(HMODULE);
                    moduleArray = (HMODULE*)moduleArrayBytes;

                    if (EnumProcessModules(processHandle, moduleArray, bytesRequired, &bytesRequired))
                    {
                        baseAddress = (uint32_t)moduleArray[0];
                    }

                    LocalFree(moduleArrayBytes);
                }
            }
        }

        CloseHandle(processHandle);
    }

    return baseAddress;
}

discordInformation procManager::scan() {
    // save information in discordInformation type
    discordInformation account;

    // JSON struct
    nlohmann::json accountJSON;

    // execution time
    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    // signature
    char json_sig[] = "\x7b\x22\x65\x6e\x76\x69\x72\x6f\x6e\x6d\x65\x6e\x74\x22";
    // Get the list of process identifiers.

    std::cout << "[+] Enumerating through all processes.." << std::endl;

    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        exit(EXIT_FAILURE); // error handling like a retard
    }


    // Calculate how many process identifiers were returned.

    cProcesses = cbNeeded / sizeof(DWORD);

    // Print the name and process identifier for each process.

    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            procManager::findProc(aProcesses[i]);
        }
    }
    _tprintf(TEXT("[+] Skipped %u wrong process(es) \n"), count);

    //
    // scan part
    // 

    // open handle to the right proc
    HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, false, procInfo.pid);


    // Get the mimum and maximum address space our JSON could be in
    SYSTEM_INFO info;

    GetSystemInfo(&info);
    MEMORY_BASIC_INFORMATION rgninfo{};

    rgninfo.BaseAddress;

    // allocate space to save json
    char json[128];


    // get base address (probaly not needed)
    //char* base = (char*)GetProcessBaseAddress(procInfo.pid);
    char* base = (char*)GetProcessBaseAddress(procInfo.pid);

    std::cout << "[+] Reading .text section into buffer.." << std::endl;
    std::cout << "[+] Scanning.." << std::endl;

    while (base < info.lpMaximumApplicationAddress) {
        // get info for section
        VirtualQueryEx(hproc, (LPCVOID)base, &rgninfo, sizeof(rgninfo));

        // check if current section is rw (read write)
        // this is because only .text is rw 
        // which we want to scan trough

        if (rgninfo.Protect == PAGE_READWRITE) {
            // set buffer as big as the section we scan trough.
            byte* local = new byte[rgninfo.RegionSize];

            // read
            SIZE_T read = 0;

            // read memory into buffer
            ReadProcessMemory(hproc, base, local, rgninfo.RegionSize, &read);

            // pattern scan for the signature.
            uint32_t result = (uint32_t)scanner::Search(local, rgninfo.RegionSize, reinterpret_cast<const uint8_t*>(json_sig), strlen(json_sig), 0xCC);


            if (result != 0)
            {
                // how many bytes we need to go from regionBase to the JSON start
                uint32_t offset = (result - (uint32_t)local);

                // to read out a certain value which we dont use
                uint32_t json_add = ((uint32_t)rgninfo.BaseAddress + offset);

                // Read value from address
                ReadProcessMemory(hproc, (void*)json_add, json, sizeof(json), &read);

            }
            delete[] local;
        }
        // add regionsize to the base address of the process
        // since we already scanned trough that one
        base += rgninfo.RegionSize;
    }

    // convert JSON to string
    std::string JSONstring = json;

    // convert string to json object
    accountJSON = nlohmann::json::parse(JSONstring);

    // convert JSON object to discordInformation struct

    // convert them all to string again
    std::string environment = accountJSON["environment"];
    std::string release     = accountJSON["release"];
    std::string email       = accountJSON["user"]["email"];
    std::string id          = accountJSON["user"]["id"];
    std::string username    = accountJSON["user"]["username"];

    // pass string to struct
    account.environment = environment;
    account.release = release;
    account.user.email = email;
    account.user.id = id;
    account.user.username = username;


    /*
     DEBUG
    */
    
    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    /*
    std::cout << "[+] Output: " << JSONstring << std::endl;*/
    std::cout << "[+] Done in " << (std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()) / 1000000.0 << "ms" << std::endl;
    


    // close handle
    CloseHandle(hproc);

    // return values
    return account;
}
