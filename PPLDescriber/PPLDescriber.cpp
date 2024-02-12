#include "PPLDescriber.hpp"

VOID ShowHelp()
{
	std::cout << R"(
    ____  ____  __    ____                      _ __       
   / __ \/ __ \/ /   / __ \___  _______________(_/ /_  ___ 
  / /_/ / /_/ / /   / / / / _ \/ ___/ ___/ ___/ / __ \/ _ \
 / ____/ ____/ /___/ /_/ /  __(__  / /__/ /  / / /_/ /  __/
/_/   /_/   /_____/_____/\___/____/\___/_/  /_/_.___/\___/ 
                                                           
		https://github.com/MzHmO )" << std::endl;
	std::wcout << L"Usage:" << std::endl;
	std::wcout << L"[Show info by PID] PPLDescriber.exe -p <PID>\r\n\tEx: PPLDescriber.exe -p 123" << std::endl;
	std::wcout << L"[Show info by process name] PPLDescriber.exe -n <Process Name>\r\n\tEx: PPLDescriber.exe -n lsass.exe" << std::endl;
}

DWORD GetProcessIdByName(LPCWSTR processName)
{
    DWORD processID = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnap, &pe32))
        {
            do
            {
                if (wcscmp(pe32.szExeFile, processName) == 0)
                {
                    processID = pe32.th32ProcessID;
                    break; 
                }
            } while (Process32NextW(hSnap, &pe32)); 
        }

        CloseHandle(hSnap); 
    }

    return processID;
}

wchar_t* getCmdOption(wchar_t** begin, wchar_t** end, const std::wstring& option)
{
	wchar_t** itr = std::find(begin, end, option);
	if (itr != end && ++itr != end)
	{
		return *itr;
	}
	return nullptr;
}

bool cmdOptionExists(wchar_t** begin, wchar_t** end, const std::wstring& option)
{
	return std::find(begin, end, option) != end;
}

std::string GetProtectionTypeDescription(UCHAR type) {
    static const std::map<UCHAR, std::string> protectionTypeDescriptions = {
        {PsProtectedTypeNone, "PsProtectedTypeNone"},
        {PsProtectedTypeProtectedLight, "PsProtectedTypeProtectedLight"},
        {PsProtectedTypeProtected, "PsProtectedTypeProtected"},
    };

    auto it = protectionTypeDescriptions.find(type);
    if (it != protectionTypeDescriptions.end()) {
        return it->second;
    }
    return "Unknown";
}

std::string GetProtectedSignerDescription(UCHAR signer) {
    static const std::map<UCHAR, std::string> protectedSignerDescriptions = {
        {PsProtectedSignerNone, "PsProtectedSignerNone"},
        {PsProtectedSignerAuthenticode, "PsProtectedSignerAuthenticode"},
        {PsProtectedSignerCodeGen, "PsProtectedSignerCodeGen"},
        {PsProtectedSignerAntimalware, "PsProtectedSignerAntimalware"},
        {PsProtectedSignerLsa, "PsProtectedSignerLsa"},
        {PsProtectedSignerWindows, "PsProtectedSignerWindows"},
        {PsProtectedSignerWinTcb, "PsProtectedSignerWinTcb"},
        {PsProtectedSignerWinSystem, "PsProtectedSignerWinSystem"},
        {PsProtectedSignerApp, "PsProtectedSignerApp"},
    };

    auto it = protectedSignerDescriptions.find(signer);
    if (it != protectedSignerDescriptions.end()) {
        return it->second;
    }
    return "Unknown";
}

DWORD ParsePPL(DWORD dwPid)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
    if (hProc == NULL || hProc == INVALID_HANDLE_VALUE)
    {
        std::wcout << L"[-] OpenProcess Failed: " << GetLastError() << std::endl;
        return -1;
    }
    PS_PROTECTION protectInfo;
    fNtQueryInformationProcess NtQueryInformationProcess = (fNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    NTSTATUS status = NtQueryInformationProcess(hProc, ProcessProtectionInformation, &protectInfo, sizeof(PS_PROTECTION), NULL);
    if (status != ERROR_SUCCESS)
    {
        DWORD winErr = LsaNtStatusToWinError(status);
        std::wcout << L"[-] Failed to get PPL Settings: " << winErr << std::endl;
    }
    
    std::cout << "[+] Type of Protection: " << GetProtectionTypeDescription(static_cast<PS_PROTECTED_TYPE>(protectInfo.Level & 0x07)) << std::endl;
    std::cout << "[+] Type of Signer: " << GetProtectedSignerDescription(static_cast<PS_PROTECTED_SIGNER>((protectInfo.Level >> 4) & 0x0F)) << std::endl;

    return 0;
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc < 3)
	{
		ShowHelp();
		return -1;
	}

    LPCWSTR procName = nullptr;
    bool isPidOption = cmdOptionExists(argv, argv + argc, L"-p");
    bool isNameOption = cmdOptionExists(argv, argv + argc, L"-n");

    DWORD dwPID = 0;
    if (isPidOption) {
        auto pidStr = getCmdOption(argv, argv + argc, L"-p");
        if (pidStr) {
            dwPID = _wtoi(pidStr); 
            ParsePPL(dwPID);
        }
    }
    else if (isNameOption) {
        procName = getCmdOption(argv, argv + argc, L"-n");
        if (procName) {
            dwPID = GetProcessIdByName(procName);
            if (dwPID == 0)
            {
                std::wcout << L"[-] Process not found" << std::endl;
                return -1;
            }
            ParsePPL(dwPID);
        }
    }
    else {
        ShowHelp();
        return -1;
    }

    return 0;
}