// References:
//   https://learn.microsoft.com/ja-jp/windows/win32/sysinfo/getting-hardware-information
//   https://learn.microsoft.com/ja-jp/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info

#include <windows.h>
#include <iostream>
#pragma comment(lib, "user32.lib")

using namespace std;

void main()
{
    SYSTEM_INFO siSysInfo;

    // Copy the hardware information to the SYSTEM_INFO structure.

    GetSystemInfo(&siSysInfo);

    // Display the contents of the SYSTEM_INFO structure.

    cout << "Hardware information: " << endl;
    cout << "  OEM ID: " << siSysInfo.dwOemId << endl;
    cout << "  Number of processors: " << siSysInfo.dwNumberOfProcessors << endl;
    cout << "  Page size: " << siSysInfo.dwPageSize << endl;
    cout << "  Processor type: " << siSysInfo.dwProcessorType << endl;
    cout << "  Minimum application address: " << siSysInfo.lpMinimumApplicationAddress << endl;
    cout << "  Maximum application address: " << siSysInfo.lpMaximumApplicationAddress << endl;
    cout << "  Active processor mask: " << siSysInfo.dwActiveProcessorMask << endl;
}