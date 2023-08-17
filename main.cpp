#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <vector>


DWORD getprocessid(const wchar_t* processname) {
	DWORD PID = 0;

	PROCESSENTRY32 processentry;
	processentry.dwSize = sizeof(processentry);

	HANDLE hsnap;
	hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(hsnap, &processentry)) {

		do {
			if (!_wcsicmp(processentry.szExeFile, processname)) {
				PID = processentry.th32ProcessID;
				break;

			}

		} while (Process32Next(hsnap, &processentry));
		CloseHandle(hsnap);
	}
	return PID;
}


uintptr_t getmodule(const wchar_t* modulename,DWORD PID) {
	uintptr_t modulea = 0;

	MODULEENTRY32 moduleentry;
	moduleentry.dwSize = sizeof(moduleentry);

	HANDLE msnap;
	msnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, PID);
	if (Module32First(msnap, &moduleentry)) {

		do {
			if (!_wcsicmp(moduleentry.szModule, modulename)) {
				modulea = uintptr_t(moduleentry.modBaseAddr);
				break;

			}

		} while (Module32Next(msnap, &moduleentry));
		CloseHandle(msnap);
	}
	return modulea;
}

uintptr_t FindDMAAddy(HANDLE hProc, uintptr_t ptr, std::vector<unsigned int> offsets)
{
	uintptr_t addr = ptr;
	for (unsigned int i = 0; i < offsets.size(); ++i)
	{
		ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), 0);
		addr += offsets[i];
	}
	return addr;
}


int main()
{
	std::cout << "Obtaining the process id of the process"<<std::endl; 
	Sleep(2000);
	DWORD PID = getprocessid(L"ac_client.exe");
	std::cout << "Found the process, AssaultCube" << std::endl;
	Sleep(2000);
	uintptr_t modBaseAddr = getmodule(L"ac_client.exe", PID);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	std::cout << "Process all access" << std::endl;
	Sleep(2000);
	std::cout << "Releasing" << std::endl;
	Sleep(2000);
	std::cout << "Obtaining the pointer to a Ammo" << std::endl;
	Sleep(2000);


	uintptr_t dynamicPtrBaseAddr = modBaseAddr + 0x10F4F4;
	std::cout << "getting the base address" << std::endl;
	Sleep(2000);
	std::cout << "editing the address" << std::endl;
	Sleep(2000);
	std::cout << "Complete" << std::endl;
	Sleep(2000);
	uintptr_t ammoAddr = FindDMAAddy(hProcess, dynamicPtrBaseAddr, { 0x0150 });

	unsigned long long ammovalue = 999999999999;
	
	WriteProcessMemory(hProcess, (BYTE*)ammoAddr, &ammovalue, sizeof(ammovalue), nullptr);


	
	



	return 0;
}