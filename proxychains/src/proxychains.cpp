 #include <Windows.h>
#include <iostream>
#include <winternl.h>
int main(int argc, char** argv)
{
	PROCESS_INFORMATION processInfo;
	STARTUPINFO startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	if (!CreateProcess(TEXT("C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe"), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo))
	{
		std::cerr << "[!] cannot create process" << std::endl;
		return 1;
	}

	auto hFile = CreateFile(TEXT("C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cerr << "[!] cannot open file " << GetLastError() <<  std::endl;
		return 1;
	}

	auto hFileMapping = CreateFileMapping(hFile, NULL, SEC_IMAGE | PAGE_READONLY, 0, 0, NULL);
	if (hFileMapping == 0)
	{
		std::cerr << "[!] cannot create file mapping " << GetLastError() <<  std::endl;
		return 1;
	}

	LPVOID hModule = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (hModule == nullptr)
	{
		std::cerr << "[!] unable to map view of file" << std::endl;
		return 1;
	}

	PIMAGE_DOS_HEADER pImgDosHeaders = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pImgNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pImgDosHeaders + pImgDosHeaders->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImgImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pImgDosHeaders + pImgNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	DWORD dwSize = (DWORD)((LPBYTE)pImgDosHeaders + pImgNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

	PROCESS_BASIC_INFORMATION basicInfo;
	NtQueryInformationProcess(processInfo.hProcess, ProcessBasicInformation, &basicInfo, sizeof(basicInfo), NULL);

	SIZE_T result = 0;

	PVOID baseAddress;
	if (!ReadProcessMemory(processInfo.hProcess, (PVOID)((ULONG_PTR)basicInfo.PebBaseAddress + FIELD_OFFSET(PEB, Reserved3[1])), &baseAddress, sizeof(PVOID), &result))
	{
		std::cerr << "[!] failed to read process memory" << std::endl;
		return 1;
	}

	for (IMAGE_IMPORT_DESCRIPTOR* iid = pImgImportDesc; iid->Name != NULL; iid++) 
	{
		if (std::string((char*)((ULONG_PTR)hModule + iid->Name)) == "KERNEL32.dll")
		{
			DWORD old;
			if (!VirtualProtectEx(processInfo.hProcess, (PVOID)((ULONG_PTR)baseAddress + pImgImportDesc->Name), sizeof(LPVOID), PAGE_READWRITE, &old))
			{
				std::cerr << "[!] failed to unlock memory" << std::endl;
				return 1;
			}

			if (!WriteProcessMemory(processInfo.hProcess, (PVOID)((ULONG_PTR)baseAddress + pImgImportDesc->Name), "libpychn.dll", 13, &result))
			{
				std::cerr << "[!] failed to write process memory " << GetLastError() << std::endl;
				return 1;
			}

			break;
		}
	}

	ResumeThread(processInfo.hThread);
}