#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include "iostream"

using namespace std;

// ONLY WORKS ON RELEASE COMPILE, COMPLIE ON 32 BIT AND 64 BIT 

std::vector<DWORD> PidList;
DWORD FindProcessId(const char* ProcessName) {
	PidList.clear();
	PROCESSENTRY32 Processes;
	Processes.dwSize = sizeof(Processes);
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	Process32First(Snapshot, &Processes);
	do {
		if (!strcmp(ProcessName, Processes.szExeFile)) {
			PidList.push_back(Processes.th32ProcessID);
		}
	} while (Process32Next(Snapshot, &Processes));
	CloseHandle(Snapshot);
	if (PidList.size() != 0)
		return PidList[PidList.size() - 1];
	return 0;
}

typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);

typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

struct loaderdata
{
	LPVOID ImageBase;

	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;

};

DWORD __stdcall LibraryLoader(LPVOID Memory)
{

	loaderdata* LoaderParams = (loaderdata*)Memory;

	PIMAGE_BASE_RELOCATION pIBR = LoaderParams->BaseReloc;

	size_t delta = (size_t)((LPBYTE)LoaderParams->ImageBase - LoaderParams->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / (sizeof(size_t)/2);// WARNING EDDITED FROM WORD
			PWORD list = (PWORD)(pIBR + 1);

			for (int i = 0; i < count; i++)
			{
				if (list[i])
				{
					PDWORD ptr = (PDWORD)((LPBYTE)LoaderParams->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	PIMAGE_IMPORT_DESCRIPTOR pIID = LoaderParams->ImportDirectory;

	// Resolve DLL imports
	while (pIID->Characteristics)
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->FirstThunk);

		HMODULE hModule = LoaderParams->fnLoadLibraryA((LPCSTR)LoaderParams->ImageBase + pIID->Name);

		if (!hModule)
			return FALSE;

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				size_t Function = (size_t)LoaderParams->fnGetProcAddress(hModule,
					(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
				size_t Function = (size_t)LoaderParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		pIID++;
	}

	if (LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		dllmain EntryPoint = (dllmain)((LPBYTE)LoaderParams->ImageBase + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);

		return EntryPoint((HMODULE)LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}
	return TRUE;
}

DWORD __stdcall stub()
{
	return 0;
}

void error(const char* error) {
	std::cout << "ERROR " << error << std::endl;
	system("pause");
}

int main(int argc, char*argv[])
{
	loaderdata LoaderParams;
	const char* exeName = "PLACEHOLDERPLACEHOLDERPLACEHOLDER"; 
	//const char* exeName = "explorer.exe";//MSBuild.exe  explorer.exe

	std::cout << "TargetProcess : " << exeName << std::endl;
	DWORD ProcessId = FindProcessId(exeName);
	if (!ProcessId) {
		error("Process not found");
		return -1;
	}
		
	std::cout << "Got Process id : " << ProcessId << std::endl;

	size_t currentExeAddres = (size_t)GetModuleHandle(0);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)currentExeAddres;
	PIMAGE_NT_HEADERS DllNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)currentExeAddres + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)(currentExeAddres + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	DWORD offsetToDllData = sectionHeaders[DllNtHeader->FileHeader.NumberOfSections - 1].VirtualAddress;

	DWORD sizeOfDll = sectionHeaders[DllNtHeader->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
	size_t AddressOfDll = (size_t)currentExeAddres + (size_t)offsetToDllData;

	#pragma warning(disable : 4996)

	//FILE* file = fopen("C:\\Users\\Liam\\source\\repos\\Beep\\x64\\Release\\Beep.dll", "rb");// 
	//fseek(file, 0, SEEK_END);
	//int sizeOfDll = ftell(file);
	//fseek(file, 0, SEEK_SET);
	//char * AddressOfDll = (char*)malloc(sizeof(char)*sizeOfDll);
	//fread(AddressOfDll, 1, sizeOfDll, file);
	//fclose(file);

	PVOID FileBuffer = VirtualAlloc(NULL, sizeOfDll, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(FileBuffer, (size_t*)AddressOfDll, sizeOfDll);

	// Target Dll's DOS Header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + pDosHeader->e_lfanew);

	//printf("file header: %p\n", pNtHeaders->OptionalHeader.Magic);

	//system("pause");
	// Opening target process.
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	if (hProcess == NULL) {
		std::cout << "cant open process Run As Admin" << std::endl; system("pause"); return -1;
	}
	std::cout << "opend Process: " << hProcess << std::endl;
		
	// Allocating memory for the DLL
	PVOID ExecutableImage = VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	//printf("alocated Memory: 0x%p\n", ExecutableImage);
	// Copy the headers to target process
	bool didwrite = WriteProcessMemory(hProcess, ExecutableImage, FileBuffer,
		pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);
	if (!didwrite) {
		printf("copying headers : %i\n", didwrite);
	}

	// Target Dll's Section Header
	PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);
	// Copying sections of the dll to the target process
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		bool writePoeration = WriteProcessMemory(hProcess, (PVOID)((LPBYTE)ExecutableImage + pSectHeader[i].VirtualAddress),
			(PVOID)((LPBYTE)FileBuffer + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData, NULL);
		//printf("Writeing Sections : %i\n", writePoeration);
	}

	// Allocating memory for the loader code.
	PVOID LoaderMemory = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE); // Allocate memory for the loader code

	//printf("loader Memory Alocated : 0x%p\n", LoaderMemory);

	LoaderParams.ImageBase = ExecutableImage;
	LoaderParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ExecutableImage + pDosHeader->e_lfanew);

	LoaderParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ExecutableImage
		+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	LoaderParams.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ExecutableImage
		+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	LoaderParams.fnLoadLibraryA = LoadLibraryA;
	LoaderParams.fnGetProcAddress = GetProcAddress;

	// Write the loader information to target process
	WriteProcessMemory(hProcess, LoaderMemory, &LoaderParams, sizeof(loaderdata),
		NULL);
	// Write the loader code to target process
	WriteProcessMemory(hProcess, (PVOID)((loaderdata*)LoaderMemory + 1), LibraryLoader,
		(size_t)stub - (size_t)LibraryLoader, NULL);
	// Create a remote thread to execute the loader code
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((loaderdata*)LoaderMemory + 1),
		LoaderMemory, 0, NULL);

	//std::cout << "Address of Loader: " << std::hex << LoaderMemory << std::endl;
	//std::cout << "Address of Image: " << std::hex << ExecutableImage << std::endl;

	// Wait for the loader to finish executing
	WaitForSingleObject(hThread, 100);
	
	
	CloseHandle(hThread);//
	//std::cin.get();

	// free the allocated loader code
	VirtualFree(FileBuffer, 0, MEM_RELEASE);//
	CloseHandle(hProcess);//
	//CloseHandle(hFile);//
	VirtualFreeEx(hProcess, LoaderMemory, 0, MEM_RELEASE);

	printf("injected\n");
	system("pause");
	return 0;
}