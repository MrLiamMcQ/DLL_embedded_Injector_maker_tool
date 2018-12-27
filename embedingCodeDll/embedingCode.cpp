// embedingCode.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include <iostream>
#include "windows.h"

#pragma warning(disable : 4996)

DWORD align(DWORD size, DWORD align, DWORD addr) {
	if (!(size % align))
		return addr + size;
	return addr + (size / align + 1) * align;
}

void endFilePath(char* string) {
	for (int i = strlen(string); i > 1; i--) {
		if (string[i] == '.') {
			string[i + 4] = '\0';
		}
	}
}

extern __declspec(dllexport) void EmbedDllFile(char* dllFile, char* InjectorFile) {
	//AllocConsole();
	//freopen("conin$", "r", stdin);
	//freopen("conout$", "w", stdout);
	//freopen("conout$", "w", stderr);
	//printf("Debugging Window:\n");

	endFilePath(dllFile);
	endFilePath(InjectorFile);

	//printf("dll name: %s\n", dllFile);
	//printf("exe name: %s\n", InjectorFile);
	
	//read dll 
	FILE* file;
	fopen_s(&file, dllFile, "rb");
	fseek(file, 0, SEEK_END);
	int fileLengh = ftell(file);
	rewind(file);
	char* buffer = (char*)malloc(sizeof(char)*fileLengh);
	fread(buffer, 1, fileLengh, file);
	fclose(file);

	// read injector
	FILE* dllFileHandel;
	fopen_s(&dllFileHandel, InjectorFile, "rb+");
	fseek(dllFileHandel, 0, SEEK_END);
	DWORD dllFileLengh = ftell(file);
	rewind(dllFileHandel);

	size_t sizeOfHeaders = dllFileLengh;
	char* InjectorFileHeader = (char*)malloc(sizeOfHeaders);
	fread(InjectorFileHeader, 1, sizeOfHeaders, dllFileHandel);
	fclose(dllFileHandel);

	// write new section header for dll
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)InjectorFileHeader;
	PIMAGE_FILE_HEADER FH = (PIMAGE_FILE_HEADER)(InjectorFileHeader + pDosHeader->e_lfanew + sizeof(DWORD));
	PIMAGE_OPTIONAL_HEADER OH = (PIMAGE_OPTIONAL_HEADER)(InjectorFileHeader + pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER SH = (PIMAGE_SECTION_HEADER)(InjectorFileHeader + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	ZeroMemory(&SH[FH->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
	CopyMemory(&SH[FH->NumberOfSections].Name, ".ATH", 8);

	SH[FH->NumberOfSections].Misc.VirtualSize = align(fileLengh, OH->SectionAlignment, 0);
	SH[FH->NumberOfSections].VirtualAddress = align(SH[FH->NumberOfSections - 1].Misc.VirtualSize, OH->SectionAlignment, SH[FH->NumberOfSections - 1].VirtualAddress);
	SH[FH->NumberOfSections].SizeOfRawData = align(fileLengh, OH->FileAlignment, 0);
	SH[FH->NumberOfSections].PointerToRawData = dllFileLengh;
	SH[FH->NumberOfSections].Characteristics = 0xE00000E0;

	OH->SizeOfImage = SH[FH->NumberOfSections].VirtualAddress + SH[FH->NumberOfSections].Misc.VirtualSize;
	FH->NumberOfSections += 1;

	// write new  edited data back
	FILE* dllFileHandel2;
	fopen_s(&dllFileHandel2, InjectorFile, "rb+");
	fwrite(InjectorFileHeader, sizeOfHeaders, 1, dllFileHandel2);
	fclose(dllFileHandel2);

	// append dll
	FILE* targFile;
	fopen_s(&targFile, InjectorFile, "ab");
	fwrite(buffer, fileLengh, 1, targFile);
	fclose(targFile);
}
