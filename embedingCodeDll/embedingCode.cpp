// embedingCode.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include <iostream>

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
			return;
		}
	}
}

void embeddFile_x64(char injectorName[],char dllName[], int dllLengh) {
	// open read dll
	FILE* file;
	fopen_s(&file, dllName, "rb");
	char* buffer = (char*)malloc(sizeof(char)*dllLengh);
	fread(buffer, 1, dllLengh, file);
	fclose(file);

	// read injector
	FILE* dllFileHandel;
	fopen_s(&dllFileHandel, injectorName, "rb+");
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
	PIMAGE_OPTIONAL_HEADER64 OH = (PIMAGE_OPTIONAL_HEADER64)(InjectorFileHeader + pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER SH = (PIMAGE_SECTION_HEADER)(InjectorFileHeader + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64));


	ZeroMemory(&SH[FH->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
	CopyMemory(&SH[FH->NumberOfSections].Name, ".ATH", 8);

	SH[FH->NumberOfSections].Misc.VirtualSize = align(dllLengh, OH->SectionAlignment, 0);
	SH[FH->NumberOfSections].VirtualAddress = align(SH[FH->NumberOfSections - 1].Misc.VirtualSize, OH->SectionAlignment, SH[FH->NumberOfSections - 1].VirtualAddress);
	SH[FH->NumberOfSections].SizeOfRawData = align(dllLengh, OH->FileAlignment, 0);
	SH[FH->NumberOfSections].PointerToRawData = dllFileLengh;
	SH[FH->NumberOfSections].Characteristics = 0xE00000E0;

	OH->SizeOfImage = SH[FH->NumberOfSections].VirtualAddress + SH[FH->NumberOfSections].Misc.VirtualSize;
	FH->NumberOfSections += 1;

	// write new back edited data to injector
	FILE* dllFileHandel2;
	fopen_s(&dllFileHandel2, injectorName, "rb+");
	fwrite(InjectorFileHeader, sizeOfHeaders, 1, dllFileHandel2);
	fclose(dllFileHandel2);

	// write dll to injector
	FILE* targFile;
	fopen_s(&targFile, injectorName, "ab");
	fwrite(buffer, dllLengh, 1, targFile);
	fclose(targFile);
	free(buffer);
}

// complie useing 32bit release for correct folder output.

extern "C" __declspec(dllexport) void EmbedDllFile(char dllFile[], char InjectorFile[]) {
	//AllocConsole();
	//freopen("conin$", "r", stdin);
	//freopen("conout$", "w", stdout);
	//freopen("conout$", "w", stderr);
	//printf("debugging window:\n");

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

	PIMAGE_DOS_HEADER dllDosHead = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(buffer + dllDosHead->e_lfanew + sizeof(DWORD));
	// 0x8664 = 64 
	// 0x014c = 32
	WORD macheanType = fileHeader->Machine;
	if (macheanType == 0x8664) {
		embeddFile_x64(InjectorFile, dllFile, fileLengh);
		return;
	}
	//printf("opened dll size: %i\n", fileLengh);

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

	//printf("opened injector size: %i\n", sizeOfHeaders);

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
	free(buffer);
}
