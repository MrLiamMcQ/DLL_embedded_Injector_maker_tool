// embedingCode.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

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

void embeddFile_x64(char injectorName[], char*&& dllData, int& dllLengh) {

	// read injector
	FILE* injectorFileHandel;
	fopen_s(&injectorFileHandel, injectorName, "rb+");
	fseek(injectorFileHandel, 0, SEEK_END);
	DWORD injectorFileLengh = ftell(injectorFileHandel);
	rewind(injectorFileHandel);
	char* injectorFileData = (char*)malloc(injectorFileLengh);
	fread(injectorFileData, 1, injectorFileLengh, injectorFileHandel);
	fseek(injectorFileHandel, 0, SEEK_SET);

	PIMAGE_DOS_HEADER pDosHeader_setup = (PIMAGE_DOS_HEADER)injectorFileData;
	PIMAGE_OPTIONAL_HEADER64 OH_setup = (PIMAGE_OPTIONAL_HEADER64)(injectorFileData + pDosHeader_setup->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

	// aligning dll data using injector file header
	int newFileLenght = align(dllLengh, OH_setup->FileAlignment, 0);
	char* newBuffer = new char[newFileLenght]();
	memcpy(newBuffer, dllData, dllLengh);
	delete[] dllData;
	dllData = newBuffer;
	dllLengh = newFileLenght;
	
	// write new section header for dll
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)injectorFileData;
	PIMAGE_FILE_HEADER FH = (PIMAGE_FILE_HEADER)(injectorFileData + pDosHeader->e_lfanew + sizeof(DWORD));
	PIMAGE_OPTIONAL_HEADER64 OH = (PIMAGE_OPTIONAL_HEADER64)(injectorFileData + pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER SH = (PIMAGE_SECTION_HEADER)(injectorFileData + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64));

	ZeroMemory(&SH[FH->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
	CopyMemory(&SH[FH->NumberOfSections].Name, ".ATH", 8);

	SH[FH->NumberOfSections].Misc.VirtualSize = align(dllLengh, OH->SectionAlignment, 0);
	SH[FH->NumberOfSections].VirtualAddress = align(SH[FH->NumberOfSections - 1].Misc.VirtualSize, OH->SectionAlignment, SH[FH->NumberOfSections - 1].VirtualAddress);
	SH[FH->NumberOfSections].SizeOfRawData = align(dllLengh, OH->FileAlignment, 0);
	SH[FH->NumberOfSections].PointerToRawData = injectorFileLengh;
	SH[FH->NumberOfSections].Characteristics = 0xE00000E0;

	OH->SizeOfImage = SH[FH->NumberOfSections].VirtualAddress + SH[FH->NumberOfSections].Misc.VirtualSize;
	FH->NumberOfSections += 1;

	// write new edited injector file and append dll to the injecotr
	fwrite(injectorFileData, injectorFileLengh, 1, injectorFileHandel);
	fwrite(dllData, dllLengh, 1, injectorFileHandel);
	fclose(injectorFileHandel);

	free(dllData);
	free(injectorFileData);
}

// complie useing 32bit release for correct folder output.

extern "C" __declspec(dllexport) void EmbedDllFile(char dllFile[], char InjectorFile[]) {

	// bug where inputed char array from c# dose not have a \0
	endFilePath(dllFile);
	endFilePath(InjectorFile);
	
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
		embeddFile_x64(InjectorFile, std::move(buffer), fileLengh);
		return;
	}

	// read injector
	FILE* injectorFileHandel;
	fopen_s(&injectorFileHandel, InjectorFile, "rb+");
	fseek(injectorFileHandel, 0, SEEK_END);
	DWORD injectorFileLengh = ftell(injectorFileHandel);
	rewind(injectorFileHandel);
	char* injectorFileData = (char*)malloc(injectorFileLengh);
	fread(injectorFileData, 1, injectorFileLengh, injectorFileHandel);
	fseek(injectorFileHandel, 0, SEEK_SET);

	PIMAGE_DOS_HEADER pDosHeader_setup = (PIMAGE_DOS_HEADER)injectorFileData;
	PIMAGE_OPTIONAL_HEADER OH_setup = (PIMAGE_OPTIONAL_HEADER)(injectorFileData + pDosHeader_setup->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

	// aligning dll data using injector file header
	int newFileLenght = align(fileLengh, OH_setup->FileAlignment, 0);
	char* newBuffer = new char[newFileLenght]();
	memcpy(newBuffer, buffer, fileLengh);
	delete[] buffer;
	buffer = newBuffer;
	fileLengh = newFileLenght;

	// write new section header for dll
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)injectorFileData;
	PIMAGE_FILE_HEADER FH = (PIMAGE_FILE_HEADER)(injectorFileData + pDosHeader->e_lfanew + sizeof(DWORD));
	PIMAGE_OPTIONAL_HEADER OH = (PIMAGE_OPTIONAL_HEADER)(injectorFileData + pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
	PIMAGE_SECTION_HEADER SH = (PIMAGE_SECTION_HEADER)(injectorFileData + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	ZeroMemory(&SH[FH->NumberOfSections], sizeof(IMAGE_SECTION_HEADER));
	CopyMemory(&SH[FH->NumberOfSections].Name, ".ATH", 8);

	SH[FH->NumberOfSections].Misc.VirtualSize = align(fileLengh, OH->SectionAlignment, 0);
	SH[FH->NumberOfSections].VirtualAddress = align(SH[FH->NumberOfSections - 1].Misc.VirtualSize, OH->SectionAlignment, SH[FH->NumberOfSections - 1].VirtualAddress);
	SH[FH->NumberOfSections].SizeOfRawData = align(fileLengh, OH->FileAlignment, 0);
	SH[FH->NumberOfSections].PointerToRawData = injectorFileLengh;
	SH[FH->NumberOfSections].Characteristics = 0xE00000E0;

	OH->SizeOfImage = SH[FH->NumberOfSections].VirtualAddress + SH[FH->NumberOfSections].Misc.VirtualSize;
	FH->NumberOfSections += 1;

	// write new edited injector file and append dll to the injecotr
	fwrite(injectorFileData, injectorFileLengh, 1, injectorFileHandel);
	fwrite(buffer, fileLengh, 1, injectorFileHandel);
	fclose(injectorFileHandel);

	free(buffer);
	free(injectorFileData);
}
