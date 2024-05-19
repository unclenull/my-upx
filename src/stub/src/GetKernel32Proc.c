/*
 * Assembly
 * cl /c /O1 /Oy /FA /DUNICODE /Oi /GS- /Zi D:\programs\tools\c\GetProcAddress.c
 * with /O2 subroutines are embeded in GetProc although they still exist
 * modify .asm
%s/\$//g | %s/@/_/g | %s/;/\/\/;/ | %s/moduleName//g
lea	r10, [rip + kernel32]
 */

#include <windows.h>
#include <winternl.h>

typedef struct _VS_VERSION_INFO {
  WORD             wLength;
  WORD             wValueLength;
  WORD             wType;
  WCHAR            szKey[sizeof("VS_VERSION_INFO") + 1];
  VS_FIXEDFILEINFO fixedFileInfo;
} myVS_VERSION_INFO;

extern PWCHAR kernel32;

PVOID GetKernel32Proc(PCHAR exportName) {
#if defined(_WIN64)
#define PEBOffset 0x60
#define LdrOffset 0x18
#define ListOffset 0x10
  PBYTE pPeb = (PBYTE)__readgsqword(PEBOffset);
#else
#define PEBOffset 0x30
#define LdrOffset 0x0c
#define ListOffset 0x0c
  PBYTE *pPeb = (PBYTE)__readfsdword(PEBOffset);
#endif

  PBYTE pLdr = *(PBYTE *)(pPeb + LdrOffset);
  PLDR_DATA_TABLE_ENTRY pModuleList = *(PLDR_DATA_TABLE_ENTRY *)(pLdr + ListOffset);

  PBYTE baseAddr = NULL;
  WCHAR moduleName[MAX_PATH];
  INT16 mask = 0x20;

  while(pModuleList->DllBase) {
    INT8 i = 0;
    for(PWCHAR p = (PWCHAR)pModuleList->Reserved5[0]; *p != 0; i++, p++) {
      if (*p >= L'A' && *p <= L'Z') {
        moduleName[i] = *p ^= mask;
      } else {
        moduleName[i] = *p;
      }
    }
    moduleName[i] = 0;
    if (!wcscmp(moduleName, kernel32)) {
      baseAddr = pModuleList->DllBase;
      break;
    }
    pModuleList = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pModuleList->InMemoryOrderLinks.Flink - ListOffset);
  }

  if (!baseAddr) {
    return NULL;
  }

  PVOID addr = NULL;
  PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddr;
  PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(baseAddr + dosHeader->e_lfanew);

  IMAGE_DATA_DIRECTORY exportDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
  for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
    if ((exportDirectory.VirtualAddress >= sectionHeader->VirtualAddress) &&
        (exportDirectory.VirtualAddress < sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData)) {
      break;
    }
  }
  PBYTE section = baseAddr + sectionHeader->VirtualAddress;

  PBYTE exportBaseAddr = section - sectionHeader->VirtualAddress;

  PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)(exportBaseAddr + exportDirectory.VirtualAddress);
  PDWORD addressOfFunctions = (PDWORD)(exportBaseAddr + exportTable->AddressOfFunctions);
  PDWORD addressOfNames = (PDWORD)(exportBaseAddr + exportTable->AddressOfNames);
  PWORD addressOfNameOrdinals = (PWORD)(exportBaseAddr + exportTable->AddressOfNameOrdinals);

  for (DWORD i = 0; i < exportTable->NumberOfNames; i++) {
    char *functionName = (char*)(exportBaseAddr + addressOfNames[i]);
    if (strcmp(functionName, exportName) == 0) {
      addr = baseAddr + addressOfFunctions[addressOfNameOrdinals[i]];
      break;
    }
  }

  return addr;
}
