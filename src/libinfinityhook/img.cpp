/*
*	Module Name:
*		img.cpp
*
*	Abstract:
*		Helper routines for extracting useful information from the PE
*		file specification.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*
*	Special thanks to Nemanja (Nemi) Mulasmajic <nm@triplefault.io>
*	for his help with the POC.
*
*/

#include "stdafx.h"
#include "img.h"
#include "hde/hde64.h"

#define OPCODE_JMP_NEAR 0xE9

/*
*	Returns the base address and size of the specified image.
*/
PVOID ImgGetBaseAddress(
	_In_opt_ const char* ImageName, 
	_Out_opt_ PULONG SizeOfImage)
{
	if (SizeOfImage)
	{
		*SizeOfImage = 0;
	}

	PVOID Buffer = NULL;
	ULONG SizeOfBuffer = 0;
	do
	{
		//
		// Get the list of all kernel drivers that are loaded.
		//
		ULONG ReturnLength = 0;
		NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, Buffer, SizeOfBuffer, &ReturnLength);
		if (NT_SUCCESS(Status))
		{
			break;
		}
		else if (Status == STATUS_INFO_LENGTH_MISMATCH || Status == STATUS_BUFFER_TOO_SMALL)
		{
			//
			// Need a bigger buffer.
			//

			SizeOfBuffer = ReturnLength;

			if (Buffer)
			{
				ExFreePool(Buffer);
				Buffer = NULL;
			}

			Buffer = ExAllocatePool(NonPagedPool, SizeOfBuffer);
			if (!Buffer)
			{
				break;
			}
		}
		else
		{
			break;
		}
	} while (TRUE);

	if (!Buffer)
	{
		return NULL;
	}

	//
	// Find the one we're looking for...
	//
	PRTL_PROCESS_MODULES SystemModules = (PRTL_PROCESS_MODULES)Buffer;
	for (ULONG i = 0; i < SystemModules->NumberOfModules; ++i)
	{
		PRTL_PROCESS_MODULE_INFORMATION ModuleInformation = &SystemModules->Modules[i];

		//
		// If you don't supply an image name, you'll get the first 
		// loaded driver which should be ntoskrnl.
		//
		if (!ImageName || !_stricmp(ImageName, (const char*)& ModuleInformation->FullPathName[ModuleInformation->OffsetToFileName]))
		{
			if (SizeOfImage)
			{
				*SizeOfImage = ModuleInformation->ImageSize;
			}
			
			PVOID ImageBase = ModuleInformation->ImageBase;

			//
			// Free the buffer. Thanks to @tandasat for catching my 
			// silly mistake.
			//
			ExFreePool(Buffer);

			return ImageBase;
		}
	}
	
	ExFreePool(Buffer);

	return NULL;
}

/*
*	Retrieves the start of a PE section and its size within an
*	image.
*/
PVOID ImgGetImageSection(
	_In_ PVOID ImageBase,
	_In_ const char* SectionName,
	_Out_opt_ PULONG SizeOfSection)
{
	//
	// Get the IMAGE_NT_HEADERS.
	//
	PIMAGE_NT_HEADERS64 NtHeaders = RtlImageNtHeader(ImageBase);
	if (!NtHeaders)
	{
		return NULL;
	}
	
	//
	// Walk the PE sections, looking for our target section.
	//
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
	for (USHORT i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i, ++SectionHeader)
	{
		if (!_strnicmp((const char*)SectionHeader->Name, SectionName, IMAGE_SIZEOF_SHORT_NAME))
		{
			if (SizeOfSection)
			{
				*SizeOfSection = SectionHeader->SizeOfRawData;
			}

			return (PVOID)((uintptr_t)ImageBase + SectionHeader->VirtualAddress);
		}
	}

	return NULL;
}

/*
*	Retrieves the address of the non-KVA shadow system call entry.
*/
PVOID ImgGetSyscallEntry()
{
	//
	// Get the base address of the kernel.
	//
	PVOID NtBaseAddress = ImgGetBaseAddress(NULL, NULL);
	if (!NtBaseAddress)
	{
		return NULL;
	}
	
	//
	// Get the LSTAR MSR. This should be KiSystemCall64 if KVA shadowing
	// is not enabled.
	//
	PVOID SyscallEntry = (PVOID)__readmsr(IA32_LSTAR_MSR);

	//
	// Get the PE section for KVASCODE. If one doesn't exit, KVA 
	// shadowing doesn't exist. This can be queried using 
	// NtQuerySystemInformation alternatively.
	//
	ULONG SizeOfSection;
	PVOID SectionBase =	ImgGetImageSection(NtBaseAddress, "KVASCODE", &SizeOfSection);
	if (!SectionBase)
	{
		return SyscallEntry;
	}

	//
	// Is the value within this KVA shadow region? If not, we're done.
	//
	if (!(SyscallEntry >= SectionBase && SyscallEntry < (PVOID)((uintptr_t)SectionBase + SizeOfSection)))
	{
		return SyscallEntry;
	}

	//
	// This is KiSystemCall64Shadow.
	//
	hde64s HDE;
	for (PCHAR KiSystemServiceUser = (PCHAR)SyscallEntry; /* */; KiSystemServiceUser += HDE.len)
	{
		//
		// Disassemble every instruction till the first near jmp (E9).
		//
		if (!hde64_disasm(KiSystemServiceUser, &HDE))
		{
			break;
		}

		if (HDE.opcode != OPCODE_JMP_NEAR)
		{
			continue;
		}

		//
		// Ignore jmps within the KVA shadow region.
		//
		PVOID PossibleSyscallEntry = (PVOID)((intptr_t)KiSystemServiceUser + (int)HDE.len + (int)HDE.imm.imm32);
		if (PossibleSyscallEntry >= SectionBase && PossibleSyscallEntry < (PVOID)((uintptr_t)SectionBase + SizeOfSection))
		{
			continue;
		}

		//
		// Found KiSystemServiceUser.
		//
		SyscallEntry = PossibleSyscallEntry;
		break;
	}

	return SyscallEntry;
}
