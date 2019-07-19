/*
*	Module Name:
*		img.h
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

#pragma once

///
/// Forward declarations.
///

PVOID ImgGetBaseAddress(
	_In_opt_ const char* ImageName, 
	_Out_opt_ PULONG SizeOfImage);

PVOID ImgGetImageSection(
	_In_ PVOID ImageBase, 
	_In_ const char* SectionName, 
	_Out_opt_ PULONG SizeOfSection);

PVOID ImgGetSyscallEntry();