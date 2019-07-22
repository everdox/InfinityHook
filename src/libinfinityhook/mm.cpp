/*
*	Module Name:
*		mm.cpp
*
*	Abstract:
*		Generic memory manipulation routines.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*
*	Special thanks to Nemanja (Nemi) Mulasmajic <nm@triplefault.io>
*	for his help with the POC.
*
*/

#include "stdafx.h"
#include "mm.h"

/*
*	Search a memory buffer for the input signature.
*/
const void* MmSearchMemory(
	_In_ const void* Buffer,
	_In_ size_t SizeOfBuffer,
	_In_ const void* Signature,
	_In_ size_t SizeOfSignature)
{
	//
	// Sanity check...
	//
	if (SizeOfSignature > SizeOfBuffer)
	{
		return NULL;
	}

	PCHAR Memory = (PCHAR)Buffer;
	
	//
	// The +1 is necessary or there will be an off-by-one error. 
	// Thanks to @milabs for reporting.
	//
	for (size_t i = 0; i < ((SizeOfBuffer - SizeOfSignature) + 1); ++i)
	{
		if (!memcmp(&Memory[i], Signature, SizeOfSignature))
		{ 
			return &Memory[i];
		}
	}

	return NULL;
}