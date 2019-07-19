/*
*	Module Name:
*		mm.h
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

#pragma once

///
/// Forward declarations.
///

const void* MmSearchMemory(
	_In_ const void* Buffer, 
	_In_ size_t SizeOfBuffer, 
	_In_ const void* Signature, 
	_In_ size_t SizeOfSignature);