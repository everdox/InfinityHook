/*
*	Module Name:
*		stdafx.h
*
*	Abstract:
*		Precompiled header.
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
/// Includes.
///

#pragma warning(push, 0)
#include <ntifs.h>
#include <ntdef.h>
#include <ntddk.h>
#include <ntstatus.h>
#include <intrin.h>

#include "ntint.h"
#pragma warning(pop)