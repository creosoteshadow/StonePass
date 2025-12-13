#pragma once
// file windows_fix.h
#define _CRT_DECLARE_NONSTDC_NAMES 1

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winternl.h>        // NTSTATUS

#include <windows.h>
#include <conio.h>
