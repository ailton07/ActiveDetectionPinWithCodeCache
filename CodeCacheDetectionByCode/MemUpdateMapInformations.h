#include <stdio.h>
#include <Windows.h>
#include <vector>

namespace WINDOWS{
	#include <windows.h>
	#include <WinDef.h>
}

#define MAX_MODULE_SIZE 256
#define RWE 0x40

// bool bListAllPages = false;

// https://github.com/x64dbg/x64dbg/blob/d7cd9c9ae7209d001bca311e951da545c47f6a41/src/bridge/bridgemain.h
//Debugger structs
typedef struct
{
    MEMORY_BASIC_INFORMATION mbi;
    char info[MAX_MODULE_SIZE];
} MEMPAGE;

std::vector<MEMPAGE> GetPageVector();