// dllmain.cpp: определяет точку входа для приложения DLL.
#include "stdafx.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		MessageBox(GetActiveWindow(), L"injected dll attached!", L"succesfull!", MB_OK);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		MessageBox(GetActiveWindow(), L"injected dll DEtached!", L"succesfull!", MB_OK);
		break;
	}
	return TRUE;
}

