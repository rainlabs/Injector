// Injector.cpp: определяет экспортированные функции для приложения DLL.
//

#include "stdafx.h"
#include "Injector.h"
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <stdexcept>

namespace Inject
{
	Injector::Injector(DWORD dwProcId, const std::string& sDllPath)
		: m_hProcess(nullptr)
		, m_hRemoteModule(nullptr)
	{
		//Open the process with read , write and execute priviledges
		m_hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwProcId);
		if (m_hProcess == nullptr) {
			// DWORD dwError = GetLastError();
			throw std::runtime_error("couldn't open target process");
		}

		LPVOID lpProcAddr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
		LPVOID lpProcParam = (LPVOID)sDllPath.c_str();
		SIZE_T szParamSize = sDllPath.size();
		DWORD dwThreadResult = 0;

		Invoke(lpProcAddr, lpProcParam, szParamSize, [&](HANDLE hThread){
			if (hThread != nullptr) {
				// Wait for end LoadLibrary call
				if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
					return;
				}

				GetExitCodeThread(hThread, &dwThreadResult);
				m_hRemoteModule = (HMODULE)dwThreadResult;
				// Get m_hRemoteModule
			}
		});
	}

	Injector::~Injector()
	{
		if (m_hProcess != nullptr) {
			CloseHandle(m_hProcess);
		}
		
		if (m_hRemoteModule != nullptr) {
			LPVOID lpProcAddr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary");
			LPVOID lpProcParam = (LPVOID)m_hRemoteModule;
			SIZE_T szParamSize = sizeof(m_hRemoteModule);
			DWORD dwThreadResult = 0;

			Invoke(lpProcAddr, lpProcParam, szParamSize, [&](HANDLE hThread){
				WaitForSingleObject(hThread, INFINITE);
				GetExitCodeThread(hThread, &dwThreadResult);
			});
		}
	}

	Injector* Injector::CreateInstance(const std::wstring &sExePath, const std::string& sDllPath)
	{
		DWORD dwProcId = GetProcessId(sExePath);
		if (dwProcId == 0) {
			return nullptr;
		}

		return CreateInstance(dwProcId, sDllPath);
	}

	Injector* Injector::CreateInstance(DWORD dwProcId, const std::string& sDllPath)
	{
		if (PathFileExistsA(sDllPath.c_str()) == FALSE) {
			return nullptr;
		}
		
		return new Injector(dwProcId, sDllPath);
	}

	//Function written by batfitch
	DWORD Injector::GetProcessId(const std::wstring& sExePath)
	{
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (hSnapshot != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32 pe = { 0 };
			pe.dwSize = sizeof(PROCESSENTRY32);
			BOOL bRet = Process32First(hSnapshot, &pe);

			do {
				if (!_wcsicmp(pe.szExeFile, sExePath.c_str())) {
					return pe.th32ProcessID;
				}
			} while (Process32Next(hSnapshot, &pe) == TRUE);

			CloseHandle(hSnapshot);
		}

		return (DWORD)0;
	}

	/*
	 * @param HANDLE process
	 * @param LPVOID procAddress
	 * @param LPVOID parameter
	 * @return HMODULE
	 */
	void Injector::Invoke(LPVOID lpProcAddr, LPVOID lpProcParam, SIZE_T szParamSize, std::function<void(HANDLE)> fpResponseHandle)
	{
		LPVOID lpMemory = nullptr; // Declare the memory we will be allocating
		HANDLE hThread = nullptr;
		BOOL bCode = FALSE;

		// Allocate space in the process for our DLL 
		lpMemory = (LPVOID)VirtualAllocEx(m_hProcess, NULL, szParamSize + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		// Write the string name of our DLL in the memory allocated 
		bCode = WriteProcessMemory(m_hProcess, (LPVOID)lpMemory, lpProcParam, szParamSize + 1, NULL);

		// Load our DLL 
		hThread = CreateRemoteThread(m_hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)lpProcAddr, (LPVOID)lpMemory, NULL, NULL);

		// do custom handle
		fpResponseHandle(hThread);

		//Lets free the memory we are not using anymore.
		VirtualFreeEx(m_hProcess, (LPVOID)lpMemory, 0, MEM_RELEASE);
	}
}
