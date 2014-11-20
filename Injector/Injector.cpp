// Injector.cpp: определяет экспортированные функции для приложения DLL.
//

#include "stdafx.h"
#include "Injector.h"
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <stdexcept>
#include <Dbghelp.h>


bool Is64BitHandle(const HANDLE &hInputHandle)
{
	// map the file to our address space
	// first, create a file mapping object
	HANDLE hMap = CreateFileMapping(
		hInputHandle,
		NULL,
		PAGE_READONLY,
		0,
		0,
		NULL);

	// next, map the file to our address space
	LPVOID lpMapAddr = MapViewOfFileEx(
		hMap,
		FILE_MAP_READ,
		0,
		0,
		0,
		NULL);

	PIMAGE_NT_HEADERS headers = ImageNtHeader(lpMapAddr);
	return (headers->FileHeader.Machine != IMAGE_FILE_MACHINE_I386);
}

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

		// Detect dll architecture
		HANDLE hFile = CreateFileA(sDllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, 
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		bool is64BitDll = Is64BitHandle(hFile);
		CloseHandle(hFile);

		// Detect process architecture
		BOOL bIs32Bit = FALSE;
		if (!IsWow64Process(m_hProcess, &bIs32Bit)) {
			CloseHandle(m_hProcess);
			throw std::runtime_error("not recognize process architecture");
		}

		// if not compatible archictures
		if (is64BitDll != (bIs32Bit == FALSE)) {
			CloseHandle(m_hProcess);
			throw std::runtime_error("Not compatible architecture dll and target process");
		}

		LPVOID lpProcAddr = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
		LPVOID lpProcParam = (LPVOID)sDllPath.c_str();
		SIZE_T szParamSize = sDllPath.size();
		DWORD dwThreadResult = 0;

		Invoke(lpProcAddr, lpProcParam, szParamSize, [&](const HANDLE &hThread){
			// Wait for end LoadLibrary call
			if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
				throw std::runtime_error("target process does not respond");
			}

			GetExitCodeThread(hThread, &dwThreadResult);
			if (dwThreadResult == 0) {
				throw std::runtime_error("DLL not loaded in target process");
			}

			// FIXME: not correct convert
			m_hRemoteModule = nullptr; // (HMODULE)dwThreadResult;
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

	DWORD Injector::GetProcessId(const std::wstring& sExePath)
	{
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (hSnapshot != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32 pe = { 0 };
			pe.dwSize = sizeof(PROCESSENTRY32);
			BOOL bRet = Process32First(hSnapshot, &pe);

			do {
				// return first matched process id (TODO: parent?)
				if (!_wcsicmp(pe.szExeFile, sExePath.c_str())) {
					return pe.th32ProcessID;
				}
			} while (Process32Next(hSnapshot, &pe) == TRUE);

			CloseHandle(hSnapshot);
		}

		return (DWORD)0;
	}

	void Injector::Invoke(LPVOID lpProcAddr, LPVOID lpProcParam, SIZE_T szParamSize, std::function<void(const HANDLE&)> fpResponseHandle)
	{
		LPVOID lpMemory = nullptr; // Declare the memory we will be allocating
		HANDLE hThread = nullptr; 
		BOOL bCode = FALSE;

		// Allocate space in the process for our DLL 
		lpMemory = (LPVOID)VirtualAllocEx(m_hProcess, NULL, szParamSize + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (lpMemory == nullptr) {
			throw std::runtime_error("VirtualAllocEx failed");
		}

		// Write the string name of our DLL in the memory allocated 
		bCode = WriteProcessMemory(m_hProcess, (LPVOID)lpMemory, lpProcParam, szParamSize + 1, NULL);
		if (bCode == FALSE) {
			VirtualFreeEx(m_hProcess, (LPVOID)lpMemory, 0, MEM_RELEASE);
			throw std::runtime_error("WriteProcessMemory failed");
		}

		// Load our DLL 
		hThread = CreateRemoteThread(m_hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)lpProcAddr, (LPVOID)lpMemory, NULL, NULL);
		if (hThread == nullptr) {
			VirtualFreeEx(m_hProcess, (LPVOID)lpMemory, 0, MEM_RELEASE);
			throw std::runtime_error("CreateRemoteThread failed");
		}

		// do custom handle
		if (fpResponseHandle != nullptr) {
			try {
				fpResponseHandle(hThread);
			}
			catch (const std::runtime_error &ex) {
				VirtualFreeEx(m_hProcess, (LPVOID)lpMemory, 0, MEM_RELEASE);
				throw;
			}
		}

		//Lets free the memory we are not using anymore.
		VirtualFreeEx(m_hProcess, (LPVOID)lpMemory, 0, MEM_RELEASE);
	}
}
