#ifndef _INJECTOR_H
#define _INJECTOR_H
#pragma once

#ifdef INJECTOR_EXPORTS
#define INJECTOR_API __declspec(dllexport)
#else
#define INJECTOR_API __declspec(dllimport)
#endif

#include <Windows.h>
#include <string>
#include <functional>

namespace Inject
{
	class INJECTOR_API Injector
	{
	public:
		static Injector* CreateInstance(const std::wstring &sExePath, const std::string& sDllPath);
		static Injector* CreateInstance(DWORD dwProcId, const std::string& sDllPath);
		static DWORD GetProcessId(const std::wstring& sExePath);
		~Injector();

	private:
		explicit Injector(DWORD dwProcId, const std::string& sDllPath);
		void Invoke(LPVOID lpProcAddr, LPVOID lpProcParam, SIZE_T szParamSize, std::function<void(HANDLE)> fpResponseHandle);

		HANDLE m_hProcess;
		HMODULE m_hRemoteModule;
	};
}

#endif // _INJECTOR_H