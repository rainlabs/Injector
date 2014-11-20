#ifndef _INJECTOR_H
#define _INJECTOR_H
#pragma once

/**
 * @brief Dll Injection library
 * @author Vladimir Zyablitskiy <zyablitskiy@gmail.com>
 * @created 20.11.2014
 */

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
		/**
		 * Get Injector instance
		 * @param string exe path or name
		 * @param string dll path
		 * @return Injector instance
		 */
		static Injector* CreateInstance(const std::wstring &sExePath, const std::string& sDllPath);

		/**
		 * Get Injector instance
		 * @param DWORD process id
		 * @param string dll path
		 * @return Injector instance
		 */
		static Injector* CreateInstance(DWORD dwProcId, const std::string& sDllPath);

		/**
		 * Get process id by name
		 * @param exe path or name
		 * @return DWORD process id
		 */
		static DWORD GetProcessId(const std::wstring& sExePath);
		~Injector();

	private:
		explicit Injector(DWORD dwProcId, const std::string& sDllPath);

		/**
		 * Invoke function in target process
		 * @param LPVOID function address
		 * @param LPVOID function parameter
		 * @param SIZE_T parameter size
		 * @param lambda function for thread handle
		 */
		void Invoke(LPVOID lpProcAddr, LPVOID lpProcParam, SIZE_T szParamSize, std::function<void(const HANDLE&)> fpResponseHandle=nullptr);

		HANDLE m_hProcess;
		HMODULE m_hRemoteModule;
	};
}

#endif // _INJECTOR_H