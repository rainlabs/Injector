// Inject.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"
#include <iostream>
#include <cstdlib>
#include <Injector.h>

#define TARGET_DLL "C:\\Users\\Rain\\Documents\\Visual Studio 2013\\Projects\\Inject\\x64\\Debug\\SimpleDll.dll"
//#define TARGET_DLL L"Shlwapi.dll"


int main(int argc, char* argv[])
{
	Inject::Injector* injector;
	try {
		injector = Inject::Injector::CreateInstance(L"notepad.exe", TARGET_DLL);
		if (injector == nullptr) {
			throw std::runtime_error("injector is nullptr (target process not found)");
		}

		std::cout << "succesfull injected!" << std::endl;
		delete injector;
	}
	catch (const std::exception& ex) {
		std::cout << "Exception: " << ex.what() << std::endl;
	}


	system("PAUSE");
	return 0;
}

