#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <DX/d3d9.h>
#include <ImGui/imgui.h>
#include <ImGui/imgui_impl_dx9.h>
#include <ImGui/imgui_impl_win32.h>
#include <tchar.h>
#include <string>
#include <WinTrust.h>
#include <SoftPub.h>
#include <algorithm>
#include <wincrypt.h>
#include <vector>

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Wintrust.lib")

DWORD GetServicePID(const wchar_t* serviceName);
bool getMaximumPrivileges(HANDLE h_Process);
std::string getDigitalSignature(const std::string& filePath);

class process {
private:
	static process* instance;
	int diagTrackPID;
	int appInfoPID;
public:
	static process* getInstance() {
		return instance;
	}
	static void setInstance(process* proc) {
		instance = proc;
	}
	int getDiagtrackPID(){
		return diagTrackPID;
	}
	int getAppInfoPID() {
		return appInfoPID;
	}
	void setDiagTrackPID(int pid) {
		diagTrackPID = pid;
	}
	void setAppInfoPID(int pid) {
		appInfoPID = pid;
	}
	void initialize();
};