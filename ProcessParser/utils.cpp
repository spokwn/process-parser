#include "../include.h"

process* process::instance = nullptr;

DWORD GetServicePID(const wchar_t* serviceName) {
    DWORD targetPID = 0;
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);

    if (scManager == NULL) {
        return 0;
    }

    SC_HANDLE service = OpenServiceW(scManager, serviceName, SERVICE_QUERY_STATUS);
    if (service == NULL) {
        CloseServiceHandle(scManager);
        return 0;
    }

    SERVICE_STATUS_PROCESS statusProcess;
    DWORD bytesNeeded;
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        (LPBYTE)&statusProcess, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        targetPID = statusProcess.dwProcessId;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return targetPID;
}

bool getMaximumPrivileges(HANDLE h_Process) {
    HANDLE h_Token;
    DWORD dw_TokenLength;
    if (OpenProcessToken(h_Process, TOKEN_READ | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &h_Token)) {
        TOKEN_PRIVILEGES* privileges = new TOKEN_PRIVILEGES[100];
        if (GetTokenInformation(h_Token, TokenPrivileges, privileges, sizeof(TOKEN_PRIVILEGES) * 100, &dw_TokenLength)) {
            for (DWORD i = 0; i < privileges->PrivilegeCount; i++) {
                privileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
            }

            if (AdjustTokenPrivileges(h_Token, false, privileges, sizeof(TOKEN_PRIVILEGES) * 100, NULL, NULL)) {
                delete[] privileges;
                CloseHandle(h_Token);
                return true;
            }
        }
        delete[] privileges;
        CloseHandle(h_Token);
    }
    return false;
}

std::string getDigitalSignature(const std::string& filePath) {
	WCHAR wideFilePath[MAX_PATH];
	MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, wideFilePath, MAX_PATH);

	if (GetFileAttributesW(wideFilePath) == INVALID_FILE_ATTRIBUTES) {
		return "Deleted";
	}

	WINTRUST_FILE_INFO fileInfo;
	ZeroMemory(&fileInfo, sizeof(fileInfo));
	fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	fileInfo.pcwszFilePath = wideFilePath;

	GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	WINTRUST_DATA winTrustData;
	ZeroMemory(&winTrustData, sizeof(winTrustData));
	winTrustData.cbStruct = sizeof(winTrustData);
	winTrustData.dwUIChoice = WTD_UI_NONE;
	winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	winTrustData.pFile = &fileInfo;

	LONG lStatus = WinVerifyTrust(NULL, &guidAction, &winTrustData);

	std::string result = "Not signed";

	if (lStatus == ERROR_SUCCESS) {
		CRYPT_PROVIDER_DATA const* psProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
		if (psProvData) {
			CRYPT_PROVIDER_DATA* nonConstProvData = const_cast<CRYPT_PROVIDER_DATA*>(psProvData);
			CRYPT_PROVIDER_SGNR* pProvSigner = WTHelperGetProvSignerFromChain(nonConstProvData, 0, FALSE, 0);
			if (pProvSigner) {
				CRYPT_PROVIDER_CERT* pProvCert = WTHelperGetProvCertFromChain(pProvSigner, 0);
				if (pProvCert && pProvCert->pCert) {
					char subjectName[256];
					CertNameToStrA(pProvCert->pCert->dwCertEncodingType,
						&pProvCert->pCert->pCertInfo->Subject,
						CERT_X500_NAME_STR,
						subjectName,
						sizeof(subjectName));

					std::string subject(subjectName);
					std::transform(subject.begin(), subject.end(), subject.begin(), ::tolower);

					if (subject.find("manthe industries, llc") != std::string::npos) {
						result = "Not signed (vapeclient)";
					}
					else if (subject.find("slinkware") != std::string::npos) {
						result = "Not signed (slinky)";
					}
					else {
						result = "Signed";
					}
				}
			}
		}
	}

	winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(NULL, &guidAction, &winTrustData);

	return result;
}


void process::initialize() {
    process::setDiagTrackPID(GetServicePID(L"DiagTrack"));
    process::setAppInfoPID(GetServicePID(L"AppInfo"));
}