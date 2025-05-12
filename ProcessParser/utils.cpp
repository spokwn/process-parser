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

static bool VerifyFileViaCatalog(LPCWSTR filePath)
{
	HANDLE hCatAdmin = NULL;
	if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
		return false;

	HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		return false;
	}

	DWORD dwHashSize = 0;
	if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, NULL, 0))
	{
		CloseHandle(hFile);
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		return false;
	}

	BYTE* pbHash = new BYTE[dwHashSize];
	if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, pbHash, 0))
	{
		delete[] pbHash;
		CloseHandle(hFile);
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		return false;
	}

	CloseHandle(hFile);

	CATALOG_INFO catInfo = { 0 };
	catInfo.cbStruct = sizeof(catInfo);

	HANDLE hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, NULL);
	bool isCatalogSigned = false;

	while (hCatInfo && CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0))
	{
		WINTRUST_CATALOG_INFO wtc = {};
		wtc.cbStruct = sizeof(wtc);
		wtc.pcwszCatalogFilePath = catInfo.wszCatalogFile;
		wtc.pbCalculatedFileHash = pbHash;
		wtc.cbCalculatedFileHash = dwHashSize;
		wtc.pcwszMemberFilePath = filePath;

		WINTRUST_DATA wtd = {};
		wtd.cbStruct = sizeof(wtd);
		wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
		wtd.pCatalog = &wtc;
		wtd.dwUIChoice = WTD_UI_NONE;
		wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
		wtd.dwProvFlags = 0;
		wtd.dwStateAction = WTD_STATEACTION_VERIFY;

		GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
		LONG res = WinVerifyTrust(NULL, &action, &wtd);

		wtd.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(NULL, &action, &wtd);

		if (res == ERROR_SUCCESS)
		{
			isCatalogSigned = true;
			break;
		}
		hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash, dwHashSize, 0, &hCatInfo);
	}

	if (hCatInfo)
		CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);

	CryptCATAdminReleaseContext(hCatAdmin, 0);
	delete[] pbHash;

	return isCatalogSigned;
}

std::string getDigitalSignature(const std::string& filePath) {
	WCHAR wideFilePath[MAX_PATH];
	MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, wideFilePath, MAX_PATH);

	if (GetFileAttributesW(wideFilePath) == INVALID_FILE_ATTRIBUTES) {
		return "Deleted";
	}

	WINTRUST_FILE_INFO fileInfo = {};
	fileInfo.cbStruct = sizeof(fileInfo);
	fileInfo.pcwszFilePath = wideFilePath;

	GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	WINTRUST_DATA winTrustData = {};
	winTrustData.cbStruct = sizeof(winTrustData);
	winTrustData.dwUIChoice = WTD_UI_NONE;
	winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
	winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	winTrustData.pFile = &fileInfo;

	LONG status = WinVerifyTrust(NULL, &guidAction, &winTrustData);

	std::string result = "Not signed";

	PCCERT_CONTEXT signingCert = nullptr;
	if (status == ERROR_SUCCESS) {
		result = "Signed";

		auto pProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
		if (pProvData) {
			auto nonConstData = const_cast<CRYPT_PROVIDER_DATA*>(pProvData);
			auto pProvSigner = WTHelperGetProvSignerFromChain(nonConstData, 0, FALSE, 0);
			if (pProvSigner) {
				auto pProvCert = WTHelperGetProvCertFromChain(pProvSigner, 0);
				if (pProvCert && pProvCert->pCert) {
					signingCert = pProvCert->pCert;
					char subjName[256] = {};
					CertNameToStrA(
						signingCert->dwCertEncodingType,
						&signingCert->pCertInfo->Subject,
						CERT_X500_NAME_STR,
						subjName,
						sizeof(subjName)
					);
					std::string subj(subjName);
					std::transform(subj.begin(), subj.end(), subj.begin(), ::tolower);
					static const char* cheats[] = {
						"manthe industries, llc",
						"slinkware",
						"amstion limited",
					};
					for (auto c : cheats) {
						if (subj.find(c) != std::string::npos) {
							result = "Cheat Signature";
							break;
						}
					}
				}
			}
		}
	}
	else {
		if (VerifyFileViaCatalog(wideFilePath)) {
			result = "Signed";
		}
	}

	winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(NULL, &guidAction, &winTrustData);

	if (signingCert) {
		DWORD hashLen = 0;
		if (CertGetCertificateContextProperty(signingCert, CERT_SHA1_HASH_PROP_ID, nullptr, &hashLen)) {
			std::vector<BYTE> hash(hashLen);
			if (CertGetCertificateContextProperty(signingCert, CERT_SHA1_HASH_PROP_ID, hash.data(), &hashLen)) {
				CRYPT_HASH_BLOB blob = { hashLen, hash.data() };

				static const LPCWSTR storeNames[] = {
					L"MY",                    // Personal
					L"Root",                  // Trusted Root CAs
					L"Trust",                 // Enterprise Trust
					L"CA",                    // Intermediate CAs
					L"UserDS",                // Active Directory User Object
					L"TrustedPublisher",      // Trusted Publishers
					L"Disallowed",            // Untrusted Certificates
					L"AuthRoot",              // Third-Party Root CAs
					L"TrustedPeople",         // Trusted People
					L"ClientAuthIssuer",      // Client Authentication Issuers
					L"CertificateEnrollment", // Certificate Enrollment Requests
					L"SmartCardRoot"          // Smart Card Trusted Roots
				};

				const DWORD contexts[] = {
					CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
					CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG
				};

				bool foundAnywhere = false;
				for (DWORD ctx : contexts) {
					for (auto storeName : storeNames) {
						HCERTSTORE hStore = CertOpenStore(
							CERT_STORE_PROV_SYSTEM_W,
							0,
							NULL,
							ctx,
							storeName
						);
						if (!hStore)
							continue;

						PCCERT_CONTEXT found = CertFindCertificateInStore(
							hStore,
							signingCert->dwCertEncodingType,
							0,
							CERT_FIND_SHA1_HASH,
							&blob,
							NULL
						);
						if (found) {
							foundAnywhere = true;
							CertFreeCertificateContext(found);
						}
						CertCloseStore(hStore, 0);
						if (foundAnywhere) break;
					}
					if (foundAnywhere) break;
				}

				if (foundAnywhere) {
					result = "Fake Signature";
				}
			}
		}
	}

	return result;
}
void process::initialize() {
    process::setDiagTrackPID(GetServicePID(L"DiagTrack"));
    process::setAppInfoPID(GetServicePID(L"AppInfo"));
}
