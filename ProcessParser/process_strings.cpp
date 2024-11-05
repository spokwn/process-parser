#include "StdAfx.h"
#include "process_strings.h"
#include "string_parser.h"


bool IsWin64(HANDLE process)
{
    BOOL retVal;
	if( IsWow64Process(process, &retVal) )
	{
		return retVal;
	}
	TCHAR errorMsg[] = "IsWow64Process";
	PrintLastError(errorMsg);
	return false;
}


bool process_strings::dump_process(DWORD pid, bool ecomode, bool pagination, string process)
{
	HANDLE ph = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
	if( ph != NULL )
	{
		TCHAR* process_name_w = new TCHAR[0x100];
		process_name_w[0] = 0;
		GetModuleBaseName(ph, 0, process_name_w, 0x100 );
		char* process_name = new char[0x100];
		process_name[0] = 0;

        strncpy_s(process_name, 0x100, process_name_w, _TRUNCATE);
		
		HANDLE hSnapshot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
		if ( hSnapshot != INVALID_HANDLE_VALUE )
		{
			this->generateModuleList(hSnapshot);
			CloseHandle(hSnapshot);
			
			bool result = this->processAllHeaps(ph, process_name, ecomode, pagination, process);

			free(process_name);
			return result;
		}else{
			fprintf(stderr,"Failed gather module information for process 0x%x (%i). ", pid, pid);
			TCHAR errorMsg[] = "dump_process";
			PrintLastError(errorMsg);
		}

		free(process_name);
		return false;
	}else{
		fprintf(stderr,"Failed open process 0x%x (%i). ", pid, pid);
		TCHAR errorMsg[] = "dump_process";
		PrintLastError(errorMsg);
	}
}

process_strings::process_strings(string_parser* parser)
{
	this->parser = parser;
}


bool process_strings::processAllHeaps(HANDLE ph, char* process_name, bool ecomode, bool pagination, string process) {
    static const __int64 MAX_ADDRESS = 0x7ffffffffff;
    static const size_t MAX_REGION_SIZE = 5000000;
    static const DWORD INVALID_PROTECT_FLAGS = PAGE_NOACCESS | PAGE_GUARD;
    static const size_t ECO_MODE_THRESHOLD = 524288000;
    
    MEMORY_BASIC_INFORMATION mbi;
    bool paging = pagination;
    __int64 address = 0;
    
    if (ecomode) {
        PROCESS_MEMORY_COUNTERS_EX pmi;
        if (GetProcessMemoryInfo(ph, (PROCESS_MEMORY_COUNTERS*)&pmi, sizeof(pmi))) {
            paging = (pmi.PrivateUsage >= ECO_MODE_THRESHOLD);
        }
    }

    char errorBuffer[256];
    
    vector<unsigned char> buffer;
    buffer.reserve(MAX_REGION_SIZE);
    
    while (address < MAX_ADDRESS) {
        const __int64 blockSize = VirtualQueryEx(
            ph, 
            reinterpret_cast<LPCVOID>(address),
            reinterpret_cast<PMEMORY_BASIC_INFORMATION>(&mbi),
            sizeof(MEMORY_BASIC_INFORMATION64)
        );
        
        if (!blockSize) break;
        
        const __int64 newAddress = reinterpret_cast<__int64>(mbi.BaseAddress) + 
                                 static_cast<__int64>(mbi.RegionSize) + 1;
                                 
        if (newAddress <= address) break;
        address = newAddress;

        const bool validProtect = !(mbi.Protect & INVALID_PROTECT_FLAGS);
        const bool validSize = mbi.RegionSize <= MAX_REGION_SIZE;
        const bool shouldProcess = mbi.State == MEM_COMMIT && validProtect && 
                                 ((!paging && validSize) || !paging);

        if (shouldProcess) {
            try {
                if (buffer.size() < mbi.RegionSize) {
                    buffer.resize(mbi.RegionSize);
                }

                SIZE_T numRead = 0;
                const bool result = ReadProcessMemory(
                    ph,
                    mbi.BaseAddress,
                    buffer.data(),
                    mbi.RegionSize,
                    &numRead
                );

                if (numRead > 0) {
                    if (numRead != static_cast<SIZE_T>(mbi.RegionSize)) {
                        strerror_s(errorBuffer, sizeof(errorBuffer), errno);
                        fprintf(stderr, 
                            "Failed to read full heap from address 0x%016llX: %s. "
                            "Only %zu of expected %zu bytes were read.\n",
                            reinterpret_cast<__int64>(mbi.BaseAddress),
                            errorBuffer,
                            numRead,
                            static_cast<SIZE_T>(mbi.RegionSize)
                        );
                    }
                    parser->parse_block(buffer.data(), numRead, process_name, process);
                }
                else if (!result) {
                    fprintf(stderr, "Failed to read from address 0x%016llX. ",
                            reinterpret_cast<__int64>(mbi.BaseAddress));

                    TCHAR errorMsg[] = "ReadProcessMemory";
                    PrintLastError(errorMsg);
                }
            }
            catch (const std::bad_alloc&) {
                fprintf(stderr, "Failed to allocate space of %zx for reading heap.",
                        static_cast<size_t>(mbi.RegionSize));
                continue;
            }
        }
    }

    return true;
}

void process_strings::generateModuleList(HANDLE hSnapshot)
{
    MODULEENTRY32W tmpModule;
    tmpModule.dwSize = sizeof(MODULEENTRY32W);  
    if (Module32FirstW(hSnapshot, &tmpModule)) 
    {
        tmpModule.dwSize = sizeof(MODULEENTRY32W);
        modules.Add(new module(tmpModule));

        while (Module32NextW(hSnapshot, &tmpModule))
        {
            modules.Add(new module(tmpModule));
            tmpModule.dwSize = sizeof(MODULEENTRY32W);
        }
    }
}

process_strings::~process_strings(void)
{
}
