#include "StdAfx.h"
#include "string_parser.h"
#include <errno.h>
#include <algorithm> 
#include "pathconverter.h"
#include "../include.h"
#include "pathclearer.h"

std::unordered_set<std::string> processedPaths;

unsigned char lowerTable[256];
bool tableInitialized = false;

int string_parser::extractImmediate( char* immediate, int immediateSize, STRING_TYPE &stringType, unsigned char* outputString )
{
	int i = 0;
	switch(stringType)
	{
		case TYPE_ASCII:
			while( i < immediateSize && isAscii[immediate[i]] )
			{
				*outputString = immediate[i];
				outputString++;
				i++;
			}
			return i;

		case TYPE_UNICODE:
			while( i+1 < immediateSize && isAscii[immediate[i]] && immediate[i+1] == 0 )
			{
				*outputString = immediate[i];
				outputString++;
				i+=2;
			}
			return i/2;

		case TYPE_UNDETERMINED:
			if( !isAscii[immediate[0]] )
			{
				return 0;
			}else if( immediateSize > 1 && immediate[1] == 0 )
			{
				stringType = TYPE_UNICODE;
				return extractImmediate( immediate, immediateSize, stringType, outputString );
			}else{
				stringType = TYPE_ASCII;
				return extractImmediate( immediate, immediateSize, stringType, outputString );
			}
	
		default:
			break;
	}
	return 0;
}

int string_parser::extractString( unsigned char* buffer, long bufferSize, long offset, unsigned char* outputString, int outputStringSize, int &outputStringLength, EXTRACT_TYPE & extractType, STRING_TYPE & stringType)
{
	// Process the string as either:
	// 1. ascii
	// 2. unicode
	// 3. x86 ASM stack pushes
	// TODO: 4. x64 ASM stack pushes
	//
	// To improve performance:
	//	Assumes MAX_STRING_SIZE > 1
	//	Assumes MinStringSize > 1
	//  Assumes offset + 3 < bufferSize
	// These assumptions must be validated by the calling function.
	
	// Supported string push formats
	// C6 45     mov byte [ebp+imm8], imm8
	// C6 85     mov byte [ebp+imm32], imm8
	// 66 C7 45  mov word [ebp+imm8], imm16
	// 66 C7 85  mov word [ebp+imm32], imm16
	// C7 45     mov dword [ebp+imm8], imm32
	// C7 85     mov dword [ebp+imm32], imm32

	// Set unknown string type
	extractType = EXTRACT_RAW;
	outputStringLength = 0;
	int i = 0;
	int instSize;
	int immSize;
	int immOffset;
	int maxStringSize;
	int size;


	unsigned _int16 value = *((unsigned _int16*) (buffer+offset));
	// Switch on the first two bytes
	switch( value )
	{
		case 0x45C6:
			//  0  1  0  [0]
			// C6 45     mov byte [ebp+imm8], imm8
			instSize = 4;
			immSize = 1;
			immOffset = instSize - immSize;
			maxStringSize = 1;
			while( offset+i+instSize < bufferSize && outputStringLength + maxStringSize < outputStringSize
					&& buffer[offset+i] == 0xC6 && buffer[offset+i+1] == 0x45 )
			{
				
				// Process this immediate
				size = this->extractImmediate( (char*) (buffer + offset + immOffset + i), immSize, stringType, outputString );
				outputString += size;
				outputStringLength += size;
				
				i+=instSize;

				if( (stringType == TYPE_UNICODE && size < ((immSize + 1) / 2) )
					|| (stringType == TYPE_ASCII && size < immSize ) )
					break;
			}
			extractType = EXTRACT_ASM;
			return i;

		case 0x85C6:
			//  0  1  0  1  2  3  4  [0]
			// C6 85     mov byte [ebp+imm32], imm8
			instSize = 8;
			immSize = 1;
			immOffset = instSize - immSize;
			maxStringSize = 1;
			while( offset+i+instSize < bufferSize && outputStringLength + maxStringSize < outputStringSize
					&& buffer[offset+i] == 0xC6 && buffer[offset+i+1] == 0x85 )
			{
				
				// Process this immediate
				size = this->extractImmediate( (char*) (buffer + offset + immOffset + i), immSize, stringType, outputString );
				outputString += size;
				outputStringLength += size;
				
				i+=instSize;

				if( (stringType == TYPE_UNICODE && size < ((immSize + 1) / 2) )
					|| (stringType == TYPE_ASCII && size < immSize ) )
					break;
			}
			extractType = EXTRACT_ASM;
			return i;

		case 0x45C7:
			// 0  1  0  [0  1  2  3]
			// C7 45     mov dword [ebp+imm8], imm32
			instSize = 7;
			immSize = 4;
			immOffset = instSize - immSize;
			maxStringSize = 4;
			while( offset+i+instSize < bufferSize && outputStringLength + maxStringSize < outputStringSize
					&& buffer[offset+i] == 0xC7 && buffer[offset+i+1] == 0x45 )
			{
				
				// Process this immediate
				size = this->extractImmediate( (char*) (buffer + offset + immOffset + i), immSize, stringType, outputString );
				outputString += size;
				outputStringLength += size;
				
				i+=instSize;

				if( (stringType == TYPE_UNICODE && size < ((immSize + 1) / 2) )
					|| (stringType == TYPE_ASCII && size < immSize ) )
					break;
			}
			extractType = EXTRACT_ASM;
			return i;

		case 0x85C7:
			// 0  1  0  1  2  3  [0  1  2  3]
			// C7 85     mov dword [ebp+imm32], imm32
			instSize = 10;
			immSize = 4;
			immOffset = instSize - immSize;
			maxStringSize = 4;
			while( offset+i+instSize < bufferSize && outputStringLength + maxStringSize < outputStringSize
					&& buffer[offset+i] == 0xC7 && buffer[offset+i+1] == 0x85 )
			{
				
				// Process this immediate
				size = this->extractImmediate( (char*) (buffer + offset + immOffset + i), immSize, stringType, outputString );
				outputString += size;
				outputStringLength += size;
				
				i+=instSize;

				if( (stringType == TYPE_UNICODE && size < ((immSize + 1) / 2) )
					|| (stringType == TYPE_ASCII && size < immSize ) )
					break;
			}
			extractType = EXTRACT_ASM;
			return i;

		case 0xC766:
			if( buffer[offset+2] == 0x45 )
			{
				// 0  1  2  0  [0  1]
				// 66 C7 45  mov word [ebp+imm8], imm16
				instSize = 6;
				immSize = 2;
				immOffset = instSize - immSize;
				maxStringSize = 2;
				while( offset+i+instSize < bufferSize && outputStringLength + maxStringSize < outputStringSize
						&& buffer[offset+i] == 0x66 && buffer[offset+i+1] == 0xC7 && buffer[offset+i+2] == 0x45 )
				{
					
					// Process this immediate
					size = this->extractImmediate( (char*) (buffer + offset + immOffset + i), immSize, stringType, outputString );
					outputString += size;
					outputStringLength += size;
					
					i+=instSize;

					if( (stringType == TYPE_UNICODE && size < ((immSize + 1) / 2) )
						|| (stringType == TYPE_ASCII && size < immSize ) )
						break;
				}
				extractType = EXTRACT_ASM;
				return i;
			}else if( buffer[offset+2] == 0x85 )
			{
				// 0  1  2  0  1  2  3  [0  1]
				// 66 C7 85  mov word [ebp+imm32], imm16
				i = 0;
				instSize = 9;
				immSize = 2;
				immOffset = instSize - immSize;
				maxStringSize = 2;
				while( offset+i+instSize < bufferSize && outputStringLength + maxStringSize < outputStringSize
						&& buffer[offset+i] == 0x66 && buffer[offset+i+1] == 0xC7 && buffer[offset+i+2] == 0x85 )
				{
					
					// Process this immediate
					size = this->extractImmediate( (char*) (buffer + offset + immOffset + i), immSize, stringType, outputString );
					outputString += size;
					outputStringLength += size;
					
					i+=instSize;

					if( (stringType == TYPE_UNICODE && size < ((immSize + 1) / 2) )
						|| (stringType == TYPE_ASCII && size < immSize ) )
						break;
				}
				extractType = EXTRACT_ASM;
				return i;
			}
			break;

		default:
			// Try to parse as ascii or unicode
			if( isAscii[buffer[offset]] )
			{
				// Consider unicode case
				if( buffer[offset+1] == 0 ) // No null dereference by assumptions
				{
					// Parse as unicode
					while( offset+i+1 < bufferSize && i/2 < outputStringSize && isAscii[buffer[offset+i]] && buffer[offset+i+1] == 0 && i/2 + 1 < outputStringSize )
					{
						// Copy this character
						outputString[i/2] = buffer[offset+i];
						
						i+=2;
					}
					outputStringLength = i / 2;
					stringType = TYPE_UNICODE;
					return i;
				}else
				{
					// Parse as ascii
					i = offset;
					while( i < bufferSize && isAscii[buffer[i]] )
						i++;
					outputStringLength = i - offset;
					if( outputStringLength > outputStringSize )
						outputStringLength = outputStringSize;

					// Copy this string to the output
					memcpy( outputString, buffer + offset, outputStringLength );
					stringType = TYPE_ASCII;
					return outputStringLength;
				}
			}
	}

	outputStringLength = 0;
	return 0;
}

bool string_parser::processContents(unsigned char* filecontents, long bufferSize, LPCSTR filename, string process) {
	if (bufferSize < options.minCharacters) return true;

	constexpr size_t STACK_BUFFER_SIZE = 4096;
	unsigned char stackBuffer[STACK_BUFFER_SIZE];
	std::unique_ptr<unsigned char[]> heapBuffer;
	unsigned char* outputString = (MAX_STRING_SIZE <= STACK_BUFFER_SIZE) ?
		stackBuffer : (heapBuffer = std::make_unique<unsigned char[]>(MAX_STRING_SIZE + 1)).get();

	if (!tableInitialized) {
		for (int i = 0; i < 256; i++) {
			lowerTable[i] = static_cast<unsigned char>(tolower(i));
		}
		tableInitialized = true;
	}

	const long endOffset = bufferSize - options.minCharacters;

	std::string tmpString;
	tmpString.reserve(MAX_STRING_SIZE);
	std::string lowerStr;
	lowerStr.reserve(MAX_STRING_SIZE);

	const bool printNormal = options.printNormal;
	const bool printUnicodeOnly = options.printUnicodeOnly;
	const bool printAsciiOnly = options.printAsciiOnly;

	EXTRACT_TYPE extractType;
	long offset = 0;

	while (offset < endOffset) {
		STRING_TYPE stringType = TYPE_UNDETERMINED;
		int outputStringSize = 0;

		int stringDiskSpace = extractString(
			filecontents, bufferSize, offset,
			outputString, MAX_STRING_SIZE,
			outputStringSize, extractType, stringType
		);

		if (outputStringSize >= options.minCharacters) {
			outputString[outputStringSize] = '\0';

			tmpString.assign(reinterpret_cast<char*>(outputString), outputStringSize);
			lowerStr.clear();

			for (char c : tmpString) {
				lowerStr += lowerTable[static_cast<unsigned char>(c)];
			}
			if (process == "DiagTrack") {
				if ((lowerStr.find("harddiskvolume") != std::string::npos) &&
					(lowerStr.find("storage\\volumesnapshot\\") == std::string::npos) &&
					(lowerStr.find(".dll") == std::string::npos))
				{
					bool print = printNormal && extractType == EXTRACT_RAW;
					if (print) {
						if ((printUnicodeOnly && stringType == TYPE_UNICODE) ||
							(printAsciiOnly && stringType == TYPE_ASCII) ||
							(!printUnicodeOnly && !printAsciiOnly)) {

							std::string convertedPath = convertPath(tmpString);

							std::string normalizedPath;
							normalizedPath.reserve(convertedPath.size());
							for (char c : convertedPath) {
								normalizedPath += lowerTable[static_cast<unsigned char>(c)];
							}

							if (processedPaths.find(normalizedPath) == processedPaths.end()) {
								processedPaths.insert(normalizedPath);
							}
						}
					}
				}
			}
			else if (process == "AppInfo") {
				PathClearer clearer(tmpString);
				std::string clearedPath = clearer.getProcessedPath();

				if (!clearedPath.empty()) {
					std::string lowerStr;
					lowerStr.reserve(clearedPath.size());
					for (char c : clearedPath) {
						lowerStr += lowerTable[static_cast<unsigned char>(c)];
					}

					if ((lowerStr.find(":\\") != std::string::npos) &&
						(lowerStr.find(".exe") != std::string::npos)&&
						(lowerStr.find(".manifest") == std::string::npos))
					{
						bool print = printNormal && extractType == EXTRACT_RAW;
						if (print) {
							if ((printUnicodeOnly && stringType == TYPE_UNICODE) ||
								(printAsciiOnly && stringType == TYPE_ASCII) ||
								(!printUnicodeOnly && !printAsciiOnly))
							{
								std::string normalizedPath;
								normalizedPath.reserve(clearedPath.size());
								for (char c : clearedPath) {
									normalizedPath += lowerTable[static_cast<unsigned char>(c)];
								}

								if (processedPaths.find(normalizedPath) == processedPaths.end()) {
									processedPaths.insert(normalizedPath);
								}
							}
						}
					}
				}
			}
			offset += stringDiskSpace;
		}
		else {
			++offset;
		}
	}
	return true;
}



bool string_parser::parse_block(unsigned char* buffer, unsigned int buffer_length, LPCSTR datasource, string process)
{
	if( buffer != NULL && buffer_length > 0)
	{
		// Process this buffer
		return this->processContents( buffer, buffer_length, datasource, process );
	}
	return false;
}

string_parser::string_parser(STRING_OPTIONS options)
{
	this->options = options;
}

bool string_parser::parse_stream(FILE* fh, LPCSTR datasource)
{
	if( fh != NULL )
	{
		
		unsigned char* buffer;
		int numRead;

		// Allocate the buffer
		buffer = new unsigned char[BLOCK_SIZE];

		do
		{
			// Read the stream in blocks of 0x50000, assuming that a string does not border the regions.
			numRead = fread( buffer, 1, BLOCK_SIZE, fh);

			if( numRead > 0 )
			{
				// We have read in the full contents now, lets process it.
				this->processContents( buffer, numRead, datasource, "DiagTrack");
			}
		}while( numRead == BLOCK_SIZE );

		// Clean up
		delete[] buffer;
		return true;
	}else{
		// Failed to open file
		char buffer[256];
		strerror_s(buffer, sizeof(buffer), errno);
		fprintf(stderr, "Invalid stream: %s.\n", buffer);
		return false;
	}
}

string_parser::~string_parser(void)
{
}
