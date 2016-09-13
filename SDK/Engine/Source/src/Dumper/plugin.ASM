; #########################################################################
;
;          Build this DLL from the batch file called BldDLL.bat
;
; #########################################################################

    .386
    .model flat, stdcall
    option casemap :none   ; case sensitive

;------------------------------------------------------------------

    include \masm32\include\windows.inc
    include \masm32\include\user32.inc
    include \masm32\include\kernel32.inc
    include ..\..\Dumper.inc

    includelib \masm32\lib\user32.lib
    includelib \masm32\lib\kernel32.lib

;------------------------------------------------------------------
      UnmapFile PROTO
      MapFile PROTO :DWORD
      MapFileR PROTO :DWORD
      ResizeMapFile PROTO :DWORD,:DWORD
      SmartUnmapFile PROTO
      SmartMapFile PROTO :DWORD
      
      LengthDisassemble PROTO :DWORD
;------------------------------------------------------------------

PE32Struct STRUCT
	PE32Offset dd ?
	ImageBase dd ?
        OriginalEntryPoint dd ?
        NtSizeOfImage dd ?
        NtSizeOfHeaders dd ?
        SizeOfOptionalHeaders dd ?
        SectionAligment dd ?
        ImportTableAddress dd ?
        ImportTableSize dd ?
        ResourceTableAddress dd ?
        ResourceTableSize dd ?
        ExportTableAddress dd ?
        ExportTableSize dd ?
        TLSTableAddress dd ?
        TLSTableSize dd ?
        RelocationTableAddress dd ?
        RelocationTableSize dd ?
        TimeDateStamp dd ?
        SectionNumber dd ?
        CheckSum dd ?
PE32Struct ENDS

FullPE32Header STRUCT
	PESignature dd ?
	Machine dw ?
	NumberOfSections dw ?
	TimeDateStamp dd ?
	PointerToSymbolTable dd ?
	NumberOfSymbols dd ?
	SizeOfOptionalHeader dw ?
	Characteristics dw ?
	Magic dw ?
	MajorLinkerVersion db ?
	MinorLinkerVersion db ?
	SizeOfCode dd ?
	SizeOfInitializedData dd ?
	SizeOfUninitializedData dd ?
	AddressOfEntryPoint dd ?
	BaseOfCode dd ?
	BaseOfData dd ?
	ImageBase dd ?
	SectionAlignment dd ?
	FileAlignment dd ?
	MajorOperatingSystemVersion dw ?
	MinorOperatingSystemVersion dw ?
	MajorImageVersion dw ?
	MinorImageVersion dw ?
	MajorSubsystemVersion dw ?
	MinorSubsystemVersion dw ?
	Reserved01 dd ?
	SizeOfImage dd ?
	SizeOfHeaders dd ?
	CheckSum dd ?
	Subsystem dw ?
	DLLCharacteristics dw ?
	SizeOfStackReserve dd ?
	SizeOfStackCommit dd ?
	SizeOfHeapReserve dd ?
	SizeOfHeapCommit dd ?
	LoaderFlags dd ?
	NumberOfRvaAndSizes dd ?
	ExportTableAddress dd ?
        ExportTableSize dd ?
        ImportTableAddress dd ?
        ImportTableSize dd ?
	ResourceTableAddress dd ?
        ResourceTableSize dd ?
        ExceptionTableAddress dd ?
        ExceptionTableSize dd ?
        CertificateTableAddress dd ?
        CertificateTableSize dd ?
        BaseRelocationTable dd ?
        BaseRelocationSize dd ?
        DebugAddress dd ?
        DebugSize dd ?
	ArchitectureAddress dd ?
	ArchitectureSize dd ?
	GlobalPtrAddress dd ?
	GlobalPtrSize dd ?
	TLSTableAddress dd ?
	TLSTableSize dd ?
	LoadConfigTableAddress dd ?
	LoadConfigTableSize dd ?
	BoundImportAddress dd ?
	BoundImportSize dd ?
	IATAddress dd ?
	IATSize dd ?
	DelayImportDescriptor dd ?
	DelayImportDescriptorSize dd ?
	COMRuntimeHeaderAddress dd ?
        COMRuntimeHeaderSize dd ?
        Reserved02 dd ?
        	   dd ?
FullPE32Header ENDS

    return MACRO arg
      mov eax, arg
      ret
    ENDM

    .data
    	szTMP db "Overlay",0h
	OldProtect dd 02040001h
	MemInfo MEMORY_BASIC_INFORMATION <?>
    .data?
 ;
 ; Mapiranje fajla
 ;
	FileHWND dd ?
	FileSize dd ?
	FileMap dd ?
	FileMapVA dd ?
	PEHeader dd ?
	NumberOfSections dd ?
	RawSize dd ?
	RawOffset dd ?
	hSaveFile dd ?
	eStart dd ?
	eSize dd ?
	oldFileSize dd ?
	NumberOfBytesWritten dd ?
	SharedOverlay dd ?
	
	PE32Structure PE32Struct <?>

	BaseSize dd ?
	BaseOffset dd ?
	ImageBase dd ?
	hFile dd ?
	PEBase dd ?
	SizeOfImage dd ?
	HeaderSize dd ?
	ProcReadAlloc dd ?
	NumOfBytesWR dd ?
	ReadDataBuffer db 1000h dup(?)
 	SmartPE32Header db 2000h dup(?)
 	SmartFileBuffer db 4000h dup(?)
    .code

LibMain proc hInstDLL:DWORD, reason:DWORD, unused:DWORD

        .if reason == DLL_PROCESS_ATTACH

            return TRUE
            ; -----------------------------
            ; If error at startup, return 0
            ; System will abort loading DLL
            ; -----------------------------

        .elseif reason == DLL_PROCESS_DETACH

        .elseif reason == DLL_THREAD_ATTACH

        .elseif reason == DLL_THREAD_DETACH
            
        .endif

        ret

LibMain Endp
;------------------------------------------------------------------
 _fix_PEHeader:
	PUSH EBP
	MOV EBP,ESP
	PUSHAD
 ; 
 ; Konverzija
 ;
	MOV EAX,DWORD PTR[EBP+8]		; Parametar 1 = FileMapVA
	SUB EBX,DWORD PTR[ImageBase]
 ;
 ; elfa_new
 ;
	MOV ECX,DWORD PTR[EAX+3Ch]
 ;
 ; PEHeader
 ;
	LEA ECX,DWORD PTR[EAX+ECX]
	MOV EAX,ECX
 ;
 ; Write New OEP
 ;
	MOV ECX,DWORD PTR[EBP+12]		;Parametar 2 = VA OEP
	SUB ECX,DWORD PTR[ImageBase]
	MOV DWORD PTR[EAX+28h],ECX

 ;
 ; NumberOfSections
 ;
	XOR ECX,ECX
	MOV CX,WORD PTR[EAX+6]
 ;
 ; Section Tabela
 ;
	ADD AX,WORD PTR[EAX+14h]
	ADD EAX,018h
	XOR ESI,ESI
	.while ECX > 0
		MOV EDX,DWORD PTR[EAX+8]
		MOV EDI,DWORD PTR[EAX+12]
		.if ESI != 0
			.if DWORD PTR[EAX+16] < EDX
				MOV DWORD PTR[EAX+16],EDX
			.else
				MOV EDX,DWORD PTR[EAX+16]
				MOV DWORD PTR[EAX+8],EDX
			.endif
;			ADD EDI,DWORD PTR[BaseOffset]
			MOV DWORD PTR[EAX+20],EDI
		.else
			INC ESI
			MOV DWORD PTR[EAX+20],EDI
			MOV DWORD PTR[BaseOffset],EDI
			.if DWORD PTR[EAX+16] < EDX
				MOV DWORD PTR[EAX+16],EDX
			.else
				MOV EDX,DWORD PTR[EAX+16]
				MOV DWORD PTR[EAX+8],EDX
			.endif
			MOV DWORD PTR[BaseSize],EDX
		.endif
		ADD EAX,28h
		DEC ECX
	.endw
	POPAD
	LEAVE
	RET 8
;------------------------------------------------------------------
GetModuleVersion proc
	MOV EAX,0106h
	RET
GetModuleVersion endp
;------------------------------------------------------------------
PastePEHeader proc dwHProcess:DWORD,dwFileName:DWORD
 ;
 ; Ova funkcija radi dump selektovanog procesa
 ;
 ; Parametar 1 => hProcess
 ; Parametar 2 => szFileName LPSTR / original gde?
 ;
	PUSHAD
	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV DWORD PTR[ProcReadAlloc],EAX

	INVOKE CreateFile,DWORD PTR[EBP+12],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	CMP EAX,-1
	JE _error_exit
	MOV DWORD PTR[hFile],EAX
	INVOKE ReadFile,DWORD PTR[hFile],DWORD PTR[ProcReadAlloc],2000h,addr NumOfBytesWR,NULL
	MOV EAX,DWORD PTR[ProcReadAlloc]
	MOV ECX,DWORD PTR[EAX+3Ch]
	XOR ESI,ESI
	.if ECX > 2000h
		MOV ESI,1
	.endif
	INVOKE CloseHandle,DWORD PTR[hFile]

	.if ESI == NULL
		PUSHAD
		MOV EAX,DWORD PTR[ProcReadAlloc]
		MOV ECX,DWORD PTR[EAX+3Ch]
		LEA EAX,DWORD PTR[EAX+ECX]		;PE.base
		MOV DWORD PTR[PEBase],EAX
	
		ADD EAX,34h
		MOV EAX,DWORD PTR[EAX]
		MOV DWORD PTR[ImageBase],EAX
		MOV EAX,DWORD PTR[PEBase]
	
		MOV EBX,DWORD PTR[PEBase]
		MOVZX ECX,WORD PTR[EBX+6]
		IMUL ECX,28h
		ADD BX,WORD PTR[EBX+14h]
		ADD EBX,18h
		ADD EBX,ECX
		SUB EBX,DWORD PTR[ProcReadAlloc]
		MOV DWORD PTR[HeaderSize],EBX
		POPAD
	
		INVOKE VirtualProtectEx,DWORD PTR[EBP+8],DWORD PTR[ImageBase],DWORD PTR[HeaderSize],PAGE_EXECUTE_READWRITE,addr OldProtect
		INVOKE WriteProcessMemory,DWORD PTR[EBP+8],DWORD PTR[ImageBase],DWORD PTR[ProcReadAlloc],DWORD PTR[HeaderSize],addr NumOfBytesWR
		TEST EAX,EAX
		JE _error_exit
	.endif

 _error_exit:
	INVOKE VirtualFree,DWORD PTR[ProcReadAlloc],NULL,MEM_RELEASE;2000h

	POPAD
	RET
PastePEHeader endp
;------------------------------------------------------------------
PastePEHeaderEx proc dwHProcess:DWORD,dwLoadedImageBase:DWORD,dwFileName:DWORD
 ;
 ; Ova funkcija radi dump selektovanog procesa
 ;
 ; Parametar 1 => hProcess
 ; Parametar 2 => szFileName LPSTR / original gde?
 ;
	PUSHAD
	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV DWORD PTR[ProcReadAlloc],EAX

	INVOKE CreateFile,dwFileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	CMP EAX,-1
	JE _error_exit
	MOV DWORD PTR[hFile],EAX
	INVOKE ReadFile,DWORD PTR[hFile],DWORD PTR[ProcReadAlloc],2000h,addr NumOfBytesWR,NULL
	MOV EAX,DWORD PTR[ProcReadAlloc]
	MOV ECX,DWORD PTR[EAX+3Ch]
	XOR ESI,ESI
	.if ECX > 2000h
		MOV ESI,1
	.endif
	INVOKE CloseHandle,DWORD PTR[hFile]

	.if ESI == NULL
		PUSHAD
		MOV EAX,DWORD PTR[ProcReadAlloc]
		MOV ECX,DWORD PTR[EAX+3Ch]
		LEA EAX,DWORD PTR[EAX+ECX]		;PE.base
		MOV DWORD PTR[PEBase],EAX
	
		ADD EAX,34h
		MOV EAX,DWORD PTR[EAX]
		MOV DWORD PTR[ImageBase],EAX
		MOV EAX,DWORD PTR[PEBase]
	
		MOV EBX,DWORD PTR[PEBase]
		MOVZX ECX,WORD PTR[EBX+6]
		IMUL ECX,28h
		ADD BX,WORD PTR[EBX+14h]
		ADD EBX,18h
		ADD EBX,ECX
		SUB EBX,DWORD PTR[ProcReadAlloc]
		MOV DWORD PTR[HeaderSize],EBX
		POPAD
	
		INVOKE VirtualProtectEx,DWORD PTR[EBP+8],dwLoadedImageBase,DWORD PTR[HeaderSize],PAGE_EXECUTE_READWRITE,addr OldProtect
		INVOKE WriteProcessMemory,DWORD PTR[EBP+8],dwLoadedImageBase,DWORD PTR[ProcReadAlloc],DWORD PTR[HeaderSize],addr NumOfBytesWR
		TEST EAX,EAX
		JE _error_exit
	.endif

 _error_exit:
	INVOKE VirtualFree,DWORD PTR[ProcReadAlloc],NULL,MEM_RELEASE;2000h

	POPAD
	RET
PastePEHeaderEx endp
;------------------------------------------------------------------
IsFileDLL proc fName:DWORD
	LOCAL Return :DWORD
	LOCAL dwFileType :DWORD
	PUSHAD

	MOV Return,0
	MOV FileMapVA,0
	INVOKE RtlZeroMemory,addr ReadDataBuffer,1000h
	INVOKE SmartMapFile,fName
	INVOKE GetBinaryType,fName,addr dwFileType
	.if EAX != NULL
		MOV EAX,dwFileType
		.if EAX != SCS_32BIT_BINARY; && EAX != SCS_DOS_BINARY
			XOR EAX,EAX
			DEC EAX
		.endif
	.else
		.if FileMapVA != 0
			MOV EDI,FileMapVA
			.if WORD PTR[EDI] != "ZM"			;Check .exe/.dll!
				XOR EAX,EAX
				DEC EAX
			.endif
			.if EAX == 0
				ADD EDI,DWORD PTR[EDI+3Ch]
				INVOKE IsBadReadPtr,EDI,4
				.if EAX == NULL
					.if WORD PTR[EDI] != "EP"		;Check PE32 file!
						XOR EAX,EAX
						DEC EAX
					.endif
					.if EAX == 0
						ASSUME EDI:PTR FullPE32Header
						.if WORD PTR[EDI].Magic != 10Bh
							XOR EAX,EAX
							DEC EAX
						.endif
						ASSUME EDI:NOTHING
					.endif
				.else
					XOR EAX,EAX
					DEC EAX
				.endif
			.endif
		.else
			XOR EAX,EAX
			DEC EAX
		.endif
	.endif
	.if FileMapVA != 0 && EAX != -1
		MOV EAX,FileMapVA
		ADD EAX,3Ch
		MOV EAX,DWORD PTR[EAX]
		ADD EAX,FileMapVA
		ASSUME EAX:PTR FullPE32Header
		MOVZX EBX,WORD PTR[EAX].Characteristics
		TEST EBX,2000h
		JE __VALIDATION_NOT_A_DLL_FILE	;File is a .dll
			MOV Return,1
     __VALIDATION_NOT_A_DLL_FILE:
		ASSUME EAX:NOTHING
		INVOKE SmartUnmapFile
	.else
		.if FileMapVA != 0
			INVOKE UnmapFile
		.endif
		MOV Return,-1			;Mapping error!
	.endif

	POPAD
	MOV EAX,Return
	RET
IsFileDLL endp
;------------------------------------------------------------------
DumpProcess proc prm1:DWORD,prm2:DWORD,prm3:DWORD,prm4:DWORD
	LOCAL ReadSize :DWORD
	LOCAL ReadBuffer :DWORD
	LOCAL Return :DWORD
 ;
 ; Ova funkcija radi dump selektovanog procesa
 ;
 ; Parametar 1 => hProcess
 ; Parametar 2 => ImageBase
 ; Parametar 3 => szFileName LPSTR / dump gde?
 ; Parametar 4 => VA OEP location
 ;
	PUSHAD
	MOV Return,0
	MOV ReadSize,1000h
	MOV ReadBuffer,offset ReadDataBuffer
	MOV EAX,DWORD PTR[EBP+12]
	MOV DWORD PTR[ImageBase],EAX
 __ReadAgain:
	INVOKE ReadProcessMemory,DWORD PTR[EBP+8],DWORD PTR[EBP+12],ReadBuffer,ReadSize,addr NumOfBytesWR
	TEST EAX,EAX
	JE _error_exit
	MOV EAX,offset ReadDataBuffer
	MOV ECX,DWORD PTR[EAX+3Ch]
	.if ECX > 1000h && ReadSize == 1000h
		MOV ReadSize,ECX
		ADD ReadSize,400h
		INVOKE VirtualAlloc,NULL,ReadSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE
		MOV ReadBuffer,EAX
		JMP __ReadAgain
	.else
		.if ReadSize != 1000h
			MOV Return,-1
			MOV EAX,ReadBuffer
			MOV ECX,DWORD PTR[EAX+3Ch]
		.endif
	.endif
	LEA EAX,DWORD PTR[EAX+ECX]		;PE.base
	MOV DWORD PTR[PEBase],EAX

	XOR ECX,ECX
	MOV CX,WORD PTR[EAX+6]			;PE.SectionsNumber
	DEC ECX

	MOV EBX,028h
	IMUL EBX,ECX
	ADD BX,WORD PTR[EAX+14h]
	ADD EBX,018h+8h

	ADD EAX,EBX
	MOV ECX,DWORD PTR[EAX]
	.if ECX < DWORD PTR[EAX+8]
		MOV ECX,DWORD PTR[EAX+8]
	.endif
	MOV EDX,DWORD PTR[EAX+4]
	ADD ECX,EDX

	MOV DWORD PTR[SizeOfImage],ECX

	INVOKE VirtualAlloc,NULL,DWORD PTR[SizeOfImage],MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV DWORD PTR[ProcReadAlloc],EAX

	INVOKE VirtualQueryEx,DWORD PTR[EBP+8],DWORD PTR[ImageBase],addr MemInfo,sizeof MemInfo
	MOV EAX,DWORD PTR[MemInfo.AllocationProtect]
	MOV DWORD PTR[OldProtect],EAX
	INVOKE VirtualProtectEx,DWORD PTR[EBP+8],DWORD PTR[ImageBase],DWORD PTR[SizeOfImage],PAGE_EXECUTE_READWRITE,addr OldProtect

	INVOKE ReadProcessMemory,DWORD PTR[EBP+8],DWORD PTR[EBP+12],DWORD PTR[ProcReadAlloc],DWORD PTR[SizeOfImage],addr NumOfBytesWR

	PUSH DWORD PTR[EBP+20]
	PUSH DWORD PTR[ProcReadAlloc]
	CALL _fix_PEHeader

	INVOKE CreateFile,DWORD PTR[EBP+16],GENERIC_READ+GENERIC_WRITE,NULL,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL
	.if EAX != -1
		MOV DWORD PTR[hFile],EAX
		INVOKE WriteFile,DWORD PTR[hFile],DWORD PTR[ProcReadAlloc],DWORD PTR[SizeOfImage],addr NumOfBytesWR,NULL
		INVOKE CloseHandle,DWORD PTR[hFile]
	.endif
	.if ReadBuffer != offset ReadDataBuffer
		INVOKE VirtualFree,ReadBuffer,NULL,MEM_RELEASE;ReadSize
	.endif

 _error_exit:
	INVOKE VirtualFree,DWORD PTR[ProcReadAlloc],NULL,MEM_RELEASE;DWORD PTR[SizeOfImage]

	POPAD
	MOV EAX,Return
	RET
DumpProcess endp
;------------------------------------------------------------------
DumpProcessEx proc prm1:DWORD,prm2:DWORD,prm3:DWORD,prm4:DWORD,dwOriginalFile:DWORD
	LOCAL Return :DWORD
	LOCAL ReadBuffer :DWORD
	LOCAL stPE32Struct : PE32Struct
 ;
 ; Ova funkcija radi dump selektovanog procesa
 ;
 ; Parametar 1 => hProcess
 ; Parametar 2 => ImageBase
 ; Parametar 3 => szFileName LPSTR / dump gde?
 ; Parametar 4 => VA OEP location
 ;
	PUSHAD
	MOV Return,0
	MOV ReadBuffer,offset ReadDataBuffer
	INVOKE PastePEHeaderEx,prm1,prm2,dwOriginalFile
	INVOKE RtlZeroMemory,addr stPE32Struct,sizeof PE32Struct
	INVOKE GetPE32DataEx,dwOriginalFile,addr stPE32Struct
	LEA EAX,DWORD PTR[stPE32Struct]
	ASSUME EAX:PTR PE32Struct
;	MOV EBX,DWORD PTR[EAX].ImageBase
;	MOV DWORD PTR[ImageBase],EBX
	MOV EBX,DWORD PTR[EAX].NtSizeOfImage
	MOV DWORD PTR[SizeOfImage],EBX
	ASSUME EAX:NOTHING
	MOV EAX,DWORD PTR[EBP+12]
	MOV DWORD PTR[ImageBase],EAX

	INVOKE VirtualAlloc,NULL,DWORD PTR[SizeOfImage],MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV DWORD PTR[ProcReadAlloc],EAX

	INVOKE VirtualQueryEx,DWORD PTR[EBP+8],DWORD PTR[ImageBase],addr MemInfo,sizeof MemInfo
	MOV EAX,DWORD PTR[MemInfo.AllocationProtect]
	MOV DWORD PTR[OldProtect],EAX
	INVOKE VirtualProtectEx,DWORD PTR[EBP+8],DWORD PTR[ImageBase],DWORD PTR[SizeOfImage],PAGE_EXECUTE_READWRITE,addr OldProtect

	INVOKE FlushInstructionCache,DWORD PTR[EBP+8],DWORD PTR[EBP+12],DWORD PTR[SizeOfImage]
	INVOKE ReadProcessMemory,DWORD PTR[EBP+8],DWORD PTR[EBP+12],DWORD PTR[ProcReadAlloc],DWORD PTR[SizeOfImage],addr NumOfBytesWR

	PUSH DWORD PTR[EBP+20]
	PUSH DWORD PTR[ProcReadAlloc]
	CALL _fix_PEHeader

	INVOKE CreateFile,DWORD PTR[EBP+16],GENERIC_READ+GENERIC_WRITE,NULL,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL
	.if EAX != -1
		MOV DWORD PTR[hFile],EAX
		INVOKE WriteFile,DWORD PTR[hFile],DWORD PTR[ProcReadAlloc],DWORD PTR[SizeOfImage],addr NumOfBytesWR,NULL
		INVOKE CloseHandle,DWORD PTR[hFile]
	.endif
	.if ReadBuffer != offset ReadDataBuffer
		INVOKE VirtualFree,ReadBuffer,NULL,MEM_RELEASE;ReadSize
	.endif

 _error_exit:
	INVOKE VirtualFree,DWORD PTR[ProcReadAlloc],NULL,MEM_RELEASE;DWORD PTR[SizeOfImage]

	POPAD
	MOV EAX,Return
	RET
DumpProcessEx endp
;------------------------------------------------------------------
DumpMemory proc dwHProcess:DWORD,dwMemoryStart:DWORD,dwMemorySize:DWORD,dwFileName:DWORD
 ;
 ; Ova funkcija radi dump selektovanog procesa
 ;
 ; Parametar 1 => hProcess
 ; Parametar 2 => MemoryStart
 ; Parametar 3 => MemorySize
 ; Parametar 4 => szFileName LPSTR / dump gde?
 ;
	PUSHAD
	INVOKE VirtualAlloc,NULL,DWORD PTR[EBP+16],MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV DWORD PTR[ProcReadAlloc],EAX

	INVOKE VirtualQueryEx,DWORD PTR[EBP+8],DWORD PTR[EBP+12],addr MemInfo,sizeof MemInfo
	MOV EAX,DWORD PTR[MemInfo.AllocationProtect]
	MOV DWORD PTR[OldProtect],EAX
	INVOKE VirtualProtectEx,DWORD PTR[EBP+8],DWORD PTR[EBP+12],DWORD PTR[EBP+16],PAGE_EXECUTE_READWRITE,addr OldProtect

	INVOKE ReadProcessMemory,DWORD PTR[EBP+8],DWORD PTR[EBP+12],DWORD PTR[ProcReadAlloc],DWORD PTR[EBP+16],addr NumOfBytesWR
	.if EAX != NULL
		INVOKE CreateFile,DWORD PTR[EBP+20],GENERIC_READ+GENERIC_WRITE,NULL,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL
		.if EAX != -1
			MOV DWORD PTR[hFile],EAX
			INVOKE WriteFile,DWORD PTR[hFile],DWORD PTR[ProcReadAlloc],DWORD PTR[EBP+16],addr NumOfBytesWR,NULL
			INVOKE CloseHandle,DWORD PTR[hFile]
		.endif
	.endif
	INVOKE VirtualFree,DWORD PTR[ProcReadAlloc],NULL,MEM_RELEASE;DWORD PTR[EBP+16]

	POPAD
	RET
DumpMemory endp
;------------------------------------------------------------------
ExtractOverlay proc szFname:DWORD,szSaveFileName:DWORD
	LOCAL Return :DWORD
	LOCAL Converted :DWORD
	LOCAL fFileAligment :DWORD
	LOCAL dwReadBuffer :DWORD
	LOCAL dwFileType :DWORD
	LOCAL AlreadyUnmaped :DWORD
	PUSHAD
	MOV Return,0
	MOV FileMapVA,0
	MOV AlreadyUnmaped,0
	INVOKE MapFileR,szFname
	INVOKE GetBinaryType,szFname,addr dwFileType
	.if EAX != NULL
		MOV EAX,dwFileType
		.if EAX != SCS_32BIT_BINARY; && EAX != SCS_DOS_BINARY
			XOR EAX,EAX
			DEC EAX
		.endif
	.else
		.if FileMapVA != 0
			MOV EDI,FileMapVA
			.if WORD PTR[EDI] != "ZM"			;Check .exe/.dll!
				XOR EAX,EAX
				DEC EAX
			.endif
			.if EAX == 0
				ADD EDI,DWORD PTR[EDI+3Ch]
				INVOKE IsBadReadPtr,EDI,4
				.if EAX == NULL
					.if WORD PTR[EDI] != "EP"		;Check PE32 file!
						XOR EAX,EAX
						DEC EAX
					.endif
					.if EAX == 0
						ASSUME EDI:PTR FullPE32Header
						.if WORD PTR[EDI].Magic != 10Bh
							XOR EAX,EAX
							DEC EAX
						.endif
						ASSUME EDI:NOTHING
					.endif
				.else
					XOR EAX,EAX
					DEC EAX
				.endif
			.endif
		.else
			XOR EAX,EAX
			DEC EAX
		.endif
	.endif
	.if FileMapVA != 0 && EAX != -1
		MOV EAX,FileMapVA
		ADD EAX,3Ch
		MOV EAX,DWORD PTR[EAX]
		ADD EAX,FileMapVA
		MOV PEHeader,EAX
		MOVZX EBX,WORD PTR[EAX+6h]
		MOV NumberOfSections,EBX
		MOV EBX,DWORD PTR[EAX+3Ch]
		MOV fFileAligment,EBX
		ADD AX,WORD PTR[EAX+14h]
		ADD EAX,18h

		MOV RawSize,NULL
		MOV ECX,NumberOfSections
		MOV EDX,DWORD PTR[EAX+20]
		.while ECX > 0
			MOV EBX,RawSize
			.if DWORD PTR[EAX+20] > EDX
				MOV EDX,DWORD PTR[EAX+20]
				MOV EBX,DWORD PTR[EAX+16]
				MOV RawSize,EBX
				MOV EBX,DWORD PTR[EAX+20]
				MOV RawOffset,EBX
			.elseif DWORD PTR[EAX+20] == EDX && EBX <= DWORD PTR[EAX+16]
				MOV EDX,DWORD PTR[EAX+20]
				MOV EBX,DWORD PTR[EAX+16]
				MOV RawSize,EBX
				MOV EBX,DWORD PTR[EAX+20]
				MOV RawOffset,EBX				
			.endif
			ADD EAX,28h
			DEC ECX
		.endw
	
		XOR EAX,EAX
		ADD EAX,RawOffset
		ADD EAX,RawSize
		.if EAX < FileSize
			MOV EBX,FileSize
			SUB EBX,EAX
			ADD EAX,FileMapVA
			MOV eStart,EAX
			MOV eSize,EBX
			MOV Return,EBX	;Size of extracted file

			INVOKE CreateFile,szSaveFileName,GENERIC_WRITE,NULL,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL
			MOV hSaveFile,EAX
			.if eSize <= 1*1024*1024
				INVOKE WriteFile,hSaveFile,eStart,eSize,addr NumberOfBytesWritten,NULL
			.else
				INC AlreadyUnmaped
				MOV EAX,eStart
				SUB EAX,FileMapVA
				MOV eStart,EAX
				INVOKE UnmapFile
				INVOKE VirtualAlloc,NULL,1*1024*1024,MEM_COMMIT,PAGE_EXECUTE_READWRITE
				MOV dwReadBuffer,EAX
				INVOKE CreateFile,szFname,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
				MOV FileHWND,EAX
				MOV ESI,1*1024*1024
				.while eSize > 0
					INVOKE SetFilePointer,FileHWND,eStart,NULL,FILE_BEGIN
					INVOKE ReadFile,FileHWND,dwReadBuffer,ESI,addr NumberOfBytesWritten,NULL
					INVOKE WriteFile,hSaveFile,dwReadBuffer,ESI,addr NumberOfBytesWritten,NULL
					ADD eStart,ESI
					.if eSize > 1*1024*1024
						SUB eSize,1*1024*1024
					.else
						MOV ESI,eSize
						INVOKE SetFilePointer,FileHWND,eStart,NULL,FILE_BEGIN
						INVOKE ReadFile,FileHWND,dwReadBuffer,ESI,addr NumberOfBytesWritten,NULL
						INVOKE WriteFile,hSaveFile,dwReadBuffer,ESI,addr NumberOfBytesWritten,NULL
						MOV eSize,0
					.endif
				.endw
				INVOKE CloseHandle,FileHWND
				INVOKE VirtualFree,dwReadBuffer,NULL,MEM_RELEASE
			.endif
			INVOKE CloseHandle,hSaveFile
		.else
			MOV Return,0h	;No overlay
		.endif
		.if AlreadyUnmaped == 0
			INVOKE UnmapFile
		.endif
	.else
		.if FileMapVA != 0
			INVOKE UnmapFile
		.endif
		MOV Return,-1		;Could not map file
	.endif

	POPAD
	MOV EAX,Return
	RET
ExtractOverlay endp
;------------------------------------------------------------------
FindOverlay proc szFname:DWORD,rOVLStart:DWORD,rOVLSize:DWORD
	LOCAL Return :DWORD
	LOCAL Converted :DWORD
	LOCAL fFileAligment :DWORD
	LOCAL dwFileType :DWORD
	PUSHAD
	MOV Return,0
	MOV FileMapVA,0
	INVOKE MapFileR,szFname
	INVOKE GetBinaryType,szFname,addr dwFileType
	.if EAX != NULL
		MOV EAX,dwFileType
		.if EAX != SCS_32BIT_BINARY; && EAX != SCS_DOS_BINARY
			XOR EAX,EAX
			DEC EAX
		.endif
	.else
		.if FileMapVA != 0
			MOV EDI,FileMapVA
			.if WORD PTR[EDI] != "ZM"			;Check .exe/.dll!
				XOR EAX,EAX
				DEC EAX
			.endif
			.if EAX == 0
				ADD EDI,DWORD PTR[EDI+3Ch]
				INVOKE IsBadReadPtr,EDI,4
				.if EAX == NULL
					.if WORD PTR[EDI] != "EP"		;Check PE32 file!
						XOR EAX,EAX
						DEC EAX
					.endif
					.if EAX == 0
						ASSUME EDI:PTR FullPE32Header
						.if WORD PTR[EDI].Magic != 10Bh
							XOR EAX,EAX
							DEC EAX
						.endif
						ASSUME EDI:NOTHING
					.endif
				.else
					XOR EAX,EAX
					DEC EAX
				.endif
			.endif
		.else
			XOR EAX,EAX
			DEC EAX
		.endif
	.endif
	.if FileMapVA != 0 && EAX != -1
		MOV EAX,FileMapVA
		ADD EAX,3Ch
		MOV EAX,DWORD PTR[EAX]
		ADD EAX,FileMapVA
		MOV PEHeader,EAX
		MOVZX EBX,WORD PTR[EAX+6h]
		MOV NumberOfSections,EBX
		MOV EBX,DWORD PTR[EAX+3Ch]
		MOV fFileAligment,EBX
		ADD AX,WORD PTR[EAX+14h]
		ADD EAX,18h

		MOV RawSize,NULL
		MOV ECX,NumberOfSections
		MOV EDX,DWORD PTR[EAX+20]
		.while ECX > 0
			MOV EBX,RawSize
			.if DWORD PTR[EAX+20] > EDX
				MOV EDX,DWORD PTR[EAX+20]
				MOV EBX,DWORD PTR[EAX+16]
				MOV RawSize,EBX
				MOV EBX,DWORD PTR[EAX+20]
				MOV RawOffset,EBX
			.elseif DWORD PTR[EAX+20] == EDX && EBX <= DWORD PTR[EAX+16]
				MOV EDX,DWORD PTR[EAX+20]
				MOV EBX,DWORD PTR[EAX+16]
				MOV RawSize,EBX
				MOV EBX,DWORD PTR[EAX+20]
				MOV RawOffset,EBX
			.endif
			ADD EAX,28h
			DEC ECX
		.endw

		XOR EAX,EAX
		ADD EAX,RawOffset
		ADD EAX,RawSize
		.if EAX < FileSize
			MOV EBX,FileSize
			SUB EBX,EAX
;			ADD EAX,FileMapVA
			MOV eStart,EAX
			MOV eSize,EBX

			MOV EAX,rOVLStart
			MOV EBX,eStart
			MOV DWORD PTR[EAX],EBX

			MOV EAX,rOVLSize
			MOV EBX,eSize
			MOV DWORD PTR[EAX],EBX

			MOV Return,1	;True
		.else
			MOV Return,0h	;No overlay
		.endif
		INVOKE UnmapFile
	.else
		.if FileMapVA != 0
			INVOKE UnmapFile
		.endif
		MOV Return,-1		;Could not map file
	.endif

	POPAD
	MOV EAX,Return
	RET
FindOverlay endp
;------------------------------------------------------------------
AddOverlay proc szFname:DWORD,szOvlFName:DWORD
	LOCAL Return :DWORD
	LOCAL CopyAlloc :DWORD
	LOCAL CopySize :DWORD
	LOCAL CopyStart :DWORD
	LOCAL dwFileType :DWORD
	PUSHAD
	MOV Return,0
	MOV FileMapVA,0
	INVOKE MapFile,szOvlFName

	.if FileMapVA != 0
		MOV EAX,FileSize
		MOV CopySize,EAX
		INVOKE VirtualAlloc,NULL,CopySize,MEM_COMMIT,PAGE_EXECUTE_READWRITE
		MOV CopyAlloc,EAX
		INVOKE RtlMoveMemory,CopyAlloc,FileMapVA,CopySize
		INVOKE UnmapFile

               	INVOKE MapFile,szFname
		MOV EAX,FileSize
               	MOV CopyStart,EAX
		INVOKE UnmapFile

		INVOKE ResizeMapFile,szFname,CopySize
		MOV EAX,FileMapVA
		ADD CopyStart,EAX
		INVOKE RtlMoveMemory,CopyStart,CopyAlloc,CopySize
		INVOKE UnmapFile

		INVOKE VirtualFree,CopyAlloc,NULL,MEM_RELEASE;CopySize
		MOV Return,1		;Success
	.else
		MOV Return,0		;Could not map file
	.endif

	POPAD
	MOV EAX,Return
	RET
AddOverlay endp
;------------------------------------------------------------------
CopyOverlay proc inFile:DWORD,outFile:DWORD
	LOCAL Return :DWORD
	PUSHAD

	INVOKE RtlZeroMemory,addr ReadDataBuffer,1000h
	INVOKE GetTempPath,1000h,addr ReadDataBuffer
	INVOKE GetTempFileName,addr ReadDataBuffer,addr szTMP,NULL,addr ReadDataBuffer
	
	MOV Return,0					;Error!
	INVOKE ExtractOverlay,inFile,addr ReadDataBuffer
	.if EAX != -1 && EAX != 0
		INVOKE AddOverlay,outFile,addr ReadDataBuffer
		.if EAX != 0
			MOV Return,1			;Success!
		.endif
	.elseif EAX == NULL
		MOV Return,2				;No overlay present!
	.endif
	INVOKE DeleteFile,addr ReadDataBuffer

	POPAD
	MOV EAX,Return
	RET
CopyOverlay endp
;------------------------------------------------------------------
GetPE32Data proc fName:DWORD,WhichSection:DWORD,WhichData:DWORD
	LOCAL Return :DWORD
	LOCAL dwFileType :DWORD
;-----------
; WhichData:
;
; 00 - PE32 offset
; 01 - ImageBase
; 02 - OriginalEntryPoint
; 03 - NtSizeOfImage
; 04 - NtSizeOfHeaders
; 05 - SizeOfOptionalHeaders
; 06 - SectionAligment
; 07 - ImportTableAddress
; 08 - ImportTableSize
; 09 - ResourceTableAddress
; 10 - ResourceTableSize
; 11 - ExportTableAddress
; 12 - ExportTableSize
; 13 - TLSTableAddress
; 14 - TLSTableSize
; 15 - RelocationTableAddress
; 16 - RelocationTableSize
; 17 - TimeDateStamp
; 18 - SectionNumber
; 19 - CheckSum
; 20 - Section.Name
; 21 - Section.VirtualOffset
; 22 - Section.VirtualSize
; 23 - Section.RawOffset
; 24 - Section.RawSize
; 25 - Section.Flags
;
	PUSHAD

	MOV FileMapVA,0
	INVOKE RtlZeroMemory,addr ReadDataBuffer,1000h
	INVOKE SmartMapFile,fName
	INVOKE GetBinaryType,fName,addr dwFileType
	.if EAX != NULL
		MOV EAX,dwFileType
		.if EAX != SCS_32BIT_BINARY; && EAX != SCS_DOS_BINARY
			XOR EAX,EAX
			DEC EAX
		.endif
	.else
		.if FileMapVA != 0
			MOV EDI,FileMapVA
			.if WORD PTR[EDI] != "ZM"			;Check .exe/.dll!
				XOR EAX,EAX
				DEC EAX
			.endif
			.if EAX == 0
				ADD EDI,DWORD PTR[EDI+3Ch]
				INVOKE IsBadReadPtr,EDI,4
				.if EAX == NULL
					.if WORD PTR[EDI] != "EP"		;Check PE32 file!
						XOR EAX,EAX
						DEC EAX
					.endif
					.if EAX == 0
						ASSUME EDI:PTR FullPE32Header
						.if WORD PTR[EDI].Magic != 10Bh
							XOR EAX,EAX
							DEC EAX
						.endif
						ASSUME EDI:NOTHING
					.endif
				.else
					XOR EAX,EAX
					DEC EAX
				.endif
			.endif
		.else
			XOR EAX,EAX
			DEC EAX
		.endif
	.endif
	.if FileMapVA != 0 && EAX != -1
		.if WhichData >= 0
			MOV EAX,FileMapVA
			ADD EAX,3Ch
			MOV EAX,DWORD PTR[EAX]
			ADD EAX,FileMapVA
			.if WhichData == 0
				MOV EDI,EAX
				SUB EDI,FileMapVA
			.elseif WhichData == 1
				MOV EDI,DWORD PTR[EAX+034h]
			.elseif WhichData == 2
				MOV EDI,DWORD PTR[EAX+028h]
			.elseif WhichData == 3
				MOV EDI,DWORD PTR[EAX+050h]
			.elseif WhichData == 4
				MOV EDI,DWORD PTR[EAX+054h]
			.elseif WhichData == 5
				MOVZX EDI,WORD PTR[EAX+014h]
			.elseif WhichData == 6
				MOV EDI,DWORD PTR[EAX+038h]
			.elseif WhichData == 7
				MOV EDI,DWORD PTR[EAX+080h]
			.elseif WhichData == 8
				MOV EDI,DWORD PTR[EAX+084h]
			.elseif WhichData == 9
				MOV EDI,DWORD PTR[EAX+088h]
			.elseif WhichData == 10
				MOV EDI,DWORD PTR[EAX+08Ch]
			.elseif WhichData == 11
				MOV EDI,DWORD PTR[EAX+078h]
			.elseif WhichData == 12
				MOV EDI,DWORD PTR[EAX+07Ch]
			.elseif WhichData == 13
				MOV EDI,DWORD PTR[EAX+0C0h]
			.elseif WhichData == 14
				MOV EDI,DWORD PTR[EAX+0C4h]
			.elseif WhichData == 15
				MOV EDI,DWORD PTR[EAX+0A0h]
			.elseif WhichData == 16
				MOV EDI,DWORD PTR[EAX+0A4h]
			.elseif WhichData == 17
				MOV EDI,DWORD PTR[EAX+008h]
			.elseif WhichData == 18
				MOVZX EDI,WORD PTR[EAX+006h]
			.elseif WhichData == 19
				MOV EDI,DWORD PTR[EAX+058h]
			.elseif WhichData == 20
				MOVZX EDI,WORD PTR[EAX+006h]
				.if WhichSection <= EDI
					ADD AX,WORD PTR[EAX+14h]
					ADD EAX,18h

					MOV EDI,28h
					IMUL EDI,WhichSection
					LEA EDI,DWORD PTR[EDI+EAX]
					PUSHAD
					INVOKE RtlMoveMemory,addr ReadDataBuffer,EDI,8
					POPAD
					MOV EDI,offset ReadDataBuffer
				.else
					MOV EDI,-1
				.endif
			.elseif WhichData == 21
				MOVZX EDI,WORD PTR[EAX+006h]
				.if WhichSection <= EDI
					ADD AX,WORD PTR[EAX+14h]
					ADD EAX,18h

					MOV EDI,28h
					IMUL EDI,WhichSection
					LEA EDI,DWORD PTR[EDI+EAX+12]
					MOV EDI,DWORD PTR[EDI]
				.else
					MOV EDI,-1
				.endif
			.elseif WhichData == 22
				MOVZX EDI,WORD PTR[EAX+006h]
				.if WhichSection <= EDI
					ADD AX,WORD PTR[EAX+14h]
					ADD EAX,18h

					MOV EDI,28h
					IMUL EDI,WhichSection
					LEA EDI,DWORD PTR[EDI+EAX+8]
					MOV EDI,DWORD PTR[EDI]
				.else
					MOV EDI,-1
				.endif
			.elseif WhichData == 23
				MOVZX EDI,WORD PTR[EAX+006h]
				.if WhichSection <= EDI
					ADD AX,WORD PTR[EAX+14h]
					ADD EAX,18h

					MOV EDI,28h
					IMUL EDI,WhichSection
					LEA EDI,DWORD PTR[EDI+EAX+20]
					MOV EDI,DWORD PTR[EDI]
				.else
					MOV EDI,-1
				.endif
			.elseif WhichData == 24
				MOVZX EDI,WORD PTR[EAX+006h]
				.if WhichSection <= EDI
					ADD AX,WORD PTR[EAX+14h]
					ADD EAX,18h

					MOV EDI,28h
					IMUL EDI,WhichSection
					LEA EDI,DWORD PTR[EDI+EAX+16]
					MOV EDI,DWORD PTR[EDI]
				.else
					MOV EDI,-1
				.endif
			.elseif WhichData == 25
				MOVZX EDI,WORD PTR[EAX+006h]
				.if WhichSection <= EDI
					ADD AX,WORD PTR[EAX+14h]
					ADD EAX,18h

					MOV EDI,28h
					IMUL EDI,WhichSection
					LEA EDI,DWORD PTR[EDI+EAX+36]
					MOV EDI,DWORD PTR[EDI]
				.else
					MOV EDI,-1
				.endif
			.endif
			MOV Return,EDI
		.endif
		INVOKE SmartUnmapFile
	.else
		.if FileMapVA != 0
			INVOKE UnmapFile
		.endif
		MOV Return,-1			;Mapping error!
	.endif

	POPAD
	MOV EAX,Return
	RET
GetPE32Data endp
;------------------------------------------------------------------
GetPE32DataFromMappedFile proc fMap:DWORD,WhichSection:DWORD,WhichData:DWORD
	LOCAL Return :DWORD
;-----------
; WhichData:
;
; 00 - PE32 offset
; 01 - ImageBase
; 02 - OriginalEntryPoint
; 03 - NtSizeOfImage
; 04 - NtSizeOfHeaders
; 05 - SizeOfOptionalHeaders
; 06 - SectionAligment
; 07 - ImportTableAddress
; 08 - ImportTableSize
; 09 - ResourceTableAddress
; 10 - ResourceTableSize
; 11 - ExportTableAddress
; 12 - ExportTableSize
; 13 - TLSTableAddress
; 14 - TLSTableSize
; 15 - RelocationTableAddress
; 16 - RelocationTableSize
; 17 - TimeDateStamp
; 18 - SectionNumber
; 19 - CheckSum
; 20 - Section.Name
; 21 - Section.VirtualOffset
; 22 - Section.VirtualSize
; 23 - Section.RawOffset
; 24 - Section.RawSize
; 25 - Section.Flags
;
	PUSHAD

	MOV EAX,fMap
	MOV FileMapVA,EAX
	INVOKE RtlZeroMemory,addr ReadDataBuffer,1000h
	.if FileMapVA != 0 && EAX != -1
		.if WhichData >= 0
			MOV EAX,FileMapVA
			ADD EAX,3Ch
			MOV EAX,DWORD PTR[EAX]
			ADD EAX,FileMapVA
			.if WhichData == 0
				MOV EDI,EAX
				SUB EDI,FileMapVA
			.elseif WhichData == 1
				MOV EDI,DWORD PTR[EAX+034h]
			.elseif WhichData == 2
				MOV EDI,DWORD PTR[EAX+028h]
			.elseif WhichData == 3
				MOV EDI,DWORD PTR[EAX+050h]
			.elseif WhichData == 4
				MOV EDI,DWORD PTR[EAX+054h]
			.elseif WhichData == 5
				MOVZX EDI,WORD PTR[EAX+014h]
			.elseif WhichData == 6
				MOV EDI,DWORD PTR[EAX+038h]
			.elseif WhichData == 7
				MOV EDI,DWORD PTR[EAX+080h]
			.elseif WhichData == 8
				MOV EDI,DWORD PTR[EAX+084h]
			.elseif WhichData == 9
				MOV EDI,DWORD PTR[EAX+088h]
			.elseif WhichData == 10
				MOV EDI,DWORD PTR[EAX+08Ch]
			.elseif WhichData == 11
				MOV EDI,DWORD PTR[EAX+078h]
			.elseif WhichData == 12
				MOV EDI,DWORD PTR[EAX+07Ch]
			.elseif WhichData == 13
				MOV EDI,DWORD PTR[EAX+0C0h]
			.elseif WhichData == 14
				MOV EDI,DWORD PTR[EAX+0C4h]
			.elseif WhichData == 15
				MOV EDI,DWORD PTR[EAX+0A0h]
			.elseif WhichData == 16
				MOV EDI,DWORD PTR[EAX+0A4h]
			.elseif WhichData == 17
				MOV EDI,DWORD PTR[EAX+008h]
			.elseif WhichData == 18
				MOVZX EDI,WORD PTR[EAX+006h]
			.elseif WhichData == 19
				MOV EDI,DWORD PTR[EAX+058h]
			.elseif WhichData == 20
				MOVZX EDI,WORD PTR[EAX+006h]
				.if WhichSection <= EDI
					ADD AX,WORD PTR[EAX+14h]
					ADD EAX,18h

					MOV EDI,28h
					IMUL EDI,WhichSection
					LEA EDI,DWORD PTR[EDI+EAX]
					PUSHAD
					INVOKE RtlMoveMemory,addr ReadDataBuffer,EDI,8
					POPAD
					MOV EDI,offset ReadDataBuffer
				.else
					MOV EDI,-1
				.endif
			.elseif WhichData == 21
				MOVZX EDI,WORD PTR[EAX+006h]
				.if WhichSection <= EDI
					ADD AX,WORD PTR[EAX+14h]
					ADD EAX,18h

					MOV EDI,28h
					IMUL EDI,WhichSection
					LEA EDI,DWORD PTR[EDI+EAX+12]
					MOV EDI,DWORD PTR[EDI]
				.else
					MOV EDI,-1
				.endif
			.elseif WhichData == 22
				MOVZX EDI,WORD PTR[EAX+006h]
				.if WhichSection <= EDI
					ADD AX,WORD PTR[EAX+14h]
					ADD EAX,18h

					MOV EDI,28h
					IMUL EDI,WhichSection
					LEA EDI,DWORD PTR[EDI+EAX+8]
					MOV EDI,DWORD PTR[EDI]
				.else
					MOV EDI,-1
				.endif
			.elseif WhichData == 23
				MOVZX EDI,WORD PTR[EAX+006h]
				.if WhichSection <= EDI
					ADD AX,WORD PTR[EAX+14h]
					ADD EAX,18h

					MOV EDI,28h
					IMUL EDI,WhichSection
					LEA EDI,DWORD PTR[EDI+EAX+20]
					MOV EDI,DWORD PTR[EDI]
				.else
					MOV EDI,-1
				.endif
			.elseif WhichData == 24
				MOVZX EDI,WORD PTR[EAX+006h]
				.if WhichSection <= EDI
					ADD AX,WORD PTR[EAX+14h]
					ADD EAX,18h

					MOV EDI,28h
					IMUL EDI,WhichSection
					LEA EDI,DWORD PTR[EDI+EAX+16]
					MOV EDI,DWORD PTR[EDI]
				.else
					MOV EDI,-1
				.endif
			.elseif WhichData == 25
				MOVZX EDI,WORD PTR[EAX+006h]
				.if WhichSection <= EDI
					ADD AX,WORD PTR[EAX+14h]
					ADD EAX,18h

					MOV EDI,28h
					IMUL EDI,WhichSection
					LEA EDI,DWORD PTR[EDI+EAX+36]
					MOV EDI,DWORD PTR[EDI]
				.else
					MOV EDI,-1
				.endif
			.endif
			MOV Return,EDI
		.endif
	.else
		MOV Return,-1			;Mapping error!
	.endif

	POPAD
	MOV EAX,Return
	RET
GetPE32DataFromMappedFile endp
;------------------------------------------------------------------
GetPE32DataEx proc fName:DWORD,dwPE32Struct:DWORD
	LOCAL Return :DWORD
	LOCAL dwFileType :DWORD
	PUSHAD

	MOV FileMapVA,0
	INVOKE RtlZeroMemory,addr ReadDataBuffer,1000h
	INVOKE SmartMapFile,fName
	INVOKE GetBinaryType,fName,addr dwFileType
	.if EAX != NULL
		MOV EAX,dwFileType
		.if EAX != SCS_32BIT_BINARY; && EAX != SCS_DOS_BINARY
			XOR EAX,EAX
			DEC EAX
		.endif
	.else
		.if FileMapVA != 0
			MOV EDI,FileMapVA
			.if WORD PTR[EDI] != "ZM"			;Check .exe/.dll!
				XOR EAX,EAX
				DEC EAX
			.endif
			.if EAX == 0
				ADD EDI,DWORD PTR[EDI+3Ch]
				INVOKE IsBadReadPtr,EDI,4
				.if EAX == NULL
					.if WORD PTR[EDI] != "EP"		;Check PE32 file!
						XOR EAX,EAX
						DEC EAX
					.endif
					.if EAX == 0
						ASSUME EDI:PTR FullPE32Header
						.if WORD PTR[EDI].Magic != 10Bh
							XOR EAX,EAX
							DEC EAX
						.endif
						ASSUME EDI:NOTHING
					.endif
				.else
					XOR EAX,EAX
					DEC EAX
				.endif
			.endif
		.else
			XOR EAX,EAX
			DEC EAX
		.endif
	.endif
	.if FileMapVA != 0 && EAX != -1
		.if dwPE32Struct != 0
			MOV EAX,FileMapVA
			ADD EAX,3Ch
			MOV EAX,DWORD PTR[EAX]
			ADD EAX,FileMapVA
				MOV ESI,dwPE32Struct
				MOV EDI,EAX
				SUB EDI,FileMapVA
				MOV DWORD PTR[ESI],EDI
				MOV EDI,DWORD PTR[EAX+034h]
				MOV DWORD PTR[ESI+4],EDI
				MOV EDI,DWORD PTR[EAX+028h]
				MOV DWORD PTR[ESI+8],EDI
				MOV EDI,DWORD PTR[EAX+050h]
				MOV DWORD PTR[ESI+12],EDI
				MOV EDI,DWORD PTR[EAX+054h]
				MOV DWORD PTR[ESI+16],EDI
				MOVZX EDI,WORD PTR[EAX+014h]
				MOV DWORD PTR[ESI+20],EDI
				MOV EDI,DWORD PTR[EAX+038h]
				MOV DWORD PTR[ESI+24],EDI
				MOV EDI,DWORD PTR[EAX+080h]
				MOV DWORD PTR[ESI+28],EDI
				MOV EDI,DWORD PTR[EAX+084h]
				MOV DWORD PTR[ESI+32],EDI
				MOV EDI,DWORD PTR[EAX+088h]
				MOV DWORD PTR[ESI+36],EDI
				MOV EDI,DWORD PTR[EAX+08Ch]
				MOV DWORD PTR[ESI+40],EDI
				MOV EDI,DWORD PTR[EAX+078h]
				MOV DWORD PTR[ESI+44],EDI
				MOV EDI,DWORD PTR[EAX+07Ch]
				MOV DWORD PTR[ESI+48],EDI
				MOV EDI,DWORD PTR[EAX+0C0h]
				MOV DWORD PTR[ESI+52],EDI
				MOV EDI,DWORD PTR[EAX+0C4h]
				MOV DWORD PTR[ESI+56],EDI
				MOV EDI,DWORD PTR[EAX+0A0h]
				MOV DWORD PTR[ESI+60],EDI
				MOV EDI,DWORD PTR[EAX+0A4h]
				MOV DWORD PTR[ESI+64],EDI
				MOV EDI,DWORD PTR[EAX+008h]
				MOV DWORD PTR[ESI+68],EDI
				MOVZX EDI,WORD PTR[EAX+006h]
				MOV DWORD PTR[ESI+72],EDI
				MOV EDI,DWORD PTR[EAX+058h]
				MOV DWORD PTR[ESI+76],EDI
			MOV Return,1
		.endif
		INVOKE SmartUnmapFile
	.else
		.if FileMapVA != 0
			INVOKE UnmapFile
		.endif
		MOV Return,-1			;Mapping error!
	.endif

	POPAD
	MOV EAX,Return
	RET
GetPE32DataEx endp
;------------------------------------------------------------------
GetPE32DataFromMappedFileEx proc fMap:DWORD,dwPE32Struct:DWORD
	LOCAL Return :DWORD
	PUSHAD

	MOV EAX,fMap
	MOV FileMapVA,EAX
	INVOKE RtlZeroMemory,addr ReadDataBuffer,1000h
	.if FileMapVA != 0 && EAX != -1
		.if dwPE32Struct != 0
			MOV EAX,FileMapVA
			ADD EAX,3Ch
			MOV EAX,DWORD PTR[EAX]
			ADD EAX,FileMapVA
				MOV ESI,dwPE32Struct
				MOV EDI,EAX
				SUB EDI,FileMapVA
				MOV DWORD PTR[ESI],EDI
				MOV EDI,DWORD PTR[EAX+034h]
				MOV DWORD PTR[ESI+4],EDI
				MOV EDI,DWORD PTR[EAX+028h]
				MOV DWORD PTR[ESI+8],EDI
				MOV EDI,DWORD PTR[EAX+050h]
				MOV DWORD PTR[ESI+12],EDI
				MOV EDI,DWORD PTR[EAX+054h]
				MOV DWORD PTR[ESI+16],EDI
				MOVZX EDI,WORD PTR[EAX+014h]
				MOV DWORD PTR[ESI+20],EDI
				MOV EDI,DWORD PTR[EAX+038h]
				MOV DWORD PTR[ESI+24],EDI
				MOV EDI,DWORD PTR[EAX+080h]
				MOV DWORD PTR[ESI+28],EDI
				MOV EDI,DWORD PTR[EAX+084h]
				MOV DWORD PTR[ESI+32],EDI
				MOV EDI,DWORD PTR[EAX+088h]
				MOV DWORD PTR[ESI+36],EDI
				MOV EDI,DWORD PTR[EAX+08Ch]
				MOV DWORD PTR[ESI+40],EDI
				MOV EDI,DWORD PTR[EAX+078h]
				MOV DWORD PTR[ESI+44],EDI
				MOV EDI,DWORD PTR[EAX+07Ch]
				MOV DWORD PTR[ESI+48],EDI
				MOV EDI,DWORD PTR[EAX+0C0h]
				MOV DWORD PTR[ESI+52],EDI
				MOV EDI,DWORD PTR[EAX+0C4h]
				MOV DWORD PTR[ESI+56],EDI
				MOV EDI,DWORD PTR[EAX+0A0h]
				MOV DWORD PTR[ESI+60],EDI
				MOV EDI,DWORD PTR[EAX+0A4h]
				MOV DWORD PTR[ESI+64],EDI
				MOV EDI,DWORD PTR[EAX+008h]
				MOV DWORD PTR[ESI+68],EDI
				MOVZX EDI,WORD PTR[EAX+006h]
				MOV DWORD PTR[ESI+72],EDI
				MOV EDI,DWORD PTR[EAX+058h]
				MOV DWORD PTR[ESI+76],EDI
			MOV Return,1
		.endif
	.else
		MOV Return,-1			;Mapping error!
	.endif

	POPAD
	MOV EAX,Return
	RET
GetPE32DataFromMappedFileEx endp
;------------------------------------------------------------------
AddNewSection proc fName:DWORD,sectionName:DWORD,sectionSize:DWORD
	LOCAL Converted :DWORD
	LOCAL FileAlignment :DWORD
	LOCAL SectionAlignment :DWORD
	LOCAL dwFileType :DWORD
	PUSHAD
 ; 
 ; Konverzija
 ;
	MOV Converted,0
	MOV FileMapVA,0
	
	INVOKE MapFile,fName
	INVOKE GetBinaryType,fName,addr dwFileType
	.if EAX != NULL
		MOV EAX,dwFileType
		.if EAX != SCS_32BIT_BINARY; && EAX != SCS_DOS_BINARY
			XOR EAX,EAX
			DEC EAX
		.endif
	.else
		.if FileMapVA != 0
			MOV EDI,FileMapVA
			.if WORD PTR[EDI] != "ZM"			;Check .exe/.dll!
				XOR EAX,EAX
				DEC EAX
			.endif
			.if EAX == 0
				ADD EDI,DWORD PTR[EDI+3Ch]
				INVOKE IsBadReadPtr,EDI,4
				.if EAX == NULL
					.if WORD PTR[EDI] != "EP"		;Check PE32 file!
						XOR EAX,EAX
						DEC EAX
					.endif
					.if EAX == 0
						ASSUME EDI:PTR FullPE32Header
						.if WORD PTR[EDI].Magic != 10Bh
							XOR EAX,EAX
							DEC EAX
						.endif
						ASSUME EDI:NOTHING
					.endif
				.else
					XOR EAX,EAX
					DEC EAX
				.endif
			.endif
		.else
			XOR EAX,EAX
			DEC EAX
		.endif
	.endif
	.if FileMapVA != 0 && EAX != -1
		MOV EAX,FileMapVA
		ADD EAX,DWORD PTR[EAX+3Ch]
		ASSUME EAX:PTR FullPE32Header
		MOV EDX,DWORD PTR[EAX].SectionAlignment
		MOV SectionAlignment,EDX
		MOV EDX,DWORD PTR[EAX].FileAlignment
		MOV FileAlignment,EDX
		ASSUME EAX:NOTHING
		INVOKE UnmapFile

		MOV EAX,sectionSize
		CDQ
		MOV ECX,FileAlignment
		DIV ECX
		IMUL EAX,FileAlignment
		.if EAX < sectionSize
			ADD EAX,FileAlignment
		.endif
		MOV sectionSize,EAX
	.else
		MOV EAX,sectionSize
	.endif

	INVOKE ResizeMapFile,fName,EAX
	.if FileMapVA != 0
		MOV EAX,FileMapVA			; Parametar 1 = FileMapVA
		MOV EDX,sectionSize			; Parametar 2 = Velicina nove sekcije
	 ;
	 ; elfa_new
	 ;
		MOV ECX,DWORD PTR[EAX+3Ch]
	 ;
	 ; PEHeader
	 ;
		LEA ECX,DWORD PTR[EAX+ECX]
		MOV EAX,ECX
	 ;
	 ; NumberOfSections
	 ;
		XOR ECX,ECX
		MOV CX,WORD PTR[EAX+6]
		INC WORD PTR[EAX+6]
	 ;
	 ; Section Tabela
	 ;
		PUSH EAX
		ADD AX,WORD PTR[EAX+14h]
		ADD EAX,018h
		MOV EBX,28h
		IMUL EBX,ECX
		MOV ECX,EAX
		ADD ECX,EBX
	
		PUSHAD
		INVOKE RtlZeroMemory,ECX,28h
		POPAD
	
		PUSHAD
		MOV EAX,sectionName
		XOR EDX,EDX
		.while EDX < 8
			MOV BL,BYTE PTR[EAX]
			MOV BYTE PTR[ECX],BL
			INC EAX
			INC ECX
			INC EDX
		.endw
		POPAD

		MOV DWORD PTR[ECX+8],EDX
		MOV EBX,DWORD PTR[ECX-20h]
		MOV EAX,DWORD PTR[ECX-1Ch]
		ADD EBX,EAX
		MOV EDI,EBX
	
		PUSHAD				;Racunamo novi VO
		MOV EAX,EBX
		CDQ
		MOV ECX,SectionAlignment
		DIV ECX
		IMUL EAX,SectionAlignment
		.if EDI > EAX
			ADD EAX,SectionAlignment
		.endif
		MOV DWORD PTR[Converted],EAX
		POPAD
		MOV EBX,DWORD PTR[Converted]
	
		POP EAX
		MOV DWORD PTR[ECX+12],EBX
		MOV DWORD PTR[ECX+16],EDX
		PUSH EBX
		MOV EBX,oldFileSize
		MOV DWORD PTR[ECX+20],EBX
		POP EBX
		MOV DWORD PTR[ECX+24h],0E0000040h
		MOV DWORD PTR[Converted],EBX

		MOV ECX,EBX
		ADD ECX,EDX
		MOV DWORD PTR[EAX+50h],ECX
	
		INVOKE UnmapFile
	.else
		.if FileMapVA != 0
			INVOKE UnmapFile
		.endif
	.endif

	POPAD
	MOV EAX,DWORD PTR[Converted]
	RET
AddNewSection endp
;------------------------------------------------------------------
DeleteLastSection proc fName:DWORD
	LOCAL SecRawOffset:DWORD
	LOCAL originalFileSize :DWORD
	LOCAL newFileSize :DWORD
	LOCAL NewSizeOfImage :DWORD
	LOCAL dwFileType :DWORD
	LOCAL Return :DWORD
	PUSHAD

	MOV Return,FALSE
	INVOKE GetBinaryType,fName,addr dwFileType
	.if EAX != NULL
		MOV EAX,dwFileType
		.if EAX != SCS_32BIT_BINARY; && EAX != SCS_DOS_BINARY
			XOR EAX,EAX
			DEC EAX
		.endif
	.else
		INVOKE MapFileR,fName
		.if FileMapVA != 0
			MOV EDI,FileMapVA
			.if WORD PTR[EDI] != "ZM"			;Check .exe/.dll!
				XOR EAX,EAX
				DEC EAX
			.endif
			.if EAX == 0
				ADD EDI,DWORD PTR[EDI+3Ch]
				INVOKE IsBadReadPtr,EDI,4
				.if EAX == NULL
					.if WORD PTR[EDI] != "EP"		;Check PE32 file!
						XOR EAX,EAX
						DEC EAX
					.endif
					.if EAX == 0
						ASSUME EDI:PTR FullPE32Header
						.if WORD PTR[EDI].Magic != 10Bh
							XOR EAX,EAX
							DEC EAX
						.endif
						ASSUME EDI:NOTHING
					.endif
				.else
					XOR EAX,EAX
					DEC EAX
				.endif
			.endif
		.else
			XOR EAX,EAX
			DEC EAX
		.endif
		INVOKE UnmapFile
	.endif
	.if EAX != -1
		INVOKE RtlZeroMemory,addr PE32Structure,sizeof PE32Struct
		INVOKE GetPE32DataEx,fName,addr PE32Structure
		.if EAX != -1
			MOV ESI,offset PE32Structure
			ASSUME ESI:PTR PE32Struct
			DEC DWORD PTR[ESI].SectionNumber
		
			PUSH 23
			PUSH DWORD PTR[ESI].SectionNumber
			PUSH fName
			CALL GetPE32Data
			MOV SecRawOffset,EAX
			
			DEC DWORD PTR[ESI].SectionNumber
		
			PUSH 21
			PUSH DWORD PTR[ESI].SectionNumber
			PUSH fName
			CALL GetPE32Data
			MOV NewSizeOfImage,EAX
			PUSH 22
			PUSH DWORD PTR[ESI].SectionNumber
			PUSH fName
			CALL GetPE32Data
			ADD NewSizeOfImage,EAX
			
			INC DWORD PTR[ESI].SectionNumber
		
			INVOKE MapFile,fName
			.if FileMapVA != NULL
				MOV EAX,FileSize
				MOV originalFileSize,EAX
				INVOKE UnmapFile
				
				MOV EAX,originalFileSize
				SUB EAX,SecRawOffset
				NEG EAX
				MOV newFileSize,EAX
			
				INVOKE ResizeMapFile,fName,newFileSize
				
				MOV EAX,FileMapVA
				ADD EAX,DWORD PTR[EAX+3Ch]
				MOV ECX,NewSizeOfImage
				MOV DWORD PTR[EAX+50h],ECX			;SizeOfImage
				MOV ECX,DWORD PTR[ESI].SectionNumber
				MOV DWORD PTR[EAX+06h],ECX			;New Section number
			
				INVOKE UnmapFile
				MOV Return,TRUE
			.else
				MOV Return,FALSE
			.endif
		.endif
		ASSUME ESI:NOTHING
	.endif

	POPAD
	MOV EAX,Return
	RET
DeleteLastSection endp
;------------------------------------------------------------------
MakeAllSectionsRWE proc fName:DWORD
	LOCAL Converted :DWORD
	LOCAL dwFileType :DWORD

	PUSHAD
	MOV Converted,0
	MOV FileMapVA,0
	INVOKE MapFile,fName
	INVOKE GetBinaryType,fName,addr dwFileType
	.if EAX != NULL
		MOV EAX,dwFileType
		.if EAX != SCS_32BIT_BINARY; && EAX != SCS_DOS_BINARY
			XOR EAX,EAX
			DEC EAX
		.endif
	.else
		.if FileMapVA != 0
			MOV EDI,FileMapVA
			.if WORD PTR[EDI] != "ZM"			;Check .exe/.dll!
				XOR EAX,EAX
				DEC EAX
			.endif
			.if EAX == 0
				ADD EDI,DWORD PTR[EDI+3Ch]
				INVOKE IsBadReadPtr,EDI,4
				.if EAX == NULL
					.if WORD PTR[EDI] != "EP"		;Check PE32 file!
						XOR EAX,EAX
						DEC EAX
					.endif
					.if EAX == 0
						ASSUME EDI:PTR FullPE32Header
						.if WORD PTR[EDI].Magic != 10Bh
							XOR EAX,EAX
							DEC EAX
						.endif
						ASSUME EDI:NOTHING
					.endif
				.else
					XOR EAX,EAX
					DEC EAX
				.endif
			.endif
		.else
			XOR EAX,EAX
			DEC EAX
		.endif
	.endif
	.if FileMapVA != 0 && EAX != -1
		MOV EAX,FileMapVA		; Parametar 1 = FileMapVA
	 ;
	 ; elfa_new
	 ;
		MOV ECX,DWORD PTR[EAX+3Ch]
	 ;
	 ; PEHeader
	 ;
		LEA ECX,DWORD PTR[EAX+ECX]
		MOV EAX,ECX
	 ;
	 ; NumberOfSections
	 ;
		XOR ECX,ECX
		MOV CX,WORD PTR[EAX+6]
	 ;
	 ; Section Tabela
	 ;
		ADD AX,WORD PTR[EAX+14h]
		ADD EAX,018h
		.while ECX > 0
			MOV DWORD PTR[EAX+24h],0E0000020h
			ADD EAX,28h
			DEC ECX
		.endw
		INVOKE UnmapFile
		MOV Converted,1
	.else
		.if FileMapVA != 0
			INVOKE UnmapFile
		.endif
	.endif

	POPAD
	MOV EAX,DWORD PTR[Converted]
	RET
MakeAllSectionsRWE endp
;------------------------------------------------------------------
ConvertVAtoFileOffset proc fMap:DWORD,Address:DWORD,retnType:DWORD
	LOCAL Converted :DWORD
	LOCAL fImageBase :DWORD
	LOCAL FsRawOffset :DWORD
	LOCAL fHeaderBase :DWORD
	LOCAL FileAligment :DWORD
	LOCAL SizeOfHeaders :DWORD
	LOCAL fNumberOfSections :DWORD
	PUSHAD
 ;
 ; Conversion
 ; retnType - 0 / Returns file offset
 ; retnType - 1 / Returns + FileMapVA
 ;
	MOV EAX,fMap			; Parametar 1 = FileMapVA
	MOV EBX,Address			; Parametar 2 = Address to be converted
 ;
 ; elfa_new
 ;
	MOV ECX,DWORD PTR[EAX+3Ch]
	MOV fHeaderBase,ECX
 ;
 ; PEHeader
 ;
	LEA ECX,DWORD PTR[EAX+ECX]
	MOV EAX,DWORD PTR[ECX+34h]	;Auto ImageBase
	MOV fImageBase,EAX
	SUB EBX,DWORD PTR[ECX+34h]	;Auto ImageBase
	MOV EAX,DWORD PTR[ECX+3Ch]	;Auto File aligment
	MOV FileAligment,EAX
	MOV EAX,DWORD PTR[ECX+54h]	;Auto SizeOfHeaders
	MOV SizeOfHeaders,EAX
	MOV EAX,ECX
 ;
 ; NumberOfSections
 ;
	XOR ECX,ECX
	MOV CX,WORD PTR[EAX+6]
	MOV fNumberOfSections,ECX
 ;
 ; Section table
 ;
	ADD AX,WORD PTR[EAX+14h]
	ADD EAX,018h
	MOV EDX,DWORD PTR[EAX+20]
	MOV FsRawOffset,EDX
	.while ECX > 0
		MOV EDX,DWORD PTR[EAX+8]
		.if EDX == NULL
			MOV EDX,DWORD PTR[EAX+16]
		.endif
		MOV EDI,DWORD PTR[EAX+12]
		.if EBX >= EDI
			ADD EDI,EDX
			.if EBX < EDI
				SUB EBX,EDI
				ADD EBX,EDX
				MOV EDX,FsRawOffset
				.if EDX < 200h && EDX < FileAligment && ECX != fNumberOfSections
					PUSH ECX
					MOV ECX,fHeaderBase
					.if DWORD PTR[EAX+20] >= ECX
						ADD EBX,DWORD PTR[EAX+20]
					.endif
					POP ECX
				.elseif (FileAligment >= 200h && EDX >= FileAligment) || (EDX == NULL)
					ADD EBX,DWORD PTR[EAX+20]
				.elseif (EDX <= FileAligment && EDX >= 200h)
					ADD EBX,DWORD PTR[EAX+20]
				.endif
;				.if EDX >= FileAligment || ECX != fNumberOfSections
;					ADD EBX,DWORD PTR[EAX+20]
;				.endif
;				.if EDX >= FileAligment || EDX >= SizeOfHeaders || EDX == 0
;					ADD EBX,DWORD PTR[EAX+20]
;				.endif
				.if retnType == 1
					ADD EBX,fMap
				.endif
				MOV ECX,1
			.endif
		.endif
		ADD EAX,28h
		DEC ECX
	.endw
	.if retnType == 1 && EBX < fMap
        	ADD EBX,fMap
	.endif
	MOV DWORD PTR[Converted],EBX
 ; 
 ; End of conversion
 ;
	POPAD
	MOV EAX,DWORD PTR[Converted]
	RET
ConvertVAtoFileOffset endp
;------------------------------------------------------------------
ConvertFileOffsetToVA proc fMap:DWORD,Address:DWORD,retnType:DWORD
	LOCAL Converted :DWORD
	LOCAL locImageBase :DWORD
 ;
 ; Konverzija
 ; retnType - 0 / Return file offset
 ; retnType - 1 / Return + ImageBase
 ;
	PUSHAD
	MOV EAX,fMap				; Parametar 1 = FileMapVA
	MOV EBX,Address				; Parametar 2 = Adresa za konverziju
	SUB EBX,EAX
 ;
 ; elfa_new
 ;
	MOV ECX,DWORD PTR[EAX+3Ch]
 ;
 ; PEHeader
 ;
	LEA ECX,DWORD PTR[EAX+ECX]
	MOV EAX,DWORD PTR[ECX+34h]	;Auto ImageBase
	MOV locImageBase,EAX
	MOV EAX,ECX
 ;
 ; NumberOfSections
 ;
	XOR ECX,ECX
	MOV CX,WORD PTR[EAX+6]
 ;
 ; Section Tabela
 ;
	ADD AX,WORD PTR[EAX+14h]
	ADD EAX,018h
	.while ECX > 0
		MOV EDX,DWORD PTR[EAX+16]
		MOV EDI,DWORD PTR[EAX+20]
		.if EBX >= EDI
			ADD EDI,EDX
			.if EBX < EDI
				MOV ECX,1
				SUB EBX,EDI
				ADD EBX,EDX
				ADD EBX,DWORD PTR[EAX+12]
				.if retnType == 1
					ADD EBX,locImageBase
				.endif
			.endif
		.endif
	ADD EAX,28h
	DEC ECX
	.endw
	MOV DWORD PTR[Converted],EBX
 ; 
 ; Izlaz iz konverzije
 ;
	POPAD
	MOV EAX,DWORD PTR[Converted]
	RET
ConvertFileOffsetToVA endp
;------------------------------------------------------------------
SetSharedOverlay proc dwFileName :DWORD
	MOV EAX,dwFileName
	MOV SharedOverlay,EAX
	RET
SetSharedOverlay endp
;------------------------------------------------------------------
GetSharedOverlay proc
	MOV EAX,SharedOverlay
	RET
GetSharedOverlay endp
;------------------------------------------------------------------
MapFile PROC fName:DWORD
	PUSHAD
	MOV FileMapVA,NULL
	INVOKE CreateFile,DWORD PTR[EBP+8],GENERIC_READ+GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	.if EAX == -1
		POPAD
		RET
	.endif
	MOV DWORD PTR[FileHWND],EAX
	INVOKE GetFileSize,DWORD PTR[FileHWND],NULL
	MOV DWORD PTR[FileSize],EAX
	INVOKE CreateFileMapping,DWORD PTR[FileHWND],NULL,4,NULL,DWORD PTR[FileSize],NULL
	MOV DWORD PTR[FileMap],EAX
	INVOKE MapViewOfFile,DWORD PTR[FileMap],2,NULL,NULL,NULL
	MOV DWORD PTR[FileMapVA],EAX
	POPAD
	RET
MapFile ENDP
;------------------------------------------------------------------
MapFileR PROC fName:DWORD
	PUSHAD
	MOV FileMapVA,NULL
	INVOKE CreateFile,DWORD PTR[EBP+8],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	.if EAX == -1
		MOV DWORD PTR[FileMapVA],0
		POPAD
		RET
	.endif
	MOV DWORD PTR[FileHWND],EAX
	INVOKE GetFileSize,DWORD PTR[FileHWND],NULL
	MOV DWORD PTR[FileSize],EAX
	INVOKE CreateFileMapping,DWORD PTR[FileHWND],NULL,2,NULL,DWORD PTR[FileSize],NULL
	MOV DWORD PTR[FileMap],EAX
	INVOKE MapViewOfFile,DWORD PTR[FileMap],4,NULL,NULL,NULL
	MOV DWORD PTR[FileMapVA],EAX
	POPAD
	RET
MapFileR ENDP
;------------------------------------------------------------------
ResizeMapFile PROC fName:DWORD,fSize:DWORD
	PUSHAD
	MOV FileMapVA,NULL	
	INVOKE CreateFile,DWORD PTR[EBP+8],GENERIC_READ+GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	.if EAX == -1
		MOV DWORD PTR[FileMapVA],0
		POPAD
		RET
	.endif
	MOV DWORD PTR[FileHWND],EAX
	INVOKE GetFileSize,DWORD PTR[FileHWND],NULL
	MOV DWORD PTR[FileSize],EAX
	MOV DWORD PTR[oldFileSize],EAX
	MOV EAX,DWORD PTR[EBP+12]
	ADD DWORD PTR[FileSize],EAX
	INVOKE CreateFileMapping,DWORD PTR[FileHWND],NULL,4,NULL,DWORD PTR[FileSize],NULL
	MOV DWORD PTR[FileMap],EAX
	INVOKE MapViewOfFile,DWORD PTR[FileMap],2,NULL,NULL,NULL
	MOV DWORD PTR[FileMapVA],EAX
	POPAD
	RET
ResizeMapFile ENDP
;------------------------------------------------------------------
UnmapFile PROC
	PUSHAD
	INVOKE UnmapViewOfFile,DWORD PTR[FileMapVA]
	INVOKE CloseHandle,DWORD PTR[FileMap]
	INVOKE SetFilePointer,DWORD PTR[FileHWND],DWORD PTR[FileSize],NULL,NULL
	INVOKE SetEndOfFile,DWORD PTR[FileHWND]
	INVOKE CloseHandle,DWORD PTR[FileHWND]
	POPAD
	RET
UnmapFile ENDP
;------------------------------------------------------------------
SmartMapFile PROC fName:DWORD
	LOCAL Return :DWORD
	LOCAL NumberOfBytesRW :DWORD
	PUSHAD
	MOV Return,0
	INVOKE CreateFile,DWORD PTR[EBP+8],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	.if EAX == -1
		MOV DWORD PTR[FileMapVA],0
		MOV Return,-1
		POPAD
		MOV EAX,Return
		RET
	.endif
	MOV DWORD PTR[FileHWND],EAX
	INVOKE GetFileSize,DWORD PTR[FileHWND],NULL
	MOV DWORD PTR[FileSize],EAX
	MOV DWORD PTR[oldFileSize],EAX
	INVOKE RtlZeroMemory,addr SmartPE32Header,2000h
	INVOKE ReadFile,FileHWND,addr SmartPE32Header,1000h,addr NumberOfBytesRW,NULL
	MOV FileMapVA,offset SmartPE32Header
	MOV FileMap,-1				;Flag for signatures!
	MOV EAX,offset SmartPE32Header
	MOV EAX,DWORD PTR[EAX+3Ch]
	.if EAX > 1000h				;Force mapping for PE32 header above 1000h (UPX 0.8x only)
		INVOKE CreateFileMapping,DWORD PTR[FileHWND],NULL,2,NULL,DWORD PTR[FileSize],NULL
		MOV DWORD PTR[FileMap],EAX
		INVOKE MapViewOfFile,DWORD PTR[FileMap],4,NULL,NULL,NULL
		MOV DWORD PTR[FileMapVA],EAX
	.endif
	POPAD
	MOV EAX,Return
	RET
SmartMapFile ENDP
;------------------------------------------------------------------
SmartUnmapFile PROC
	PUSHAD

	.if FileMap == -1
		INVOKE CloseHandle,DWORD PTR[FileHWND]
	.else
		INVOKE UnmapFile
	.endif

	POPAD
	RET
SmartUnmapFile ENDP
;------------------------------------------------------------------
_dlde:
	include ..\..\ldex86bin.inc
;------------------------------------------------------------------
StaticLengthDisassemble proc dwAddress:DWORD
	PUSHAD
	PUSH dwAddress
	CALL _dlde
	MOV DWORD PTR[ESP+1Ch],EAX
	POPAD
	RET
StaticLengthDisassemble endp
;------------------------------------------------------------------
End LibMain