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
    include \masm32\include\psapi.inc
    include ..\..\xInclude.inc

    includelib \masm32\lib\user32.lib
    includelib \masm32\lib\kernel32.lib
    includelib \masm32\lib\psapi.lib
;------------------------------------------------------------------
sCustomHandler STRUCT
	hBreakPoint dd ?
	hSingleStep dd ?
	hAccessViolation dd ?
	hIllegalInstruction dd ?
	hNonContinuableException dd ?
	hArrayBoundsException dd ?
	hFloatDenormalOperand dd ?
	hFloatDevideByZero dd ?
	hIntegerDevideByZero dd ?
	hIntegerOverflow dd ?
	hPrivilegedInstruction dd ?
	hPageGuard dd ?
	hEverythingElse dd ?
	hCreateThread dd ?
	hExitThread dd ?
	hCreateProcess dd ?
	hExitProcess dd ?
	hLoadDll dd ?
	hUnloadDll dd ?
	hOutputDebugString dd ?
sCustomHandler ENDS

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
;------------------------------------------------------------------
    return MACRO arg
      mov eax, arg
      ret
    ENDM
;------------------------------------------------------------------
      LoadLibraryManager PROTO :DWORD
      LoadLibraryCleanupManager PROTO
      CopyStubToTmpForBaseReservation PROTO :DWORD,:DWORD,:DWORD
      MapFileWriteEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
      UnmapFileEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
;------------------------------------------------------------------
 .data
	MAX_BPX_COUNT dd 100
	BPX_INT3 db 0CCh
	Timeout dd INFINITE
	OldProtect dd 02040001h
	szCmdLineFormat db 22h,"%s",22h," %s",0h
	szKernel db "kernel32.dll",0h
	szExitProcess db "ExitProcess",0h
	szPSAPI db "psapi.dll",0h
	szEnumProcessModules db "EnumProcessModules",0h
	szGetModuleBaseName db "GetModuleBaseNameA",0h
	szDebugSetProcessKillOnExit db "DebugSetProcessKillOnExit",0h
	szDebugActiveProcessStop db "DebugActiveProcessStop",0h
 .data?
	pProcessInfo PROCESS_INFORMATION <?>
	pStartupInfo STARTUPINFO <?>
	CustomHandler sCustomHandler <?>
	DbgEvent DEBUG_EVENT <?>
	DbgContext CONTEXT <?>
	MemInfo MEMORY_BASIC_INFORMATION <?>
	MemoryInfo MEMORY_BASIC_INFORMATION <?>
	szFileName_p dd ?
	szCmdLine_p dd ?
	szCurDir_p dd ?
	hProcess dd ?
	hThread dd ?
	hProcessId dd ?
	hThreadId dd ?
	hDebugger dd ?
	NumOfBytesWR dd ?
	NotHandled dd ?
	ExceptionNumber dd ?
	retnData dd ?
	HideDbgAlloc dd ?
	HideDbgLastEIP dd ?
	HideDbgBPX dd ?
	GlobalAttachCallback dd ?

	FirstBPX dd ?
	FileLoadedBaseAddress dd ?
	BPX_DLLLoaderBase dd ?
	BPX_DLLCallBack dd ?
	BPX_DLLEntryPoint dd ?
	BPX_PageGuard dd ?
	BPX_RestoreAddr dd ?
	BPX_SafeDelete dd ?
	BPX_READBUFFER db 100 dup(?)
	BPX_DISASSMBUFFER db 100 dup(?)
	BPX_CallBack dd 400 dup(?)
	BPX_List dd 400 dup(?)
	BPX_Type db 400 dup(?)
	BPX_Stolen_Bytes db 400 dup(?)
	
	LockHandle dd ?
	SpecialDebug db 100 dup(?)		;Za sve osim exceptiona
	DBG_ReadData db 1000 dup(?)
	DBG_Temp dd ?
	DBG_RealignBase dd ?
	DBG_FoundAPIBase dd ?
	DBG_Code dd ?
	DBG_DbgContext dd ?
	DBG_ThreadHandleList db 1024 dup(?)

	SEHGoneWild dd ?
	SEHGoneWildProtection dd ?
	LastException dd ?
	LastExceptionAddress dd ?
	ProcessExitCode dd ?

	DebugLibraryName db 1024 dup(?)
	szDLLTestFileName db 1024 dup(?)
	LoadedLibraryHandles db 1024 dup(?)
    .code

;------------------------------------------------------------------
LibMain proc hInstDLL:DWORD, reason:DWORD, unused:DWORD

        .if reason == DLL_PROCESS_ATTACH
            MOV EAX,hInstDLL
            MOV hDebugger,EAX
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
GetModuleVersion proc
	MOV EAX,0107h
	RET
GetModuleVersion endp
;------------------------------------------------------------------
InitDllUnpack proc
	PUSHAD

        MOV ESI,FileLoadedBaseAddress
        ADD ESI,03000h
        INVOKE lstrlen,addr DebugLibraryName
        MOV EDI,EAX
	INVOKE WriteProcessMemory,DWORD PTR[hProcess],ESI,addr DebugLibraryName,EDI,addr NumOfBytesWR

	POPAD
	RET
InitDllUnpack endp
;------------------------------------------------------------------
CopyStubToTmpForBaseReservation proc ImageBase:DWORD,DoCopy:DWORD,LoaderSz:DWORD
	LOCAL memAlloc1 :DWORD
	LOCAL memAlloc2 :DWORD
	LOCAL rsFileHWND :DWORD
	LOCAL rsFileSize :DWORD
	LOCAL rsFileMap :DWORD
	LOCAL rsFileMapVA :DWORD	
	PUSHAD

	INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV memAlloc1,EAX
	INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV memAlloc2,EAX
	INVOKE GetModuleFileName,hDebugger,memAlloc1,1024
	MOV ESI,memAlloc1
	INVOKE lstrlen,ESI
	ADD ESI,EAX
	.while BYTE PTR[ESI] != "\"
		MOV BYTE PTR[ESI],0
		DEC ESI
	.endw
	INVOKE lstrcpy,memAlloc2,memAlloc1
	INVOKE lstrcpy,LoaderSz,memAlloc1
;	MOV ESI,memAlloc2
;	INVOKE lstrlen,ESI
;	ADD ESI,EAX
;	DEC ESI
;	DEC ESI
;	.while BYTE PTR[ESI] != "\"
;		MOV BYTE PTR[ESI],0
;		DEC ESI
;	.endw
	MOV ESI,memAlloc1
	INVOKE lstrlen,ESI
	ADD ESI,EAX
	MOV DWORD PTR[ESI],"\pmt"
	MOV DWORD PTR[ESI+4],"buts"
	MOV DWORD PTR[ESI+8],"lld."
	INVOKE lstrcpy,memAlloc2,memAlloc2
	MOV ESI,memAlloc2
	INVOKE lstrlen,ESI
	ADD ESI,EAX
	MOV DWORD PTR[ESI],"\pmt"
	MOV DWORD PTR[ESI+4],"x0pa"
	MOV DWORD PTR[ESI+8],"lld."
	MOV ESI,LoaderSz
	INVOKE lstrlen,ESI
	ADD ESI,EAX
	MOV DWORD PTR[ESI],"\pmt"
	MOV DWORD PTR[ESI+4],"buts"
	MOV DWORD PTR[ESI+8],"exe."
	.if DoCopy == 1
		INVOKE CopyFile,memAlloc1,memAlloc2,FALSE
	
		INVOKE MapFileWriteEx,memAlloc2,NULL,addr rsFileHWND,addr rsFileSize,addr rsFileMap,addr rsFileMapVA
		.if rsFileMapVA > 0
			MOV EDI,ImageBase
			MOV ESI,rsFileMapVA
			ADD ESI,DWORD PTR[ESI+3Ch]
			ASSUME ESI:PTR FullPE32Header
			MOV DWORD PTR[ESI].ImageBase,EDI
			ASSUME ESI:NOTHING
			INVOKE UnmapFileEx,rsFileHWND,rsFileSize,rsFileMap,rsFileMapVA
		.endif
	.else
		INVOKE DeleteFile,memAlloc2
	.endif

	INVOKE VirtualFree,memAlloc1,NULL,MEM_RELEASE
	INVOKE VirtualFree,memAlloc2,NULL,MEM_RELEASE

	POPAD
	RET
CopyStubToTmpForBaseReservation endp
;------------------------------------------------------------------
MapFileWriteEx PROC fName:DWORD,dwReadOrWrite:DWORD,dwFileHWND:DWORD,dwFileSize:DWORD,dwFileMap:DWORD,dwFileMapVA:DWORD
	LOCAL Return :DWORD
	PUSHAD
	MOV Return,0
	INVOKE CreateFile,DWORD PTR[EBP+8],GENERIC_READ+GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	.if EAX == -1
		MOV EBX,dwFileMapVA
		MOV DWORD PTR[EBX],0
		MOV Return,-1
		POPAD
		MOV EAX,Return
		RET
	.endif
	MOV EBX,dwFileHWND
	MOV DWORD PTR[EBX],EAX
	INVOKE GetFileSize,EAX,NULL
	MOV EBX,dwFileSize
	MOV DWORD PTR[EBX],EAX
	MOV EAX,dwFileHWND
	INVOKE CreateFileMapping,DWORD PTR[EAX],NULL,4,NULL,DWORD PTR[EBX],NULL
	MOV EBX,dwFileMap
	MOV DWORD PTR[EBX],EAX
	INVOKE MapViewOfFile,DWORD PTR[EBX],2,NULL,NULL,NULL
	MOV EBX,dwFileMapVA
	MOV DWORD PTR[EBX],EAX
	POPAD
	MOV EAX,Return
	RET
MapFileWriteEx ENDP
;------------------------------------------------------------------
UnmapFileEx PROC dwFileHWND:DWORD,dwFileSize:DWORD,dwFileMap:DWORD,dwFileMapVA:DWORD
	PUSHAD
	INVOKE UnmapViewOfFile,dwFileMapVA
	INVOKE CloseHandle,dwFileMap
	INVOKE SetFilePointer,dwFileHWND,dwFileSize,NULL,NULL
	INVOKE SetEndOfFile,dwFileHWND
	INVOKE CloseHandle,dwFileHWND
	POPAD
	RET
UnmapFileEx ENDP
;------------------------------------------------------------------
ClearDebug proc
 ;
 ; Ova funkcija inicira promenjive
 ;
	MOV Timeout,INFINITE
	INVOKE RtlZeroMemory,addr BPX_READBUFFER,100
	INVOKE RtlZeroMemory,addr BPX_DISASSMBUFFER,100
	INVOKE RtlZeroMemory,addr BPX_CallBack,400
	INVOKE RtlZeroMemory,addr BPX_List,400*4
	INVOKE RtlZeroMemory,addr BPX_Type,400
	INVOKE RtlZeroMemory,addr BPX_Stolen_Bytes,400
	INVOKE RtlZeroMemory,addr DBG_ThreadHandleList,1024
	RET
ClearDebug endp
;------------------------------------------------------------------
InitDebug proc dwExePath:DWORD,dwCmdLine:DWORD,dwCurDir:DWORD

	LOCAL szCmdLine :DWORD
 ;
 ; Ova funkcija inicira debug proces
 ;
	PUSHAD
	CALL ClearDebug
 ;
 ; Prvi parametar je LPSTR ka imenu i putanji debug .exe fajla
 ;
	MOV EAX,DWORD PTR[EBP+8]
	MOV DWORD PTR[szFileName_p],EAX
 ;
 ; Drugi parametar je LPSTR ka command line-u
 ;
	MOV EAX,DWORD PTR[EBP+12]
	MOV DWORD PTR[szCmdLine_p],EAX
 ;
 ; Treci parametar je LPSTR ka current direktorijumu
 ;
	MOV EAX,DWORD PTR[EBP+16]
	MOV DWORD PTR[szCurDir_p],EAX
 ;
 ; Kreiraj proces
 ;
	.if dwCmdLine == NULL
		INVOKE CreateProcess,DWORD PTR[szFileName_p],dwCmdLine,NULL,NULL,FALSE,DEBUG_PROCESS+DEBUG_ONLY_THIS_PROCESS,NULL,DWORD PTR[szCurDir_p],addr pStartupInfo,addr pProcessInfo
	.else
	       	INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
	       	MOV szCmdLine,EAX
		PUSH dwCmdLine
		PUSH dwExePath
		PUSH offset szCmdLineFormat
		PUSH szCmdLine
		CALL wsprintf
		ADD ESP,16
		INVOKE CreateProcess,NULL,szCmdLine,NULL,NULL,FALSE,DEBUG_PROCESS+DEBUG_ONLY_THIS_PROCESS,NULL,DWORD PTR[szCurDir_p],addr pStartupInfo,addr pProcessInfo
		MOV ESI,EAX
	        INVOKE VirtualFree,szCmdLine,NULL,MEM_RELEASE
		MOV EAX,ESI
	.endif
 ;
 ; Da li je proces uspesno kreiran?
 ;
	.if EAX != 0
		MOV EAX,DWORD PTR[pProcessInfo]
		MOV DWORD PTR[hProcess],EAX
		MOV EAX,DWORD PTR[pProcessInfo+4]
		MOV DWORD PTR[hThread],EAX
		MOV EAX,DWORD PTR[pProcessInfo+8]
		MOV DWORD PTR[hProcessId],EAX
		MOV EAX,DWORD PTR[pProcessInfo+12]
		MOV DWORD PTR[hThreadId],EAX
		MOV DWORD PTR[retnData],offset pProcessInfo
	.else
		MOV DWORD PTR[hProcess],0
		MOV DWORD PTR[retnData],0
	.endif
	MOV ProcessExitCode,NULL
	POPAD
 ;
 ; Kreiranje procesa je zavrseno
 ;
	MOV EAX,DWORD PTR[retnData]
	RET
InitDebug endp
;------------------------------------------------------------------
InitDLLDebug proc dwDLLPath:DWORD,ReserveModuleBase:DWORD,dwCmdLine:DWORD,dwCurDir:DWORD,dwCALLBACK:DWORD
	LOCAL Return :DWORD
	LOCAL memAlloc1 :DWORD
	LOCAL rsImageBase :DWORD
	LOCAL rsFileHWND :DWORD
	LOCAL rsFileSize :DWORD
	LOCAL rsFileMap :DWORD
	LOCAL rsFileMapVA :DWORD
	PUSHAD

	MOV Return,NULL
	MOV rsImageBase,NULL
	INVOKE MapFileWriteEx,dwDLLPath,NULL,addr rsFileHWND,addr rsFileSize,addr rsFileMap,addr rsFileMapVA
	.if rsFileMapVA > 0
		MOV ESI,rsFileMapVA
		ADD ESI,DWORD PTR[ESI+3Ch]
		ASSUME ESI:PTR FullPE32Header
		MOV EDI,DWORD PTR[ESI].ImageBase
		MOV EAX,DWORD PTR[ESI].AddressOfEntryPoint
		MOV rsImageBase,EDI
		MOV BPX_DLLEntryPoint,EAX
		ASSUME ESI:NOTHING
		INVOKE UnmapFileEx,rsFileHWND,rsFileSize,rsFileMap,rsFileMapVA
	.endif
	.if rsImageBase != NULL
		INVOKE lstrcpy,addr DebugLibraryName,dwDLLPath
		INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
		MOV memAlloc1,EAX	
		INVOKE CopyStubToTmpForBaseReservation,rsImageBase,ReserveModuleBase,memAlloc1
		INVOKE InitDebug,memAlloc1,dwCmdLine,dwCurDir
		MOV Return,EAX
		INVOKE VirtualFree,memAlloc1,NULL,MEM_RELEASE
		MOV EAX,dwCALLBACK
		MOV BPX_DLLCallBack,EAX
	.endif

	POPAD
	MOV EAX,Return
	RET
InitDLLDebug endp
;------------------------------------------------------------------
GetDebuggedDLLBaseAddress proc
	MOV EAX,BPX_DLLLoaderBase
	RET
GetDebuggedDLLBaseAddress endp
;------------------------------------------------------------------
GetDebuggedFileBaseAddress proc
	MOV EAX,FileLoadedBaseAddress
	RET
GetDebuggedFileBaseAddress endp
;------------------------------------------------------------------
StopDebug proc
	PUSHAD
 ;
 ; Zaustavljamo debugee process
 ;
	.if DWORD PTR[hProcess] != 0
		INVOKE TerminateThread,DWORD PTR[hThread],NULL
		INVOKE TerminateProcess,DWORD PTR[hProcess],NULL
		MOV DWORD PTR[retnData],1
	.else
		MOV DWORD PTR[retnData],0
	.endif
        
	POPAD
	MOV EAX,DWORD PTR[retnData]
	RET
StopDebug endp
;------------------------------------------------------------------
SetCustomHandler proc dwWhichException:DWORD,dwCALLBACK:DWORD
	PUSHAD
 ;
 ; Ovde postavljamo sve custom handlere
 ;
 ; Parametar 1 => Koji handler
 ; Parametar 2 => Adresa funkcije za handleing
 ;
	MOV EAX,DWORD PTR[EBP+8]
	MOV EBX,DWORD PTR[EBP+12]
	.if EAX == 1
		MOV DWORD PTR[CustomHandler.hBreakPoint],EBX
	.endif
	.if EAX == 2
		MOV DWORD PTR[CustomHandler.hSingleStep],EBX
	.endif
	.if EAX == 3
		MOV DWORD PTR[CustomHandler.hAccessViolation],EBX
	.endif
	.if EAX == 4
		MOV DWORD PTR[CustomHandler.hIllegalInstruction],EBX
	.endif
	.if EAX == 5
		MOV DWORD PTR[CustomHandler.hNonContinuableException],EBX
	.endif
	.if EAX == 6
		MOV DWORD PTR[CustomHandler.hArrayBoundsException],EBX
	.endif
	.if EAX == 7
		MOV DWORD PTR[CustomHandler.hFloatDenormalOperand],EBX
	.endif
	.if EAX == 8
		MOV DWORD PTR[CustomHandler.hFloatDevideByZero],EBX
	.endif
	.if EAX == 9
		MOV DWORD PTR[CustomHandler.hIntegerDevideByZero],EBX
	.endif
	.if EAX == 10
		MOV DWORD PTR[CustomHandler.hIntegerOverflow],EBX
	.endif
	.if EAX == 11
		MOV DWORD PTR[CustomHandler.hPrivilegedInstruction],EBX
	.endif
	.if EAX == 12
		MOV DWORD PTR[CustomHandler.hPageGuard],EBX
	.endif
	.if EAX == 13
		MOV DWORD PTR[CustomHandler.hEverythingElse],EBX
	.endif
	.if EAX == 14
		MOV DWORD PTR[CustomHandler.hCreateThread],EBX
	.endif
	.if EAX == 15
		MOV DWORD PTR[CustomHandler.hExitThread],EBX
	.endif
	.if EAX == 16
		MOV DWORD PTR[CustomHandler.hCreateProcess],EBX
	.endif
	.if EAX == 17
		MOV DWORD PTR[CustomHandler.hExitProcess],EBX
	.endif
	.if EAX == 18
		MOV DWORD PTR[CustomHandler.hLoadDll],EBX
	.endif
	.if EAX == 19
		MOV DWORD PTR[CustomHandler.hUnloadDll],EBX
	.endif
	.if EAX == 20
		MOV DWORD PTR[CustomHandler.hOutputDebugString],EBX
	.endif
	POPAD
	RET
SetCustomHandler endp
;------------------------------------------------------------------
RestoreBPX proc dwAddress:DWORD
	PUSHAD
 ;
 ; Ova funkcija vraca breakpoint
 ;
 ; Parametar 1 => adresa breakpointa
 ;
	MOV EAX,dwAddress

	MOV EBX,offset BPX_List
	XOR ECX,ECX
	XOR EDX,EDX
	.while ECX <= DWORD PTR[MAX_BPX_COUNT]
		.if DWORD PTR[EBX] == EAX
			MOV EDX,4
			IMUL EDX,ECX
			MOV ECX,DWORD PTR[MAX_BPX_COUNT]
		.endif
		INC ECX
		ADD EBX,4
	.endw
	MOV EBX,offset BPX_List
	LEA EBX,DWORD PTR[EBX+EDX]
	MOV ECX,offset BPX_Stolen_Bytes
	LEA ECX,DWORD PTR[ECX+EDX]

	PUSHAD
	INVOKE WriteProcessMemory,DWORD PTR[hProcess],EAX,ECX,1,addr NumOfBytesWR
	POPAD

	MOV EAX,offset BPX_Type
	LEA EAX,DWORD PTR[EAX+EDX]

	.if BYTE PTR[EAX] == 1
		PUSH dwAddress
		CALL DeleteBPX	
	.endif

	POPAD
	RET
RestoreBPX endp
;------------------------------------------------------------------
DeleteBPX proc dwBpxAddress:DWORD
	PUSHAD
 ;
 ; Ova funkcija vraca breakpoint
 ;
 ; Parametar 1 => adresa breakpointa
 ;
	MOV EAX,DWORD PTR[EBP+8]

	MOV EBX,offset BPX_List
	XOR ECX,ECX
	XOR EDX,EDX
	.while ECX <= DWORD PTR[MAX_BPX_COUNT]
		.if DWORD PTR[EBX] == EAX
			MOV EDX,4
			IMUL EDX,ECX
			MOV ECX,DWORD PTR[MAX_BPX_COUNT]
		.endif
		INC ECX
		ADD EBX,4
	.endw

	PUSHAD
	MOV ECX,offset BPX_Stolen_Bytes
	LEA ECX,DWORD PTR[ECX+EDX]
	INVOKE WriteProcessMemory,DWORD PTR[hProcess],EAX,ECX,1,addr NumOfBytesWR
	POPAD

	MOV EBX,offset BPX_List			;Adresa BPXa
	LEA EBX,DWORD PTR[EBX+EDX]
	MOV DWORD PTR[EBX],0

	MOV EBX,offset BPX_Stolen_Bytes		;Ukradeni bajtovi
	LEA EBX,DWORD PTR[EBX+EDX]
	MOV BYTE PTR[EBX],0

	MOV EBX,offset BPX_Type			;Tip BPXa
	LEA EBX,DWORD PTR[EBX+EDX]
	MOV BYTE PTR[EBX],0

	POPAD
	RET
DeleteBPX endp
;------------------------------------------------------------------
SafeDeleteBPX proc dwBpxAddress:DWORD
	PUSHAD
 ;
 ; Ova funkcija vraca breakpoint
 ;
 ; Parametar 1 => adresa breakpointa
 ;

	MOV EAX,DWORD PTR[EBP+8]
	MOV DWORD PTR[BPX_SafeDelete],EAX

	POPAD
	RET
SafeDeleteBPX endp
;------------------------------------------------------------------
SetBPX proc dwBpxAddress:DWORD,dwBpxType:DWORD,dwCALLBACK:DWORD
	PUSHAD
 ;
 ; Ova funkcija postavlja breakpoint
 ;
 ; Parametar 1 => adresa breakpointa
 ; Parametar 2 => tip breakpointa
 ;
 ; Parametar 2 / 00 - Always
 ;             / 01 - SingleShot
 ;
 ; Parametar 3 / Bpx_Callback

	INVOKE ReadProcessMemory,DWORD PTR[hProcess],DWORD PTR[EBP+8],addr BPX_READBUFFER,1,addr NumOfBytesWR
	INVOKE VirtualProtectEx,DWORD PTR[hProcess],DWORD PTR[EBP+8],1,PAGE_READWRITE,addr OldProtect
	INVOKE WriteProcessMemory,DWORD PTR[hProcess],DWORD PTR[EBP+8],addr BPX_INT3,1,addr NumOfBytesWR

	MOV EBX,offset BPX_List
	XOR ECX,ECX
	XOR EDX,EDX
	.while ECX <= DWORD PTR[MAX_BPX_COUNT]
		.if DWORD PTR[EBX] == 0
			MOV EDX,4
			IMUL EDX,ECX
			MOV ECX,DWORD PTR[MAX_BPX_COUNT]
		.endif
		INC ECX
		ADD EBX,4
	.endw
	MOV EBX,offset BPX_List			;Zapisujemo adresu BPXa
	LEA EBX,DWORD PTR[EBX+EDX]
	MOV EAX,DWORD PTR[EBP+8]
	MOV DWORD PTR[EBX],EAX

	MOV EBX,offset BPX_Type			;Tip breakpointa
	LEA EBX,DWORD PTR[EBX+EDX]
	MOV EAX,DWORD PTR[EBP+12]
	MOV BYTE PTR[EBX],AL

	MOV ECX,offset BPX_READBUFFER		;Ukradeni bajt
	MOV EBX,offset BPX_Stolen_Bytes
	LEA EBX,DWORD PTR[EBX+EDX]
	MOV EAX,DWORD PTR[ECX]
	MOV BYTE PTR[EBX],AL

	MOV EBX,offset BPX_CallBack		;Moguci CALLBack
	LEA EBX,DWORD PTR[EBX+EDX]
	MOV EAX,DWORD PTR[EBP+16]
	MOV DWORD PTR[EBX],EAX

	POPAD
	RET
SetBPX endp
;------------------------------------------------------------------
GetRealAPIAddress proc dwBaseAddress:DWORD,dwAPIaddress:DWORD

	LOCAL dwLocalAlloc :DWORD
	LOCAL dwLocalNameAlloc :DWORD
	LOCAL gpaAddress :DWORD
	LOCAL loadlibBase :DWORD
	LOCAL dwDummy :DWORD
	LOCAL dwPSAPIloaded :DWORD
	LOCAL dwDLLNameHash :DWORD
	LOCAL FoundDllBase :DWORD

	PUSHAD
	MOV DBG_Temp,0
	MOV DBG_RealignBase,0
	INVOKE GetModuleHandle,dwBaseAddress
	.if EAX == 0
		INVOKE LoadLibrary,dwBaseAddress
		MOV DBG_Temp,EAX
	.endif
	MOV loadlibBase,EAX
	INVOKE GetProcAddress,EAX,dwAPIaddress
	MOV gpaAddress,EAX
	
	MOV dwPSAPIloaded,0
	MOV FoundDllBase,0
        INVOKE GetModuleHandle,addr szPSAPI
	.if EAX == 0
		INVOKE LoadLibrary,addr szPSAPI
		MOV dwPSAPIloaded,EAX
	.endif
        .if EAX != 0
		MOV ESI,EAX
                INVOKE GetProcAddress,ESI,addr szEnumProcessModules
                MOV EDI,EAX
                INVOKE GetProcAddress,ESI,addr szGetModuleBaseName
                MOV ESI,EAX

	       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
	       	MOV dwLocalAlloc,EAX
	       	INVOKE VirtualAlloc,NULL,MAX_PATH,MEM_COMMIT,PAGE_EXECUTE_READWRITE
	       	MOV dwLocalNameAlloc,EAX
		LEA EAX,DWORD PTR[dwDummy]
		PUSH EAX
		PUSH 800h
		PUSH dwLocalAlloc
		PUSH hProcess
		CALL EDI

		.if EAX == 1
			MOV EAX,dwBaseAddress
			.while BYTE PTR[EAX] != 0
				INC EAX
			.endw
			.while BYTE PTR[EAX] != '\' && EAX >= dwBaseAddress && BYTE PTR[EAX] != 0
				DEC EAX
			.endw
			INC EAX
			.if BYTE PTR[EAX-1] != '\'
				MOV EAX,dwBaseAddress
			.endif
			XOR EBX,EBX
			CDQ
			.while BYTE PTR[EAX] != 0
				MOVZX EDX,BYTE PTR[EAX]
				.if DL >= 41h && DL <= 5Ah
					ADD DL,20h
				.endif
				ROL EBX,7
				XOR BL,DL
				INC EAX
			.endw
			MOV dwDLLNameHash,EBX

			MOV EDI,dwLocalAlloc
			.while DWORD PTR[EDI] != 0 && DWORD PTR[FoundDllBase] == 0
				PUSH MAX_PATH
				PUSH dwLocalNameAlloc
				PUSH DWORD PTR[EDI]
				PUSH hProcess
				CALL ESI

				MOV EAX,dwLocalNameAlloc
				XOR EBX,EBX
				CDQ
				.while BYTE PTR[EAX] != 0
					MOVZX EDX,BYTE PTR[EAX]
					.if DL >= 41h && DL <= 5Ah
						ADD DL,20h
					.endif
					ROL EBX,7
					XOR BL,DL
					INC EAX
				.endw
				.if EBX == dwDLLNameHash
					MOV EAX,DWORD PTR[EDI]
					MOV FoundDllBase,EAX
				.endif

				ADD EDI,4
			.endw
		.endif

		INVOKE VirtualFree,dwLocalAlloc,2000h,MEM_DECOMMIT
		INVOKE VirtualFree,dwLocalAlloc,NULL,MEM_RELEASE;2000h
		INVOKE VirtualFree,dwLocalNameAlloc,MAX_PATH,MEM_DECOMMIT
		INVOKE VirtualFree,dwLocalNameAlloc,NULL,MEM_RELEASE;MAX_PATH
        .endif

	.if dwPSAPIloaded != NULL
		INVOKE FreeLibrary,dwPSAPIloaded
	.endif

	MOV EAX,gpaAddress
	.if FoundDllBase > 0
		SUB EAX,loadlibBase
		ADD EAX,FoundDllBase
	.endif
	.if DBG_FoundAPIBase == 0
		PUSH EAX
		MOV EAX,gpaAddress
		.if FoundDllBase > 0
			SUB EAX,loadlibBase
			ADD EAX,FoundDllBase
		.endif
		MOV DBG_FoundAPIBase,EAX
		POP EAX
	.endif
	.if EAX != gpaAddress
		INVOKE ReadProcessMemory,DWORD PTR[hProcess],EAX,addr DBG_ReadData,1000,addr NumOfBytesWR
		.if EAX != 0
			MOV BYTE PTR[DBG_ReadData+999],0C3h
			LEA EAX,DWORD PTR[DBG_ReadData]
			MOV DBG_RealignBase,EAX
		.else
			MOV EAX,gpaAddress
		.endif
	.endif

	MOV DWORD PTR[ESP+1Ch],EAX
	POPAD
	RET
GetRealAPIAddress endp
;------------------------------------------------------------------
RealignAPIaddress:
	.if DBG_RealignBase > 0
		SUB EAX,DBG_RealignBase
		ADD EAX,DBG_FoundAPIBase
	.endif
	RET
;------------------------------------------------------------------
SetAPIBreakPoint proc dwDllName:DWORD,dwApiName:DWORD,dwBpxType:DWORD,dwBpxPlace:DWORD,dwCALLBACK:DWORD
	PUSHAD
 ;
 ; Ova postavlja breakpoint na API
 ;
 ; Parametar 1 - LPSTR dll_name
 ; Parametar 2 - LPSTR api_name
 ; Parametar 3 - BPX type
 ; Parametar 4 - BPX place	- 0 beginning
 ;				- 1 end
 ; Parameter 5 - CallBack
 ;

  .if DWORD PTR[EBP+24] != 0 && DWORD PTR[EBP+8] != 0 && DWORD PTR[EBP+12] != 0
	PUSH DWORD PTR[EBP+12]
	PUSH DWORD PTR[EBP+8]
	CALL GetRealAPIAddress

	.if DWORD PTR[EBP+20] == 0
		CALL RealignAPIaddress
		PUSH DWORD PTR[EBP+24]			;BPX on start
		PUSH DWORD PTR[EBP+16]
		PUSH EAX
		CALL SetBPX
	.elseif DWORD PTR[EBP+20] == 1
		MOV ECX,EAX
		XOR EAX,EAX
		.while EAX < 20h
			PUSH ECX
			CALL _dlde
			.if BYTE PTR[ECX] == 0C3h && EAX == 1
				MOV EAX,ECX
			.elseif BYTE PTR[ECX] == 0C2h && EAX == 3
				MOV EAX,ECX
			.endif
			ADD ECX,EAX
		.endw
		CALL RealignAPIaddress
		PUSH DWORD PTR[EBP+24]			;BPX on end
		PUSH DWORD PTR[EBP+16]
		PUSH EAX
		CALL SetBPX
	.endif
  .endif

  .if DBG_Temp != NULL
	INVOKE FreeLibrary,DBG_Temp
  .endif

	POPAD
	RET
SetAPIBreakPoint endp
;------------------------------------------------------------------
DeleteAPIBreakPoint proc dwDllName:DWORD,dwApiName:DWORD,dwBpxPlace:DWORD
	PUSHAD
 ;
 ; Ova uklanja breakpoint sa APIa
 ;
 ; Parametar 1 - LPSTR dll_name
 ; Parametar 2 - LPSTR api_name
 ; Parametar 3 - BPX place
 ;

  .if DWORD PTR[EBP+8] != 0 && DWORD PTR[EBP+12] != 0
	PUSH DWORD PTR[EBP+12]
	PUSH DWORD PTR[EBP+8]
	CALL GetRealAPIAddress

	.if DWORD PTR[EBP+16] == 0
		CALL RealignAPIaddress
		PUSH EAX
		CALL DeleteBPX
	.elseif DWORD PTR[EBP+16] == 1
		MOV ECX,EAX
		XOR EAX,EAX
		.while EAX < 20h
			PUSH ECX
			CALL _dlde
			.if BYTE PTR[ECX] == 0C3h && EAX == 1
				MOV EAX,ECX
			.elseif BYTE PTR[ECX] == 0C2h && EAX == 3
				MOV EAX,ECX
			.endif
			ADD ECX,EAX
		.endw
		CALL RealignAPIaddress
		PUSH EAX
		CALL DeleteBPX
	.endif
  .endif

  .if DBG_Temp != NULL
	INVOKE FreeLibrary,DBG_Temp
  .endif

	POPAD
	RET
DeleteAPIBreakPoint endp
;------------------------------------------------------------------
SafeDeleteAPIBreakPoint proc dwDllName:DWORD,dwApiName:DWORD,dwBpxPlace:DWORD
	PUSHAD
 ;
 ; Ova uklanja breakpoint sa APIa
 ;
 ; Parametar 1 - LPSTR dll_name
 ; Parametar 2 - LPSTR api_name
 ; Parametar 3 - BPX place
 ;

  .if DWORD PTR[EBP+8] != 0 && DWORD PTR[EBP+12] != 0
	PUSH DWORD PTR[EBP+12]
	PUSH DWORD PTR[EBP+8]
	CALL GetRealAPIAddress

	.if DWORD PTR[EBP+16] == 0
		CALL RealignAPIaddress
		MOV DWORD PTR[BPX_SafeDelete],EAX
	.elseif DWORD PTR[EBP+16] == 1
		MOV ECX,EAX
		XOR EAX,EAX
		.while EAX < 20h
			PUSH ECX
			CALL _dlde
			.if BYTE PTR[ECX] == 0C3h && EAX == 1
				MOV EAX,ECX
			.elseif BYTE PTR[ECX] == 0C2h && EAX == 3
				MOV EAX,ECX
			.endif
			ADD ECX,EAX
		.endw
		CALL RealignAPIaddress
		MOV DWORD PTR[BPX_SafeDelete],EAX
	.endif
  .endif

  .if DBG_Temp != NULL
	INVOKE FreeLibrary,DBG_Temp
  .endif

	POPAD
	RET
SafeDeleteAPIBreakPoint endp
;------------------------------------------------------------------
GetContextData proc dwIndexOfRegister:DWORD
	PUSHAD
 ;
 ; Ovde uzimamo podatke o vrednostima registara
 ;
 ; Parametar 1 => Index podatka koji se vraca
 ;
	MOV DWORD PTR[retnData],0
	MOV DWORD PTR DS:[DbgContext.ContextFlags],10007h
	INVOKE OpenThread,THREAD_ALL_ACCESS,FALSE,DWORD PTR[DbgEvent.dwThreadId]
	MOV ESI,EAX
	INVOKE GetThreadContext,ESI,addr DbgContext
	.if EAX != 0
		MOV EAX,DWORD PTR[EBP+8]
		XOR EBX,EBX
		.if EAX == 0
			INVOKE CloseHandle,ESI
			POPAD
			RET
		.elseif EAX == 1
			MOV EBX,DWORD PTR[DbgContext.regEax]
		.elseif EAX == 2
			MOV EBX,DWORD PTR[DbgContext.regEbx]
		.elseif EAX == 3
			MOV EBX,DWORD PTR[DbgContext.regEcx]
		.elseif EAX == 4
			MOV EBX,DWORD PTR[DbgContext.regEdx]
		.elseif EAX == 5
			MOV EBX,DWORD PTR[DbgContext.regEdi]
		.elseif EAX == 6
			MOV EBX,DWORD PTR[DbgContext.regEsi]
		.elseif EAX == 7
			MOV EBX,DWORD PTR[DbgContext.regEbp]
		.elseif EAX == 8
			MOV EBX,DWORD PTR[DbgContext.regEsp]
		.elseif EAX == 9
			MOV EBX,DWORD PTR[DbgContext.regEip]
		.elseif EAX == 10
			MOV EBX,DWORD PTR[DbgContext.regFlag]
		.elseif EAX == 11
			MOV EBX,DWORD PTR[DbgContext.iDr0]
		.elseif EAX == 12
			MOV EBX,DWORD PTR[DbgContext.iDr1]
		.elseif EAX == 13
			MOV EBX,DWORD PTR[DbgContext.iDr2]
		.elseif EAX == 14
			MOV EBX,DWORD PTR[DbgContext.iDr3]
		.elseif EAX == 15
			MOV EBX,DWORD PTR[DbgContext.iDr6]
		.elseif EAX == 16
			MOV EBX,DWORD PTR[DbgContext.iDr7]
		.endif
		MOV DWORD PTR[retnData],EBX
	.else
		INVOKE CloseHandle,ESI
		POPAD
		RET
	.endif

	INVOKE CloseHandle,ESI
	POPAD
	MOV EAX,DWORD PTR[retnData]
	RET
GetContextData endp
;------------------------------------------------------------------
SetBPXContextData proc
	PUSH EBP
	MOV EBP,ESP
	PUSHAD
 ;
 ; Ovde vracamo izvrsavanje na EIP = EIP-1
 ;
	MOV EBX,DWORD PTR[DbgContext.regEip]
	DEC EBX
	MOV DWORD PTR[DbgContext.regEip],EBX
	INVOKE OpenThread,THREAD_ALL_ACCESS,FALSE,DWORD PTR[DbgEvent.dwThreadId]
	MOV ESI,EAX
	INVOKE SetThreadContext,ESI,addr DbgContext
	INVOKE CloseHandle,ESI

	POPAD
	LEAVE
	RET
SetBPXContextData endp
;------------------------------------------------------------------
SetContextData proc dwIndexOfRegister:DWORD,dwNewRegisterValue:DWORD
	PUSHAD
 ;
 ; Ovde uzimamo podatke o vrednostima registara
 ;
 ; Parametar 1 => Index podatka koji se vraca
 ; Parametar 2 => Nova vrednost
 ;
	MOV DWORD PTR[retnData],0
	MOV DWORD PTR DS:[DbgContext.ContextFlags],10007h
	INVOKE OpenThread,THREAD_ALL_ACCESS,FALSE,DWORD PTR[DbgEvent.dwThreadId]
	MOV ESI,EAX
	INVOKE GetThreadContext,ESI,addr DbgContext
	.if EAX != 0
		MOV EAX,DWORD PTR[EBP+8]
		MOV ECX,DWORD PTR[EBP+12]
		XOR EBX,EBX
		.if EAX == 0
			INVOKE CloseHandle,ESI
			POPAD
			RET
		.elseif EAX == 1
			MOV DWORD PTR[DbgContext.regEax],ECX
		.elseif EAX == 2
			MOV DWORD PTR[DbgContext.regEbx],ECX
		.elseif EAX == 3
			MOV DWORD PTR[DbgContext.regEcx],ECX
		.elseif EAX == 4
			MOV DWORD PTR[DbgContext.regEdx],ECX
		.elseif EAX == 5
			MOV DWORD PTR[DbgContext.regEdi],ECX
		.elseif EAX == 6
			MOV DWORD PTR[DbgContext.regEsi],ECX
		.elseif EAX == 7
			MOV DWORD PTR[DbgContext.regEbp],ECX
		.elseif EAX == 8
			MOV DWORD PTR[DbgContext.regEsp],ECX
		.elseif EAX == 9
			MOV DWORD PTR[DbgContext.regEip],ECX
		.elseif EAX == 10
			MOV DWORD PTR[DbgContext.regFlag],ECX
		.elseif EAX == 11
			MOV DWORD PTR[DbgContext.iDr0],ECX
		.elseif EAX == 12
			MOV DWORD PTR[DbgContext.iDr1],ECX
		.elseif EAX == 13
			MOV DWORD PTR[DbgContext.iDr2],ECX
		.elseif EAX == 14
			MOV DWORD PTR[DbgContext.iDr3],ECX
		.elseif EAX == 15
			MOV DWORD PTR[DbgContext.iDr6],ECX
		.elseif EAX == 16
			MOV DWORD PTR[DbgContext.iDr7],ECX
		.endif
		MOV DWORD PTR[retnData],1
	.else
		INVOKE CloseHandle,ESI
		POPAD
		RET
	.endif

	CALL UpdateContextData
	INVOKE CloseHandle,ESI
	POPAD
	MOV EAX,DWORD PTR[retnData]
	RET
SetContextData endp
;------------------------------------------------------------------
UpdateContextData proc
	PUSH EBP
	MOV EBP,ESP
	PUSHAD

	INVOKE OpenThread,THREAD_ALL_ACCESS,FALSE,DWORD PTR[DbgEvent.dwThreadId]
	MOV ESI,EAX
	INVOKE SetThreadContext,ESI,addr DbgContext
	INVOKE CloseHandle,ESI
	
	POPAD
	LEAVE
	RET
UpdateContextData endp
;------------------------------------------------------------------
ActivateBPX proc dwAddress:DWORD
	PUSHAD
 ;
 ; Ova funkcija vraca breakpoint
 ;
 ; Parametar 1 => adresa breakpointa
 ;
	INVOKE WriteProcessMemory,DWORD PTR[hProcess],dwAddress,addr BPX_INT3,1,addr NumOfBytesWR

	POPAD
	RET
ActivateBPX endp
;------------------------------------------------------------------
RemoveMemoryBPX proc dwMemoryStart:DWORD,dwSizeOfMemory:DWORD
	PUSHAD
 ;
 ; Ova funkcija uklanja memoriski breakpoint
 ;
 ; Parametar 1 => adresa breakpointa
 ; Parametar 2 => velicina memorije
 ;
	INVOKE VirtualQueryEx,DWORD PTR[hProcess],DWORD PTR[EBP+8],addr MemInfo,sizeof MemInfo
	MOV EAX,DWORD PTR[MemInfo.AllocationProtect]
	MOV DWORD PTR[OldProtect],EAX
	INVOKE VirtualProtectEx,DWORD PTR[hProcess],DWORD PTR[EBP+8],DWORD PTR[EBP+12],PAGE_EXECUTE_READWRITE,addr OldProtect
	MOV DWORD PTR[BPX_PageGuard],0

	POPAD
	RET
RemoveMemoryBPX endp
;------------------------------------------------------------------
SetMemoryBPX proc dwMemoryStart:DWORD,dwSizeOfMemory:DWORD,dwCALLBACK:DWORD
	PUSHAD
 ;
 ; Ova funkcija postavlja memoriski breakpoint
 ;
 ; Parametar 1 => adresa breakpointa
 ; Parametar 2 => velicina memorije
 ; Parametar 3 => CALLBack
 ;
	MOV EAX,DWORD PTR[EBP+16]
	MOV DWORD PTR[BPX_PageGuard],EAX
	INVOKE VirtualQueryEx,DWORD PTR[hProcess],DWORD PTR[EBP+8],addr MemInfo,sizeof MemInfo
	MOV EAX,DWORD PTR[MemInfo.AllocationProtect]
	MOV DWORD PTR[OldProtect],EAX
	INVOKE VirtualProtectEx,DWORD PTR[hProcess],DWORD PTR[EBP+8],DWORD PTR[EBP+12],PAGE_EXECUTE_READWRITE+PAGE_GUARD,addr OldProtect

	POPAD
	RET
SetMemoryBPX endp
;------------------------------------------------------------------
 _hideDbgEngineS:
	ASSUME FS:NOTHING
	PUSHFD
	PUSHAD

	MOV EAX,DWORD PTR FS:[18h]	;BeingDebug
	MOV EAX,DWORD PTR[EAX+30h]
	LEA EAX,DWORD PTR[EAX+2]
	MOV WORD PTR[EAX],0

	MOV EAX,DWORD PTR FS:[18h]	;ProcessHeap
	MOV EAX,DWORD PTR [EAX+30h]
	MOV EAX,DWORD PTR[EAX+18h]
	MOV DWORD PTR[EAX+10h],0

	MOV EAX,DWORD PTR FS:[30h]	;NtGlobalFlag
	ADD EAX,8E4180C9h
	ADD EAX,71BE7F9Fh
	MOV DWORD PTR[EAX],0

	POPAD
	POPFD
	INT 3
 _hideDbgEngineE:

HideDbg proc
	PUSHAD

	INVOKE VirtualAllocEx,DWORD PTR[hProcess],NULL,1000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV DWORD PTR[HideDbgAlloc],EAX

	MOV DWORD PTR[HideDbgBPX],EAX
	MOV EAX,offset _hideDbgEngineS
	MOV EBX,offset _hideDbgEngineE
	SUB EBX,offset _hideDbgEngineS
	DEC EBX
	ADD DWORD PTR[HideDbgBPX],EBX
	INC EBX

	INVOKE WriteProcessMemory,DWORD PTR[hProcess],DWORD PTR[HideDbgAlloc],EAX,EBX,addr NumOfBytesWR

	PUSH rEIP
	CALL GetContextData
	MOV DWORD PTR[HideDbgLastEIP],EAX

	PUSH DWORD PTR[HideDbgAlloc]
	PUSH rEIP
	CALL SetContextData

	POPAD
	RET
HideDbg endp
;------------------------------------------------------------------
CurrentExceptionNumber proc
	MOV EAX,DWORD PTR[ExceptionNumber]
	RET
CurrentExceptionNumber endp
;------------------------------------------------------------------
ClearExceptionNumber proc
	MOV DWORD PTR[ExceptionNumber],0
	RET
ClearExceptionNumber endp
;------------------------------------------------------------------
Find proc MemStart:DWORD,MemSize:DWORD,Pattern:DWORD,PatternSize:DWORD,WildCard:DWORD ;WildCard is a pointer

	LOCAL TempLocalAlloc	:DWORD
	LOCAL Found		:DWORD
	LOCAL Return		:DWORD

	PUSHAD
	MOV EAX,WildCard
	.if EAX != 0
		MOVZX EAX,BYTE PTR[EAX]
		MOV WildCard,EAX
	.endif
	MOV Return,0
	INVOKE VirtualAlloc,NULL,MemSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV TempLocalAlloc,EAX
	INVOKE ReadProcessMemory,hProcess,MemStart,TempLocalAlloc,MemSize,addr NumOfBytesWR
	.if EAX == NULL
		INVOKE VirtualQueryEx,hProcess,MemStart,addr MemoryInfo,sizeof MemoryInfo
		MOV EAX,MemoryInfo.BaseAddress
		ADD EAX,MemoryInfo.RegionSize
		SUB EAX,MemStart
		MOV MemSize,EAX
		INVOKE ReadProcessMemory,hProcess,MemStart,TempLocalAlloc,MemSize,addr NumOfBytesWR
	.endif
	.if EAX != 0
		MOV EAX,TempLocalAlloc
		XOR EBX,EBX
		MOV ECX,MemSize
		DEC ECX
		MOV EDI,Pattern
		MOV BL,BYTE PTR[EDI]
		DEC PatternSize						;Zbog 0 kao pocetnog offseta
		.while ECX > 0
			PUSH EAX
			.if BYTE PTR[EAX] == BL
				MOV EDX,1
				MOV Found,1
				INC EAX
				.while EDX <= PatternSize
					MOV BL,BYTE PTR[EDI+EDX]
					.if BYTE PTR[EAX] != BL && BYTE PTR[WildCard] != BL
						MOV Found,0
						MOV EDX,PatternSize
					.endif
					INC EAX
					INC EDX
				.endw
				.if Found == 1
					MOV ECX,1
				.else
					MOV BL,BYTE PTR[EDI]
				.endif
			.endif
			POP EAX
			INC EAX
			DEC ECX
		.endw
	.endif
	.if Found == 1
		DEC EAX
		SUB EAX,TempLocalAlloc
		ADD EAX,MemStart
		MOV Return,EAX
	.endif
	INVOKE VirtualFree,TempLocalAlloc,MemSize,MEM_DECOMMIT
	INVOKE VirtualFree,TempLocalAlloc,NULL,MEM_RELEASE;MemSize

	POPAD
	MOV EAX,Return
	RET
Find endp
;------------------------------------------------------------------
SehGoneWildProtection proc
	.if SEHGoneWildProtection == 0
		INC SEHGoneWildProtection
	.else
		DEC SEHGoneWildProtection
	.endif
	RET
SehGoneWildProtection endp
;------------------------------------------------------------------
GetTerminationData proc
	LEA EAX,DWORD PTR[DbgEvent]
	RET
GetTerminationData endp
;------------------------------------------------------------------
GetDebugData proc
	INVOKE GetTerminationData
	RET
GetDebugData endp
;------------------------------------------------------------------
GetExitCode proc
	MOV EAX,ProcessExitCode
	RET
GetExitCode endp
;------------------------------------------------------------------
AttachDebugger proc dwProcessId:DWORD,dwKillOnExit:DWORD,DebugInfo:DWORD,dwCALLBACK:DWORD
	PUSHAD

	.if dwProcessId != NULL
		INVOKE DebugActiveProcess,dwProcessId
		.if EAX != NULL
			.if dwKillOnExit == FALSE
				INVOKE GetModuleHandle,addr szKernel
				MOV EBX,EAX
				INVOKE GetProcAddress,EBX,addr szDebugSetProcessKillOnExit
				.if EAX != NULL
					PUSH dwKillOnExit
					CALL EAX
				.endif
			.endif
			MOV EAX,dwCALLBACK
			MOV GlobalAttachCallback,EAX
			MOV EAX,DebugInfo
			MOV DBG_DbgContext,EAX
			INVOKE DebugLoop
		.endif
	.endif

	POPAD
	RET
AttachDebugger endp
;------------------------------------------------------------------
DetachDebugger proc dwProcessId:DWORD
	LOCAL Return :DWORD
	PUSHAD

	MOV Return,0
	.if dwProcessId != NULL
		INVOKE GetModuleHandle,addr szKernel
		MOV EBX,EAX
		INVOKE GetProcAddress,EBX,addr szDebugActiveProcessStop
		.if EAX != NULL
			MOV ESI,EAX
			MOV EAX,offset DBG_ThreadHandleList
			MOV ECX,64
			.while ECX > NULL
				.if DWORD PTR[EAX] != NULL && DWORD PTR[EAX] != -1
					INVOKE SuspendThread,DWORD PTR[EAX]
				.endif
				ADD EAX,8
				DEC ECX
			.endw
			INVOKE ContinueDebugEvent,DWORD PTR[DbgEvent.dwProcessId],DWORD PTR[DbgEvent.dwThreadId],DBG_Code
			MOV EAX,offset DBG_ThreadHandleList
			MOV ECX,64
			.while ECX > NULL
				.if DWORD PTR[EAX] != NULL && DWORD PTR[EAX] != -1
					INVOKE ResumeThread,DWORD PTR[EAX]
				.endif
				ADD EAX,8
				DEC ECX
			.endw
			INVOKE RtlZeroMemory,addr DBG_ThreadHandleList,1024
			PUSH dwProcessId
			CALL ESI
			MOV Return,EAX
		.endif
	.endif

	POPAD
	MOV EAX,Return
	RET
DetachDebugger endp
;------------------------------------------------------------------
DebugLoopEx proc dwTimeOut:DWORD

	MOV EAX,dwTimeOut
	MOV Timeout,EAX
	INVOKE DebugLoop
	RET
DebugLoopEx endp
;------------------------------------------------------------------
DebugLoop proc
	PUSHAD
 ;
 ; Ovde se izvrsava debug loop
 ;
	MOV DWORD PTR[FirstBPX],1
	MOV DWORD PTR[retnData],0
	MOV DWORD PTR[ExceptionNumber],0
	MOV DWORD PTR[SEHGoneWild],0
	.while -1
		MOV DBG_Code,DBG_CONTINUE
		MOV DWORD PTR[NotHandled],0
		INVOKE WaitForDebugEvent,addr DbgEvent,Timeout
		CALL _clear_special_debug				;Brisemo SpecialDebug strukturu
 ;
 ; CREATE_THREAD_DEBUG_EVENT
 ;
		.if DWORD PTR[DbgEvent.dwDebugEventCode] == CREATE_THREAD_DEBUG_EVENT
			MOV EDX,64
			MOV EAX,offset DBG_ThreadHandleList
			MOV EBX,DWORD PTR[DbgEvent.u.CreateThread.hThread]
			MOV ECX,DWORD PTR[DbgEvent.dwThreadId]
			.while EDX > NULL && DWORD PTR[EAX] != NULL && DWORD PTR[EAX] != -1
				ADD EAX,8
				DEC EDX
			.endw
			MOV DWORD PTR[EAX],EBX
			MOV DWORD PTR[EAX+4],ECX
			.if DWORD PTR[CustomHandler.hCreateThread] != 0
				MOV EAX,DWORD PTR[DbgEvent.u.CreateThread.lpStartAddress]
				MOV DWORD PTR[SpecialDebug],EAX
				MOV EAX,DWORD PTR[DbgEvent.u.CreateThread.lpThreadLocalBase]
				MOV DWORD PTR[SpecialDebug+4],EAX
				MOV EAX,DWORD PTR[DbgEvent.u.CreateThread.hThread]
				MOV DWORD PTR[SpecialDebug+8],EAX

				PUSH offset SpecialDebug
				CALL DWORD PTR[CustomHandler.hCreateThread]
				XOR EAX,EAX
			.endif
		.endif
 ;
 ; EXIT_THREAD_DEBUG_EVENT
 ;
		.if DWORD PTR[DbgEvent.dwDebugEventCode] == EXIT_THREAD_DEBUG_EVENT
			MOV ECX,64
			MOV EAX,offset DBG_ThreadHandleList
			MOV EBX,DWORD PTR[DbgEvent.dwThreadId]
			.while ECX > NULL && DWORD PTR[EAX+4] != EBX
				ADD EAX,8
				DEC ECX
			.endw
			.if ECX > NULL
				MOV DWORD PTR[EAX],-1
				MOV DWORD PTR[EAX+4],-1
			.endif
			.if DWORD PTR[CustomHandler.hExitThread] != 0
				MOV EAX,DWORD PTR[DbgEvent.u.ExitThread.dwExitCode]
				MOV DWORD PTR[SpecialDebug],EAX

				PUSH offset SpecialDebug
				CALL DWORD PTR[CustomHandler.hExitThread]
				XOR EAX,EAX
			.endif
		.endif
 ;
 ; CREATE_PROCESS_DEBUG_EVENT
 ;
		.if DWORD PTR[DbgEvent.dwDebugEventCode] == CREATE_PROCESS_DEBUG_EVENT
			.if GlobalAttachCallback != 0 && FirstBPX == 1
				MOV EBX,DBG_DbgContext
				ASSUME EBX:PTR PROCESS_INFORMATION
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.hProcess]
				MOV DWORD PTR[EBX].hProcess,EAX
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.hThread]
				MOV DWORD PTR[EBX].hThread,EAX
				MOV EAX,DWORD PTR[DbgEvent.dwProcessId]
				MOV DWORD PTR[EBX].dwProcessId,EAX
				MOV DWORD PTR[EBX].dwThreadId,NULL
				ASSUME EBX:NOTHING
			.elseif FirstBPX == 1
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.lpBaseOfImage]
				MOV FileLoadedBaseAddress,EAX
			.endif
			.if DWORD PTR[CustomHandler.hCreateProcess] != 0
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.hFile]
				MOV DWORD PTR[SpecialDebug],EAX
				MOV LockHandle,EAX
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.hProcess]
				MOV DWORD PTR[SpecialDebug+4],EAX
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.hThread]
				MOV DWORD PTR[SpecialDebug+8],EAX
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.lpBaseOfImage]
				MOV DWORD PTR[SpecialDebug+12],EAX
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.dwDebugInfoFileOffset]
				MOV DWORD PTR[SpecialDebug+16],EAX
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.nDebugInfoSize]
				MOV DWORD PTR[SpecialDebug+20],EAX
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.lpThreadLocalBase]
				MOV DWORD PTR[SpecialDebug+24],EAX
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.lpStartAddress]
				MOV DWORD PTR[SpecialDebug+28],EAX
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.lpImageName]
				MOV DWORD PTR[SpecialDebug+32],EAX
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.fUnicode]
				MOV DWORD PTR[SpecialDebug+36],EAX

				PUSH offset SpecialDebug
				CALL DWORD PTR[CustomHandler.hCreateProcess]
				XOR EAX,EAX
			.else
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.hFile]
				MOV LockHandle,EAX
			.endif
			.if BPX_DLLCallBack != NULL
				MOV EAX,DWORD PTR[DbgEvent.u.CreateProcessInfo.lpBaseOfImage]
				ADD EAX,01000h
                                PUSH offset InitDllUnpack
                                PUSH 1
                                PUSH EAX
				CALL SetBPX
			.endif
		.endif
 ;
 ; EXIT_PROCESS_DEBUG_EVENT
 ;
		.if DWORD PTR[DbgEvent.dwDebugEventCode] == EXIT_PROCESS_DEBUG_EVENT
			.if DWORD PTR[CustomHandler.hExitProcess] != 0
				MOV EAX,DWORD PTR[DbgEvent.u.ExitProcess.dwExitCode]
				MOV DWORD PTR[SpecialDebug],EAX
				MOV ProcessExitCode,EAX

				PUSH offset SpecialDebug
				CALL DWORD PTR[CustomHandler.hExitProcess]
				XOR EAX,EAX
			.else
				MOV EAX,DWORD PTR[DbgEvent.u.ExitProcess.dwExitCode]
				MOV ProcessExitCode,EAX
			.endif
			MOV EAX,DWORD PTR[DbgEvent.dwProcessId]
			.if EAX == DWORD PTR[hProcessId]
				MOV DWORD PTR[retnData],1
				MOV DBG_Code,DBG_CONTINUE
				INVOKE ContinueDebugEvent,DWORD PTR[DbgEvent.dwProcessId],DWORD PTR[DbgEvent.dwThreadId],DBG_Code
				MOV EAX,offset _exit_debug_loop
				JMP EAX
	       		.else
				MOV DBG_Code,DBG_CONTINUE
				INVOKE ContinueDebugEvent,DWORD PTR[DbgEvent.dwProcessId],DWORD PTR[DbgEvent.dwThreadId],DBG_Code
			.endif
		.endif
 ;
 ; LOAD_DLL_DEBUG_EVENT
 ;
		.if DWORD PTR[DbgEvent.dwDebugEventCode] == LOAD_DLL_DEBUG_EVENT
			MOV EAX,DWORD PTR[DbgEvent.u.LoadDll.hFile]
			MOV DWORD PTR[SpecialDebug],EAX
			MOV EAX,DWORD PTR[DbgEvent.u.LoadDll.lpBaseOfDll]
			MOV DWORD PTR[SpecialDebug+4],EAX
			MOV EAX,DWORD PTR[DbgEvent.u.LoadDll.dwDebugInfoFileOffset]
			MOV DWORD PTR[SpecialDebug+8],EAX
			MOV EAX,DWORD PTR[DbgEvent.u.LoadDll.nDebugInfoSize]
			MOV DWORD PTR[SpecialDebug+12],EAX
			MOV EAX,DWORD PTR[DbgEvent.u.LoadDll.lpImageName]
			MOV DWORD PTR[SpecialDebug+16],EAX
			MOV EAX,DWORD PTR[DbgEvent.u.LoadDll.fUnicode]
			MOV DWORD PTR[SpecialDebug+20],EAX
			INVOKE LoadLibraryManager,addr SpecialDebug
			.if DWORD PTR[CustomHandler.hLoadDll] != 0
				PUSH offset SpecialDebug
				CALL DWORD PTR[CustomHandler.hLoadDll]
				XOR EAX,EAX
			.endif
			.if BPX_DLLCallBack != NULL
				INVOKE RtlZeroMemory,addr szDLLTestFileName,1024
				INVOKE GetFileSize,DWORD PTR[DbgEvent.u.LoadDll.hFile],NULL
				MOV ESI,EAX
				INVOKE CreateFileMapping,DWORD PTR[DbgEvent.u.LoadDll.hFile],NULL,PAGE_READONLY,NULL,ESI,NULL
				.if EAX != NULL
					MOV ESI,EAX
					INVOKE MapViewOfFile,ESI,FILE_MAP_READ,NULL,NULL,NULL
					.if EAX != NULL
						MOV EDI,EAX
						INVOKE GetCurrentProcess
						MOV EBX,EAX
						INVOKE GetMappedFileNameA,EBX,EDI,addr szDLLTestFileName,1024
						MOV EBX,offset DebugLibraryName
						INVOKE lstrlen,EBX
						ADD EBX,EAX
						.while BYTE PTR[EBX] != "\"
							DEC EBX
						.endw
						PUSH EBX
						MOV EBX,offset szDLLTestFileName
						INVOKE lstrlen,EBX
						ADD EBX,EAX
						.while BYTE PTR[EBX] != "\"
							DEC EBX
						.endw
						POP ECX
						INVOKE lstrcmpi,EBX,ECX
						.if EAX == NULL
							MOV EAX,DWORD PTR[DbgEvent.u.LoadDll.lpBaseOfDll]
							MOV BPX_DLLLoaderBase,EAX
							ADD EAX,BPX_DLLEntryPoint
			                                PUSH BPX_DLLCallBack
			                                PUSH 1
			                                PUSH EAX
							CALL SetBPX
							MOV BPX_DLLCallBack,NULL
						.endif
						INVOKE UnmapViewOfFile,EDI
					.endif
					INVOKE CloseHandle,ESI
				.endif
			.endif
		.endif
 ;
 ; UNLOAD_DLL_DEBUG_EVENT
 ;
		.if DWORD PTR[DbgEvent.dwDebugEventCode] == UNLOAD_DLL_DEBUG_EVENT
			.if DWORD PTR[CustomHandler.hUnloadDll] != 0
				MOV EAX,DWORD PTR[DbgEvent.u.UnloadDll.lpBaseOfDll]
				MOV DWORD PTR[SpecialDebug],EAX

				PUSH offset SpecialDebug
				CALL DWORD PTR[CustomHandler.hUnloadDll]
				XOR EAX,EAX
			.endif
		.endif
 ;
 ; OUTPUT_DEBUG_STRING_EVENT
 ;
		.if DWORD PTR[DbgEvent.dwDebugEventCode] == OUTPUT_DEBUG_STRING_EVENT
			.if DWORD PTR[CustomHandler.hOutputDebugString] != 0
				MOV EAX,DWORD PTR[DbgEvent.u.DebugString.lpDebugStringData]
				MOV DWORD PTR[SpecialDebug],EAX
				MOV EAX,DWORD PTR[DbgEvent.u.DebugString.fUnicode]
				MOV DWORD PTR[SpecialDebug+4],EAX
				MOV EAX,DWORD PTR[DbgEvent.u.DebugString.nDebugStringiLength]
				MOV DWORD PTR[SpecialDebug+6],EAX

				PUSH offset SpecialDebug
				CALL DWORD PTR[CustomHandler.hOutputDebugString]
				XOR EAX,EAX
			.endif
		.endif
 ;
 ; EXCEPTION_DEBUG_EVENT
 ;
		.if DWORD PTR[DbgEvent.dwDebugEventCode] == EXCEPTION_DEBUG_EVENT
			.if DWORD PTR[DbgEvent.u.Exception.dwFirstChance] == FALSE
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
				MOV DWORD PTR[retnData],EAX
				MOV DBG_Code,DBG_EXCEPTION_NOT_HANDLED
				INVOKE ContinueDebugEvent,DWORD PTR[DbgEvent.dwProcessId],DWORD PTR[DbgEvent.dwThreadId],DBG_Code
				MOV EAX,offset _exit_debug_loop
				JMP EAX
			.else
				MOV EBX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
				.if SEHGoneWildProtection == 1 && EAX == LastException && EAX != STATUS_BREAKPOINT && EAX != STATUS_GUARD_PAGE_VIOLATION && EAX != STATUS_SINGLE_STEP
					.if EBX != LastExceptionAddress && LastExceptionAddress != NULL && LastException == STATUS_ACCESS_VIOLATION
						INC SEHGoneWild
						.if SEHGoneWild == 20
							MOV SEHGoneWild,0
							CALL StopDebug
						.endif
					.endif
				.elseif EAX != LastException
					MOV LastException,0
				.endif
				MOV LastException,EAX
				MOV LastExceptionAddress,EBX
			.endif
			INC DWORD PTR[ExceptionNumber]
			MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
 ;
 ; Custom handler
 ;
			.if DWORD PTR[CustomHandler.hEverythingElse] != 0
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
				PUSH EAX
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
				CALL DWORD PTR[CustomHandler.hEverythingElse]
			.endif
 ;
 ; INT3 breakpoint
 ;
			.if EAX == STATUS_BREAKPOINT
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
				.if DWORD PTR[CustomHandler.hBreakPoint] != 0
					PUSH EAX
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
					CALL DWORD PTR[CustomHandler.hBreakPoint]
				.else
   ;
   ; Proveravamo da li smo mi postavili bpx?
   ;
					MOV EBX,offset BPX_List
					XOR ECX,ECX
					MOV EDX,-1
					.while ECX <= DWORD PTR[MAX_BPX_COUNT]
						.if DWORD PTR[EBX] == EAX
							MOV EDX,4
							IMUL EDX,ECX
							MOV ECX,DWORD PTR[MAX_BPX_COUNT]
						.endif
						INC ECX
						ADD EBX,4
					.endw
   ;
   ; Vracamo bpx, postavljamo singleshot na sledecu instrukciju i nastavljamo izvrsavanje
   ;	
					MOV EBX,offset BPX_Type
					LEA EBX,DWORD PTR[EBX+EDX]
					.if EDX != -1 && BYTE PTR[EBX] == 1
						PUSH EAX				;SingleShot
						CALL RestoreBPX
						PUSH 0
						CALL GetContextData			;Uzimamo context
						CALL SetBPXContextData			;Vracamo EIP za 1,pre INT3a
						MOV DWORD PTR[BPX_RestoreAddr],0
					.elseif EDX != -1 && BYTE PTR[EBX] == 0
						PUSH EAX				;Save EIP

						PUSH EAX				;Always
						CALL RestoreBPX				;DeleteBPX

						PUSH 0
						CALL GetContextData			;Uzimamo context

						MOV EBX,DWORD PTR[DbgContext.regFlag]
						XOR EBX,100h
						MOV DWORD PTR[DbgContext.regFlag],EBX

						CALL UpdateContextData			;SingleStep via TrapFlag
						CALL SetBPXContextData			;Vracamo EIP za 1,pre INT3a

						POP EAX					;Restore EIP
						MOV DWORD PTR[BPX_RestoreAddr],EAX
					.endif
   ;
   ; Pozivamo moguce BPX_CallBackove
   ;
					MOV EBX,offset BPX_CallBack
					LEA EBX,DWORD PTR[EBX+EDX]
					.if EDX != -1 && DWORD PTR[EBX] != 0
						CALL DWORD PTR[EBX]
					.endif
   ;
   ; HideDBG ;)
   ;
					.if DWORD PTR[FirstBPX] == 1
						CALL HideDbg
						.if GlobalAttachCallback != NULL
							CALL GlobalAttachCallback
							MOV GlobalAttachCallback,NULL
						.endif
					.endif
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
					.if DWORD PTR[HideDbgBPX] == EAX
						PUSHAD
						INVOKE VirtualFreeEx,DWORD PTR[hProcess],DWORD PTR[HideDbgAlloc],1000h,MEM_DECOMMIT
						INVOKE VirtualFreeEx,DWORD PTR[hProcess],DWORD PTR[HideDbgAlloc],NULL,MEM_RELEASE
						POPAD
						PUSH DWORD PTR[HideDbgLastEIP]
						PUSH rEIP
						CALL SetContextData
						MOV DWORD PTR[HideDbgBPX],0
						MOV DWORD PTR[HideDbgLastEIP],0
						MOV DWORD PTR[HideDbgAlloc],0
						MOV DBG_Code,DBG_CONTINUE
						MOV EAX,offset _dbg_loop
						JMP EAX
					.endif
   ;
   ; Ako mi nismo postavili INT3
   ;
					.if EDX == -1 && DWORD PTR[FirstBPX] == 0
						MOV DBG_Code,DBG_EXCEPTION_NOT_HANDLED
						INVOKE ContinueDebugEvent,DWORD PTR[DbgEvent.dwProcessId],DWORD PTR[DbgEvent.dwThreadId],DBG_Code
						MOV EAX,offset _dbg_loop_end
						JMP EAX
					.endif
					MOV DWORD PTR[FirstBPX],0
				.endif
				MOV DWORD PTR[NotHandled],1
			.endif
 ;
 ; PageGuard event
 ;
			.if EAX == STATUS_GUARD_PAGE_VIOLATION
				.if DWORD PTR[BPX_PageGuard] != 0
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
					CALL DWORD PTR[BPX_PageGuard]
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
				.endif
				.if DWORD PTR[CustomHandler.hPageGuard] != 0
					PUSH EAX
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
					CALL DWORD PTR[CustomHandler.hPageGuard]
				.endif
;				MOV DWORD PTR[BPX_PageGuard],0
				MOV DWORD PTR[NotHandled],1
				MOV DBG_Code,DBG_CONTINUE
				MOV EAX,offset _dbg_loop
				JMP EAX
			.endif
 ;
 ; SigleStep event
 ;
			.if EAX == STATUS_SINGLE_STEP
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
				.if DWORD PTR[BPX_SafeDelete] != 0
					PUSH DWORD PTR[BPX_SafeDelete]
					CALL DeleteBPX
					MOV DWORD PTR[BPX_SafeDelete],0
					MOV DWORD PTR[NotHandled],1
					MOV DBG_Code,DBG_CONTINUE
					MOV EAX,offset _dbg_loop
					JMP EAX
				.endif
				.if DWORD PTR[BPX_RestoreAddr] != 0
					PUSH DWORD PTR[BPX_RestoreAddr]
					CALL ActivateBPX
					MOV DWORD PTR[BPX_RestoreAddr],0
					MOV DWORD PTR[NotHandled],1
					MOV DBG_Code,DBG_CONTINUE
					MOV EAX,offset _dbg_loop
					JMP EAX
				.endif
				.if DWORD PTR[CustomHandler.hSingleStep] != 0
					PUSH EAX
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
					CALL DWORD PTR[CustomHandler.hSingleStep]
				.endif
				MOV DWORD PTR[NotHandled],1
				MOV DBG_Code,DBG_EXCEPTION_NOT_HANDLED
				XOR EAX,EAX 
				MOV EAX,offset _dbg_loop
				JMP EAX
			.endif
 ;
 ; Access violation
 ;
			.if EAX == STATUS_ACCESS_VIOLATION
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
				.if DWORD PTR[CustomHandler.hAccessViolation] != 0
					PUSH EAX
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
					CALL DWORD PTR[CustomHandler.hAccessViolation]
				.endif
				MOV DWORD PTR[NotHandled],1
				MOV DBG_Code,DBG_EXCEPTION_NOT_HANDLED
				INVOKE ContinueDebugEvent,DWORD PTR[DbgEvent.dwProcessId],DWORD PTR[DbgEvent.dwThreadId],DBG_Code
				MOV EAX,offset _dbg_loop_end
				JMP EAX
			.endif
 ;
 ; Invalid lock sequence
 ;
			.if EAX == 0C000001Eh
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
				MOV DWORD PTR[NotHandled],1
				MOV DBG_Code,DBG_EXCEPTION_NOT_HANDLED
				XOR EAX,EAX
			.endif
 ;
 ; Illegal instruction
 ;
			.if EAX == STATUS_ILLEGAL_INSTRUCTION
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
				.if DWORD PTR[CustomHandler.hIllegalInstruction] != 0
					PUSH EAX
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
					CALL DWORD PTR[CustomHandler.hIllegalInstruction]
				.endif
				MOV DWORD PTR[NotHandled],1
				MOV DBG_Code,DBG_EXCEPTION_NOT_HANDLED
				XOR EAX,EAX
			.endif
 ;
 ; Non continuable exception
 ;
			.if EAX == STATUS_NONCONTINUABLE_EXCEPTION
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
				.if DWORD PTR[CustomHandler.hNonContinuableException] != 0
					PUSH EAX
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
					CALL DWORD PTR[CustomHandler.hNonContinuableException]
				.endif
				MOV DWORD PTR[retnData],STATUS_NONCONTINUABLE_EXCEPTION
				MOV DWORD PTR[NotHandled],1
				MOV DBG_Code,DBG_EXCEPTION_NOT_HANDLED
				INVOKE ContinueDebugEvent,DWORD PTR[DbgEvent.dwProcessId],DWORD PTR[DbgEvent.dwThreadId],DBG_Code
				MOV EAX,offset _exit_debug_loop
				JMP EAX
				XOR EAX,EAX
			.endif
 ;
 ; Bound array exeption
 ;
			.if EAX == STATUS_ARRAY_BOUNDS_EXCEEDED
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
				.if DWORD PTR[CustomHandler.hArrayBoundsException] != 0
					PUSH EAX
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
					CALL DWORD PTR[CustomHandler.hArrayBoundsException]
				.endif
				MOV DWORD PTR[NotHandled],1
				MOV DBG_Code,DBG_EXCEPTION_NOT_HANDLED
				XOR EAX,EAX
			.endif
 ;
 ; Float denormal
 ;
			.if EAX == STATUS_FLOAT_DENORMAL_OPERAND 
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
				.if DWORD PTR[CustomHandler.hFloatDenormalOperand] != 0
					PUSH EAX
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
					CALL DWORD PTR[CustomHandler.hFloatDenormalOperand]
				.endif
				MOV DWORD PTR[NotHandled],1
				MOV DBG_Code,DBG_EXCEPTION_NOT_HANDLED
				XOR EAX,EAX
			.endif
 ;
 ; Float devision by zero
 ;
			.if EAX == STATUS_FLOAT_DIVIDE_BY_ZERO 
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
				.if DWORD PTR[CustomHandler.hFloatDevideByZero] != 0
					PUSH EAX
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
					CALL DWORD PTR[CustomHandler.hFloatDevideByZero]
				.endif
				MOV DWORD PTR[NotHandled],1
				MOV DBG_Code,DBG_EXCEPTION_NOT_HANDLED
				XOR EAX,EAX
			.endif
 ;
 ; Integer devision by zero
 ;
			.if EAX == STATUS_INTEGER_DIVIDE_BY_ZERO 
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
				.if DWORD PTR[CustomHandler.hIntegerDevideByZero] != 0
					PUSH EAX
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
					CALL DWORD PTR[CustomHandler.hIntegerDevideByZero]
				.endif
				MOV DWORD PTR[NotHandled],1
				MOV DBG_Code,DBG_EXCEPTION_NOT_HANDLED
				XOR EAX,EAX
			.endif
 ;
 ; Integer overflow
 ;
			.if EAX == STATUS_INTEGER_OVERFLOW
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
				.if DWORD PTR[CustomHandler.hIntegerOverflow] != 0
					PUSH EAX
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
					CALL DWORD PTR[CustomHandler.hIntegerOverflow]
				.endif
				MOV DWORD PTR[NotHandled],1
				MOV DBG_Code,DBG_EXCEPTION_NOT_HANDLED
				XOR EAX,EAX
			.endif
 ;
 ; Privileged instruction
 ;
			.if EAX == STATUS_PRIVILEGED_INSTRUCTION
				MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionAddress]
				.if DWORD PTR[CustomHandler.hPrivilegedInstruction] != 0
					PUSH EAX
					MOV EAX,DWORD PTR[DbgEvent.u.Exception.pExceptionRecord.ExceptionCode]
					CALL DWORD PTR[CustomHandler.hPrivilegedInstruction]
				.endif
				MOV DBG_Code,DBG_EXCEPTION_NOT_HANDLED
				XOR EAX,EAX
			.endif
		.endif
 _dbg_loop:
		INVOKE ContinueDebugEvent,DWORD PTR[DbgEvent.dwProcessId],DWORD PTR[DbgEvent.dwThreadId],DBG_Code
		.if DBG_Code != DBG_EXCEPTION_NOT_HANDLED
			CMP EAX,1
			JNE _exit_debug_loop
		.endif
 _dbg_loop_end:
	.endw

 _exit_debug_loop:
	INVOKE LoadLibraryCleanupManager
	INVOKE CloseHandle,LockHandle
	INVOKE CloseHandle,DWORD PTR[hThread]
	INVOKE CloseHandle,DWORD PTR[hProcess]
	MOV DWORD PTR[hProcess],0
	MOV DWORD PTR[hThread],0
	MOV DWORD PTR[hProcessId],0
	MOV DWORD PTR[hThreadId],0

	POPAD
	MOV EAX,DWORD PTR[retnData]
	RET

 _clear_special_debug:
	PUSHAD
	INVOKE RtlZeroMemory,addr SpecialDebug,100
	POPAD
	RET

DebugLoop endp
;------------------------------------------------------------------
ForceClose proc
	PUSHAD
	CALL StopDebug			;Terminate the debugee!
	INVOKE ContinueDebugEvent,hProcessId,hThreadId,DBG_CONTINUE
	XOR EAX,EAX
	INC EAX
	.while EAX == 1
		INVOKE WaitForDebugEvent,addr DbgEvent,100
		INVOKE ContinueDebugEvent,hProcessId,hThreadId,DBG_CONTINUE
	.endw

	INVOKE LoadLibraryCleanupManager
	INVOKE CloseHandle,LockHandle
	INVOKE CloseHandle,DWORD PTR[hThread]
	INVOKE CloseHandle,DWORD PTR[hProcess]
	MOV DWORD PTR[hProcess],0
	MOV DWORD PTR[hThread],0
	MOV DWORD PTR[hProcessId],0
	MOV DWORD PTR[hThreadId],0
	POPAD
	RET
ForceClose endp
;------------------------------------------------------------------
LoadLibraryCleanupManager proc
	PUSHAD
	
	MOV EDI,offset LoadedLibraryHandles
	.while DWORD PTR[EDI] != NULL
		INVOKE CloseHandle,DWORD PTR[EDI]
		ADD EDI,4
	.endw
	INVOKE RtlZeroMemory,addr LoadedLibraryHandles,1024

	POPAD
	RET
LoadLibraryCleanupManager endp
;------------------------------------------------------------------
LoadLibraryManager proc DbgStruct:DWORD
	LOCAL hLoadedDll_Base :DWORD
	LOCAL hLoadedDll_File :DWORD
	PUSHAD

	MOV EAX,DbgStruct
	ASSUME EAX:PTR LOAD_DLL_DEBUG_INFO
	MOV EBX,DWORD PTR[EAX].lpBaseOfDll
	MOV hLoadedDll_Base,EBX
	MOV EAX,DWORD PTR[EAX].hFile
	MOV hLoadedDll_File,EAX
	ASSUME EAX:NOTHING
	MOV EDI,offset LoadedLibraryHandles
	.while DWORD PTR[EDI] != NULL
		ADD EDI,4
	.endw
	MOV DWORD PTR[EDI],EAX

	POPAD
	RET
LoadLibraryManager endp
;------------------------------------------------------------------
_dlde:
	include ..\..\ldex86bin.inc
;------------------------------------------------------------------
LengthDisassemble proc dwAddress:DWORD
	PUSHAD
	.if hProcess > 0
		MOV EAX,dwAddress
		INVOKE ReadProcessMemory,DWORD PTR[hProcess],EAX,addr DBG_ReadData,20,addr NumOfBytesWR	
		LEA EAX,DWORD PTR[DBG_ReadData]
	.else
		XOR EAX,EAX
	.endif
	MOV DWORD PTR[ESP+1Ch],EAX
	POPAD
	.if EAX != NULL
		PUSH EAX
		CALL _dlde
	.endif
	RET
LengthDisassemble endp
;------------------------------------------------------------------
LengthDisassembleEx proc dwProcessHandle:DWORD,dwAddress:DWORD
	PUSHAD
	.if dwProcessHandle > 0
		MOV EAX,dwAddress
		INVOKE ReadProcessMemory,dwProcessHandle,EAX,addr DBG_ReadData,20,addr NumOfBytesWR	
		LEA EAX,DWORD PTR[DBG_ReadData]
	.else
		XOR EAX,EAX
	.endif
	MOV DWORD PTR[ESP+1Ch],EAX
	POPAD
	.if EAX != NULL
		PUSH EAX
		CALL _dlde
	.endif
	RET
LengthDisassembleEx endp
;------------------------------------------------------------------
End LibMain