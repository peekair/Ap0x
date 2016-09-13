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
    include ..\..\Relocater.inc    

    includelib \masm32\lib\user32.lib
    includelib \masm32\lib\kernel32.lib
    includelib \masm32\lib\psapi.lib

;------------------------------------------------------------------
      UnmapFile PROTO
      MapFile PROTO :DWORD
      MapFileEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
      UnmapFileEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
      ConvertVA2FO PROTO :DWORD,:DWORD
;------------------------------------------------------------------

    return MACRO arg
      mov eax, arg
      ret
    ENDM

    .data

    .data?
 ;
 ; File mapping
 ;
	FileHWND dd ?
	FileSize dd ?
	FileMap dd ?
	FileMapVA dd ?
	ImageBase dd ?
 ;
 ; Engine variables
 ;
	MemoryRelocation dd ?
	MemoryRelocationSize dd ?
	RelocationLastPage dd ?
	RelocationStartPosition dd ?
	RelocationWritePosition dd ?
	dwOldImageBase dd ?
	dwNewImageBase dd ?
	MemInfo MEMORY_BASIC_INFORMATION <?>
    .code

;------------------------------------------------------------------
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
GetModuleVersion proc
	MOV EAX,0100h
	RET
GetModuleVersion endp
;------------------------------------------------------------------
RelocaterInit proc dwMemSize:DWORD,inOldImageBase:DWORD,inNewImageBase:DWORD
	PUSHAD

	INVOKE IsBadReadPtr,MemoryRelocation,4
	.if MemoryRelocation == NULL || EAX != NULL
		MOV EAX,dwMemSize
		.if EAX == NULL
			MOV EAX,100*1024
		.endif
		INVOKE VirtualAlloc,NULL,EAX,MEM_COMMIT,PAGE_EXECUTE_READWRITE
		MOV MemoryRelocation,EAX
	.else
		INVOKE RtlZeroMemory,MemoryRelocation,dwMemSize
	.endif
	MOV RelocationLastPage,0
	MOV EAX,MemoryRelocation
	MOV RelocationStartPosition,EAX
	ADD EAX,8
	MOV RelocationWritePosition,EAX
	
	MOV EAX,inOldImageBase
	MOV dwOldImageBase,EAX
	MOV EAX,inNewImageBase
	MOV dwNewImageBase,EAX

	POPAD
	RET
RelocaterInit endp
;------------------------------------------------------------------
RelocaterAddNewRelocation proc hProcess:DWORD,dwRelocateAddress:DWORD,dwRelocateState:DWORD
	LOCAL NumOfBytesWR :DWORD
	LOCAL RelocateBuffer :DWORD
	PUSHAD

	INVOKE VirtualQueryEx,hProcess,dwRelocateAddress,addr MemInfo,sizeof MemInfo
	MOV EAX,RelocationLastPage
	.if DWORD PTR[MemInfo].BaseAddress != EAX || EAX == NULL
		MOV EAX,DWORD PTR[MemInfo].BaseAddress
		MOV RelocationLastPage,EAX
		MOV EDI,RelocationWritePosition
		MOV ESI,RelocationStartPosition
		.if DWORD PTR[ESI] == NULL
			SUB EAX,dwNewImageBase
			MOV DWORD PTR[ESI],EAX
		.else
			SUB EAX,dwNewImageBase
			SUB EDI,ESI
			MOV DWORD PTR[ESI+4],EDI
			MOV EDI,RelocationWritePosition
			MOV RelocationStartPosition,EDI
			MOV DWORD PTR[EDI],EAX
			ADD EDI,8
			MOV RelocationWritePosition,EDI
		.endif
	.endif
	MOV EDI,RelocationWritePosition
	MOV EAX,dwRelocateAddress
	SUB EAX,RelocationLastPage
	XOR EAX,00003000h
	MOV WORD PTR[EDI],AX
	ADD RelocationWritePosition,2

	POPAD
	RET
RelocaterAddNewRelocation endp
;------------------------------------------------------------------
RelocaterEstimatedSize proc
	MOV EAX,RelocationWritePosition
	SUB EAX,MemoryRelocation
	ADD EAX,8
	RET
RelocaterEstimatedSize endp
;------------------------------------------------------------------
RelocaterExportRelocation proc dwMapedExportVA:DWORD,dwExportRVA:DWORD,dwFileMapVA:DWORD
	LOCAL RelocationSize :DWORD
	PUSHAD

	.if RelocationStartPosition != -1
		MOV EDI,RelocationWritePosition
		MOV ESI,RelocationStartPosition
		SUB EDI,ESI
		MOV DWORD PTR[ESI+4],EDI
	.endif

	MOV ECX,RelocationWritePosition
	SUB ECX,MemoryRelocation
	MOV RelocationSize,ECX
	INVOKE RtlMoveMemory,dwMapedExportVA,MemoryRelocation,ECX
	
	INVOKE VirtualFree,MemoryRelocation,MemoryRelocationSize,MEM_DECOMMIT
	INVOKE VirtualFree,MemoryRelocation,NULL,MEM_RELEASE
	
 ;
 ; Konacno updateujemo PE.Header
 ;
	MOV EAX,dwFileMapVA			; Parametar 2 = FileMapVA
 ;
 ; elfa_new
 ;
	MOV ECX,DWORD PTR[EAX+3Ch]
 ;
 ; PEHeader
 ;
	LEA ECX,DWORD PTR[EAX+ECX]
	MOV EAX,ECX
	MOV EBX,dwNewImageBase
	MOV DWORD PTR[EAX+34h],EBX
	ADD EAX,0A0h

	MOV EBX,dwExportRVA
	MOV DWORD PTR[EAX],EBX
	ADD EAX,4
	MOV EBX,RelocationSize
	MOV DWORD PTR[EAX],EBX

	POPAD
	RET
RelocaterExportRelocation endp
;------------------------------------------------------------------
RelocaterChangeFileBase proc dwFileName:DWORD,NewImageBase:DWORD
	LOCAL Error :DWORD
	LOCAL RelocationTable :DWORD
	LOCAL RelocationSize :DWORD
 	PUSHAD

	MOV Error,0
	INVOKE MapFile,dwFileName
	.if FileMapVA != 0
		MOV EBX,FileMapVA
		.if WORD PTR[EBX] != 'ZM'
			MOV Error,1
		.endif
		.if Error == NULL
			ADD EBX,3Ch
			ADD BX,WORD PTR[EBX]		;WinME/98/95 compatibility!
			SUB BX,3Ch			;
			.if WORD PTR[EBX] != 'EP'
				MOV Error,2
			.endif
			.if Error == NULL
				MOV EAX,DWORD PTR[EBX+034h]
				MOV ImageBase,EAX
				MOV EAX,DWORD PTR[EBX+0A0h]
				ADD EAX,ImageBase
				INVOKE ConvertVA2FO,FileMapVA,EAX
				ADD EAX,FileMapVA
				MOV RelocationTable,EAX
				.if EAX != FileMapVA
					MOV ESI,RelocationTable
					.if ESI != 0
						MOV EDI,ImageBase
						MOV EAX,NewImageBase
						.if EAX != EDI
							.while DWORD PTR[ESI] != 0
								MOV EDX,DWORD PTR[ESI]
								MOV EAX,DWORD PTR[ESI+4]
								MOV RelocationSize,EAX
								ADD RelocationSize,ESI
								ADD ESI,8
								.while ESI < RelocationSize
									MOVZX EAX,WORD PTR[ESI]
									MOV EBX,EAX
									SHR EBX,12
									MOV ECX,EBX
									IMUL EBX,1000h
									SUB EAX,EBX
									ADD EAX,EDX
									ADD EAX,ImageBase
									.if ECX == 3
										INVOKE ConvertVA2FO,FileMapVA,EAX
										ADD EAX,FileMapVA
										SUB DWORD PTR[EAX],EDI
										MOV ECX,NewImageBase
										ADD DWORD PTR[EAX],ECX
									.endif
									ADD ESI,2
								.endw
							.endw
						.endif
					.endif
				.else
					MOV Error,3		;No reloc section
				.endif
				MOV EBX,FileMapVA
				ADD EBX,3Ch
				ADD BX,WORD PTR[EBX]		;WinME/98/95 compatibility!
				SUB BX,3Ch			;
				MOV EAX,NewImageBase
				MOV DWORD PTR[EBX+034h],EAX
				INVOKE UnmapFile
			.endif
		.endif
	.endif

	POPAD
	MOV EAX,Error
	RET
RelocaterChangeFileBase endp
;------------------------------------------------------------------
RelocaterGrabRelocationTable proc hProcess:DWORD,dwMemStart:DWORD,dwMemSize:DWORD
	LOCAL Return :DWORD
	LOCAL OldProtect :DWORD
	LOCAL NumOfBytesWR :DWORD	
	PUSHAD

	MOV Return,NULL
	INVOKE VirtualQueryEx,hProcess,dwMemStart,addr MemInfo,sizeof MemInfo
	MOV EAX,DWORD PTR[MemInfo.AllocationProtect]
	MOV DWORD PTR[OldProtect],EAX
	INVOKE VirtualProtectEx,hProcess,dwMemStart,dwMemSize,PAGE_EXECUTE_READWRITE,addr OldProtect

	INVOKE ReadProcessMemory,hProcess,dwMemStart,MemoryRelocation,dwMemSize,addr NumOfBytesWR
	.if EAX != NULL
		MOV EAX,MemoryRelocation
		MOV RelocationWritePosition,EAX
		MOV EAX,dwMemSize
		ADD RelocationWritePosition,EAX
		MOV RelocationStartPosition,-1
	.endif

	POPAD
	MOV EAX,Return
	RET
RelocaterGrabRelocationTable endp
;------------------------------------------------------------------
RelocaterGrabRelocationTableEx proc hProcess:DWORD,dwMemStart:DWORD,dwMemSize:DWORD,dwSizeOfImage:DWORD
	LOCAL Return :DWORD
	LOCAL OldProtect :DWORD
	LOCAL NumOfBytesWR :DWORD
	LOCAL ProcReadAlloc :DWORD
	PUSHAD

	MOV Return,NULL
	INVOKE VirtualQueryEx,hProcess,dwMemStart,addr MemInfo,sizeof MemInfo
	MOV EAX,DWORD PTR[MemInfo.RegionSize]
	.if dwMemSize == NULL || EAX < dwMemSize
		MOV ESI,DWORD PTR[MemInfo.RegionSize]
	.else
		MOV ESI,dwMemSize
	.endif
	MOV EAX,DWORD PTR[MemInfo.AllocationProtect]
	MOV DWORD PTR[OldProtect],EAX
	INVOKE VirtualProtectEx,hProcess,dwMemStart,dwMemSize,PAGE_EXECUTE_READWRITE,addr OldProtect
	INVOKE VirtualAlloc,NULL,ESI,MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV DWORD PTR[ProcReadAlloc],EAX

	INVOKE ReadProcessMemory,hProcess,dwMemStart,ProcReadAlloc,ESI,addr NumOfBytesWR
	.if EAX != NULL
		MOV ESI,DWORD PTR[ProcReadAlloc]
		MOV EBX,dwSizeOfImage
		.while DWORD PTR[ESI] != NULL && DWORD PTR[ESI+4] != NULL && DWORD PTR[ESI] < EBX && DWORD PTR[ESI+4] <= 2000h
			ADD ESI,DWORD PTR[ESI+4]
		.endw
		SUB ESI,DWORD PTR[ProcReadAlloc]
		.if ESI > NULL
			PUSH ESI
			PUSH dwMemStart
			PUSH hProcess
			CALL RelocaterGrabRelocationTable
			MOV Return,EAX
		.endif
	.endif
	INVOKE VirtualFree,DWORD PTR[ProcReadAlloc],NULL,MEM_RELEASE

	POPAD
	MOV EAX,Return
	RET
RelocaterGrabRelocationTableEx endp
;------------------------------------------------------------------
RelocaterMakeSnapshoot proc hProcess:DWORD,dwSaveFileName:DWORD,dwMemStart:DWORD,dwMemSize:DWORD
	LOCAL hFile :DWORD
	LOCAL Return :DWORD
	LOCAL OldProtect :DWORD
	LOCAL NumOfBytesWR :DWORD
	LOCAL ProcReadAlloc :DWORD
	PUSHAD

	MOV Return,NULL
	INVOKE VirtualAlloc,NULL,dwMemSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV DWORD PTR[ProcReadAlloc],EAX

	INVOKE VirtualQueryEx,hProcess,dwMemStart,addr MemInfo,sizeof MemInfo
	MOV EAX,DWORD PTR[MemInfo.AllocationProtect]
	MOV DWORD PTR[OldProtect],EAX
	INVOKE VirtualProtectEx,hProcess,dwMemStart,dwMemSize,PAGE_EXECUTE_READWRITE,addr OldProtect

	INVOKE ReadProcessMemory,hProcess,dwMemStart,DWORD PTR[ProcReadAlloc],dwMemSize,addr NumOfBytesWR
	.if EAX != NULL
		INVOKE CreateFile,dwSaveFileName,GENERIC_READ+GENERIC_WRITE,NULL,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL
		.if EAX != -1
			MOV DWORD PTR[hFile],EAX
			INVOKE WriteFile,DWORD PTR[hFile],DWORD PTR[ProcReadAlloc],dwMemSize,addr NumOfBytesWR,NULL
			INVOKE CloseHandle,DWORD PTR[hFile]
			INC Return
		.endif
	.endif
	INVOKE VirtualFree,DWORD PTR[ProcReadAlloc],NULL,MEM_RELEASE

	POPAD
	MOV EAX,Return
	RET
RelocaterMakeSnapshoot endp
;------------------------------------------------------------------
RelocaterCompareTwoSnapshots proc hProcess:DWORD,dwLoadedImageBase:DWORD,ntSizeOfImage:DWORD,dwDump1:DWORD,dwDump2:DWORD,dwMemStart:DWORD
	LOCAL Return :DWORD
	LOCAL rsFileHWND1 :DWORD
	LOCAL rsFileSize1 :DWORD
	LOCAL rsFileMap1 :DWORD
	LOCAL rsFileMapVA1 :DWORD
	LOCAL rsFileHWND2 :DWORD
	LOCAL rsFileSize2 :DWORD
	LOCAL rsFileMap2 :DWORD
	LOCAL rsFileMapVA2 :DWORD
	PUSHAD

	MOV Return,NULL
	INVOKE MapFileEx,dwDump1,NULL,addr rsFileHWND1,addr rsFileSize1,addr rsFileMap1,addr rsFileMapVA1
	INVOKE MapFileEx,dwDump2,NULL,addr rsFileHWND2,addr rsFileSize2,addr rsFileMap2,addr rsFileMapVA2
	.if rsFileMapVA1 > NULL && rsFileMapVA2 > NULL
		MOV EAX,dwLoadedImageBase
		.if AX == NULL
			ROR EAX,8
			.if AX == NULL
				MOV EBX,4
			.else
				MOV EBX,3
			.endif
		.else
			MOV EBX,2
		.endif
		DEC EBX
		MOV EAX,dwLoadedImageBase
		ADD ntSizeOfImage,EAX

		MOV EDI,rsFileMapVA1
		MOV ESI,rsFileMapVA2
		MOV ECX,rsFileSize1
		CDQ
		.while ECX > 0
			MOVZX EAX,BYTE PTR[ESI]
			.if AL != BYTE PTR[EDI]
				PUSH ESI
				PUSH EDI
				MOV EBX,5
				XOR EDX,EDX
				.while EDX == NULL
					MOV EAX,ntSizeOfImage
					.if DWORD PTR[ESI] <= EAX
						MOV EAX,dwLoadedImageBase
						.if DWORD PTR[ESI] >= EAX
							INC EDX
						.endif
					.endif
					DEC EBX
					DEC ESI
					DEC EDI
				.endw
				INC ESI
				INC EDI

				.if EBX > NULL && EDX != NULL
					MOV EDX,dwMemStart
	                      		ADD EDX,ESI
	                      		SUB EDX,rsFileMapVA2
					INVOKE RelocaterAddNewRelocation,hProcess,EDX,NULL
					ADD EDI,3
					ADD ESI,3
					SUB ECX,3
					POP EAX
					POP EAX
				.else
					POP EDI
					POP ESI
				.endif
			.endif
			INC ESI
			INC EDI
			DEC ECX
		.endw
		INC Return
	.endif
	INVOKE UnmapFileEx,rsFileHWND1,rsFileSize1,rsFileMap1,rsFileMapVA1
	INVOKE UnmapFileEx,rsFileHWND2,rsFileSize2,rsFileMap2,rsFileMapVA2

	POPAD
	MOV EAX,Return
	RET
RelocaterCompareTwoSnapshots endp
;------------------------------------------------------------------
; Predefinisane funkcije
;------------------------------------------------------------------
MapFile PROC fName:DWORD
	PUSHAD
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
MapFileEx PROC fName:DWORD,dwReadOrWrite:DWORD,dwFileHWND:DWORD,dwFileSize:DWORD,dwFileMap:DWORD,dwFileMapVA:DWORD
	LOCAL Return :DWORD
	PUSHAD
	MOV Return,0
	INVOKE CreateFile,DWORD PTR[EBP+8],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
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
	INVOKE CreateFileMapping,DWORD PTR[EAX],NULL,2,NULL,DWORD PTR[EBX],NULL
	MOV EBX,dwFileMap
	MOV DWORD PTR[EBX],EAX
	INVOKE MapViewOfFile,DWORD PTR[EBX],4,NULL,NULL,NULL
	MOV EBX,dwFileMapVA
	MOV DWORD PTR[EBX],EAX
	POPAD
	MOV EAX,Return
	RET
MapFileEx ENDP
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
ConvertVA2FO PROC fMap:DWORD,fAddr:DWORD

	LOCAL Converted :DWORD

	PUSHAD
 ;
 ; Konverzija
 ;
	MOV EAX,fMap		; Parametar 1 = FileMapVA
	MOV EBX,fAddr		; Parametar 2 = Adresa za konverziju
	SUB EBX,DWORD PTR[ImageBase]
 ;
 ; elfa_new
 ;
	XOR ECX,ECX
	MOV CX,WORD PTR[EAX+3Ch]
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
		MOV EDX,DWORD PTR[EAX+8]
		MOV EDI,DWORD PTR[EAX+12]
		.if EBX >= EDI
			ADD EDI,EDX
			.if EBX < EDI
				MOV ECX,1
				SUB EBX,EDI
				ADD EBX,EDX
				ADD EBX,DWORD PTR[EAX+20]
;				ADD EBX,DWORD PTR[EBP+8]
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
ConvertVA2FO ENDP
;------------------------------------------------------------------
End LibMain