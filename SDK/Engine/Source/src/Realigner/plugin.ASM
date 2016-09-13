; #########################################################################
;
;          Build this DLL from the batch file called BldDLL.bat
;
; #########################################################################

    .586
    .model flat, stdcall
    option casemap :none   ; case sensitive

;------------------------------------------------------------------

	include \masm32\include\windows.inc
	include \masm32\include\kernel32.inc
	include \masm32\include\masm32.inc
	include \masm32\include\psapi.inc
	include ..\..\Realigner.inc	

	includelib \masm32\lib\kernel32.lib
	includelib \masm32\lib\masm32.lib
	includelib \masm32\lib\psapi.lib
;------------------------------------------------------------------
; Define functions
;
      UnmapFile PROTO
      MapFile PROTO :DWORD
      IsBadReadPtrEx PROTO :DWORD,:DWORD
      GetSectionData PROTO :DWORD,:DWORD
      PreProcessResourceTable PROTO
      GetModuleExportNumber PROTO :DWORD
      ValidateImportTable PROTO :DWORD,:DWORD,:DWORD
      ConvertVAtoFileOffset PROTO :DWORD,:DWORD,:DWORD
      ReadHandler PROTO C :DWORD,:DWORD,:DWORD,:DWORD
      SafeHandler PROTO C :DWORD,:DWORD,:DWORD,:DWORD
      GetCommonControlsData PROTO
;
; End definition
;------------------------------------------------------------------
NtImportDirectory STRUCT
	ImportLockupTable dd ?
	TimeDateStamp dd ?
	ForwarderChain dd ?
	NameRVA dd ?
	ImportAddressTable dd ?
NtImportDirectory ENDS

NtSectionInfo STRUCT
	NtSectionName db 8 dup(?)			;+0
	SectionVirtualSize dd ?				;+8
	SectionVirtualAddress dd ?			;+12
	SectionSizeOfRawData dd ?			;+16
	SectionPointerToRawData dd ?			;+20
	SectionPointerToRelocations dd ?		;+24
	SectionPointerToLinenumbers dd ?		;+28
	SectionNumberOfRelocations dw ?			;+32
	SectionNumberOfLinenumbers dw ?			;+34
	SectionCharacteristics dd ?			;+36
NtSectionInfo ENDS

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

NtTLSDirectory STRUCT
	RawDataStartVA dd ?
	RawDataEndVA dd ?
	AddressOfIndex dd ?
	AddressOfCallbacks dd ?
	SizeOfZeroFill dd ?
	TLSCharacteristics dd ?
NtTLSDirectory ENDS

NtImportDirectory STRUCT
	ImportLockupTable dd ?
	TimeDateStamp dd ?
	ForwarderChain dd ?
	NameRVA dd ?
	ImportAddressTable dd ?
NtImportDirectory ENDS

NtExportTable STRUCT
	ExportFlags dd ?
	TimeDateStamp dd ?
	MajorVer dw ?
	MinorVer dw ?
	NameRVA dd ?
	OrdinalBase dd ?
	AddressTableEntries dd ?
	NumberOfNamePointers dd ?
	ExportAddressTableRVA dd ?
	NamePointerRVA dd ?
	OrdinalTableRVA dd ?
NtExportTable ENDS

sSEH STRUCT
	OrgEsp            DD ?
	OrgEbp            DD ?
	SaveEip           DD ?
sSEH ENDS

InstSehFrame2 MACRO ContinueAddr
	ASSUME FS : NOTHING

	MOV  SEH2.SaveEip, ContinueAddr
	MOV  SEH2.OrgEbp, EBP
	PUSH OFFSET ReadHandler
	PUSH FS:[0]
	MOV  SEH2.OrgEsp, ESP
	MOV  FS:[0], ESP
ENDM

KillSehFrame MACRO
	POP  FS:[0]
	ADD  ESP, 4
ENDM

    return MACRO arg
      mov eax, arg
      ret
    ENDM
;------------------------------------------------------------------
 .data
	szCOMCTL32 db "comctl32.dll",0h
	szCOMCTL32RelativePath db "\system32\comctl32.dll",0h
	szKernel32 db "kernel32.dll",0h
 .data?
        hEngine dd ?
        hComCtl32 dd ?
 ;
 ; File mapping variables
 ;
	FileHWND dd ?
	FileSize dd ?
	oldFileSize dd ?
	FileMap dd ?
	FileMapVA dd ?

	ImageBase dd ?
 	ContinueSafeAddress dd ?
 	ContinueSafeError dd ?
 	ContinueSafeESP dd ?
 	ContinueSafeEBP dd ?
	SEH2 sSEH <?>
	BAD_READ_ERROR_EXIT dd ?
	MemInfo MEMORY_BASIC_INFORMATION <?>
	ValidationNotifyOnBadImport dd ?
	PE32SelectedSectionInfo db 40 dup(?)
	szMiscBuff db 1024 dup(?)
 .code

;------------------------------------------------------------------
LibMain proc hInstDLL:DWORD, reason:DWORD, unused:DWORD

        .if reason == DLL_PROCESS_ATTACH
        	MOV EAX,hInstDLL
        	MOV hEngine,EAX
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
RealignPE proc dwFileMap:DWORD,dwFileSize:DWORD,dwRealingMode:DWORD
	LOCAL FileAlignment :DWORD
	LOCAL PE32Offset :DWORD
	LOCAL CurrentSection :DWORD
	LOCAL Return :DWORD
	PUSHAD
	
	MOV Return,-1
	MOV CurrentSection,0
	INVOKE IsBadReadPtrEx,dwFileMap,dwFileSize
	.if EAX == NULL
		MOV EDI,dwFileMap
		ADD EDI,DWORD PTR[EDI+03Ch]
		ASSUME EDI:PTR FullPE32Header
		MOV PE32Offset,EDI
		MOVZX EAX,WORD PTR[EDI].SizeOfOptionalHeader
		MOVZX ESI,WORD PTR[EDI].NumberOfSections
		.if DWORD PTR[EDI].FileAlignment == 1000h
			MOV DWORD PTR[EDI].FileAlignment,200h
		.endif
		MOV EDX,DWORD PTR[EDI].FileAlignment
		MOV FileAlignment,EDX
		ADD EDI,EAX
		ADD EDI,18h
		ASSUME EDI:PTR NtSectionInfo
		.while ESI > 0
			MOV EAX,DWORD PTR[EDI].SectionPointerToRawData
			ADD EAX,dwFileMap
			MOV ECX,DWORD PTR[EDI].SectionSizeOfRawData
			;.if ECX == NULL
			;	INC ECX
			;.endif
			ADD ECX,EAX
			DEC ECX
			.while ECX >= EAX && BYTE PTR[ECX] == 0 ; changed > to >=
				DEC ECX
			.endw
			INC ECX
			SUB ECX,EAX
			MOV EAX,ECX
			MOV ECX,FileAlignment
			CDQ
			DIV ECX
			.if EDX != 0
				INC EAX
			.endif
			IMUL EAX,FileAlignment
			MOV ECX,EAX
			.if CurrentSection == NULL
				MOV EBX,PE32Offset
				ASSUME EBX:PTR FullPE32Header
				MOV EAX,DWORD PTR[EDI].SectionPointerToRawData
				MOV DWORD PTR[EBX].SizeOfHeaders,EAX
				MOV EAX,DWORD PTR[EDI].SectionVirtualAddress
				MOV DWORD PTR[EBX].SectionAlignment,EAX
				MOV DWORD PTR[EDI].SectionSizeOfRawData,ECX
			.else
				PUSH DWORD PTR[EDI].SectionPointerToRawData
				MOV DWORD PTR[EDI].SectionSizeOfRawData,ECX
				SUB EDI,sizeof NtSectionInfo
				MOV EAX,DWORD PTR[EDI].SectionPointerToRawData
				ADD EAX,DWORD PTR[EDI].SectionSizeOfRawData
				ADD EDI,sizeof NtSectionInfo
				MOV DWORD PTR[EDI].SectionPointerToRawData,EAX
				ADD EAX,dwFileMap
				POP EBX
				ADD EBX,dwFileMap
				INVOKE RtlMoveMemory,EAX,EBX,ECX
			.endif
			DEC ESI
			INC CurrentSection
			ADD EDI,sizeof NtSectionInfo
		.endw
		SUB EDI,sizeof NtSectionInfo
		MOV EAX,DWORD PTR[EDI].SectionPointerToRawData
		ADD EAX,DWORD PTR[EDI].SectionSizeOfRawData
		MOV Return,EAX
		ASSUME EDI:NOTHING
	.endif
	
	POPAD
	MOV EAX,Return
	RET
RealignPE endp
;------------------------------------------------------------------
IsPE32FileValid proc dwFileName:DWORD
	LOCAL Return :DWORD
	LOCAL DontUnmap :DWORD
	LOCAL CorrectedImageSize :DWORD
	PUSHAD

	MOV Return,0
	INVOKE MapFile,dwFileName
	.if FileMapVA > 0 && Return == NULL
		.if EAX == -1
			MOV DontUnmap,1
		.else
			MOV DontUnmap,0
		.endif
		MOV ESI,FileMapVA
		MOV EDI,ESI
		ADD ESI,DWORD PTR[ESI+3Ch]
		INVOKE IsBadReadPtr,ESI,sizeof FullPE32Header
		.if EAX == NULL && WORD PTR[EDI] == "ZM"
			ASSUME ESI:PTR FullPE32Header
			.if DWORD PTR[ESI].PESignature == "EP"
				.if WORD PTR[ESI].Magic == 10Bh
					MOV EAX,DWORD PTR[ESI].SizeOfImage
					XOR EDX,EDX
					MOV ECX,DWORD PTR[ESI].SectionAlignment			;Power of (pecoff.doc)
					.if ECX == NULL
						MOV Return,49					;File is not valid PE32!
						CALL __VALIDATION_EXIT
					.endif
					DIV ECX
					.if EDX != 0
						INC EAX
					.endif
					IMUL EAX,DWORD PTR[ESI].SectionAlignment
					MOV CorrectedImageSize,EAX
					MOV EAX,DWORD PTR[ESI].AddressOfEntryPoint		;Surface check!
					.if EAX > CorrectedImageSize
						MOV Return,49					;File is not valid PE32!
						CALL __VALIDATION_EXIT
					.endif
					MOV EAX,DWORD PTR[ESI].ImageBase
					XOR EDX,EDX
					MOV ECX,1000h						;Default 64k
					DIV ECX
					.if EDX != 0						;Division reminder must be null!
						MOV Return,49					;File is not valid PE32!
						CALL __VALIDATION_EXIT
					.endif
					MOV EAX,DWORD PTR[ESI].SectionAlignment
					.if EAX < DWORD PTR[ESI].FileAlignment			;See pecoff.doc
						MOV Return,49					;File is not valid PE32!
						CALL __VALIDATION_EXIT
					.endif
					MOV EAX,DWORD PTR[ESI].FileAlignment
					XOR EDX,EDX
					MOV ECX,2						;Power of 2 (pecoff.doc)
					DIV ECX
					.if EDX != 0 || DWORD PTR[ESI].FileAlignment > 1000h	;Division reminder must be null!
						MOV Return,49					;File is not valid PE32!
						CALL __VALIDATION_EXIT
					.endif
					MOVZX EAX,WORD PTR[ESI].Characteristics
					TEST EAX,2000h
					JE __VALIDATION_NOT_A_DLL_FILE				;File is a .dll
						MOV EAX,DWORD PTR[ESI].ExportTableAddress
						.if EAX > CorrectedImageSize
							MOV Return,49				;File is not valid PE32!
							CALL __VALIDATION_EXIT
						.else
							MOV EAX,DWORD PTR[ESI].ExportTableAddress
							ADD EAX,DWORD PTR[ESI].ExceptionTableSize
							.if EAX > CorrectedImageSize && EAX != NULL
								MOV Return,49			;File is not valid PE32!
								CALL __VALIDATION_EXIT
							.endif
						.endif
						MOV EAX,DWORD PTR[ESI].BaseRelocationTable
						.if EAX > CorrectedImageSize
							MOV Return,49				;File is not valid PE32!
							CALL __VALIDATION_EXIT
						.else
							MOV EAX,DWORD PTR[ESI].BaseRelocationTable
							ADD EAX,DWORD PTR[ESI].BaseRelocationSize
							.if EAX > CorrectedImageSize && EAX != NULL
								MOV Return,49			;File is not valid PE32!
								CALL __VALIDATION_EXIT
							.endif
							.if DWORD PTR[ESI].BaseRelocationTable != NULL
								MOV EAX,DWORD PTR[ESI].BaseRelocationTable
								ADD EAX,DWORD PTR[ESI].ImageBase
								INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,1
								MOV EDI,EAX
								INVOKE IsBadReadPtrEx,EDI,DWORD PTR[ESI].BaseRelocationSize
								.if EAX != NULL
									MOV Return,49			;File is not valid PE32!
									CALL __VALIDATION_EXIT
								.endif
							.endif
						.endif
  __VALIDATION_NOT_A_DLL_FILE:
;					MOVZX EAX,WORD PTR[ESI].Characteristics
;					TEST EAX,8000h
;					JE __VALIDATION_BYTES_NOT_RESERVED_HIGH				;File is a .dll
;						MOV Return,51						;File is not valid PE32, but it can be fixed!
;  __VALIDATION_BYTES_NOT_RESERVED_HIGH:
;					MOV EAX,DWORD PTR[ESI].GlobalPtrAddress
;					.if DWORD PTR[ESI].GlobalPtrSize != 0 && DWORD PTR[ESI].NumberOfRvaAndSizes >= 9
;						MOV Return,49					;File is not valid PE32!
;						CALL __VALIDATION_EXIT
;					.elseif EAX > DWORD PTR[ESI].SizeOfImage && DWORD PTR[ESI].NumberOfRvaAndSizes >= 9
;						MOV Return,49					;File is not valid PE32!
;						CALL __VALIDATION_EXIT
;					.else
;						.if DWORD PTR[ESI].NumberOfRvaAndSizes >= 9
;							MOV EAX,DWORD PTR[ESI].GlobalPtrAddress
;							ADD EAX,DWORD PTR[ESI].GlobalPtrSize
;							.if EAX > DWORD PTR[ESI].SizeOfImage && EAX != NULL
;								MOV Return,49			;File is not valid PE32!
;								CALL __VALIDATION_EXIT
;							.endif
;						.endif
;					.endif
					MOV EAX,DWORD PTR[ESI].ImportTableAddress
					.if EAX > CorrectedImageSize && EAX != NULL
						MOV Return,49					;File is not valid PE32!
						CALL __VALIDATION_EXIT
;					.else
;						MOV EAX,DWORD PTR[ESI].ImportTableAddress
;						ADD EAX,DWORD PTR[ESI].ImportTableSize
;						.if EAX > CorrectedImageSize && EAX != NULL
;							MOV Return,49				;File is not valid PE32!
;							CALL __VALIDATION_EXIT
;						.endif
					.else
						.if DWORD PTR[ESI].ImportTableAddress != NULL
							MOV EAX,DWORD PTR[ESI].ImportTableAddress
							ADD EAX,DWORD PTR[ESI].ImageBase
							INVOKE ValidateImportTable,EAX,DWORD PTR[ESI].ImageBase,DWORD PTR[ESI].SizeOfImage
							.if EAX == -1
								MOV Return,49				;File is not valid PE32!
								CALL __VALIDATION_EXIT
							.elseif EAX == -2 && ValidationNotifyOnBadImport == 1
								MOV Return,-1				;File has invalid APIs!
							.endif
							MOV EAX,DWORD PTR[ESI].ImportTableAddress
							ADD EAX,DWORD PTR[ESI].ImageBase
							INVOKE GetSectionData,FileMapVA,EAX
							.if EAX != -1
								ASSUME EAX:PTR NtSectionInfo
								MOV EAX,DWORD PTR[EAX].SectionCharacteristics
								ASSUME EAX:NOTHING
								TEST EAX,80000000h
								JNE __IMPORT_SECTION_IS_WRITABLE		;Test section attribute!
								TEST EAX,00000040h
								JNE __IMPORT_SECTION_IS_WRITABLE		;Test section attribute!
									.if EAX != 60000020h			;VB fix!
										MOV Return,51			;File is not valid PE32, but it can be fixed!
									.endif
	  __IMPORT_SECTION_IS_WRITABLE:
	  						.else
								MOV Return,49					;File is not valid PE32!
								CALL __VALIDATION_EXIT
	  						.endif
						.endif
					.endif
					MOV EAX,DWORD PTR[ESI].TLSTableAddress
					.if DWORD PTR[ESI].NumberOfRvaAndSizes >= 6
						.if EAX > CorrectedImageSize && EAX != NULL
							MOV Return,49					;File is not valid PE32!
							CALL __VALIDATION_EXIT
						.else
							MOV EAX,DWORD PTR[ESI].TLSTableAddress
							ADD EAX,DWORD PTR[ESI].TLSTableSize
							.if EAX > CorrectedImageSize && EAX != NULL
								MOV Return,49				;File is not valid PE32!
								CALL __VALIDATION_EXIT
							.endif
							.if DWORD PTR[ESI].TLSTableAddress != NULL
								MOV EAX,DWORD PTR[ESI].TLSTableAddress
								ADD EAX,DWORD PTR[ESI].ImageBase
								INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,1
								MOV EDI,EAX
								INVOKE IsBadReadPtrEx,EDI,DWORD PTR[ESI].TLSTableSize
								.if EAX != NULL
									MOV Return,49			;File is not valid PE32!
									CALL __VALIDATION_EXIT
								.endif
							.endif
						.endif
						.if DWORD PTR[ESI].TLSTableAddress > 0
							MOV EAX,DWORD PTR[ESI].TLSTableAddress
							ADD EAX,DWORD PTR[ESI].ImageBase
							INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,1
							MOV EDI,EAX
							INVOKE IsBadReadPtrEx,EDI,sizeof NtTLSDirectory
							.if EAX == NULL
								ASSUME EDI:PTR NtTLSDirectory
								.if DWORD PTR[EDI].RawDataStartVA != NULL
									MOV EAX,DWORD PTR[EDI].RawDataStartVA
									SUB EAX,DWORD PTR[ESI].ImageBase
									.if EAX > CorrectedImageSize
										MOV Return,49			;File is not valid PE32!
										CALL __VALIDATION_EXIT
									.endif
								.endif
								.if DWORD PTR[EDI].RawDataEndVA != NULL
									MOV EAX,DWORD PTR[EDI].RawDataEndVA
									SUB EAX,DWORD PTR[ESI].ImageBase
									.if EAX > CorrectedImageSize
										MOV Return,49			;File is not valid PE32!
										CALL __VALIDATION_EXIT
									.endif
								.endif
								.if DWORD PTR[EDI].AddressOfIndex != NULL
									MOV EAX,DWORD PTR[EDI].AddressOfIndex
									SUB EAX,DWORD PTR[ESI].ImageBase
									.if EAX > CorrectedImageSize
										MOV Return,49			;File is not valid PE32!
										CALL __VALIDATION_EXIT
									.endif
								.endif
								.if DWORD PTR[EDI].AddressOfCallbacks != NULL
									MOV EAX,DWORD PTR[EDI].AddressOfCallbacks
									SUB EAX,DWORD PTR[ESI].ImageBase
									.if EAX > CorrectedImageSize
										MOV Return,49			;File is not valid PE32!
										CALL __VALIDATION_EXIT
									.endif
								.endif
								ASSUME EDI:NOTHING
							.endif
						.endif
					.endif
					MOV EAX,DWORD PTR[ESI].LoadConfigTableAddress
					.if DWORD PTR[ESI].NumberOfRvaAndSizes >= 11
						.if EAX > CorrectedImageSize && EAX != NULL
							MOV Return,51				;File is not valid PE32, but it can be fixed!
						.else
							MOV EAX,DWORD PTR[ESI].LoadConfigTableAddress
							ADD EAX,DWORD PTR[ESI].LoadConfigTableSize
							.if EAX > CorrectedImageSize && EAX != NULL
								MOV Return,51			;File is not valid PE32, but it can be fixed!
							.endif
							.if DWORD PTR[ESI].LoadConfigTableAddress != NULL
								MOV EAX,DWORD PTR[ESI].LoadConfigTableAddress
								ADD EAX,DWORD PTR[ESI].ImageBase
								INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,1
								MOV EDI,EAX
								INVOKE IsBadReadPtrEx,EDI,DWORD PTR[ESI].LoadConfigTableSize
								.if EAX != NULL
									MOV Return,51		;File is not valid PE32, but it can be fixed!
								.endif
							.endif
						.endif
					.endif
					MOV EAX,DWORD PTR[ESI].BoundImportAddress
					.if DWORD PTR[ESI].NumberOfRvaAndSizes >= 12
						.if EAX > CorrectedImageSize && EAX != NULL
							MOV Return,51				;File is not valid PE32, but it can be fixed!
						.else
							MOV EAX,DWORD PTR[ESI].BoundImportAddress
							ADD EAX,DWORD PTR[ESI].BoundImportSize
							.if EAX > CorrectedImageSize && EAX != NULL
								MOV Return,51			;File is not valid PE32, but it can be fixed!
							.endif
							.if DWORD PTR[ESI].BoundImportAddress != NULL
								MOV EAX,DWORD PTR[ESI].BoundImportAddress
								ADD EAX,DWORD PTR[ESI].ImageBase
								INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,1
								MOV EDI,EAX
								INVOKE IsBadReadPtrEx,EDI,DWORD PTR[ESI].BoundImportSize
								.if EAX != NULL
									MOV Return,51		;File is not valid PE32, but it can be fixed!
								.endif
							.endif
						.endif
					.endif
					MOV EAX,DWORD PTR[ESI].IATAddress
					.if DWORD PTR[ESI].NumberOfRvaAndSizes >= 13
						.if EAX > CorrectedImageSize && EAX != NULL
							MOV Return,51				;File is not valid PE32, but it can be fixed!
						.else
							MOV EAX,DWORD PTR[ESI].IATAddress
							ADD EAX,DWORD PTR[ESI].IATSize
							.if EAX > CorrectedImageSize && EAX != NULL
								MOV Return,51			;File is not valid PE32, but it can be fixed!
							.endif
						.endif
					.endif
					MOV EAX,DWORD PTR[ESI].COMRuntimeHeaderAddress
					.if DWORD PTR[ESI].NumberOfRvaAndSizes >= 15
						.if EAX > CorrectedImageSize && EAX != NULL
							MOV Return,51				;File is not valid PE32, but it can be fixed!
						.else
							MOV EAX,DWORD PTR[ESI].COMRuntimeHeaderAddress
							ADD EAX,DWORD PTR[ESI].COMRuntimeHeaderSize
							.if EAX > CorrectedImageSize && EAX != NULL
								MOV Return,51			;File is not valid PE32, but it can be fixed!
							.endif
							.if DWORD PTR[ESI].COMRuntimeHeaderAddress != NULL
								MOV EAX,DWORD PTR[ESI].COMRuntimeHeaderAddress
								ADD EAX,DWORD PTR[ESI].ImageBase
								INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,1
								MOV EDI,EAX
								INVOKE IsBadReadPtrEx,EDI,DWORD PTR[ESI].COMRuntimeHeaderSize
								.if EAX != NULL
									MOV Return,51		;File is not valid PE32, but it can be fixed!
								.endif
							.endif
						.endif
					.endif
					MOV EAX,DWORD PTR[ESI].ResourceTableAddress
					.if DWORD PTR[ESI].NumberOfRvaAndSizes >= 3
						.if EAX > CorrectedImageSize && EAX != NULL
							MOV Return,51				;File is not valid PE32, but it can be fixed!
							CALL __VALIDATION_EXIT
						.else
							MOV EAX,DWORD PTR[ESI].ResourceTableAddress
							ADD EAX,DWORD PTR[ESI].ResourceTableSize
							.if EAX > CorrectedImageSize && EAX != NULL
								MOV Return,51			;File is not valid PE32, but it can be fixed!
								CALL __VALIDATION_EXIT
							.endif
							MOV EAX,DWORD PTR[ESI].ResourceTableAddress
							ADD EAX,DWORD PTR[ESI].ImageBase
							INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,1
							MOV EDI,EAX
							INVOKE IsBadReadPtrEx,EDI,10
							.if EAX != NULL && WORD PTR[ESI].NumberOfSections > 1
								MOV Return,51			;File is not valid PE32, but it can be fixed!
								CALL __VALIDATION_EXIT
							.endif
						.endif
					.endif

 					MOV EDI,FileMapVA					;Section check!
					ADD EDI,DWORD PTR[EDI+3Ch]
					ADD DI,WORD PTR[EDI+14h]
					ADD EDI,18h
					ASSUME EDI:PTR NtSectionInfo
					MOVZX ECX,WORD PTR[ESI].NumberOfSections
					DEC ECX							;Don't check last section!
					.while ECX > 0
						PUSH ECX
						MOV EAX,DWORD PTR[EDI].SectionVirtualSize
						XOR EDX,EDX
						MOV ECX,DWORD PTR[ESI].SectionAlignment		;Power of (pecoff.doc)
						.if ECX == NULL
							MOV Return,49				;File is not valid PE32!
							CALL __VALIDATION_EXIT
						.endif
						DIV ECX
						.if EDX != 0
							INC EAX
						.endif
						IMUL EAX,DWORD PTR[ESI].SectionAlignment
						ADD EAX,DWORD PTR[EDI].SectionVirtualAddress
						ADD EDI,sizeof NtSectionInfo
						.if EAX > DWORD PTR[EDI].SectionVirtualAddress
							POP ECX
							MOV Return,49				;File is not valid PE32!
							CALL __VALIDATION_EXIT
						.endif
						MOV EAX,DWORD PTR[ESI].AddressOfEntryPoint
						MOV EBX,EAX
						ADD EBX,DWORD PTR[EDI].SectionVirtualSize
						.if EAX >= DWORD PTR[EDI].SectionVirtualAddress && EAX <= EBX
							MOV EAX,DWORD PTR[EDI].SectionCharacteristics
							TEST EAX,040000000h
							JNE __SECTION_NOT_READABLE
							TEST EAX,80000000h
							JNE __SECTION_NOT_READABLE
							TEST EAX,020000000h
							JNE __SECTION_NOT_READABLE
								MOV Return,51			;File is not valid PE32, but it can be fixed!
					__SECTION_NOT_READABLE:
						.endif
						POP ECX
						DEC ECX
					.endw

					MOV EDI,FileMapVA					;Section check!
					ADD EDI,DWORD PTR[EDI+3Ch]
					ADD DI,WORD PTR[EDI+14h]
					ADD EDI,18h
					ASSUME EDI:PTR NtSectionInfo
					MOVZX ECX,WORD PTR[ESI].NumberOfSections
					DEC ECX
					IMUL ECX,sizeof NtSectionInfo
					ADD EDI,ECX
					MOV EAX,DWORD PTR[EDI].SectionPointerToRawData
					ADD EAX,DWORD PTR[EDI].SectionSizeOfRawData
					.if EAX > FileSize && DWORD PTR[EDI].SectionSizeOfRawData != NULL
						MOV Return,49					;File is not valid PE32!
						CALL __VALIDATION_EXIT
					.endif
					
					MOV EDI,FileMapVA					;Section check!
					ADD EDI,DWORD PTR[EDI+3Ch]
					ADD DI,WORD PTR[EDI+14h]
					ADD EDI,18h
					ASSUME EDI:PTR NtSectionInfo
					MOVZX ECX,WORD PTR[ESI].NumberOfSections
					DEC ECX
					IMUL ECX,sizeof NtSectionInfo
					ADD EDI,ECX
					MOV EAX,DWORD PTR[EDI].SectionVirtualSize
					ADD EAX,DWORD PTR[EDI].SectionVirtualAddress
					XOR EDX,EDX
					MOV ECX,DWORD PTR[ESI].SectionAlignment			;Power of (pecoff.doc)
					.if ECX == NULL
						MOV Return,49					;File is not valid PE32!
						CALL __VALIDATION_EXIT
					.endif
					DIV ECX
					.if EDX != 0
						INC EAX
					.endif
					IMUL EAX,DWORD PTR[ESI].SectionAlignment
					ADD EAX,0F000h
					.if DWORD PTR[ESI].SizeOfImage > EAX
						MOV Return,49					;File is not valid PE32!
						CALL __VALIDATION_EXIT
					.endif

					INVOKE PreProcessResourceTable
					.if EAX != NULL
						MOV Return,51					;File is not valid PE32, but it can be fixed!
					.endif
					ASSUME EDI:NOTHING
				.elseif WORD PTR[ESI].Magic == 20Bh
					MOV Return,39						;File is not PE32!
				.else
					MOV Return,56						;File is not PE32 file!
				.endif
			.else
				MOV Return,56							;File is not PE32 file!
			.endif
			ASSUME ESI:NOTHING
		.else
			MOV Return,56								;File is not PE32 file!
		.endif
	.else
		MOV Return,48									;File could not be mapped!
	.endif

	PUSH EAX
  __VALIDATION_EXIT:
  	POP EAX											;Realign stack!
	INVOKE UnmapFile
	.if Return > NULL
		MOV Return,NULL
	.else
		MOV Return,1
	.endif

	POPAD
	MOV EAX,Return
	RET
IsPE32FileValid endp
;------------------------------------------------------------------
IsBadReadPtrEx proc dwAddress:DWORD,dwSize:DWORD
	LOCAL Return :DWORD
	LOCAL MaximumAddress :DWORD
	PUSHAD

	MOV Return,0
	MOV BAD_READ_ERROR_EXIT,offset __BAD_READ_ERROR_EXIT
	InstSehFrame2 <offset ReadHandler>			;Create a SEH just in case!
	XOR EBX,EBX
	MOV ESI,dwSize
	MOV EDI,dwAddress
	MOV MaximumAddress,ESI
	ADD MaximumAddress,EDI
	.while ESI > 0
		INVOKE VirtualQuery,EDI,addr MemInfo,sizeof MemInfo
		.if DWORD PTR[MemInfo.State] != MEM_FREE && DWORD PTR[MemInfo.State] != MEM_RESERVE
			ADD EDI,DWORD PTR[MemInfo.RegionSize]
			.if ESI > DWORD PTR[MemInfo.RegionSize]
				SUB ESI,DWORD PTR[MemInfo.RegionSize]
			.else
				XOR ESI,ESI
			.endif
		.else
			INC EBX
			.break
		.endif
	.endw
 __BAD_READ_ERROR_EXIT:
	KillSehFrame
	MOV ECX,DWORD PTR[MemInfo.BaseAddress]
	ADD ECX,DWORD PTR[MemInfo.RegionSize]
	.if MaximumAddress > ECX
		INC EBX
	.endif
	.if EBX != NULL
		INC Return
	.endif

	POPAD
	MOV EAX,Return
	RET
IsBadReadPtrEx endp
;------------------------------------------------------------------
PreProcessResourceTable proc
	LOCAL pType :DWORD
	LOCAL pName :DWORD
	LOCAL pRSRC :DWORD
	LOCAL pSize :DWORD
	LOCAL pFirst :DWORD
	LOCAL pDataRVA :DWORD
	LOCAL Level1_CNT :DWORD
	LOCAL Level2_CNT :DWORD
	LOCAL Level3_CNT :DWORD
	LOCAL Return :DWORD
	PUSHAD

	MOV ContinueSafeError,0
	MOV ContinueSafeAddress,offset __PROCESS_RESOURCESS_ERROR_EXIT
	ASSUME FS:NOTHING
	PUSH offset SafeHandler
	PUSH DWORD PTR FS:[0]
	MOV DWORD PTR FS:[0],ESP

	MOV Return,0
	MOV pFirst,0
	MOV EAX,FileMapVA
	ADD EAX,DWORD PTR[EAX+3Ch]
	MOV EBX,DWORD PTR[EAX+34h]
	MOV ImageBase,EBX
	MOV EBX,DWORD PTR[EAX+8Ch]
	MOV EAX,DWORD PTR[EAX+88h]
	.if EAX != 0
		ADD EAX,ImageBase
		INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,1
		MOV pRSRC,EAX

		INVOKE IsBadReadPtrEx,pRSRC,20
		.if EAX == NULL
			MOV EAX,pRSRC
			MOVZX EBX,WORD PTR[EAX+12]
			ADD BX,WORD PTR[EAX+14]
			MOV Level1_CNT,EBX
			ADD EAX,16
			.while Level1_CNT > 0
				MOV EBX,DWORD PTR[EAX]
				MOV pType,EBX
				MOV EBX,DWORD PTR[EAX+4]
				XOR EBX,80000000h
				ADD EBX,pRSRC
				MOVZX ECX,WORD PTR[EBX+12]
				ADD CX,WORD PTR[EBX+14]
				MOV Level2_CNT,ECX
				ADD EBX,16
	                        .while Level2_CNT > 0
					MOV ECX,DWORD PTR[EBX]
					MOV pName,ECX
					MOV ECX,DWORD PTR[EBX+4]
					XOR ECX,80000000h
					ADD ECX,pRSRC
					MOVZX EDX,WORD PTR[ECX+12]
					ADD DX,WORD PTR[ECX+14]
					MOV Level3_CNT,EDX
					ADD ECX,16
					.while Level3_CNT > 0
						MOV EDX,DWORD PTR[ECX+4]
						ADD EDX,pRSRC
						MOV EDI,DWORD PTR[EDX]
						MOV pDataRVA,EDI
						MOV EDI,DWORD PTR[EDX+4]
						MOV pSize,EDI

						.if pFirst != NULL
							.if pType == 2 || pType == 3 || pType == 5 || pType == 0Ch || pType == 0Eh || pType == 18h
								PUSHAD
								MOV EAX,pDataRVA
								.if EAX != NULL
									ADD EAX,ImageBase
									INVOKE GetSectionData,FileMapVA,EAX
									ASSUME EAX:PTR NtSectionInfo
									MOV EBX,DWORD PTR[EAX].SectionPointerToRawData
									ADD EBX,DWORD PTR[EAX].SectionSizeOfRawData
									ASSUME EAX:NOTHING
									MOV EAX,pDataRVA
									.if EAX != NULL
										ADD EAX,ImageBase
										INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,NULL
										.if EAX < FileSize && EAX < EBX
											ADD EAX,pSize
											.if EAX > FileSize
												MOV EBX,EAX
												MOV EAX,FileSize
												XOR EDX,EDX
												MOV ECX,1000h						;Default 64k
												DIV ECX
												IMUL EAX,1000h
												.if EDX != 0						;Division reminder must be null!
													ADD EAX,1000h
												.endif
												.if EBX > EAX
													MOV Return,-1
												.endif
											.endif
										.endif
									.endif
								.endif
								POPAD
							.endif
						.endif
						INC pFirst
						ADD ECX,8
						DEC Level3_CNT
					.endw
					ADD EBX,8
					DEC Level2_CNT
	                        .endw
				ADD EAX,8
				DEC Level1_CNT
			.endw
;		.else
;			MOV Return,-1
		.endif
	.endif
__PROCESS_RESOURCESS_ERROR_EXIT:
	POP DWORD PTR FS:[0]
	ADD ESP,4
	.if ContinueSafeError == 1
		MOV Return,-1
	.endif

	POPAD
	MOV EAX,Return
	RET
PreProcessResourceTable endp
;------------------------------------------------------------------
ValidateImportTable proc dwIATAddress:DWORD,dwImageBase:DWORD,dwSizeOfImage:DWORD
	LOCAL MaxExportNumber :DWORD
	LOCAL ItIsNotOrdinal :DWORD
	LOCAL hCurrentDll :DWORD
	LOCAL LoadedDll :DWORD
	LOCAL fImageBase :DWORD
	LOCAL fDllName :DWORD
	LOCAL fIATStart :DWORD
	LOCAL BreakIt :DWORD
	LOCAL Return :DWORD
	PUSHAD

;	INVOKE SetErrorMode,SEM_FAILCRITICALERRORS+SEM_NOGPFAULTERRORBOX+SEM_NOOPENFILEERRORBOX

	MOV BreakIt,0
	MOV Return,0
	MOV fIATStart,0
	MOV EBX,dwIATAddress
	MOV EAX,dwImageBase
	MOV fImageBase,EAX

	MOV ESI,FileMapVA
	ADD ESI,DWORD PTR[ESI+3Ch]
	ASSUME ESI:PTR FullPE32Header
	.if DWORD PTR[ESI].NumberOfRvaAndSizes >= 13
		MOV EAX,DWORD PTR[ESI].IATAddress
		ADD EAX,DWORD PTR[ESI].ImageBase
	        INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,1			;Get fileoffset location
	        MOV ESI,EAX
		INVOKE IsBadReadPtrEx,ESI,4
		.if EAX == NULL
			MOV fIATStart,ESI
		.endif
	.endif
	ASSUME ESI:NOTHING

        INVOKE ConvertVAtoFileOffset,FileMapVA,EBX,1				;Get fileoffset location
        MOV ESI,EAX
	INVOKE IsBadReadPtrEx,ESI,8
	.if EAX == NULL
	        ASSUME ESI:PTR NtImportDirectory				;Now we check all .dlls imported by application
	        .while BreakIt == 0 && DWORD PTR[ESI].ImportAddressTable != NULL
	        	.if ESI == fIATStart && fIATStart != 0
	        		MOV BreakIt,1
				.break
	        	.endif
			.if DWORD PTR[ESI].ImportLockupTable == NULL
				MOV EAX,DWORD PTR[ESI].ImportAddressTable
				.if EAX < dwSizeOfImage
					ADD EAX,fImageBase
					INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,1	;Get fileoffset location
					INVOKE IsBadReadPtrEx,EAX,4
				.else
					XOR EAX,EAX
					INC EAX
				.endif
			.else
				MOV EAX,DWORD PTR[ESI].ImportLockupTable
				.if EAX < dwSizeOfImage
					ADD EAX,fImageBase
					INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,1	;Get fileoffset location
					INVOKE IsBadReadPtrEx,EAX,4
				.else
					XOR EAX,EAX
					INC EAX
				.endif
			.endif
			.if EAX == NULL
				MOV EAX,DWORD PTR[ESI].NameRVA
				ADD EAX,fImageBase
				INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,1	;Get fileoffset location
				MOV fDllName,EAX				;Location of dll file name in import table
				INVOKE IsBadReadPtrEx,fDllName,8
				.if EAX == NULL || DWORD PTR[ESI].NameRVA == NULL
					MOV LoadedDll,0
					MOV hCurrentDll,0
					.if DWORD PTR[ESI].NameRVA != NULL
						INVOKE lstrcmpi,fDllName,addr szCOMCTL32
						.if EAX != NULL
							INVOKE GetModuleHandle,fDllName
							.if EAX != NULL
								MOV hCurrentDll,EAX
							.else
;								INVOKE LoadLibraryEx,NULL,fDllName,DONT_RESOLVE_DLL_REFERENCES
								INVOKE LoadLibrary,fDllName
								.if EAX == NULL
									MOV hCurrentDll,0
								.else
									MOV hCurrentDll,EAX
									MOV LoadedDll,1
								.endif
							.endif
						.else
							MOV EAX,hComCtl32
							MOV EBX,EAX
							MOV hCurrentDll,EAX
							MOV LoadedDll,NULL
						.endif
					.else
						INVOKE GetModuleHandle,addr szKernel32
						MOV hCurrentDll,EAX
					.endif
					.if Return != -1 && hCurrentDll != NULL
						INVOKE GetModuleExportNumber,hCurrentDll
						MOV MaxExportNumber,EAX
						.if DWORD PTR[ESI].ImportLockupTable != NULL
							.if DWORD PTR[ESI].TimeDateStamp != -1 && DWORD PTR[ESI].ImportLockupTable == NULL; && DWORD PTR[ESI].ForwarderChain != -1
								MOV EAX,DWORD PTR[ESI].ImportAddressTable
							.else
								MOV EAX,DWORD PTR[ESI].ImportLockupTable
							.endif
						.else
							MOV EAX,DWORD PTR[ESI].ImportAddressTable
						.endif
						ADD EAX,fImageBase
						INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,1	;Get fileoffset location
						MOV EDI,EAX
						INVOKE IsBadReadPtrEx,EDI,4
						.if EAX == NULL
							.while BreakIt == 0 && DWORD PTR[EDI] != NULL
								MOV ItIsNotOrdinal,0
								MOV EAX,DWORD PTR[EDI]
								TEST EAX,80000000h
								JNE __is_ordinal
									ADD EAX,fImageBase
									INVOKE ConvertVAtoFileOffset,FileMapVA,EAX,1	;Get fileoffset location
									MOV EBX,EAX
									INVOKE IsBadReadPtrEx,EAX,4
									.if EAX != NULL
										MOV Return,-1		;.dll file not found!
										MOV BreakIt,1
									.else
										ADD EBX,2		;skip hint!
										INVOKE GetProcAddress,hCurrentDll,EBX
										.if EAX == 0 && ValidationNotifyOnBadImport == NULL
											MOV Return,-1	;.dll file not found!
											MOV BreakIt,1
										.elseif EAX == 0 && ValidationNotifyOnBadImport == 1
											MOV Return,-2	;Invalid API present!
											MOV BreakIt,1
										.endif
									.endif
									MOV ItIsNotOrdinal,1
							 __is_ordinal:
							 	.if ItIsNotOrdinal == NULL
									XOR EAX,80000000h
									.if EAX <= MaxExportNumber
										INVOKE GetProcAddress,hCurrentDll,EAX
										.if EAX == 0 && ValidationNotifyOnBadImport == NULL
											MOV Return,-1	;.dll file not found!
											MOV BreakIt,1
										.elseif EAX == 0 && ValidationNotifyOnBadImport == 1
											MOV Return,-2	;Invalid API present!
											MOV BreakIt,1
										.endif
									.else
										MOV Return,-1		;.dll file not found!
										MOV BreakIt,1
									.endif
							 	.endif
								ADD EDI,4
							.endw
						.else
							.if LoadedDll == 1
					 			INVOKE FreeLibrary,hCurrentDll
					 		.endif						
							MOV Return,-1		;.dll file not found!
							.break			;Error while reading API name/Ordinal!
						.endif
						.if LoadedDll == 1
				 			INVOKE FreeLibrary,hCurrentDll
				 		.endif
					.endif
				.else
					MOV Return,-1				;.dll file not found!
					.break					;Error while reading .dll name!
				.endif
				ADD ESI,sizeof NtImportDirectory
				INVOKE IsBadReadPtrEx,ESI,sizeof NtImportDirectory
				.if EAX != NULL
					.break					;MEW case, IAT at the end of the file without the NULL IAT thunk
				.endif
			.else
				.break
			.endif
	        .endw
	        ASSUME ESI:NOTHING
	.else
		MOV Return,-1		;.dll file not found!
	.endif
	
;	INVOKE SetErrorMode,NULL

	POPAD
	MOV EAX,Return
	RET
ValidateImportTable endp
;------------------------------------------------------------------
GetCommonControlsData proc
	LOCAL dummy :DWORD
	LOCAL dwThisProcess :DWORD
	LOCAL dwLoadedDLLModules :DWORD
	PUSHAD

	MOV hComCtl32,NULL
	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV dwLoadedDLLModules,EAX
	INVOKE GetCurrentProcess
	MOV dwThisProcess,EAX
	INVOKE EnumProcessModules,dwThisProcess,dwLoadedDLLModules,800h,addr dummy
	.if EAX != NULL
		MOV ESI,dwLoadedDLLModules
		.while DWORD PTR[ESI] != NULL
			ADD ESI,4
		.endw
		SUB ESI,4
		.while ESI > dwLoadedDLLModules
			INVOKE GetModuleBaseName,dwThisProcess,DWORD PTR[ESI],addr szMiscBuff,1024
			INVOKE lstrcmpi,addr szMiscBuff,addr szCOMCTL32
			.if EAX == NULL
				MOV EAX,DWORD PTR[ESI]
				.if hComCtl32 < EAX
					MOV hComCtl32,EAX
				.endif
			.endif
			SUB ESI,4
		.endw
	.endif
	INVOKE VirtualFree,dwLoadedDLLModules,NULL,MEM_RELEASE
	.if hComCtl32 == NULL
		INVOKE RtlZeroMemory,addr szMiscBuff,1024
		INVOKE GetWindowsDirectory,addr szMiscBuff,1024
		INVOKE lstrcat,addr szMiscBuff,addr szCOMCTL32RelativePath
		INVOKE LoadLibrary,addr szMiscBuff
		MOV hComCtl32,EAX
	.endif

	POPAD
	RET
GetCommonControlsData endp
;------------------------------------------------------------------
GetModuleExportNumber proc dwModuleHandle:DWORD
	LOCAL Return :DWORD
	PUSHAD

	MOV ESI,dwModuleHandle
	.if ESI != NULL
		ADD ESI,DWORD PTR[ESI+3Ch]
		ASSUME ESI:PTR FullPE32Header
		MOV EAX,DWORD PTR[ESI].ExportTableAddress
		ADD EAX,dwModuleHandle
		ASSUME ESI:NOTHING
		MOV ESI,EAX
		ASSUME ESI:PTR NtExportTable
		MOV EAX,DWORD PTR[ESI].AddressTableEntries		;NumberOfNamePointers
		ADD EAX,DWORD PTR[ESI].OrdinalBase
		ASSUME ESI:NOTHING
		MOV Return,EAX
	.else
		MOV Return,1000
	.endif

	POPAD
	MOV EAX,Return
	RET
GetModuleExportNumber endp
;------------------------------------------------------------------
GetSectionData proc fMap:DWORD,Address:DWORD
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
	INVOKE RtlZeroMemory,addr PE32SelectedSectionInfo,sizeof NtSectionInfo
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
		.elseif EDX < DWORD PTR[EAX+16]
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
				MOV ECX,1
				MOV EBX,EAX
			.endif
		.endif
		ADD EAX,28h
		DEC ECX
	.endw
	INVOKE IsBadReadPtrEx,EBX,sizeof NtSectionInfo
	MOV DWORD PTR[ESP+1Ch],EAX
	.if EAX == NULL
		INVOKE RtlMoveMemory,addr PE32SelectedSectionInfo,EBX,sizeof NtSectionInfo
	.endif
 ;
 ; End of conversion
 ;
	POPAD
	.if EAX == NULL
		MOV EAX,offset PE32SelectedSectionInfo
	.else
		XOR EAX,EAX
		DEC EAX
	.endif
	RET
GetSectionData endp
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
		.elseif EDX < DWORD PTR[EAX+16]
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
SafeHandler PROC C pExcept:DWORD,pFrame:DWORD,pContext:DWORD,pDispatch:DWORD

	MOV  EAX, pContext		;After file unlocking process SEH!
	ASSUME EAX : PTR CONTEXT

	MOV ContinueSafeError,1
	PUSH ContinueSafeAddress	;Instead of SEH.SaveEip!
	POP  [EAX].regEip
	MOV  EAX, ExceptionContinueExecution

	RET
SafeHandler ENDP
;------------------------------------------------------------------
ReadHandler PROC C pExcept:DWORD,pFrame:DWORD,pContext:DWORD,pDispatch:DWORD
	MOV  EAX, pContext		;After file unlocking process SEH!
	ASSUME EAX : PTR CONTEXT

	PUSH BAD_READ_ERROR_EXIT	;Instead of SEH.SaveEip!
	POP  [EAX].regEip
	PUSH SEH2.OrgEsp
	POP  [EAX].regEsp
	PUSH SEH2.OrgEbp
	POP [EAX].regEbp

	MOV  EAX, ExceptionContinueExecution
	RET
ReadHandler ENDP
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
End LibMain