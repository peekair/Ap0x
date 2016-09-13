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
    include ..\..\Importer.inc

    includelib \masm32\lib\user32.lib
    includelib \masm32\lib\kernel32.lib
    includelib \masm32\lib\psapi.lib

;------------------------------------------------------------------

sDLL_Name STRUCT
 	AllocatedAt dd ?
	DLLNumber dd ?
	CurrentWritePosition dd ?
	LastDllName dd ?
sDLL_Name ENDS

sAPI_Name STRUCT
 	AllocatedAt dd ?
	APINumber dd ?
	CurrentWritePosition dd ?
	LastAPITrunk dd ?
sAPI_Name ENDS

sIAT_Table STRUCT
	OriginalFirstTrunk dd ?
	TimeDateStamp dd ?
	ForwarderChain dd ?
	szName dd ?
	FirstTrunks dd ?
sIAT_Table ENDS

sIAT_Table_header STRUCT
	AllocatedAt dd ?
	CurrentWritePosition dd ?
sIAT_Table_header ENDS

    return MACRO arg
      mov eax, arg
      ret
    ENDM

    .data
	DLL_Name sDLL_Name <>
	IAT_Table sIAT_Table <>
	IAT_Table_header sIAT_Table_header <>
	API_Name sAPI_Name <>
	MemInfo MEMORY_BASIC_INFORMATION <>
 ;
 ; Forwarded APIs
 ;
	szNTDLL_1 db "ntdll.dll",0h
	szNTDLL_2 db "NTDLL.dll",0h
	szNTDLL_3 db "NTDLL.DLL",0h
	szKERNEL32 db "kernel32.dll",0h
	szRestoreLastError db "RestoreLastError",0h	;RestoreLastError
	szSetLastError db "SetLastError",0h
    .data?
	AllocSize dd ?
	APITableNumber dd ?
	APITable db 800 dup(?)				;VA alocirane memorije za API stringove
	APITableAddresses db 800 dup(?)			;VA alocirane memorije za API pointere (ka stringovima)
	APITableAddressesCurrentWritePosition db 800 dup(?)
	RelativeName dd ?
	ImageBase dd ?
	ImportTableAddress dd ?
	ImportTableSize dd ?
	Converted dd ?
	FinalIAT dd ?
	ReturnEDI dd ?
	EstimatedSize dd ?
	Ordinal dd ?
 ;
 ; Mapiranje fajla
 ;
	FileHWND dd ?
	FileSize dd ?
	FileMap dd ?
	FileMapVA dd ?
	oldFileSize dd ?
 ;
 ; Misc variables
 ;
	MoveIAT dd ?
	NeededSpace dd ?
	dwListType dd ?
	APINameBuffer db 1024 dup(?)
	ForwarderDLLBuffer db 1024 dup(?)
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
ImporterSetAutoFixOptions proc dwOption:DWORD
	PUSHAD
	MOV EAX,dwOption
	MOV dwListType,EAX
	POPAD
	RET
ImporterSetAutoFixOptions endp
;------------------------------------------------------------------
GetModuleVersion proc
	MOV EAX,0106h
	RET
GetModuleVersion endp
;------------------------------------------------------------------

 _alloc_new_space:
	PUSHAD
 ;
 ; Ovde iniciramo .dll imena 
 ;
	INC DWORD PTR[APITableNumber]

	INVOKE VirtualAlloc,0,DWORD PTR[AllocSize],MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV EBX,DWORD PTR[APITableNumber]
	MOV ECX,offset APITable
	MOV DWORD PTR[ECX+EBX*4],EAX

	INVOKE VirtualAlloc,0,DWORD PTR[AllocSize],MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV EBX,DWORD PTR[APITableNumber]
	MOV ECX,offset APITableAddresses
	MOV DWORD PTR[ECX+EBX*4],EAX
	ADD EAX,8			;Prvi DWORD je rezervisan za broj APIja
					;Drugi za prvi RVA od kojeg se zapisuju pointeri ka imenima
	MOV ECX,offset APITableAddressesCurrentWritePosition
	MOV DWORD PTR[ECX+EBX*4],EAX

	POPAD
	RET
;------------------------------------------------------------------
 _init_erase_api_table:
	PUSHAD
	MOV DWORD PTR[APITableNumber],-1
	XOR AL,AL
	MOV ECX,100
	MOV EDI,offset APITable
 	REP STOS DWORD PTR[EDI]
	MOV ECX,100
	MOV EDI,offset APITableAddresses
 	REP STOS DWORD PTR[EDI]
	MOV ECX,100
	MOV EDI,offset APITableAddressesCurrentWritePosition
 	REP STOS DWORD PTR[EDI]
	POPAD
	RET
;------------------------------------------------------------------
 _init_dll_name:
	PUSHAD
 ;
 ; Ovde iniciramo .dll imena 
 ;
	INVOKE VirtualAlloc,0,DWORD PTR[AllocSize],MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV DWORD PTR[DLL_Name.AllocatedAt],EAX
	MOV DWORD PTR[DLL_Name.CurrentWritePosition],EAX
	MOV DWORD PTR[DLL_Name.DLLNumber],0

	POPAD
	RET
;------------------------------------------------------------------
 _init_api_name:
	PUSHAD
 ;
 ; Ovde iniciramo API imena 
 ;
	INVOKE VirtualAlloc,0,DWORD PTR[AllocSize],MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV DWORD PTR[API_Name.AllocatedAt],EAX
	MOV DWORD PTR[API_Name.CurrentWritePosition],EAX
	ADD DWORD PTR[API_Name.CurrentWritePosition],6 	;zbog hinta i SizeOfAPINames
	MOV DWORD PTR[API_Name.APINumber],0

	MOV EAX,DWORD PTR[API_Name.AllocatedAt]		;zbog inicijalnog hinta
	MOV DWORD PTR[EAX],2

	POPAD
	RET
;------------------------------------------------------------------
 _init_iat_table:
	PUSHAD
 ;
 ; Ovde iniciramo IAT tablicu
 ;
	INVOKE VirtualAlloc,0,DWORD PTR[AllocSize],MEM_COMMIT,PAGE_EXECUTE_READWRITE
	MOV DWORD PTR[IAT_Table_header.AllocatedAt],EAX
	MOV DWORD PTR[IAT_Table_header.CurrentWritePosition],EAX

	CALL _clear_iat_table

	POPAD
	RET
;------------------------------------------------------------------
 _clear_iat_table:
	MOV DWORD PTR[IAT_Table.OriginalFirstTrunk],0
	MOV DWORD PTR[IAT_Table.TimeDateStamp],0
	MOV DWORD PTR[IAT_Table.ForwarderChain],0
	MOV DWORD PTR[IAT_Table.szName],0
	MOV DWORD PTR[IAT_Table.FirstTrunks],0
	RET
;------------------------------------------------------------------
 _copy_dll_name:
	PUSHAD
	MOV EAX,DWORD PTR[DLL_Name.CurrentWritePosition]
	PUSH EAX
	INVOKE lstrcpy,EDI,EAX
	POP EAX
	INVOKE lstrlen,EAX
	INC EAX
	ADD DWORD PTR[DLL_Name.CurrentWritePosition],EAX
	ADD EDI,EAX
	MOV DWORD PTR[ReturnEDI],EDI
	POPAD
	RET
;------------------------------------------------------------------
 _free:
	PUSHAD
	INVOKE VirtualFree,EAX,DWORD PTR[AllocSize],MEM_DECOMMIT
	INVOKE VirtualFree,EAX,NULL,MEM_RELEASE;DWORD PTR[AllocSize]
	POPAD
	RET
;------------------------------------------------------------------
 _cleanup:
	PUSHAD
	MOV EAX,DWORD PTR[DLL_Name.AllocatedAt]
	.if EAX != NULL
		CALL _free
		MOV EAX,DWORD PTR[API_Name.AllocatedAt]
		CALL _free
		MOV EAX,DWORD PTR[IAT_Table_header.AllocatedAt]
		CALL _free
	
		MOV EBX,DWORD PTR[APITableNumber]
		.if DWORD PTR[APITableNumber] != -1
			MOV ECX,offset APITable
		 _free_me_1:
				MOV EAX,DWORD PTR[ECX+EBX*4]
				CALL _free
				DEC EBX
				CMP EBX,-1
				JNE _free_me_1
		.endif

		MOV EBX,DWORD PTR[APITableNumber]
		.if DWORD PTR[APITableNumber] != -1
			MOV ECX,offset APITableAddresses
		 _free_me_2:
				MOV EAX,DWORD PTR[ECX+EBX*4]
				CALL _free
				DEC EBX
				CMP EBX,-1
				JNE _free_me_2
		.endif
	.endif

	POPAD
	RET
;------------------------------------------------------------------
 _covert_VA_to_FO:
	PUSH EBP
	MOV EBP,ESP
	PUSHAD
 ; 
 ; Konverzija
 ;
	MOV EAX,DWORD PTR[EBP+8]		; Parametar 1 = FileMapVA
	MOV EBX,DWORD PTR[EBP+12]		; Parametar 2 = Adresa za konverziju
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
				ADD EBX,DWORD PTR[EBP+8]
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
	MOV EBX,DWORD PTR[Converted]
	LEAVE
	RET 8
;------------------------------------------------------------------
 _covert_FO_to_VA:
	PUSH EBP
	MOV EBP,ESP
	PUSHAD
 ; 
 ; Konverzija
 ;
	MOV EAX,DWORD PTR[EBP+8]		; Parametar 1 = FileMapVA
	MOV EBX,DWORD PTR[EBP+12]		; Parametar 2 = Adresa za konverziju
	SUB EBX,EAX
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
		MOV EDX,DWORD PTR[EAX+16]
		MOV EDI,DWORD PTR[EAX+20]
		.if EBX >= EDI
			ADD EDI,EDX
			.if EBX < EDI
				MOV ECX,1
				SUB EBX,EDI
				ADD EBX,EDX
				ADD EBX,DWORD PTR[EAX+12]
;				ADD EBX,DWORD PTR[ImageBase]
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
	MOV EDX,DWORD PTR[Converted]
	LEAVE
	RET 8
;------------------------------------------------------------------
 _get_section_vs:
	PUSH EBP
	MOV EBP,ESP
	PUSHAD
 ; 
 ; Konverzija
 ;
	MOV EAX,DWORD PTR[EBP+8]		; Parametar 1 = FileMapVA
	MOV EBX,DWORD PTR[EBP+12]		; Parametar 2 = Adresa za konverziju
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
				MOV EBX,DWORD PTR[EAX+8]
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
	LEAVE
	RET 8
;------------------------------------------------------------------
;------------------------------------------------------------------
 _init_all:
ImporterInit proc dwMemorySize:DWORD,dwImageBase:DWORD
	PUSHAD
 ;
 ; Inicijalizacija promenljivih
 ;
	MOV EAX,DWORD PTR[EBP+8]
	MOV DWORD PTR[AllocSize],EAX
	MOV EAX,DWORD PTR[EBP+12]
	MOV DWORD PTR[ImageBase],EAX
	MOV DWORD PTR[DLL_Name.LastDllName],0
	MOV DWORD PTR[API_Name.LastAPITrunk],0
	MOV DWORD PTR[RelativeName],0
	MOV DWORD PTR[ImportTableAddress],0
	MOV DWORD PTR[ImportTableSize],0
	MOV DWORD PTR[Converted],0
	MOV DWORD PTR[MoveIAT],0
	MOV DWORD PTR[EstimatedSize],220
 ;
 ; Alociranje prostora
 ;
	CALL _cleanup
	CALL _init_dll_name
	CALL _init_api_name
	CALL _init_iat_table
	CALL _init_erase_api_table
	POPAD
	RET
ImporterInit endp
;------------------------------------------------------------------
;------------------------------------------------------------------
 _add_new_dll:
ImporterAddNewDll proc dwDLLName:DWORD,dwFirstThunk:DWORD
	PUSHAD
 ;
 ; Povecavamo broj .dll fajlova
 ;
	INC DWORD PTR[DLL_Name.DLLNumber]
 ;
 ; Snimamo ime .dll fajla
 ;
	MOV EAX,DWORD PTR[DLL_Name.CurrentWritePosition]
 ;
 ; Snimamo poslednje ime .dll fajla
 ;
	MOV DWORD PTR[DLL_Name.LastDllName],EAX
	PUSH EAX
 ;
 ; Parametar 1 ove funkcije je pointer ka imenu .dll fajla
 ;
	MOV EBX,DWORD PTR[EBP+8]

	PUSH EBX
	INVOKE lstrcpy,EAX,EBX
	POP EBX
	INVOKE lstrlen,EBX
	ADD DWORD PTR[EstimatedSize],EAX
	ADD DWORD PTR[EstimatedSize],20
 ;
 ; Snimamo poziciju na koju ce sledece ime biti snimljeno
 ;
	INC EAX
	ADD DWORD PTR[DLL_Name.CurrentWritePosition],EAX
 ;
 ; Parametar 2 ove funkcije je pointer ka FirstTrunku
 ;
	POP EAX
	SUB EAX,DWORD PTR[DLL_Name.AllocatedAt]
	MOV DWORD PTR[IAT_Table.szName],EAX

	MOV EAX,DWORD PTR[EBP+12]

	MOV DWORD PTR[IAT_Table.FirstTrunks],EAX
 ;
 ; Kopiramo sadrzaj IAT_table u alociranu memoriju za to 
 ;
	MOV ECX,5
	MOV EDI,DWORD PTR[IAT_Table_header.CurrentWritePosition]
	MOV ESI,offset IAT_Table
	REP MOVS DWORD PTR ES:[EDI],DWORD PTR DS:[ESI]

	MOV DWORD PTR[IAT_Table_header.CurrentWritePosition],EDI
 ;
 ; Brisemo IAT strukturu
 ;
	CALL _clear_iat_table
 ;
 ; Alocirajmo novi prostor za pointere ka imenima
 ;
	CALL _alloc_new_space
	POPAD
	RET
ImporterAddNewDll endp
;------------------------------------------------------------------
;------------------------------------------------------------------
 _add_new_api:
ImporterAddNewAPI proc dwAPIName:DWORD,dwThunkValue:DWORD
	PUSHAD
 ;
 ; Povecavamo broj APIja
 ;
	INC DWORD PTR[API_Name.APINumber]
 ;
 ; Snimamo ime APIja
 ;
	MOV EAX,DWORD PTR[API_Name.CurrentWritePosition]
	PUSH EAX
 ;
 ; Parametar 1 ove funkcije je pointer ka API stringu
 ;
	MOV EBX,DWORD PTR[EBP+8]
 .if EBX > 10000h
	PUSH EBX
	INVOKE lstrcpy,EAX,EBX
	POP EBX
	INVOKE lstrlen,EBX
	ADD DWORD PTR[EstimatedSize],EAX
	ADD DWORD PTR[EstimatedSize],3
 ;
 ; Snimamo poziciju na koju ce sledece ime biti snimljeno
 ;
 ;	INC EAX
	ADD EAX,3	; zbog hinta
	ADD DWORD PTR[API_Name.CurrentWritePosition],EAX

	MOV EBX,EAX	; Zbog ukupne relativne duzine
	POP EAX
	ADD EBX,EAX	; Dodaj duzinu stringa
	SUB EBX,7	; 3/Oduzmi hint od sledeceg API imena
 ; Izmene u EBX
	SUB EAX,DWORD PTR[API_Name.AllocatedAt]
	SUB EAX,6
	MOV DWORD PTR[RelativeName],EAX
 ;
 ; Ukupna relativna duzina
 ;
	MOV ECX,DWORD PTR[API_Name.AllocatedAt]
	SUB EBX,DWORD PTR[API_Name.AllocatedAt]
 ; Izmena EAX => EBX / ADD => MOV
	MOV DWORD PTR[ECX],EBX
 ;
 ; Ovde zapisujemo prvi pointer ka API stringovima
 ;
	MOV EAX,DWORD PTR[EBP+12]
 ;	SUB EAX,DWORD PTR[ImageBase]

	MOV EBX,DWORD PTR[APITableNumber]
	MOV ECX,offset APITableAddresses
	MOV EBX,DWORD PTR[ECX+EBX*4]
	ADD EBX,4
	CMP DWORD PTR[EBP+12],0
	JE _dont_update_first
 ;
 ; Ovde radimo proveru ispravnosti IATa
 ;
	MOV ECX,DWORD PTR[API_Name.LastAPITrunk]
	ADD ECX,4
	.if DWORD PTR[EBX] == 0
		MOV DWORD PTR[EBX],EAX
 ;
 ; Dodato u cilju koriscenja ImporterAddNewDll funkcije sa FirstThunk NULL parametrom
 ;
		PUSHAD
		MOV EBX,DWORD PTR[IAT_Table_header.CurrentWritePosition]
		SUB EBX,4
		MOV DWORD PTR[EBX],EAX
		POPAD

	.else
		.if EAX != ECX
			PUSHAD
			PUSH DWORD PTR[EBP+12]
			PUSH DWORD PTR[DLL_Name.LastDllName]
			CALL _add_new_dll
			POPAD
			PUSHAD
			PUSH DWORD PTR[EBP+12]
			PUSH DWORD PTR[EBP+8]
			CALL _add_new_api
			POPAD
			MOV EAX,offset _exit_adding_new_api
			JMP EAX
		.endif
	.endif
 _dont_update_first:
.else
	POP EAX
	ROL EBX,8
	XOR BL,0FFh
	ROR EBX,8
	MOV DWORD PTR[RelativeName],EBX
 ;
 ; Ovde zapisujemo prvi pointer ka API stringovima
 ;
	MOV EAX,DWORD PTR[EBP+12]

	MOV EBX,DWORD PTR[APITableNumber]
	MOV ECX,offset APITableAddresses
	MOV EBX,DWORD PTR[ECX+EBX*4]
	ADD EBX,4
	CMP DWORD PTR[EBP+12],0
	JE _dont_update_first_ordinal
 ;
 ; Ovde radimo proveru ispravnosti IATa
 ;
	MOV ECX,DWORD PTR[API_Name.LastAPITrunk]
	ADD ECX,4
	.if DWORD PTR[EBX] == 0
		MOV DWORD PTR[EBX],EAX
 ;
 ; Dodato u cilju koriscenja ImporterAddNewDll funkcije sa FirstThunk NULL parametrom
 ;
		PUSHAD
		MOV EBX,DWORD PTR[IAT_Table_header.CurrentWritePosition]
		SUB EBX,4
		MOV DWORD PTR[EBX],EAX
		POPAD

	.else
		.if EAX != ECX
			PUSHAD
			PUSH DWORD PTR[EBP+12]
			PUSH DWORD PTR[DLL_Name.LastDllName]
			CALL _add_new_dll
			POPAD
			PUSHAD
			PUSH DWORD PTR[EBP+12]
			PUSH DWORD PTR[EBP+8]
			CALL _add_new_api
			POPAD
			MOV EAX,offset _exit_adding_new_api
			JMP EAX
		.endif
	.endif
 _dont_update_first_ordinal:
.endif
 ;
 ; Sada upisujemo novu relativnu lokaciju 
 ;
	MOV EBX,DWORD PTR[APITableNumber]
	MOV ECX,offset APITableAddressesCurrentWritePosition
	MOV EBX,DWORD PTR[ECX+EBX*4]
	MOV EAX,DWORD PTR[RelativeName]
	MOV DWORD PTR[EBX],EAX
	MOV EBX,DWORD PTR[APITableNumber]
	ADD DWORD PTR[ECX+EBX*4],4
 ;
 ; Uvecavamo broj APIja za trenutan .dll
 ;
	MOV EBX,DWORD PTR[APITableNumber]
	MOV ECX,offset APITableAddresses
	MOV EBX,DWORD PTR[ECX+EBX*4]
	INC DWORD PTR[EBX]
 _exit_adding_new_api:

 ;
 ; Snimamo poslednji API trunk
 ;
	MOV EAX,DWORD PTR[EBP+12]
	MOV DWORD PTR[API_Name.LastAPITrunk],EAX
	XOR EAX,EAX
	POPAD
	RET
ImporterAddNewAPI endp
;------------------------------------------------------------------
;------------------------------------------------------------------
 _export_IAT:
ImporterExportIAT proc dwStorePlace:DWORD,dwFileMap:DWORD
	PUSHAD
 ;
 ; Sada exportujemo finalni IAT
 ;
 ; Header
 ;
	PUSHAD
	PUSH DWORD PTR[EBP+8]
	PUSH DWORD PTR[EBP+12]
	CALL _covert_VA_to_FO
	MOV DWORD PTR[FinalIAT],EBX
	POPAD

	MOV ESI,DWORD PTR[FinalIAT]
	PUSH ESI
	MOV ESI,DWORD PTR[EBP+8]
	SUB ESI,DWORD PTR[ImageBase]
	MOV DWORD PTR[ImportTableAddress],ESI	; Snimamo pocetnu adresu IAT tablice
	POP ESI

 ;
 ; Reset CWP
 ;
	MOV EAX,DWORD PTR[DLL_Name.AllocatedAt]
	MOV DWORD PTR[DLL_Name.CurrentWritePosition],EAX

	MOV EDI,DWORD PTR[FinalIAT]
 ;	ADD EDI,20		; Stedimo prostor jer nam ne treba 2 prazna null IAT terminatora

	MOV ECX,DWORD PTR[DLL_Name.DLLNumber]
	PUSH ECX
	PUSH EAX
	INC ECX
	MOV EAX,20
	IMUL EAX,ECX
	ADD EDI,EAX
	INC EDI			;Ovde ce biti snimljena imena .dll fajlova
	POP EAX
	POP ECX

	PUSH EDI
	SUB EDI,DWORD PTR[FinalIAT]
	DEC EDI
	MOV DWORD PTR[ImportTableSize],EDI	; Ovde snimamo velicinu IATa
	POP EDI

	.if MoveIAT == 1
		PUSHAD
		PUSH EBP
		MOV EDX,offset APITableAddresses
		MOV EBX,DWORD PTR[API_Name.AllocatedAt]
		XOR ESI,ESI
		XOR EDI,EDI
		XOR ECX,ECX
		.while ECX <= DWORD PTR[APITableNumber]
			MOV EAX,DWORD PTR[EDX+ECX*4]
			.if DWORD PTR[EAX+4] > ESI
				MOV ESI,DWORD PTR[EAX+4]	;High
				MOV EBP,ECX
			.endif
			.if DWORD PTR[EAX+4] < EDI || EDI == NULL
				.if DWORD PTR[EAX+4] != NULL
					MOV EDI,DWORD PTR[EAX+4];Low
				.endif
			.endif
			INC ECX
		.endw
		SUB ESI,EDI
		MOV ECX,EBP
                POP EBP
                MOV EAX,DWORD PTR[EDX+ECX*4]
                MOV ECX,DWORD PTR[EAX]
                IMUL ECX,4
                ADD ECX,4
                ADD ECX,ESI
		MOV DWORD PTR[ESP+1Ch],ECX
		POPAD
		ADD DWORD PTR[ImportTableAddress],EAX
		ADD ESI,EAX
		ADD EDI,EAX
	.endif

	MOV EAX,DWORD PTR[IAT_Table_header.AllocatedAt]
	.while ECX > 0 
		MOV EDX,3
		.while EDX > 0
			MOV EBX,DWORD PTR[EAX]
			MOV DWORD PTR[ESI],EBX
			ADD ESI,4
			ADD EAX,4
			DEC EDX
		.endw
 ;
 ; Upisujemo pointer offset ka imenu
 ;
		CALL _copy_dll_name
		PUSH EDI
		SUB EDI,DWORD PTR[FinalIAT]
		MOV EBX,DWORD PTR[EBP+8]
		ADD EBX,EDI

		SUB EBX,DWORD PTR[ImageBase]

		MOV DWORD PTR[ESI],EBX
		ADD ESI,4
		ADD EAX,4
		POP EDI
 ;
 ; Upisujemo FirstTrunk
 ;
		MOV EBX,DWORD PTR[EAX]
		SUB EBX,DWORD PTR[ImageBase]
		MOV DWORD PTR[ESI],EBX
		ADD ESI,4
		ADD EAX,4

		MOV EDI,DWORD PTR[ReturnEDI]
		DEC ECX
	.endw
 ;
 ; Sada upisujemo 
 ;
	MOV EDX,offset APITableAddresses
	MOV EBX,DWORD PTR[API_Name.AllocatedAt]
 ;
 ; Kopiramo imena
 ;
	PUSHAD
	MOV ECX,DWORD PTR[EBX]
	ADD EBX,4
     _copy_api_name_bytes:
		MOV AL,BYTE PTR[EBX]
		MOV BYTE PTR[EDI],AL
		INC EDI
		INC EBX
		DEC ECX
		JNE _copy_api_name_bytes
 ;	MOV EDI,DWORD PTR[ReturnEDI]		<= Ne menjamo EDI jer je pointer ka tablici API imena
	POPAD
 ;	MOV DWORD PTR[ReturnEDI],EDI

	XOR ECX,ECX
	.while ECX <= DWORD PTR[APITableNumber]
		MOV EAX,DWORD PTR[EDX+ECX*4]
			PUSHAD
			MOV ECX,DWORD PTR[EAX]
			MOV EBX,DWORD PTR[EAX+4]
			ADD EAX,8
			.while ECX > 0
				MOV DWORD PTR[Ordinal],0
				MOV EDX,DWORD PTR[EAX]
				ROL EDX,8
				.if DL == 0FFh
					MOV DWORD PTR[Ordinal],1
					MOV DL,80h
					ROR EDX,8
				.else
					ROR EDX,8
					ADD EDX,EDI
				.endif

				PUSHAD

				PUSH EBX			; Ovde konvertujemo VA u FO
				PUSH DWORD PTR[EBP+12]
				CALL _covert_VA_to_FO

				PUSH EDX

				.if DWORD PTR[Ordinal] == 0
					PUSH EDX		; Ovde konvertujemo FO u VA
					PUSH DWORD PTR[EBP+12]
					CALL _covert_FO_to_VA
				.endif

				MOV DWORD PTR[EBX],EDX
				POP EDX

				POPAD				; Kraj konverzije

				ADD EBX,4
				ADD EAX,4
				DEC ECX
			.endw

			XOR EDX,EDX
			PUSHAD			; Ovde konvertujemo VA u FO

			PUSH EBX
			PUSH DWORD PTR[EBP+12]
			CALL _covert_VA_to_FO

			MOV DWORD PTR[EBX],EDX  ; Zbog praznog null terminate bajta
			POPAD

			POPAD
		INC ECX
	.endw
 ;
 ; Tablica je zapisana, sada ciscenje alocirane memorije
 ;
	CALL _cleanup
 ;
 ; Konacno updateujemo PE.Header
 ;
	MOV EAX,DWORD PTR[EBP+12]		; Parametar 2 = FileMapVA
 ;
 ; elfa_new
 ;
	MOV ECX,DWORD PTR[EAX+3Ch]
 ;
 ; PEHeader
 ;
	LEA ECX,DWORD PTR[EAX+ECX]
	MOV EAX,ECX
	ADD EAX,80h

	MOV EBX,DWORD PTR[ImportTableAddress]
	MOV DWORD PTR[EAX],EBX
	ADD EAX,4
	MOV EBX,DWORD PTR[ImportTableSize]
	MOV DWORD PTR[EAX],EBX

	POPAD
	RET
ImporterExportIAT endp
;------------------------------------------------------------------
ImporterCleanup proc
	CALL _cleanup
	RET
ImporterCleanup endp
;------------------------------------------------------------------
ImporterFindAPIWriteLocation proc dwAPIName:DWORD
	LOCAL dwFoundIt :DWORD
	LOCAL PossibleAddress :DWORD
	PUSHAD

	MOV dwFoundIt,0
	XOR ECX,ECX
	.while ECX <= APITableNumber && dwFoundIt == 0
		MOV EAX,offset APITableAddresses	;VA tablice ka stringovima
		MOV EBX,DWORD PTR[EAX+ECX*4]
		MOV EAX,DWORD PTR[API_Name.AllocatedAt]	;VA stringova
		ADD EAX,6
		MOV EDX,DWORD PTR[EBX+4]
		MOV PossibleAddress,EDX
		MOV EDX,DWORD PTR[EBX]
		LEA EDI,DWORD PTR[EBX+8]
		.while EDX > 0 && dwFoundIt == 0
			MOV ESI,EAX
			ADD ESI,DWORD PTR[EDI]

			PUSHAD
			INVOKE lstrcmp,ESI,dwAPIName
			.if EAX == NULL
				SUB PossibleAddress,4
				MOV dwFoundIt,1
			.endif
			POPAD

			ADD EDI,4
			ADD PossibleAddress,4
			DEC EDX
		.endw
		INC ECX
	.endw

	POPAD
	.if dwFoundIt != 0
		MOV EAX,PossibleAddress
	.else
		XOR EAX,EAX
	.endif
	RET
ImporterFindAPIWriteLocation endp
;------------------------------------------------------------------
ImporterRelocateWriteLocation proc dwAddValue:DWORD
	LOCAL PossibleAddress :DWORD
	PUSHAD

	XOR ECX,ECX
	.while ECX <= APITableNumber
		MOV EAX,offset APITableAddresses	;VA tablice ka stringovima
		MOV EBX,DWORD PTR[EAX+ECX*4]
		MOV EAX,DWORD PTR[API_Name.AllocatedAt]	;VA stringova
		ADD EAX,6
		MOV EDX,dwAddValue
		ADD DWORD PTR[EBX+4],EDX
		MOV EDX,DWORD PTR[EBX]
		LEA EDI,DWORD PTR[EBX+8]
		INC ECX
	.endw
	MOV ECX,DWORD PTR[DLL_Name.DLLNumber]
	MOV EDX,dwAddValue
	MOV EAX,DWORD PTR[IAT_Table_header.AllocatedAt]
	.while ECX > 0 
		ADD EAX,16
		ADD DWORD PTR[EAX],EDX
		ADD EAX,4
		DEC ECX
	.endw

	POPAD
	RET
ImporterRelocateWriteLocation endp
;------------------------------------------------------------------
ImporterEstimatedSize proc
	XOR EAX,EAX
	.if MoveIAT == 1
		PUSHAD
		PUSH EBP
		MOV EDX,offset APITableAddresses
		MOV EBX,DWORD PTR[API_Name.AllocatedAt]
		XOR ESI,ESI
		XOR EDI,EDI
		XOR ECX,ECX
		.while ECX <= DWORD PTR[APITableNumber]
			MOV EAX,DWORD PTR[EDX+ECX*4]
			.if DWORD PTR[EAX+4] > ESI
				MOV ESI,DWORD PTR[EAX+4]	;High
				MOV EBP,ECX
			.endif
			.if DWORD PTR[EAX+4] < EDI || EDI == NULL
				.if DWORD PTR[EAX+4] != NULL
					MOV EDI,DWORD PTR[EAX+4];Low
				.endif
			.endif
			INC ECX
		.endw
		SUB ESI,EDI
		MOV ECX,EBP
                MOV EAX,DWORD PTR[EDX+ECX*4]
                MOV ECX,DWORD PTR[EAX]
                IMUL ECX,4
                ADD ECX,4
                ADD ECX,ESI
                POP EBP
                MOV DWORD PTR[ESP+1Ch],ECX
		POPAD
	.endif
	ADD EAX,DWORD PTR[EstimatedSize]
	RET
ImporterEstimatedSize endp
;------------------------------------------------------------------
ImporterGetAPIName proc dwAPIAddress:DWORD
	LOCAL foundAPIAddress :DWORD
	LOCAL LoadedLibrary :DWORD
	LOCAL NTDLL_handle :DWORD

	PUSHAD
	INVOKE GetModuleHandle,offset szNTDLL_1
	MOV NTDLL_handle,EAX
	MOV DWORD PTR[foundAPIAddress],0
	MOV DWORD PTR[LoadedLibrary],0
	MOV EBX,DWORD PTR[DLL_Name.AllocatedAt]
	INVOKE IsBadCodePtr,EBX
	.if EAX == 0
		MOV EBX,DWORD PTR[DLL_Name.AllocatedAt]
		MOV ECX,DWORD PTR[DLL_Name.DLLNumber]
		.while ECX > 0
			PUSHAD
			INVOKE GetModuleHandle,EBX
			.if EAX == 0
				INVOKE LoadLibrary,EBX
				MOV LoadedLibrary,EAX
			.endif
			MOV DWORD PTR SS:[ESP+1Ch],EAX
			POPAD
			
			.if EAX != NTDLL_handle
				PUSH dwAPIAddress
				PUSH EAX
				CALL _z0mbie_gpa
				.if EAX != 0
					CALL _GetTrueAPIName
					MOV DWORD PTR[foundAPIAddress],EAX
					XOR ECX,ECX
					INC ECX
				.else
					PUSHAD
					INVOKE lstrlen,EBX
					MOV DWORD PTR SS:[ESP+1Ch],EAX
					POPAD
					LEA EBX,DWORD PTR[EAX+EBX+1]
				.endif
			.endif

			.if LoadedLibrary != 0
				PUSHAD
				INVOKE FreeLibrary,LoadedLibrary
				MOV LoadedLibrary,0
				POPAD
			.endif

			DEC ECX
		.endw
	.endif
	
	.if DWORD PTR[foundAPIAddress] == 0 && NTDLL_handle != 0
		PUSH dwAPIAddress
		PUSH NTDLL_handle
		CALL _z0mbie_gpa
		.if EAX != 0
			MOV DWORD PTR[foundAPIAddress],EAX
		.endif
	.endif

	POPAD
	MOV EAX,DWORD PTR[foundAPIAddress]
	RET
ImporterGetAPIName endp
;------------------------------------------------------------------
ImporterGetDLLIndexEx proc dwAPIAddress:DWORD,dwDLLBases:DWORD
	LOCAL foundAPIAddress :DWORD
	LOCAL dwTestAPIAddress :DWORD

	PUSHAD
	
	MOV EAX,dwAPIAddress
	MOV dwTestAPIAddress,EAX

	MOV DWORD PTR[foundAPIAddress],-1
	MOV ECX,1
	MOV EBX,dwDLLBases
	.if EBX != 0
		.while DWORD PTR[EBX] != 0 && ECX != 0
			MOV EAX,dwTestAPIAddress
			.if dwListType == 1
				SUB EAX,DWORD PTR[EBX+4]
				ADD EAX,DWORD PTR[EBX]
			.endif
			PUSH EAX
			PUSH DWORD PTR[EBX]
			CALL _z0mbie_gpa
			.if EAX != 0
				MOV EAX,EBX
				SUB EAX,dwDLLBases
				.if dwListType == 1
					MOV ECX,8
				.else
					MOV ECX,4
				.endif
				CDQ
				DIV ECX
				MOV DWORD PTR[foundAPIAddress],EAX
				XOR ECX,ECX
			.endif
			.if dwListType == 1
				ADD EBX,8
			.else
				ADD EBX,4
			.endif
		.endw
	.endif
	POPAD
	MOV EAX,DWORD PTR[foundAPIAddress]
	RET
ImporterGetDLLIndexEx endp
;------------------------------------------------------------------
ImporterGetAPINameEx proc dwAPIAddress:DWORD,dwDLLBases:DWORD
	LOCAL foundAPIAddress :DWORD
	LOCAL NTDLL_handle :DWORD

	PUSHAD
	INVOKE GetModuleHandle,offset szNTDLL_1
	MOV NTDLL_handle,EAX
	MOV DWORD PTR[foundAPIAddress],0
	MOV EBX,dwDLLBases
	.if EBX != 0
		.while DWORD PTR[EBX] != 0 && foundAPIAddress == 0
			MOV EAX,DWORD PTR[EBX]
			.if EAX != NTDLL_handle
				PUSH dwAPIAddress
				PUSH DWORD PTR[EBX]
				CALL _z0mbie_gpa
				.if EAX != 0
					CALL _GetTrueAPIName
					MOV DWORD PTR[foundAPIAddress],EAX
					XOR ECX,ECX
					INC ECX
				.endif
        		.endif
			.if dwListType == 1
				ADD EBX,8
			.else
				ADD EBX,4
			.endif
		.endw
	.endif

	.if DWORD PTR[foundAPIAddress] == 0 && NTDLL_handle != 0
		PUSH dwAPIAddress
		PUSH NTDLL_handle
		CALL _z0mbie_gpa
		.if EAX != 0
			MOV DWORD PTR[foundAPIAddress],EAX
		.endif
	.endif

	POPAD
	MOV EAX,DWORD PTR[foundAPIAddress]
	RET
ImporterGetAPINameEx endp
;------------------------------------------------------------------
ImporterGetAPINameFromDebugee proc dwProcess:DWORD,dwAPIAddress:DWORD
	LOCAL aDLLBases :DWORD
	LOCAL aMiscBuffer :DWORD
	LOCAL aDLLSortedBases :DWORD
	LOCAL dummy :DWORD
	LOCAL UsedLoadLibrary :DWORD
	LOCAL dwCurrentLibrary :DWORD
	LOCAL ReturnInfo :DWORD

	PUSHAD
	MOV ReturnInfo,0	;Critical error
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aDLLBases,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aDLLSortedBases,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aMiscBuffer,EAX

	INVOKE EnumProcessModules,dwProcess,aDLLBases,800h,addr dummy
	MOV EDI,aDLLSortedBases
	MOV ESI,aDLLBases
	.if EAX == 0
		MOV ReturnInfo,-1	;Error, process terminated!
		JMP _error_exit_api_searcher
	.endif
	.while DWORD PTR[ESI] != 0
		MOV UsedLoadLibrary,0
		MOV EAX,DWORD PTR[ESI]
		INVOKE GetModuleFileNameEx,dwProcess,EAX,aMiscBuffer,MAX_PATH
		INVOKE lstrlen,aMiscBuffer
		ADD EAX,aMiscBuffer
;
; OLD way, but since imports can be loaded from .drv and other images we load import from all files but .exe files!
;		.if DWORD PTR[EAX-4] == 'lld.' || DWORD PTR[EAX-4] == 'llD.' || DWORD PTR[EAX-4] == 'LLD.'
		.if DWORD PTR[EAX-4] != 'exe.' && DWORD PTR[EAX-4] != 'exE.' && DWORD PTR[EAX-4] != 'EXE.' && DWORD PTR[EAX-4] != 'ExE.'
; WIN9x/ME compatibility!
			.while BYTE PTR[EAX] != '\'
				DEC EAX
			.endw
			INC EAX
; End compatibility!
			MOV dwCurrentLibrary,EAX
			INVOKE GetModuleHandle,aMiscBuffer
			.if EAX == NULL
				INVOKE GetModuleHandle,dwCurrentLibrary
				.if EAX == NULL
					INVOKE LoadLibrary,aMiscBuffer
					MOV dwCurrentLibrary,EAX
					MOV UsedLoadLibrary,1
				.endif
			.endif
			MOV DWORD PTR[EDI],EAX		;Store .dll base in debugger
			ADD EDI,4
			MOV EAX,DWORD PTR[ESI]
			MOV DWORD PTR[EDI],EAX		;Store .dll base in debugee
			ADD EDI,4
			.if UsedLoadLibrary == 0
				MOV DWORD PTR[ESI],-1
			.else
				MOV EAX,dwCurrentLibrary
				MOV DWORD PTR[ESI],EAX
			.endif
		.else
			MOV DWORD PTR[ESI],-1
		.endif
		ADD ESI,4
	.endw

	MOV dwListType,1
	PUSH aDLLSortedBases
	PUSH dwAPIAddress
	CALL ImporterGetDLLIndexEx
	.if EAX != -1
		PUSHAD
		MOV ESI,EAX
		MOV EAX,aDLLSortedBases
		MOV EDX,dwAPIAddress
		.while ESI > 0
			ADD EAX,8
			DEC ESI
		.endw
		MOV EBX,DWORD PTR[EAX+4]	;Now points to .dll base inside debugee!
		MOV ECX,DWORD PTR[EAX]		;Now points to .dll base inside debugger!
		SUB EDX,EBX
		ADD EDX,ECX
		MOV dwAPIAddress,EDX
		POPAD

		PUSH aDLLSortedBases
		PUSH dwAPIAddress
		CALL ImporterGetAPINameEx
		MOV ReturnInfo,EAX
	.endif
	MOV dwListType,0

 _error_exit_api_searcher:

	INVOKE VirtualFree,aMiscBuffer,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aMiscBuffer,NULL,MEM_RELEASE;2000h
	INVOKE VirtualFree,aMiscBuffer,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aMiscBuffer,NULL,MEM_RELEASE;2000h
       	INVOKE VirtualFree,aDLLSortedBases,2000h,MEM_DECOMMIT
       	INVOKE VirtualFree,aDLLSortedBases,NULL,MEM_RELEASE;2000h

	MOV ESI,aDLLBases			;Free all loaded libraries
	.while DWORD PTR[ESI] != 0
		.if DWORD PTR[ESI] != -1
			INVOKE FreeLibrary,DWORD PTR[ESI]
		.endif
		ADD ESI,4
	.endw
	POPAD
	MOV EAX,ReturnInfo
	RET
ImporterGetAPINameFromDebugee endp
;------------------------------------------------------------------
ImporterGetDLLNameFromDebugee proc dwProcess:DWORD,dwAPIAddress:DWORD
	LOCAL aDLLBases :DWORD
	LOCAL aMiscBuffer :DWORD
	LOCAL aDLLSortedBases :DWORD
	LOCAL dummy :DWORD
	LOCAL UsedLoadLibrary :DWORD
	LOCAL dwCurrentLibrary :DWORD
	LOCAL ReturnInfo :DWORD

	PUSHAD
	MOV ReturnInfo,0	;Critical error
	INVOKE RtlZeroMemory,addr ForwarderDLLBuffer,1024
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aDLLBases,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aDLLSortedBases,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aMiscBuffer,EAX

	INVOKE EnumProcessModules,dwProcess,aDLLBases,800h,addr dummy
	MOV EDI,aDLLSortedBases
	MOV ESI,aDLLBases
	.if EAX == 0
		MOV ReturnInfo,-1	;Error, process terminated!
		JMP _error_exit_api_searcher
	.endif
	.while DWORD PTR[ESI] != 0
		MOV UsedLoadLibrary,0
		MOV EAX,DWORD PTR[ESI]
		INVOKE GetModuleFileNameEx,dwProcess,EAX,aMiscBuffer,MAX_PATH
		INVOKE lstrlen,aMiscBuffer
		ADD EAX,aMiscBuffer
;
; OLD way, but since imports can be loaded from .drv and other images we load import from all files but .exe files!
;		.if DWORD PTR[EAX-4] == 'lld.' || DWORD PTR[EAX-4] == 'llD.' || DWORD PTR[EAX-4] == 'LLD.'
		.if DWORD PTR[EAX-4] != 'exe.' && DWORD PTR[EAX-4] != 'exE.' && DWORD PTR[EAX-4] != 'EXE.' && DWORD PTR[EAX-4] != 'ExE.'
; WIN9x/ME compatibility!
			.while BYTE PTR[EAX] != '\'
				DEC EAX
			.endw
			INC EAX
; End compatibility!
			MOV dwCurrentLibrary,EAX
			INVOKE GetModuleHandle,aMiscBuffer
			.if EAX == NULL
				INVOKE GetModuleHandle,dwCurrentLibrary
				.if EAX == NULL
					INVOKE LoadLibrary,aMiscBuffer
					MOV dwCurrentLibrary,EAX
					MOV UsedLoadLibrary,1
				.endif
			.endif
			MOV DWORD PTR[EDI],EAX		;Store .dll base in debugger
			ADD EDI,4
			MOV EAX,DWORD PTR[ESI]
			MOV DWORD PTR[EDI],EAX		;Store .dll base in debugee
			ADD EDI,4
			.if UsedLoadLibrary == 0
				MOV DWORD PTR[ESI],-1
			.else
				MOV EAX,dwCurrentLibrary
				MOV DWORD PTR[ESI],EAX
			.endif
		.else
			MOV DWORD PTR[ESI],-1
		.endif
		ADD ESI,4
	.endw

	MOV dwListType,1
	PUSH aDLLSortedBases
	PUSH dwAPIAddress
	CALL ImporterGetDLLIndexEx
	.if EAX != -1
		MOV ESI,EAX
		MOV EAX,aDLLSortedBases
		MOV EDX,dwAPIAddress
		.while ESI > 0
			ADD EAX,8
			DEC ESI
		.endw
		MOV EBX,DWORD PTR[EAX+4]	;Now points to .dll base inside debugee!
		MOV ESI,EBX

		PUSH aDLLSortedBases
		PUSH dwAPIAddress
		CALL ImporterGetAPINameEx

		INVOKE GetModuleFileNameEx,dwProcess,ESI,addr APINameBuffer,1024
		MOV EAX,offset APINameBuffer
		INVOKE lstrlen,offset APINameBuffer
		ADD EAX,offset APINameBuffer
		.while BYTE PTR[EAX] != '\'
			DEC EAX
		.endw
		INC EAX
		.if DWORD PTR[ForwarderDLLBuffer] != NULL
			MOV EAX,offset ForwarderDLLBuffer
			INVOKE lstrlen,offset ForwarderDLLBuffer
			ADD EAX,offset ForwarderDLLBuffer
			.while BYTE PTR[EAX] != '\'
				DEC EAX
			.endw
			INC EAX
		.endif
		MOV ReturnInfo,EAX
	.endif
	MOV dwListType,0

 _error_exit_api_searcher:

	INVOKE VirtualFree,aMiscBuffer,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aMiscBuffer,NULL,MEM_RELEASE;2000h
	INVOKE VirtualFree,aMiscBuffer,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aMiscBuffer,NULL,MEM_RELEASE;2000h
       	INVOKE VirtualFree,aDLLSortedBases,2000h,MEM_DECOMMIT
       	INVOKE VirtualFree,aDLLSortedBases,NULL,MEM_RELEASE;2000h

	MOV ESI,aDLLBases			;Free all loaded libraries
	.while DWORD PTR[ESI] != 0
		.if DWORD PTR[ESI] != -1
			INVOKE FreeLibrary,DWORD PTR[ESI]
		.endif
		ADD ESI,4
	.endw
	POPAD
	MOV EAX,ReturnInfo
	RET
ImporterGetDLLNameFromDebugee endp
;------------------------------------------------------------------
ImporterGetRemoteAPIAddress proc dwProcess:DWORD,dwAPIAddress:DWORD
	LOCAL aDLLBases :DWORD
	LOCAL aMiscBuffer :DWORD
	LOCAL aDLLSortedBases :DWORD
	LOCAL dummy :DWORD
	LOCAL UsedLoadLibrary :DWORD
	LOCAL dwCurrentLibrary :DWORD
	LOCAL ReturnInfo :DWORD

	PUSHAD
	MOV ReturnInfo,0	;Critical error
	INVOKE RtlZeroMemory,addr ForwarderDLLBuffer,1024
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aDLLBases,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aDLLSortedBases,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aMiscBuffer,EAX

	INVOKE EnumProcessModules,dwProcess,aDLLBases,800h,addr dummy
	MOV EDI,aDLLSortedBases
	MOV ESI,aDLLBases
	.if EAX == 0
		MOV ReturnInfo,-1	;Error, process terminated!
		JMP _error_exit_api_searcher
	.endif
	.while DWORD PTR[ESI] != 0
		MOV UsedLoadLibrary,0
		MOV EAX,DWORD PTR[ESI]
		INVOKE GetModuleFileNameEx,dwProcess,EAX,aMiscBuffer,MAX_PATH
		INVOKE lstrlen,aMiscBuffer
		ADD EAX,aMiscBuffer
;
; OLD way, but since imports can be loaded from .drv and other images we load import from all files but .exe files!
;		.if DWORD PTR[EAX-4] == 'lld.' || DWORD PTR[EAX-4] == 'llD.' || DWORD PTR[EAX-4] == 'LLD.'
		.if DWORD PTR[EAX-4] != 'exe.' && DWORD PTR[EAX-4] != 'exE.' && DWORD PTR[EAX-4] != 'EXE.' && DWORD PTR[EAX-4] != 'ExE.'
; WIN9x/ME compatibility!
			.while BYTE PTR[EAX] != '\'
				DEC EAX
			.endw
			INC EAX
; End compatibility!
			MOV dwCurrentLibrary,EAX
			INVOKE GetModuleHandle,aMiscBuffer
			.if EAX == NULL
				INVOKE GetModuleHandle,dwCurrentLibrary
				.if EAX == NULL
					INVOKE LoadLibrary,aMiscBuffer
					MOV dwCurrentLibrary,EAX
					MOV UsedLoadLibrary,1
				.endif
			.endif
			MOV DWORD PTR[EDI],EAX		;Store .dll base in debugger
			ADD EDI,4
			MOV EAX,DWORD PTR[ESI]
			MOV DWORD PTR[EDI],EAX		;Store .dll base in debugee
			ADD EDI,4
			.if UsedLoadLibrary == 0
				MOV DWORD PTR[ESI],-1
			.else
				MOV EAX,dwCurrentLibrary
				MOV DWORD PTR[ESI],EAX
			.endif
		.else
			MOV DWORD PTR[ESI],-1
		.endif
		ADD ESI,4
	.endw

	MOV dwListType,1
	PUSH aDLLSortedBases
	PUSH dwAPIAddress
	CALL ImporterGetDLLIndexEx
	.if EAX != -1
		PUSHAD
		MOV ESI,EAX
		MOV EAX,aDLLSortedBases
		MOV EDX,dwAPIAddress
		.while ESI > 0
			ADD EAX,8
			DEC ESI
		.endw
		MOV EBX,DWORD PTR[EAX+4]	;Now points to .dll base inside debugee!
		MOV ECX,DWORD PTR[EAX]		;Now points to .dll base inside debugger!
		SUB EDX,EBX
		ADD EDX,ECX
		MOV dwAPIAddress,EDX
		POPAD

		MOV EAX,dwAPIAddress
		MOV ReturnInfo,EAX
	.endif
	MOV dwListType,0

 _error_exit_api_searcher:

	INVOKE VirtualFree,aMiscBuffer,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aMiscBuffer,NULL,MEM_RELEASE;2000h
	INVOKE VirtualFree,aMiscBuffer,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aMiscBuffer,NULL,MEM_RELEASE;2000h
       	INVOKE VirtualFree,aDLLSortedBases,2000h,MEM_DECOMMIT
       	INVOKE VirtualFree,aDLLSortedBases,NULL,MEM_RELEASE;2000h

	MOV ESI,aDLLBases			;Free all loaded libraries
	.while DWORD PTR[ESI] != 0
		.if DWORD PTR[ESI] != -1
			INVOKE FreeLibrary,DWORD PTR[ESI]
		.endif
		ADD ESI,4
	.endw
	POPAD
	MOV EAX,ReturnInfo
	RET
ImporterGetRemoteAPIAddress endp
;------------------------------------------------------------------
ImporterAutoSearchIAT proc szDumpFileName:DWORD,inImageBase:DWORD,SearchFromAddress:DWORD,NTSizeOfImage:DWORD,rIATStart:DWORD,rIATSize:DWORD
	LOCAL aProcessMemory :DWORD
	LOCAL NumOfBytesWR :DWORD
	PUSHAD

	MOV EAX,inImageBase
	MOV ImageBase,EAX

	PUSH szDumpFileName
	CALL _map_file
	MOV EAX,FileMapVA
       	MOV aProcessMemory,EAX

	.if EAX > 0
		PUSH SearchFromAddress
		PUSH aProcessMemory
		CALL _covert_VA_to_FO
		XCHG EAX,EBX
		MOV ECX,NTSizeOfImage
		ADD ECX,aProcessMemory
		.if ECX < EAX
			XOR EAX,EAX
			MOV EBX,rIATStart
			MOV DWORD PTR[EBX],EAX
			MOV EBX,rIATSize
			MOV DWORD PTR[EBX],EAX
			JMP _search_error_exit
		.endif
		SUB ECX,EAX
		MOV EDX,NTSizeOfImage
		ADD EDX,inImageBase
		.while ECX > 0
			.if WORD PTR[EAX] == 15FFh || WORD PTR[EAX] == 25FFh
				MOV EDI,DWORD PTR[EAX+2]
				PUSH EDI
				PUSH aProcessMemory
				CALL _covert_VA_to_FO
				.if EDI > inImageBase && EDI < EDX && DWORD PTR[EBX] > 10000h
					PUSH EAX
					PUSH EBX
					PUSH EDI
					PUSH aProcessMemory
					CALL _covert_VA_to_FO
					XCHG EAX,EBX
					POP EBX
					MOV ESI,EAX
					POP EAX
					CMP BYTE PTR[ESI],0
					JE _search_next
					XOR EDI,EDI
					.while EDI == 0 && ESI > aProcessMemory
						.if DWORD PTR[ESI] == 0 && DWORD PTR[ESI-4] == 0
							INC EDI
						.endif
						SUB ESI,4
					.endw
					ADD ESI,8
					PUSH EDX
					PUSH ESI
					PUSH aProcessMemory
					CALL _covert_FO_to_VA
					XCHG EAX,EDX
					ADD EAX,inImageBase
					MOV EBX,rIATStart
					MOV DWORD PTR[EBX],EAX
					POP EDX
					
					MOV ECX,NTSizeOfImage
					ADD ECX,aProcessMemory
					XOR EDI,EDI
					.while EDI == 0 && ESI < ECX
						.if DWORD PTR[ESI] == 0 && DWORD PTR[ESI+4] == 0
							INC EDI
						.endif
						ADD ESI,4
					.endw
					SUB ESI,4
					PUSH EDX
					PUSH ESI
					PUSH aProcessMemory
					CALL _covert_FO_to_VA
					XCHG EAX,EDX
					ADD EAX,inImageBase
					MOV EBX,rIATStart
					MOV ECX,DWORD PTR[EBX]
					SUB EAX,ECX
					MOV EBX,rIATSize
					MOV DWORD PTR[EBX],EAX
					POP EDX

					XOR ECX,ECX
					INC ECX
				.endif
			.endif
 _search_next:
			INC EAX
			DEC ECX
		.endw
	.endif
 _search_error_exit:
	CALL _unmap_file
	POPAD
	RET
ImporterAutoSearchIAT endp
;------------------------------------------------------------------
ImporterAutoSearchIATEx proc hProcess:DWORD,inImageBase:DWORD,SearchFromAddress:DWORD,NTSizeOfImage:DWORD,rIATStart:DWORD,rIATSize:DWORD
	LOCAL aProcessMemory :DWORD
	LOCAL NumOfBytesWR :DWORD
	PUSHAD

	MOV EAX,inImageBase
	MOV ImageBase,EAX

	INVOKE VirtualAlloc,NULL,NTSizeOfImage,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aProcessMemory,EAX
	INVOKE ReadProcessMemory,hProcess,SearchFromAddress,aProcessMemory,NTSizeOfImage,addr NumOfBytesWR

	.if EAX > 0
;		MOV EAX,SearchFromAddress
;		SUB EAX,inImageBase
;		ADD EAX,aProcessMemory
		MOV EAX,aProcessMemory
		MOV ECX,NTSizeOfImage
		ADD ECX,aProcessMemory
		.if ECX < EAX
			XOR EAX,EAX
			MOV EBX,rIATStart
			MOV DWORD PTR[EBX],EAX
			MOV EBX,rIATSize
			MOV DWORD PTR[EBX],EAX
			JMP _search_error_exit
		.endif
		SUB ECX,EAX
		MOV EDX,NTSizeOfImage
		ADD EDX,inImageBase
		.while ECX > 0
			.if WORD PTR[EAX] == 15FFh || WORD PTR[EAX] == 25FFh
				MOV EDI,DWORD PTR[EAX+2]
				MOV EBX,EDI
				SUB EBX,SearchFromAddress
				ADD EBX,aProcessMemory
				.if EDI > inImageBase && EDI < EDX && DWORD PTR[EBX] > 10000h
					PUSH EAX
					PUSH EBX
					MOV EAX,EDI
					SUB EAX,SearchFromAddress
					ADD EAX,aProcessMemory
					POP EBX
					MOV ESI,EAX
					POP EAX
					CMP BYTE PTR[ESI],0
					JE _search_next
					XOR EDI,EDI
					.while EDI == 0 && ESI > aProcessMemory
						.if DWORD PTR[ESI] == 0 && DWORD PTR[ESI-4] == 0
							INC EDI
						.endif
						SUB ESI,4
					.endw
					ADD ESI,8
					PUSH EDX
					MOV EDX,ESI
					XCHG EAX,EDX
					SUB EAX,aProcessMemory
					ADD EAX,SearchFromAddress
					MOV EBX,rIATStart
					MOV DWORD PTR[EBX],EAX
					POP EDX
					
					MOV ECX,NTSizeOfImage
					ADD ECX,aProcessMemory
					XOR EDI,EDI
					.while EDI == 0 && ESI < ECX
						.if DWORD PTR[ESI] == 0 && DWORD PTR[ESI+4] == 0
							INC EDI
						.endif
						ADD ESI,4
					.endw
					SUB ESI,4
					PUSH EDX
					MOV EAX,ESI
					SUB EAX,aProcessMemory
					ADD EAX,SearchFromAddress
					MOV EBX,rIATStart
					MOV ECX,DWORD PTR[EBX]
					SUB EAX,ECX
					MOV EBX,rIATSize
					MOV DWORD PTR[EBX],EAX
					POP EDX

					XOR ECX,ECX
					INC ECX
				.endif
			.endif
 _search_next:
			INC EAX
			DEC ECX
		.endw
	.endif
 _search_error_exit:
 	INVOKE VirtualFree,aProcessMemory,NULL,MEM_RELEASE

	POPAD
	RET
ImporterAutoSearchIATEx endp
;------------------------------------------------------------------
ImporterAutoFixIAT proc hProcess:DWORD,szDumpFileName:DWORD,inImageBase:DWORD,SearchStart:DWORD,SearchSize:DWORD,SearchStep:DWORD
	LOCAL aDLLBases :DWORD
	LOCAL aDLLSortedBases :DWORD
	LOCAL aMiscBuffer :DWORD
	LOCAL aSearchMemory :DWORD
	LOCAL aExeFilePath :DWORD
	LOCAL aExePathHash :DWORD
	LOCAL aExePathLength :DWORD
	LOCAL dummy :DWORD
	LOCAL LastDllId :DWORD
	LOCAL LastDllName :DWORD
	LOCAL AddDll :DWORD
	LOCAL UsedLoadLibrary :DWORD
	LOCAL APIFoundNumber :DWORD
	LOCAL NumOfBytesWR :DWORD
	LOCAL dwTrueAPIAddress :DWORD
	LOCAL dwTestRead :DWORD
	LOCAL dwCurrentLibrary :DWORD
	LOCAL ReturnInfo :DWORD
	PUSHAD

	MOV ReturnInfo,0	;Critical error
	MOV LastDllId,-1
	MOV APIFoundNumber,0
	MOV dwListType,1
	MOV dwTrueAPIAddress,0

	.if SearchStep == 0
		MOV SearchStep,1
	.endif
	
	PUSH inImageBase
	PUSH 51200		;50kb per .dll
	CALL ImporterInit

       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV LastDllName,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aDLLBases,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aDLLSortedBases,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aMiscBuffer,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aExeFilePath,EAX

	INVOKE EnumProcessModules,hProcess,aDLLBases,800h,addr dummy
	MOV ESI,aDLLBases
	MOV EDI,aDLLSortedBases
	.if EAX == 0
		MOV ReturnInfo,401h	;Error, process terminated!
 		JMP _error_exit_iat_fixer
	.endif
	
	INVOKE GetModuleFileNameEx,hProcess,inImageBase,aExeFilePath,MAX_PATH
	MOV EAX,DWORD PTR[aExeFilePath]
	.while BYTE PTR[EAX] != 0
		.if BYTE PTR[EAX] >= 'A' && BYTE PTR[EAX] <= 'Z'
			ADD BYTE PTR[EAX],32
		.endif
		INC EAX
	.endw
	.while BYTE PTR[EAX] != '\'
		MOV BYTE PTR[EAX],0
		DEC EAX
	.endw
	SUB EAX,DWORD PTR[aExeFilePath]
	MOV DWORD PTR[aExePathLength],EAX

	PUSH DWORD PTR[aExePathLength]
	PUSH DWORD PTR[aExeFilePath]
	CALL ZombieHash
	MOV DWORD PTR[aExePathHash],EAX

	.while DWORD PTR[ESI] != 0
		MOV UsedLoadLibrary,0
		MOV EAX,DWORD PTR[ESI]
		INVOKE GetModuleFileNameEx,hProcess,EAX,aMiscBuffer,MAX_PATH
		INVOKE lstrlen,aMiscBuffer
		ADD EAX,aMiscBuffer
;
; OLD way, but since imports can be loaded from .drv and other images we load import from all files but .exe files!
;		.if DWORD PTR[EAX-4] == 'lld.' || DWORD PTR[EAX-4] == 'llD.' || DWORD PTR[EAX-4] == 'LLD.'
		.if DWORD PTR[EAX-4] != 'exe.' && DWORD PTR[EAX-4] != 'exE.' && DWORD PTR[EAX-4] != 'EXE.' && DWORD PTR[EAX-4] != 'ExE.'
; WIN9x/ME compatibility!
			.while BYTE PTR[EAX] != '\'
				DEC EAX
			.endw
			INC EAX
; End compatibility!
			MOV dwCurrentLibrary,EAX
			INVOKE GetModuleHandle,aMiscBuffer
			.if EAX == NULL
				INVOKE GetModuleHandle,dwCurrentLibrary
				.if EAX == NULL
					INVOKE LoadLibrary,aMiscBuffer
					MOV dwCurrentLibrary,EAX
					MOV UsedLoadLibrary,1
				.endif
			.endif
			MOV DWORD PTR[EDI],EAX		;Store .dll base in debugger
			ADD EDI,4
			MOV EAX,DWORD PTR[ESI]
			MOV DWORD PTR[EDI],EAX		;Store .dll base in debugee
			ADD EDI,4
			.if UsedLoadLibrary == 0
				MOV DWORD PTR[ESI],-1
			.else
				MOV EAX,dwCurrentLibrary
				MOV DWORD PTR[ESI],EAX
			.endif
		.else
			MOV DWORD PTR[ESI],-1
		.endif
		ADD ESI,4
	.endw

       	INVOKE VirtualAlloc,NULL,SearchSize,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV aSearchMemory,EAX
	INVOKE ReadProcessMemory,hProcess,SearchStart,aSearchMemory,SearchSize,addr NumOfBytesWR
	.if EAX == 1
		MOV EDI,aSearchMemory
		MOV EBX,SearchStart
		MOV EAX,SearchSize
		MOV ECX,SearchStep
		CDQ
		DIV ECX
		MOV ECX,EAX
		.while ECX > 0
			MOV EDX,DWORD PTR[EDI]
			PUSHAD
                        INVOKE ReadProcessMemory,hProcess,EDX,addr dwTestRead,4,addr NumOfBytesWR
			MOV DWORD PTR[ESP+1Ch],EAX
			POPAD
			.if EAX != NULL
;			.if EAX > 70000000h
				PUSH aDLLSortedBases
				PUSH EDX
				CALL ImporterGetDLLIndexEx
				.if EAX != -1
					.if EAX != LastDllId
						MOV LastDllId,EAX
						MOV ESI,EAX
						MOV EAX,aDLLSortedBases
						.while ESI > 0
							ADD EAX,8
							DEC ESI
						.endw
						MOV EAX,DWORD PTR[EAX+4]	;Now points to .dll base inside debugee!
						PUSHAD
						PUSHAD
						INVOKE RtlZeroMemory,aMiscBuffer,2000h
						POPAD
						INVOKE GetModuleFileNameEx,hProcess,EAX,aMiscBuffer,MAX_PATH
						
						MOV EAX,DWORD PTR[aMiscBuffer]
						ADD EAX,DWORD PTR[aExePathLength]
						.if BYTE PTR[EAX] == '\'
							PUSH DWORD PTR[aExePathLength]
							PUSH DWORD PTR[aMiscBuffer]
							CALL ZombieHash
							.if EAX == DWORD PTR[aExePathHash]
								MOV EAX,DWORD PTR[aMiscBuffer]
								ADD EAX,DWORD PTR[aExePathLength]
								INC EAX
							.endif
						.else
							INVOKE lstrlen,aMiscBuffer
							ADD EAX,aMiscBuffer
							.while BYTE PTR[EAX] != '\'
								DEC EAX
							.endw
							INC EAX
						.endif
						MOV DWORD PTR SS:[ESP+1Ch],EAX
						POPAD

						MOV AddDll,0

						PUSHAD
						XOR EDI,EDI
						MOV ESI,EAX
						INVOKE lstrcmp,ESI,addr szNTDLL_1
						.if EAX == 0
							MOV EDI,1
						.endif
						INVOKE lstrcmp,ESI,addr szNTDLL_2
						.if EAX == 0
							MOV EDI,1
						.endif
						INVOKE lstrcmp,ESI,addr szNTDLL_3
						.if EAX == 0
							MOV EDI,1
						.endif
						.if EDI == 1
							MOV EAX,offset szKERNEL32
							MOV DWORD PTR SS:[ESP+1Ch],EAX
							PUSHAD
							INVOKE lstrcmp,LastDllName,addr szKERNEL32
							.if EAX != 0
								MOV AddDll,1
							.endif
							POPAD
						.endif
						POPAD

						.if AddDll == 0
							PUSHAD
							MOV ESI,EAX
							INVOKE lstrcmp,ESI,LastDllName
							.if EAX != 0
								MOV AddDll,1
							.endif
							POPAD
						.endif

						.if AddDll == 1
							PUSHAD
							PUSHAD
							INVOKE RtlZeroMemory,LastDllName,2000h
							POPAD
							INVOKE lstrcpy,LastDllName,EAX
							POPAD
							PUSH 0
							PUSH EAX
							CALL ImporterAddNewDll
						.endif
					.endif
;
; WE NOW ALIGN THE API ADDRESS TO BASE ADDRESS OF DLL LOADED INTO DEBUGGER MEMORY!
;
					PUSHAD
					MOV ESI,LastDllId
					MOV EAX,aDLLSortedBases
					.while ESI > 0
						ADD EAX,8
						DEC ESI
					.endw
					MOV EBX,DWORD PTR[EAX+4]	;Now points to .dll base inside debugee!
					MOV ECX,DWORD PTR[EAX]		;Now points to .dll base inside debugger!
					SUB EDX,EBX
					ADD EDX,ECX
					MOV dwTrueAPIAddress,EDX
					POPAD

					PUSH aDLLSortedBases
					PUSH dwTrueAPIAddress
					CALL ImporterGetAPINameEx

					PUSHAD
					.if EAX > 0FFFFh
						XOR EDI,EDI
						MOV ESI,EAX
						INVOKE lstrcmp,ESI,offset szRestoreLastError
						.if EAX == 0
							MOV EDI,offset szSetLastError
						.endif
						.if EDI != 0
							MOV DWORD PTR SS:[ESP+1Ch],EDI
						.endif
					.endif
					POPAD

					.if EAX != 0
						PUSH EBX
						PUSH EAX
						CALL ImporterAddNewAPI
						INC APIFoundNumber
					.endif
				.endif
			.endif
			ADD EDI,SearchStep
			ADD EBX,SearchStep
			DEC ECX
		.endw
		.if APIFoundNumber > 0
			CALL ImporterEstimatedSize

			PUSH szDumpFileName
			CALL _map_file

			PUSH EAX
			PUSH FileMapVA
			CALL _calculate_needed_space
	
	               	CALL _unmap_file
			ADD EAX,DWORD PTR[NeededSpace]
			
			PUSH EAX
			PUSH szDumpFileName
			CALL _resize_map_file
	
			PUSH EAX
			PUSH FileMapVA
			CALL _add_new_section
			ADD EAX,inImageBase
			
			PUSH FileMapVA
			PUSH EAX
			CALL ImporterExportIAT
			
			PUSH FileMapVA
			CALL _make_all_sections_writtable
			
			CALL _unmap_file
			MOV ReturnInfo,400h	;Success
		.else
			MOV ReturnInfo,405h	;No API found
		.endif
	.else
		MOV ReturnInfo,404h		;Memory could not be read
	.endif

	MOV ESI,aDLLBases			;Free all loaded libraries
	.while DWORD PTR[ESI] != 0
		.if DWORD PTR[ESI] != -1
			INVOKE FreeLibrary,DWORD PTR[ESI]
		.endif
		ADD ESI,4
	.endw
 
 _error_exit_iat_fixer:

	INVOKE VirtualFree,aDLLBases,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aDLLBases,NULL,MEM_RELEASE;2000h
	INVOKE VirtualFree,aDLLSortedBases,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aDLLSortedBases,NULL,MEM_RELEASE;2000h
	INVOKE VirtualFree,aMiscBuffer,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aMiscBuffer,NULL,MEM_RELEASE;2000h
	INVOKE VirtualFree,aSearchMemory,SearchSize,MEM_DECOMMIT
	INVOKE VirtualFree,aSearchMemory,NULL,MEM_RELEASE;SearchSize
 	INVOKE VirtualFree,aExeFilePath,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aExeFilePath,NULL,MEM_RELEASE;2000h
	INVOKE VirtualFree,LastDllName,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,LastDllName,NULL,MEM_RELEASE;2000h

	MOV dwListType,0

	POPAD
	MOV EAX,ReturnInfo
	RET
ImporterAutoFixIAT endp
;------------------------------------------------------------------
ZombieHash proc dwAddress:DWORD,dwLength:DWORD
	LOCAL Return :DWORD

	PUSHAD
	MOV EAX,dwAddress
	MOV ECX,dwLength
	XOR EBX,EBX
	CDQ
	.while ECX > 0
		.if BYTE PTR[EAX] >= 'A' && BYTE PTR[EAX] <= 'Z'
			ADD BYTE PTR[EAX],32
		.endif
		MOV DL,BYTE PTR[EAX]
		ROL EBX,7
		XOR BL,DL
		INC EAX
		DEC ECX
	.endw
	MOV Return,EBX
	POPAD
	MOV EAX,Return
	RET
ZombieHash endp
;------------------------------------------------------------------
 _calculate_needed_space:
	PUSH EBP
	MOV EBP,ESP
	PUSHAD
 ; 
 ; Konverzija
 ;
	MOV EAX,DWORD PTR[EBP+8]		; Parametar 1 = FileMapVA
	MOV EDX,DWORD PTR[EBP+12]		; Parametar 2 = Velicina nove sekcije
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
	MOV EBX,28h
	IMUL EBX,ECX
	MOV ECX,EAX
	ADD ECX,EBX

	MOV EBX,DWORD PTR[ECX-20h]
	MOV EAX,DWORD PTR[ECX-1Ch]
	ADD EBX,EAX
	MOV EDI,EBX

	PUSHAD				;Racunamo novi VO
	MOV EAX,EBX
	CDQ
	MOV ECX,1000h
	DIV ECX
	IMUL EAX,1000h
	.if EDI > EAX
		ADD EAX,1000h
	.endif
	MOV DWORD PTR[Converted],EAX
	POPAD
	MOV EBX,DWORD PTR[Converted]
	SUB EBX,EDI
	MOV DWORD PTR[NeededSpace],EBX

	POPAD
	LEAVE
	RET 8
;------------------------------------------------------------------
 _make_all_sections_writtable:
	PUSH EBP
	MOV EBP,ESP
	PUSHAD
 ; 
 ; Konverzija
 ;
	MOV EAX,DWORD PTR[EBP+8]		; Parametar 1 = FileMapVA
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

	POPAD
	LEAVE
	RET 4
;------------------------------------------------------------------
 _add_new_section:
	PUSH EBP
	MOV EBP,ESP
	PUSHAD
 ; 
 ; Konverzija
 ;
	MOV EAX,DWORD PTR[EBP+8]		; Parametar 1 = FileMapVA
	MOV EDX,DWORD PTR[EBP+12]		; Parametar 2 = Velicina nove sekcije
	SUB EDX,DWORD PTR[NeededSpace]
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

	MOV BYTE PTR[ECX],'.'
	MOV BYTE PTR[ECX+1],'a'
	MOV BYTE PTR[ECX+2],'p'
	MOV BYTE PTR[ECX+3],'0'
	MOV BYTE PTR[ECX+4],'x'

	MOV DWORD PTR[ECX+8],EDX
	MOV EBX,DWORD PTR[ECX-20h]
	MOV EAX,DWORD PTR[ECX-1Ch]
	ADD EBX,EAX
	MOV EDI,EBX

	PUSHAD				;Racunamo novi VO
	MOV EAX,EBX
	CDQ
	MOV ECX,1000h
	DIV ECX
	IMUL EAX,1000h
	.if EDI > EAX
		ADD EAX,1000h
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

	POPAD
	MOV EAX,DWORD PTR[Converted]
	LEAVE
	RET 8
;------------------------------------------------------------------
;
;OLD Z0MBiE's GPA
;
; _z0mbie_gpa:
;	  PUSHAD
;	  MOV EBX,DWORD PTR SS:[ESP+24h]
;	  MOV ECX,EBX
;	  ADD EBX,DWORD PTR DS:[EBX+3Ch]
;	  MOV EBX,DWORD PTR DS:[EBX+78h]
;	  ADD EBX,ECX
;	  MOV EDI,DWORD PTR DS:[EBX+20h]
;	  ADD EDI,ECX
;	  XOR ESI,ESI
;	L080:
;	  LEA EDX,DWORD PTR DS:[EDI+ESI*4]
;	  MOV EDX,DWORD PTR DS:[EDX]
;	  ADD EDX,ECX
;	  XOR EAX,EAX
;	  MOV EBP,EDX
;	  MOV EDX,DWORD PTR DS:[EBX+24h]
;	  ADD EDX,ECX
;	  MOVZX EDX,WORD PTR DS:[EDX+ESI*2]
;	  MOV EAX,DWORD PTR DS:[EBX+1Ch]
;	  ADD EAX,ECX
;	  MOV EAX,DWORD PTR DS:[EAX+EDX*4]
;	  ADD EAX,ECX
;	  CMP EAX,DWORD PTR SS:[ESP+28h]
;	  JE L094
;	  INC ESI
;	  CMP ESI,DWORD PTR DS:[EBX+18h]
;	  JB L080
;	  XOR EAX,EAX
;	  MOV DWORD PTR SS:[ESP+1Ch],EAX
;	  POPAD
;	  RET 8
;	L094:
;	  MOV DWORD PTR SS:[ESP+1Ch],EBP
;	  POPAD
;	  RET 8
 _z0mbie_gpa:
;------------------------------------------------------------------
ImporterGetAPINameOrOrdinal proc dwDLLBases:DWORD,dwAPIAddress:DWORD
	LOCAL OrdinalBase : DWORD
	LOCAL EATEnteries : DWORD
	LOCAL NameEnteries :DWORD
	LOCAL ExportTable :DWORD
	LOCAL ExportTableSize :DWORD
	LOCAL Found : DWORD
	LOCAL Forwarder :DWORD
	LOCAL ForwarderHandle :DWORD
	LOCAL CurrentOrdinal :DWORD
	PUSHAD

       	INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_EXECUTE_READWRITE
       	MOV Forwarder,EAX

	MOV Found,-1
	MOV ESI,dwDLLBases
	MOV EDI,dwAPIAddress
	MOV EAX,ESI
	ADD EAX,DWORD PTR[ESI+3Ch]

	MOV ECX,DWORD PTR[EAX+78h]
	MOV ExportTable,ECX
	MOV ExportTableSize,ECX
	MOV ECX,DWORD PTR[EAX+7Ch]
	ADD ExportTableSize,ECX
	ADD ExportTableSize,ESI
	ADD ExportTable,ESI

	MOV EAX,DWORD PTR[EAX+78h]
	ADD EAX,ESI

	MOV ECX,DWORD PTR[EAX+16]
	MOV OrdinalBase,ECX
	MOV ECX,DWORD PTR[EAX+20]
	MOV EATEnteries,ECX
	MOV ECX,DWORD PTR[EAX+24]
	MOV NameEnteries,ECX
	MOV EDX,DWORD PTR[EAX+28]
	ADD EDX,ESI

	XOR ECX,ECX
	.while ECX < EATEnteries
		MOV EBX,DWORD PTR[EDX]
		ADD EBX,ESI
		.if EBX == EDI
			MOV Found,ECX
		.endif
		.if EBX >= ExportTable && EBX <= ExportTableSize
			PUSHAD		;Forwarder found!
			PUSHAD
			INVOKE RtlZeroMemory,Forwarder,1000h
			POPAD
			MOV CurrentOrdinal,ECX
			MOV ESI,EBX
			INVOKE lstrcpy,Forwarder,ESI
			MOV ECX,1000h
			MOV EAX,Forwarder
			.while BYTE PTR[EAX] != '.' && ECX > 10
				DEC ECX
				INC EAX
			.endw
			.if ECX > 10h
				MOV DWORD PTR[EAX+1],'lld'
				INVOKE GetModuleHandle,Forwarder
				MOV ForwarderHandle,EAX
				INVOKE lstrcpy,Forwarder,ESI
				MOV EAX,Forwarder
				.while BYTE PTR[EAX] != '.'
					INC EAX
				.endw
				INC EAX
				.if BYTE PTR[EAX] != '#'
					INVOKE GetProcAddress,ForwarderHandle,EAX
					.if EAX == EDI
						PUSHAD
						INVOKE RtlZeroMemory,addr ForwarderDLLBuffer,1024
						INVOKE GetModuleFileName,dwDLLBases,addr ForwarderDLLBuffer,1024
						POPAD
						MOV ECX,CurrentOrdinal
						MOV Found,ECX
					.endif
				.else
					INC EAX
;
; StrToInt ripped from Delphi :)
;
					MOV EDI,0CCCCCCCh
					MOV EDX,EAX
					XOR EAX,EAX
					MOV EBX,30h
					.while BL != 0
						SUB BL,30h
						.if BL > 9
							.break
						.endif
						.if EAX > EDI
							.break
						.endif
						LEA EAX,DWORD PTR[EAX+EAX*4]
						ADD EAX,EAX
						ADD EAX,EBX
						MOVZX EBX,BYTE PTR[EDX]
						INC EDX
					.endw
;
; You can learn something usefull while reversing :)
;
					INVOKE GetProcAddress,ForwarderHandle,EAX
					.if EAX == EDI
						PUSHAD
						INVOKE RtlZeroMemory,addr ForwarderDLLBuffer,1024
						INVOKE GetModuleFileName,dwDLLBases,addr ForwarderDLLBuffer,1024
						POPAD
						MOV ECX,CurrentOrdinal
						MOV Found,ECX
					.endif
				.endif
			.endif
			POPAD
		.endif
		ADD EDX,4
		INC ECX
	.endw

	.if Found != -1
		MOV ECX,Found
		
                MOV EDX,DWORD PTR[EAX+36]
		ADD EDX,ESI
		XOR EBX,EBX
		PUSH EAX
		MOV EAX,EATEnteries
		.while WORD PTR[EDX] != CX && EAX != 0
			ADD EDX,2
			INC EBX
			DEC EAX
		.endw
		.if EAX == 0
			MOV EBX,ECX			;MFC!
		.endif
		XCHG ECX,EBX
		POP EAX

		.if ECX <= NameEnteries
			MOV EDX,DWORD PTR[EAX+32]
			ADD EDX,ESI
			LEA EDX,DWORD PTR[EDX+ECX*4]
                        MOV EDX,DWORD PTR[EDX]
                        ADD EDX,ESI
			MOV Found,EDX
		.else
			ADD EBX,OrdinalBase
;			XOR EBX,80000000h		We won`t do this!
			MOV Found,EBX
		.endif
	.endif

	INVOKE VirtualFree,Forwarder,1000h,MEM_DECOMMIT
	INVOKE VirtualFree,Forwarder,NULL,MEM_RELEASE;1000h

	POPAD
	MOV EAX,Found
	.if EAX == -1
		INC EAX
	.endif
	RET
ImporterGetAPINameOrOrdinal endp
;------------------------------------------------------------------
ImporterGetAddedDllCount proc
	MOV EAX,DWORD PTR[DLL_Name.DLLNumber]
	RET
ImporterGetAddedDllCount endp
;------------------------------------------------------------------
ImporterGetAddedAPICount proc
	MOV EAX,DWORD PTR[API_Name.APINumber]
	RET
ImporterGetAddedAPICount endp
;------------------------------------------------------------------
ImporterMoveIAT proc
	.if MoveIAT == 1
		DEC MoveIAT
	.else
		INC MoveIAT
	.endif
	RET
ImporterMoveIAT endp
;------------------------------------------------------------------
 _GetTrueAPIName:
	PUSHAD
	.if EAX > 0FFFFh
		MOV ESI,EAX
		INVOKE RtlZeroMemory,addr APINameBuffer,256
		INVOKE lstrcpy,addr APINameBuffer,ESI
		MOV EAX,offset APINameBuffer
	.endif
	MOV DWORD PTR SS:[ESP+1Ch],EAX
	POPAD
	RET
;------------------------------------------------------------------
_resize_map_file:
	PUSH EBP
	MOV EBP,ESP
	PUSHAD
	INVOKE CreateFile,DWORD PTR[EBP+8],GENERIC_READ+GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	.if EAX == -1
		POPAD
		LEAVE
		RET 8
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
	LEAVE
	RET 8
;------------------------------------------------------------------
_map_file:
	PUSH EBP
	MOV EBP,ESP
	PUSHAD
	INVOKE CreateFile,DWORD PTR[EBP+8],GENERIC_READ+GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	.if EAX == -1
		POPAD
		LEAVE
		RET 4
	.endif
	MOV DWORD PTR[FileHWND],EAX
	INVOKE GetFileSize,DWORD PTR[FileHWND],NULL
	MOV DWORD PTR[FileSize],EAX
	INVOKE CreateFileMapping,DWORD PTR[FileHWND],NULL,4,NULL,DWORD PTR[FileSize],NULL
	MOV DWORD PTR[FileMap],EAX
	INVOKE MapViewOfFile,DWORD PTR[FileMap],2,NULL,NULL,NULL
	MOV DWORD PTR[FileMapVA],EAX
	POPAD
	LEAVE
	RET 4
;------------------------------------------------------------------
_unmap_file:
	PUSHAD
	INVOKE UnmapViewOfFile,DWORD PTR[FileMapVA]
	INVOKE CloseHandle,DWORD PTR[FileMap]
	INVOKE SetFilePointer,DWORD PTR[FileHWND],DWORD PTR[FileSize],NULL,NULL
	INVOKE SetEndOfFile,DWORD PTR[FileHWND]
	INVOKE CloseHandle,DWORD PTR[FileHWND]
	POPAD
	RET
;------------------------------------------------------------------
;------------------------------------------------------------------
End LibMain