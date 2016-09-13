;------------------------------------------------------------------
      .586
      .model flat, stdcall
      option casemap :none   ; case sensitive

      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc
      include \masm32\include\advapi32.inc
      include \masm32\include\comdlg32.inc
      include \masm32\include\shell32.inc
      include xInclude.inc
      
      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib
      includelib \masm32\lib\comdlg32.lib
      includelib \masm32\lib\advapi32.lib
      includelib \masm32\lib\shell32.lib
;------------------------------------------------------------------
	WndProc PROTO :DWORD,:DWORD,:DWORD,:DWORD 
	TimerProc PROTO :DWORD,:DWORD,:DWORD,:DWORD
 .data
      dlgname       db "TESTWIN",0
      dlgTitle      db "[UPX 1.x - 2.x Unpacker]",0h
 ;
 ; Ucitavanje UnpackEngine-a
 ;
	szInitDebug db "InitDebug",0h
	szSetBPX db "SetBPX",0h
	szRestoreBPX db "RestoreBPX",0h
	szClearDebug db "ClearDebug",0h
	szDebugLoop db "DebugLoop",0h
	szStopDebug db "StopDebug",0h
	szDeleteBPX db "DeleteBPX",0h
	szSetMemoryBPX db "SetMemoryBPX",0h
	szRemoveMemoryBPX db "RemoveMemoryBPX",0h
	szGetContextData db "GetContextData",0h
	szSetContextData db "SetContextData",0h
	szSetCustomHandler db "SetCustomHandler",0h
	szSetAPIBreakPoint db "SetAPIBreakPoint",0h
	szDeleteAPIBreakPoint db "DeleteAPIBreakPoint",0h
	szCurrentExceptionNumber db "CurrentExceptionNumber",0h
	szClearExceptionNumber db "ClearExceptionNumber",0h
	szSafeDeleteAPIBreakPoint db "SafeDeleteAPIBreakPoint",0h
	szSafeDeleteBPX db "SafeDeleteBPX",0h
	szLengthDisassemble db "LengthDisassemble",0h
	szFind db "Find",0h
	szImporterInit db "ImporterInit",0h
	szImporterAddNewDll db "ImporterAddNewDll",0h
	szImporterAddNewAPI db "ImporterAddNewAPI",0h
	szImporterExportIAT db "ImporterExportIAT",0h
	szImporterEstimatedSize db "ImporterEstimatedSize",0h
	szDumpProcess db "DumpProcess",0h
	szPastePEHeader db "PastePEHeader",0h
	szDumpMemory db "DumpMemory",0h
	szFindOverlay db "FindOverlay",0h
	szCopyOverlay db "CopyOverlay",0h
	szGetPE32Data db "GetPE32Data",0h
	szAddNewSection db "AddNewSection",0h
	szMakeAllSectionsRWE db "MakeAllSectionsRWE",0h
	szRealignPE db "RealignPE",0h
	szDebugger db "Debugger.dll",0h
	szImporter db "Importer.dll",0h
	szDumper db "Dumper.dll",0h
	szRealign db "Realign.dll",0h
 ;
 ; Promenljive za OpenFileName dialog
 ;
	ofn OPENFILENAME <>
	FilterString db "All Files",0,"*.*",0h,0h
	OurTitle db "RL!deUPX 1.x - 2.x - coded by Reversing Labs",0h
 ;
 ; Razno
 ;
	szUnpackedExe db "unpacked.exe",0h
 ;
 ; Updater.dll
 ;
 	szUpdaterDll db "Updater.dll",0h
        szUpdateEngine db "UpdateEngine",0h
 	WinVer OSVERSIONINFO <>
 ;
 ; Messages
 ;
	szAboutTitle db "[About]",0h
	szAboutText db "RL!deUPX 1.x - 2.x unpacker",0Dh,0Ah,0Dh,0Ah,"Visit Reversing Labs at http://www.reversinglabs.com",0Dh,0Ah,0Dh,0Ah,"  Minimum engine version needed:",0Dh,0Ah,"- DebuggerEngine 1.2 by RevLabs",0Dh,0Ah,"- DumperEngine 1.2 by RevLabs",0Dh,0Ah,"- ImporterEngine 1.2 by RevLabs",0Dh,0Ah,"- UpdaterEngine 1.0 by RevLabs",0Dh,0Ah,"- Realign 1.5 by y0da",0Dh,0Ah,0Dh,0Ah,"Unpacker coded by Reversing Labs",0h
	szErrorText db "[Error] Error while opening file or file not selected!",0h
	szFatalErrorText db "[Fatal Unpacking Error] Please mail file you tried to unpack to Reversing Labs!",0h
	szErrorTitle db "[Error]",0h
	szMsgText db "[Success] File has been unpacked to unpacked.exe",0h
	szMsgTitle db "[Success]",0h
	szNotPackErrorText db "[Error] Selected file is not packed with UPX 1.x - 2.x",0h
	szDllErrorText db "[Error] Could not load nessesary engine .dll files!",0h
	szInitUnpack db "Unpack started...",0h
	szEndUnpack db "Unpack ended...",0h
	szLoadLibraryBPX db "+ LoadLibrary BPX => %s",0h
	szGetProcAddrBPX db "+ GetProcAddress BPX => %s",0h
	szxGetProcAddrBPX db "+ GetProcAddress BPX => %08X",0h
	szOEPJmpBPX db "+ OEP Jump BPX => %08X",0h
	szDumped db "+ Process dumped",0h
	szIATFixed db "+ IAT has been fixed",0h
	szRealing db "+ Realigning file",0h
	szLogCopyOverlay db "+ Moving overlay to unpacked file",0h
	szCopyOverlayText db "Do you want to copy overlay from original file?",0h
	szCopyOverlayTitle db "Confirmation:",0h
 .data?
 ;
 ; Ucitavanje UnpackEngine-a
 ;
	hRealignPE dd ?
	hDumper dd ?
	hImporter dd ?
	hDebugger dd ?
	cInitDebug dd ?
	cSetBPX dd ?
	cDebugLoop dd ?
	cClearDebug dd ?
	cStopDebug dd ?
	cSetCustomHandler dd ?
	cSetContextData dd ?
	cRestoreBPX dd ?
	cDeleteBPX dd ?
	cSetMemoryBPX dd ?
	cRemoveMemoryBPX dd ?
	cGetContextData dd ?
	cSetAPIBreakPoint dd ?
	cDeleteAPIBreakPoint dd ?
	cCurrentExceptionNumber dd ?
	cClearExceptionNumber dd ?
	cSafeDeleteAPIBreakPoint dd ?
	cSafeDeleteBPX dd ?
	cLengthDisassemble dd ?
	cFind dd ?
	cImporterInit dd ?
	cImporterAddNewDll dd ?
	cImporterAddNewAPI dd ?
	cImporterExportIAT dd ?
	cImporterEstimatedSize dd ?
	cDumpProcess dd ?
	cPastePEHeader dd ?
	cDumpMemory dd ?
	cFindOverlay dd ?
	cCopyOverlay dd ?
	cGetPE32Data dd ?
	cAddNewSection dd ?
	cMakeAllSectionsRWE dd ?
	cRealignPE dd ?
 ;
 ; Mapiranje fajla
 ;
	FileHWND dd ?
	FileSize dd ?
	FileMap dd ?
	FileMapVA dd ?
 ;
 ; Ostale promenljive
 ;
	hInstance dd ?
	buffer db 512 dup(?)
	szUnpackFileName db 512 dup(?)
	szOpenFileName db 512 dup(?)
	Converted dd ?

	SizeOfImage dd ?
	ImageBase dd ?
	PackedOEP dd ?
	UnpackedOEP dd ?
	rOVLStart dd ?
	rOVLSize dd ?
 ;
 ; ProcesInfo pointer
 ;
	pDbgData dd ?
 ;
 ; Updater called?
 ;
	UpdateCalled dd ?
 ;
 ; Read buffer for ReadProcessMemory
 ;
	NumOfBytesWR dd ?
	ReadBuffer db 1024h dup(?)
 ;
 ; UPX 1.x - 2.x specific
 ;
	PackBPX1 dd ?
	PackBPX2 dd ?
	PackBPX3 dd ?
	PackBPX4 dd ?
	NeededSpace dd ?

	HW dd ?
	BoxHwnd dd ?
	tESP dd ?
 .code

start:
;------------------------------------------------------------------
	ASSUME FS:NOTHING
	PUSH offset _SehExit
	PUSH DWORD PTR FS:[0]
	MOV FS:[0],ESP

        INVOKE GetModuleHandle,NULL
        MOV DWORD PTR[hInstance],EAX
        INVOKE DialogBoxParam,hInstance,ADDR dlgname,0,ADDR WndProc,0
        INVOKE ExitProcess,eax
	RET
 _unpack:
	MOV DWORD PTR[tESP],ESP
	PUSH offset szInitUnpack
	CALL _show_log_message

	CALL _init_dlls
	CALL _get_PE_header_data
	CALL _init_importer
	CALL _init_debugger
	CALL _init_breakpoints
	CALL DWORD PTR[cDebugLoop]

	PUSH offset rOVLSize
	PUSH offset rOVLStart
	PUSH offset szOpenFileName
	CALL cFindOverlay

	.if rOVLSize > 0
		INVOKE MessageBox,NULL,addr szCopyOverlayText,addr szCopyOverlayTitle,44h
		.if EAX == 6
			PUSH offset szLogCopyOverlay
			CALL _show_log_message

			PUSH offset szUnpackFileName
			PUSH offset szOpenFileName
			CALL DWORD PTR[cCopyOverlay]
		.endif
	.endif

	PUSH offset szEndUnpack
	CALL _show_log_message
	RET
;------------------------------------------------------------------
 _SehExit:
	POP FS:[0]
	ADD ESP,4
	INVOKE MessageBox,NULL,addr szFatalErrorText,addr szErrorTitle,30h
	INVOKE ExitProcess,NULL
	RET
;------------------------------------------------------------------
WndProc proc hWin   :DWORD,
             uMsg   :DWORD,
             wParam :DWORD,
             lParam :DWORD

      .if uMsg == WM_INITDIALOG
		invoke SendMessage,hWin,WM_SETTEXT,0,ADDR dlgTitle
		invoke LoadIcon,hInstance,500    ; icon ID
		PUSH EAX
		PUSH 0
		PUSH 80h
		PUSH hWin
		CALL SendMessage
		PUSH 700
		PUSH DWORD PTR DS:[hWin]
		CALL GetDlgItem
		PUSH 1
		PUSH 700
		PUSH [hWin]
		CALL CheckDlgButton
		MOV EAX,[hWin]
		MOV [HW],EAX

      .elseif uMsg == WM_DROPFILES
		PUSHAD
		invoke DragQueryFile,wParam,0,ADDR buffer,256
		INVOKE lstrcpy,addr szOpenFileName,addr buffer
		INVOKE lstrcpy,addr szUnpackFileName,addr buffer
		.if BYTE PTR[szOpenFileName] == 0
			INVOKE MessageBox,NULL,addr szErrorText,addr szErrorTitle,30h
			MOV ESP,DWORD PTR[tESP]
			RET
		.endif
		CALL _get_dump_file_name
		PUSH offset szOpenFileName
		PUSH 102
		PUSH DWORD PTR DS:[hWin]
		CALL SetDlgItemText
		POPAD

      .elseif uMsg == WM_CLOSE
        invoke EndDialog,hWin,0

      .elseif uMsg == WM_COMMAND

        .if wParam == 107
		PUSHAD
		PUSH 6Fh
		PUSH DWORD PTR DS:[HW]
		CALL GetDlgItem
		MOV [BoxHwnd],EAX
		PUSH 0
		PUSH 0
		PUSH 184h
		PUSH [BoxHwnd]
		CALL SendMessage
		POPAD
		.if DWORD PTR[szOpenFileName] != 0
			CALL _unpack
		.else
			INVOKE MessageBox,NULL,addr szErrorText,addr szErrorTitle,30h
		.endif
        .endif
        .if wParam == 108
		CALL _get_exe_file
		PUSH offset szOpenFileName
		PUSH 102
		PUSH DWORD PTR DS:[hWin]
		CALL SetDlgItemText
        .endif
        .if wParam == 109
		PUSH 40h
		PUSH offset szAboutTitle
		PUSH offset szAboutText
		PUSH [hWin]
		CALL MessageBox
        .endif
        .if wParam == 110
		invoke EndDialog,hWin,0
        .endif

      .endif

	INVOKE IsWindowVisible,DWORD PTR[hWin]
	.if EAX == TRUE && DWORD PTR[UpdateCalled] == 0
		MOV DWORD PTR[UpdateCalled],1
		INVOKE SetTimer,DWORD PTR[HW],101,1000,addr TimerProc
	.endif

    xor eax, eax
    ret

WndProc endp
;------------------------------------------------------------------
TimerProc proc hWnd:DWORD,uMSG:DWORD,idEvent:DWORD,dwTime:DWORD
	PUSHAD
	
	.if idEvent == 101
		INVOKE KillTimer,DWORD PTR[HW],101
		MOV DWORD PTR[WinVer.dwOSVersionInfoSize],sizeof OSVERSIONINFO
		INVOKE GetVersionEx,addr WinVer
		.if DWORD PTR[WinVer.dwPlatformId] == VER_PLATFORM_WIN32_NT
			INVOKE LoadLibrary,addr szUpdaterDll
			INVOKE GetProcAddress,EAX,addr szUpdateEngine
			.if EAX != 0
				PUSH DWORD PTR[HW]
				PUSH 1
				CALL EAX
			.endif
		.endif
	.endif

	POPAD
	RET
TimerProc endp
;------------------------------------------------------------------
_init_breakpoints:
	PUSHAD

	PUSH offset _load_library_call
	PUSH 0
	PUSH DWORD PTR[PackBPX1]
	CALL DWORD PTR[cSetBPX]

	PUSH offset _get_proc_addr_call_1
	PUSH 0
	PUSH DWORD PTR[PackBPX2]
	CALL DWORD PTR[cSetBPX]

	.if DWORD PTR[PackBPX4] != 0
		PUSH offset _get_proc_addr_call_2
		PUSH 0
		PUSH DWORD PTR[PackBPX4]
		CALL DWORD PTR[cSetBPX]
	.endif

	PUSH offset _oep_jump
	PUSH 1
	PUSH DWORD PTR[PackBPX3]
	CALL DWORD PTR[cSetBPX]

	POPAD
	RET
;------------------------------------------------------------------
 _show_log_message:
	PUSH EBP
	MOV EBP,ESP
	PUSHAD
	PUSH [EBP+8]
	PUSH 0
	PUSH 180h
	PUSH [BoxHwnd]
	CALL SendMessage
	PUSH 0
	PUSH 0
	PUSH 18Bh
	PUSH [BoxHwnd]
	CALL SendMessage
	DEC EAX
	PUSH 0
	PUSH EAX
	PUSH 186h
	PUSH [BoxHwnd]
	CALL SendMessage
	POP EBP
	POPAD
	LEAVE
	RET 4
;------------------------------------------------------------------
;
; BPX CALLBack
;
 _load_library_call:
	PUSHAD

	PUSH 2					;EBX write address
	CALL DWORD PTR[cGetContextData]
	PUSH EAX

	PUSH 1					;EAX addr LPSTR .dll name
	CALL DWORD PTR[cGetContextData]

	PUSHAD
	MOV EBX,DWORD PTR[pDbgData]
	MOV EBX,DWORD PTR[EBX]
	INVOKE ReadProcessMemory,EBX,EAX,addr ReadBuffer,100,addr NumOfBytesWR
	POPAD

	PUSHAD
	PUSH offset ReadBuffer
	PUSH offset szLoadLibraryBPX
	PUSH offset buffer
	CALL wsprintf
	ADD ESP,0Ch
	POPAD

	PUSH offset ReadBuffer
	CALL DWORD PTR[cImporterAddNewDll]

	PUSH offset buffer
	CALL _show_log_message

	POPAD
	RET

 _get_proc_addr_call_2:
	PUSHAD

	PUSH 2
	CALL DWORD PTR[cGetContextData]		;EBX write address

	PUSH EAX

	PUSH 1					;EAX addr LPSTR API name
	CALL DWORD PTR[cGetContextData]	

	.if EAX > DWORD PTR[ImageBase]
		PUSHAD
		MOV EBX,DWORD PTR[pDbgData]
		MOV EBX,DWORD PTR[EBX]
		PUSHAD
		INVOKE RtlZeroMemory,addr ReadBuffer,100
		POPAD
		INVOKE ReadProcessMemory,EBX,EAX,addr ReadBuffer,100,addr NumOfBytesWR
		POPAD
		PUSH offset ReadBuffer

		PUSHAD
		PUSH offset ReadBuffer
		PUSH offset szGetProcAddrBPX
		PUSH offset buffer
		CALL wsprintf
		ADD ESP,0Ch
		POPAD
	.else
		PUSHAD
		PUSH EAX
		PUSH offset szxGetProcAddrBPX
		PUSH offset buffer
		CALL wsprintf
		ADD ESP,0Ch
		POPAD

		PUSH EAX
	.endif
	CALL DWORD PTR[cImporterAddNewAPI]

	PUSH offset buffer
	CALL _show_log_message

	POPAD
	RET

 _get_proc_addr_call_1:
	PUSHAD

	PUSH 2
	CALL DWORD PTR[cGetContextData]		;EBX write address

	PUSH EAX

	PUSH 5					;EDI addr LPSTR API name
	CALL DWORD PTR[cGetContextData]	

	.if EAX > DWORD PTR[ImageBase]
		PUSHAD
		MOV EBX,DWORD PTR[pDbgData]
		MOV EBX,DWORD PTR[EBX]
		PUSHAD
		INVOKE RtlZeroMemory,addr ReadBuffer,100
		POPAD
		INVOKE ReadProcessMemory,EBX,EAX,addr ReadBuffer,100,addr NumOfBytesWR
		POPAD
		PUSH offset ReadBuffer

		PUSHAD
		PUSH offset ReadBuffer
		PUSH offset szGetProcAddrBPX
		PUSH offset buffer
		CALL wsprintf
		ADD ESP,0Ch
		POPAD
	.else
		PUSHAD
		PUSH EAX
		PUSH offset szxGetProcAddrBPX
		PUSH offset buffer
		CALL wsprintf
		ADD ESP,0Ch
		POPAD

		PUSH EAX
	.endif
	CALL DWORD PTR[cImporterAddNewAPI]

	PUSH offset buffer
	CALL _show_log_message

	POPAD
	RET

 _oep_jump:
	PUSHAD

	PUSHAD
	PUSH DWORD PTR[UnpackedOEP]
	PUSH offset szOEPJmpBPX
	PUSH offset buffer
	CALL wsprintf
	ADD ESP,0Ch
	POPAD

	PUSH offset buffer
	CALL _show_log_message

	PUSH DWORD PTR[UnpackedOEP]
	PUSH offset szUnpackFileName
	PUSH DWORD PTR[ImageBase]
	MOV EAX,DWORD PTR[pDbgData]
	MOV EAX,DWORD PTR[EAX]
	PUSH EAX
	CALL DWORD PTR[cDumpProcess]

	PUSH offset szDumped
	CALL _show_log_message

	CALL DWORD PTR[cStopDebug]

	CALL DWORD PTR[cImporterEstimatedSize]

	PUSH offset szUnpackFileName
	CALL _map_file

	PUSH EAX
	PUSH DWORD PTR[FileMapVA]
	CALL _calculate_needed_space

	CALL _unmap_file
	ADD EAX,DWORD PTR[NeededSpace]

	PUSH EAX
	PUSH offset szUnpackFileName
	CALL _resize_map_file

	PUSH EAX
	PUSH DWORD PTR[FileMapVA]
	CALL _add_new_section
	ADD EAX,DWORD PTR[ImageBase]

	PUSH DWORD PTR[FileMapVA]
	PUSH EAX
	CALL DWORD PTR[cImporterExportIAT]

	PUSH offset szIATFixed
	CALL _show_log_message

	PUSH DWORD PTR[FileMapVA]
	CALL _make_all_sections_writtable

	PUSH 700
	PUSH [HW]
	CALL IsDlgButtonChecked
	.if EAX == TRUE
		PUSH offset szRealing
		CALL _show_log_message

		PUSH 2
		PUSH DWORD PTR[FileSize]
		PUSH DWORD PTR[FileMapVA]
		CALL DWORD PTR[cRealignPE]
	.endif

	CALL _unmap_file

	INVOKE MessageBox,NULL,addr szMsgText,addr szMsgTitle,40h

	POPAD
	RET
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
	ADD EAX,0F8h
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
	ADD EAX,0F8h
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
	INC WORD PTR[EAX+6]
 ;
 ; Section Tabela
 ;
	PUSH EAX
	ADD EAX,0F8h
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
	MOV DWORD PTR[ECX+20],EBX
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
	ADD EAX,0F8h
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
	ADD EAX,0F8h
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
	MOV EAX,DWORD PTR[Converted]
	LEAVE
	RET 8
;------------------------------------------------------------------
_init_debugger:
	PUSHAD

	PUSH NULL
	PUSH NULL
	PUSH offset szOpenFileName
	CALL DWORD PTR[cInitDebug]
	MOV DWORD PTR[pDbgData],EAX

	POPAD
	RET
;------------------------------------------------------------------
_init_importer:
	PUSHAD

	PUSH DWORD PTR[ImageBase]
	PUSH 30720
	CALL DWORD PTR[cImporterInit]

	POPAD
	RET
;------------------------------------------------------------------
_init_dlls:
	PUSHAD
	INVOKE LoadLibrary,addr szDebugger
	MOV DWORD PTR[hDebugger],EAX
	.if DWORD PTR[hDebugger] != 0
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szInitDebug
		MOV DWORD PTR[cInitDebug],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szSetBPX
		MOV DWORD PTR[cSetBPX],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szDebugLoop
		MOV DWORD PTR[cDebugLoop],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szClearDebug
		MOV DWORD PTR[cClearDebug],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szStopDebug
		MOV DWORD PTR[cStopDebug],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szSetCustomHandler
		MOV DWORD PTR[cSetCustomHandler],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szRestoreBPX
		MOV DWORD PTR[cRestoreBPX],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szDeleteBPX
		MOV DWORD PTR[cDeleteBPX],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szGetContextData
		MOV DWORD PTR[cGetContextData],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szSetContextData
		MOV DWORD PTR[cSetContextData],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szSetMemoryBPX
		MOV DWORD PTR[cSetMemoryBPX],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szRemoveMemoryBPX
		MOV DWORD PTR[cRemoveMemoryBPX],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szSetAPIBreakPoint
		MOV DWORD PTR[cSetAPIBreakPoint],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szDeleteAPIBreakPoint
		MOV DWORD PTR[cDeleteAPIBreakPoint],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szCurrentExceptionNumber
		MOV DWORD PTR[cCurrentExceptionNumber],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szClearExceptionNumber
		MOV DWORD PTR[cClearExceptionNumber],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szSafeDeleteAPIBreakPoint
		MOV DWORD PTR[cSafeDeleteAPIBreakPoint],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szSafeDeleteBPX
		MOV DWORD PTR[cSafeDeleteBPX],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szLengthDisassemble
		MOV DWORD PTR[cLengthDisassemble],EAX
		INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szFind
		MOV DWORD PTR[cFind],EAX
	.else
		INVOKE MessageBox,NULL,addr szDllErrorText,addr szErrorTitle,30h
		INVOKE ExitProcess,NULL
	.endif

	INVOKE LoadLibrary,addr szImporter
	MOV DWORD PTR[hImporter],EAX
	.if DWORD PTR[hImporter] != 0
		INVOKE GetProcAddress,DWORD PTR[hImporter],addr szImporterInit
		MOV DWORD PTR[cImporterInit],EAX
		INVOKE GetProcAddress,DWORD PTR[hImporter],addr szImporterAddNewDll
		MOV DWORD PTR[cImporterAddNewDll],EAX
		INVOKE GetProcAddress,DWORD PTR[hImporter],addr szImporterAddNewAPI
		MOV DWORD PTR[cImporterAddNewAPI],EAX
		INVOKE GetProcAddress,DWORD PTR[hImporter],addr szImporterExportIAT
		MOV DWORD PTR[cImporterExportIAT],EAX
		INVOKE GetProcAddress,DWORD PTR[hImporter],addr szImporterEstimatedSize
		MOV DWORD PTR[cImporterEstimatedSize],EAX
	.else
		INVOKE MessageBox,NULL,addr szDllErrorText,addr szErrorTitle,30h
		INVOKE ExitProcess,NULL
	.endif

	INVOKE LoadLibrary,addr szDumper
	MOV DWORD PTR[hDumper],EAX
	.if DWORD PTR[hDumper] != 0
		INVOKE GetProcAddress,DWORD PTR[hDumper],addr szDumpProcess
		MOV DWORD PTR[cDumpProcess],EAX
		INVOKE GetProcAddress,DWORD PTR[hDumper],addr szPastePEHeader
		MOV DWORD PTR[cPastePEHeader],EAX
		INVOKE GetProcAddress,DWORD PTR[hDumper],addr szDumpMemory
		MOV DWORD PTR[cDumpMemory],EAX
		INVOKE GetProcAddress,DWORD PTR[hDumper],addr szCopyOverlay
		MOV DWORD PTR[cCopyOverlay],EAX
		INVOKE GetProcAddress,DWORD PTR[hDumper],addr szGetPE32Data
		MOV DWORD PTR[cGetPE32Data],EAX
		INVOKE GetProcAddress,DWORD PTR[hDumper],addr szAddNewSection
		MOV DWORD PTR[cAddNewSection],EAX
		INVOKE GetProcAddress,DWORD PTR[hDumper],addr szMakeAllSectionsRWE
		MOV DWORD PTR[cMakeAllSectionsRWE],EAX
		INVOKE GetProcAddress,DWORD PTR[hDumper],addr szFindOverlay
		MOV DWORD PTR[cFindOverlay],EAX
	.else
		INVOKE MessageBox,NULL,addr szDllErrorText,addr szErrorTitle,30h
		INVOKE ExitProcess,NULL
	.endif

	INVOKE LoadLibrary,addr szRealign
	MOV DWORD PTR[hRealignPE],EAX
	.if DWORD PTR[hRealignPE] != 0
		INVOKE GetProcAddress,DWORD PTR[hRealignPE],addr szRealignPE
		MOV DWORD PTR[cRealignPE],EAX
	.else
		INVOKE MessageBox,NULL,addr szDllErrorText,addr szErrorTitle,30h
		INVOKE ExitProcess,NULL
	.endif

	POPAD
	RET
;------------------------------------------------------------------
_get_exe_file:
	PUSHAD

        INVOKE GetModuleHandle,NULL
        MOV DWORD PTR[hInstance],EAX

	PUSH 260
	PUSH offset buffer
	CALL RtlZeroMemory

	MOV ofn.lStructSize,SIZEOF ofn
	MOV ofn.lpstrFilter, OFFSET FilterString
	MOV ofn.lpstrFile, OFFSET buffer
	MOV ofn.nMaxFile,512
	MOV ofn.Flags, OFN_FILEMUSTEXIST or \
			OFN_PATHMUSTEXIST or OFN_LONGNAMES or\
			OFN_EXPLORER or OFN_HIDEREADONLY
	MOV  ofn.lpstrTitle, OFFSET OurTitle
	INVOKE GetOpenFileName, ADDR ofn

	INVOKE lstrcpy,addr szOpenFileName,addr buffer
	INVOKE lstrcpy,addr szUnpackFileName,addr buffer
	.if BYTE PTR[szOpenFileName] == 0
		INVOKE MessageBox,NULL,addr szErrorText,addr szErrorTitle,30h
		POPAD
		RET
	.endif
	CALL _get_dump_file_name

	POPAD
	RET
;------------------------------------------------------------------
_get_dump_file_name:
	PUSHAD
	MOV ECX,offset szUnpackFileName
	ADD ECX,512
	.while BYTE PTR[ECX] != '\'
		DEC ECX
	.endw
	INC ECX
	MOV BYTE PTR[ECX],0
	INVOKE lstrcpy,ECX,addr szUnpackedExe

	POPAD
	RET
;------------------------------------------------------------------
_resize_map_file:
	PUSH EBP
	MOV EBP,ESP
	PUSHAD
	INVOKE CreateFile,DWORD PTR[EBP+8],GENERIC_READ+GENERIC_WRITE,NULL,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	.if EAX == -1
		INVOKE MessageBox,NULL,addr szErrorText,addr szErrorTitle,30h
		MOV ESP,DWORD PTR[tESP]
		RET
	.endif
	MOV DWORD PTR[FileHWND],EAX
	INVOKE GetFileSize,DWORD PTR[FileHWND],NULL
	MOV DWORD PTR[FileSize],EAX
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
	INVOKE CreateFile,DWORD PTR[EBP+8],GENERIC_READ+GENERIC_WRITE,NULL,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	.if EAX == -1
		INVOKE MessageBox,NULL,addr szErrorText,addr szErrorTitle,30h
		MOV ESP,DWORD PTR[tESP]
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
_get_PE_header_data:
	PUSHAD
	PUSH offset szOpenFileName
	CALL _map_file

	MOV EAX,DWORD PTR[FileMapVA]
	MOVZX ECX,WORD PTR[EAX+3Ch]
	LEA ECX,DWORD PTR[EAX+ECX]
	MOV EDX,DWORD PTR[ECX+34h]		;Read ImageBase
	MOV DWORD PTR[ImageBase],EDX
	MOV EDX,DWORD PTR[ECX+28h]		;Read PackedOEP
	MOV DWORD PTR[PackedOEP],EDX
	MOV EDX,DWORD PTR[ImageBase]
	ADD DWORD PTR[PackedOEP],EDX

	PUSH DWORD PTR[PackedOEP]
	PUSH DWORD PTR[FileMapVA]
	CALL _covert_VA_to_FO

	PUSH EAX
	CALL _find_bpx

	CALL _unmap_file
	POPAD
	RET
;------------------------------------------------------------------
_find_bpx:
	PUSH EBP
	MOV EBP,ESP

	MOV EAX,DWORD PTR[FileMapVA]
	ADD EAX,DWORD PTR[EBP+8]
	MOV DWORD PTR[PackBPX4],0

	MOV EDX,1000				;BPX1
	.while DWORD PTR[EAX] != 08C78350h && EDX > 0
		INC EAX
		DEC EDX
	.endw
	.if EDX == 0
		INVOKE MessageBox,NULL,addr szNotPackErrorText,addr szErrorTitle,30h
		PUSH offset szEndUnpack
		CALL _show_log_message
		MOV ESP,DWORD PTR[tESP]
		RET
	.endif
	MOV ECX,EAX
	SUB EAX,DWORD PTR[FileMapVA]
	SUB EAX,DWORD PTR[EBP+8]
	ADD EAX,DWORD PTR[PackedOEP]
	MOV DWORD PTR[PackBPX1],EAX		;LoadLibrary

	MOV EAX,ECX
	MOV EDX,1000				;BPX2
	.while WORD PTR[EAX] != 4857h && EDX > 0
		.if WORD PTR[EAX] == 4750h
			PUSH EAX
			SUB EAX,DWORD PTR[FileMapVA]
			SUB EAX,DWORD PTR[EBP+8]
			ADD EAX,DWORD PTR[PackedOEP]
			MOV DWORD PTR[PackBPX4],EAX		;GetProcAddress for ordinals
			POP EAX
		.endif
		INC EAX
		DEC EDX
	.endw
	.if EDX == 0
		INVOKE MessageBox,NULL,addr szNotPackErrorText,addr szErrorTitle,30h
		PUSH offset szEndUnpack
		CALL _show_log_message
		MOV ESP,DWORD PTR[tESP]
		RET
	.endif
	MOV ECX,EAX
	SUB EAX,DWORD PTR[FileMapVA]
	SUB EAX,DWORD PTR[EBP+8]
	ADD EAX,DWORD PTR[PackedOEP]
	MOV DWORD PTR[PackBPX2],EAX		;GetProcAddress

	MOV EAX,ECX
	MOV EDX,1000				;BPX3
	.while BYTE PTR[EAX] != 0E9h && EDX > 0
		INC EAX
		DEC EDX
	.endw
	.if EDX == 0
		INVOKE MessageBox,NULL,addr szNotPackErrorText,addr szErrorTitle,30h
		PUSH offset szEndUnpack
		CALL _show_log_message
		MOV ESP,DWORD PTR[tESP]
		RET
	.endif
	MOV ECX,EAX
	SUB EAX,DWORD PTR[FileMapVA]
	SUB EAX,DWORD PTR[EBP+8]
	ADD EAX,DWORD PTR[PackedOEP]
	MOV DWORD PTR[PackBPX3],EAX		;OEP jump
	MOV EBX,DWORD PTR[ECX+1]
	ADD EBX,EAX
	ADD EBX,5
	MOV DWORD PTR[UnpackedOEP],EBX

	LEAVE
	RET 4
;------------------------------------------------------------------
end start