;------------------------------------------------------------------
; LGPL 3.0
; UPX 1.x - 3.x [PE32 dll/exe] unpacker from Reversing Labs
;                                            www.reversinglabs.com
;------------------------------------------------------------------
      .586
      .model flat, stdcall
      option casemap :none   ; case sensitive

      include \masm32\include\windows.inc
      include \masm32\include\user32.inc
      include \masm32\include\kernel32.inc
      include \masm32\include\comdlg32.inc
      include \masm32\include\shell32.inc
      include sdk\xIncludeAll.inc

      includelib \masm32\lib\user32.lib
      includelib \masm32\lib\kernel32.lib
      includelib \masm32\lib\comdlg32.lib
      includelib \masm32\lib\shell32.lib
;------------------------------------------------------------------
	WndProc PROTO :DWORD,:DWORD,:DWORD,:DWORD
	TimerProc PROTO :DWORD,:DWORD,:DWORD,:DWORD
	SehHandler PROTO C :DWORD,:DWORD,:DWORD,:DWORD
	MapFileEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
	UnmapFileEx PROTO :DWORD,:DWORD,:DWORD,:DWORD

	AddLogMessage PROTO :DWORD
	GetFileDialog PROTO
	cbCreateProcess PROTO :DWORD
	cbFindPatterns PROTO
	InitializeUnpacker PROTO :DWORD,:DWORD
	HideUnpacker PROTO
	ExtractResource PROTO :DWORD,:DWORD
	DeleteExtractedFiles PROTO
	GetUnpackerFolder PROTO
	ExtractNeededFiles PROTO
	cbLoadLibrary PROTO
	cbGetProcAddress PROTO
	cbEntryPoint PROTO
	cbMakeSnapShoot1 PROTO
;------------------------------------------------------------------
sSEH STRUCT
	OrgEsp dd ?
	OrgEbp dd ?
	SaveEip dd ?
sSEH ENDS
;------------------------------------------------------------------
InstSehFrame MACRO ContinueAddr
	ASSUME FS : NOTHING

	MOV  SEH.SaveEip, ContinueAddr
	MOV  SEH.OrgEbp, EBP
	PUSH OFFSET SehHandler
	PUSH FS:[0]
	MOV  SEH.OrgEsp, ESP
	MOV  FS:[0], ESP
ENDM

KillSehFrame MACRO
	POP  FS:[0]
	ADD  ESP, 4
ENDM
;------------------------------------------------------------------
 .data
	szOpen db "open",0h
 	szBinary db "BINARY",0h
 	rcLoader db "#9000",0h
 	rcStub db "#9001",0h
	dlgname  db "TESTWIN",0h
	dlgTitle db "[UPX 1.x - 3.x Unpacker]",0h
	FilterString db "All Files",0,"*.*",0h,0h
	OurTitle db "RL!deUPX 1.x - 3.x from Reversing Labs",0h
	szUnpackedFile db "%s.unpacked.%s",0h
	szAboutTitle db "[About]",0h
	szAboutText db "RL!deUPX 1.x - 3.x unpacker",0Dh,0Ah,0Dh,0Ah,"Visit Reversing Labs at http://www.reversinglabs.com",0Dh,0Ah,0Dh,0Ah,"  Minimum engine version needed:",0Dh,0Ah,"- DebuggerEngine 1.7 by RevLabs",0Dh,0Ah,"- DumperEngine 1.6 by RevLabs",0Dh,0Ah,"- ImporterEngine 1.6 by RevLabs",0Dh,0Ah,"- UpdaterEngine 1.2 by RevLabs",0Dh,0Ah,"- Realign 1.0 by RevLabs",0Dh,0Ah,"- Relocater 1.0 by RevLabs",0Dh,0Ah,0Dh,0Ah,"Unpacker coded by Reversing Labs",0h
	szErrorText db "[Error] Error while opening file or file not selected!",0h
	szFatalErrorText db "[Fatal Unpacking Error] Please mail file you tried to unpack to Reversing Labs!",0h
	szUpdatedText db "UnpackerEngine has been updated, press Ok to restart the program!",0h
	szUpdatedTitle db "[Update]",0h
	szErrorTitle db "[Error]",0h
	szMsgText db "[Success] File has been unpacked!",0h
	szMsgTitle db "[Success]",0h
	szNotPackErrorText db "[Error] File is not packed with UPX 1.x - 3.x",0h
	szFileBroken db "[Error] Selected file is not a valid PE32 file!",0h
	szInitUnpack db "-> Unpack started...",0h
	szEndUnpack db "-> Unpack ended...",0h
	szLoadLibraryBPX db "[x] LoadLibrary BPX -> %s",0h
	szGetProcAddrBPX db "[x] GetProcAddress BPX -> %s",0h
	szxGetProcAddrBPX db "[x] GetProcAddress BPX -> %08X",0h
	szOEPJmpBPX db "[x] Entry Point at: %08X",0h
	szFileUnpacked db "[x] File has been unpacked to: %s",0h
	szDumped db "[x] Process dumped!",0h
	szIATFixed db "[x] IAT has been fixed!",0h
	szRealing db "[x] Realigning file!",0h
	szPastePEHeader db "[x] Paste PE32 header!",0h
	szExportRelocation db "[x] Exporting relocations!",0h
	szRelocationChangeBase db "[x] Rebase file image!",0h
	szLogCopyOverlay db "[x] Moving overlay to unpacked file!",0h
	szCopyOverlayText db "Do you want to copy overlay from original file?",0h
	szCopyOverlayTitle db "Confirmation:",0h
	szTempAp0x db "ap0x.dll",0h
	szTempFolder db "tmp\",0h
	szTempLoader db "stub.exe",0h
	szTempStub db "stub.dll",0h
	szMySection db ".RLv15",0h
	szSnapShoot1 db "snapshoot.1",0h
	szSnapShoot2 db "snapshoot.2",0h
	
;
; Unpacker Data:
;
	
	glWildCard db 0
	dtPattern1 db 050h,083h,0C7h,008h,0FFh
	dtPattern1Size dd 5
	dtPattern1CallBack dd offset cbLoadLibrary
	dtPattern1BPXAddress dd 0

	dtPattern2 db 050h,047h,000h,057h,048h,0F2h,0AEh
	dtPattern2Size dd 7
	dtPattern2CallBack dd offset cbGetProcAddress
	dtPattern2BPXAddress dd 0

	dtPattern3 db 057h,048h,0F2h,0AEh,000h,0FFh
	dtPattern3Size dd 6
	dtPattern3CallBack dd offset cbGetProcAddress
	dtPattern3BPXAddress dd 0

	dtPattern4 db 089h,0F9h,057h,048h,0F2h,0AEh,052h,0FFh
	dtPattern4Size dd 8
	dtPattern4CallBack dd offset cbGetProcAddress
	dtPattern4BPXAddress dd 0

	dtPattern5 db 061h,0E9h
	dtPattern5Size dd 2
	dtPattern5CallBack dd offset cbEntryPoint
	dtPattern5BPXAddress dd 0
	
	dtPattern51 db 083h,0ECh,000h,0E9h
	dtPattern51Size dd 4
	dtPattern51CallBack dd offset cbEntryPoint
	dtPattern51BPXAddress dd 0

	dtPattern6 db 031h,0C0h,08Ah,007h,047h,009h,0C0h,074h,022h,03Ch,0EFh,
		      077h,011h,001h,0C3h,08Bh,003h,086h,0C4h,0C1h,0C0h,010h,
		      086h,0C4h,001h,0F0h,089h,003h,0EBh,0E2h,024h,00Fh,0C1h,
		      0E0h,010h,066h,08Bh,007h,083h,0C7h,002h,0EBh,0E2h
	dtPattern6Size dd 43
	dtPattern6CallBack dd offset cbMakeSnapShoot1
	dtPattern6BPXAddress dd 0
	
	dtSecondSnapShootOnEP db 1
 .data?
	cbInitCallBack dd ?
	fdFileIsDll db ?
	fdImageBase dd ?
	fdSizeOfImage dd ?
	fdLoadedBase dd ?
	fdEntryPoint dd ?
	SnapshootMemoryStartRVA dd ?
	SnapshootMemorySize dd ?
	fdProcessInfo PROCESS_INFORMATION <?>
	MAJOR_DEBUG_ERROR_EXIT dd ?
	SEH sSEH <?>

	hInstance dd ?
	BoxHandle dd ?
	WindowHandle dd ?
	UpdateCalled dd ?
	UnpackerRunning dd ?
	ofn OPENFILENAME <?>
	GlobalBuffer db 1024 dup(?)
	GlobalBackBuffer db 1024 dup(?)
	GlobalTempBuffer db 1024 dup(?)
	GlobalUnpackerFolderBuffer db 1024 dup(?)
	SnapShoot1 db 1024 dup(?)
	SnapShoot2 db 1024 dup(?)
	UnpackFileNameBuffer db 1024 dup(?)
	szReadStringData db 256 dup(?)
 .code

start:
;------------------------------------------------------------------
        INVOKE GetModuleHandle,NULL
        MOV hInstance,EAX
        INVOKE GetUnpackerFolder
        INVOKE DialogBoxParam,hInstance,addr dlgname,NULL,addr WndProc,NULL
        INVOKE ExitProcess,EAX
	RET
;------------------------------------------------------------------
WndProc proc hWin :DWORD,uMsg :DWORD,wParam :DWORD,lParam :DWORD

      .if uMsg == WM_INITDIALOG
		INVOKE SendMessage,hWin,WM_SETTEXT,0,addr dlgTitle
		INVOKE LoadIcon,hInstance,500
		INVOKE SendMessage,hWin,80h,NULL,EAX
		INVOKE GetDlgItem,hWin,700
		INVOKE CheckDlgButton,hWin,700,1
		MOV EAX,hWin
		MOV WindowHandle,EAX

      .elseif uMsg == WM_DROPFILES
		INVOKE DragQueryFile,wParam,NULL,addr GlobalBuffer,1024
		INVOKE SetDlgItemText,hWin,102,addr GlobalBuffer

      .elseif uMsg == WM_CLOSE
		INVOKE EndDialog,hWin,NULL

      .elseif uMsg == WM_COMMAND
        .if wParam == 107
        	.if UnpackerRunning == NULL
        		INC UnpackerRunning
			INVOKE GetDlgItem,hWin,6Fh
			MOV BoxHandle,EAX
			INVOKE SendMessage,BoxHandle,184h,NULL,NULL
			INVOKE InitializeUnpacker,addr GlobalBuffer,addr cbFindPatterns
			INVOKE DeleteFile,addr SnapShoot1
			INVOKE DeleteFile,addr SnapShoot2
			INVOKE DeleteExtractedFiles
			DEC UnpackerRunning
		.endif
        .elseif wParam == 108
        	INVOKE GetFileDialog
		INVOKE SetDlgItemText,hWin,102,addr GlobalBuffer
        .elseif wParam == 109
		INVOKE MessageBox,hWin,addr szAboutText,addr szAboutTitle,40h
        .elseif wParam == 110
		INVOKE EndDialog,hWin,NULL
        .endif
      .endif

	INVOKE IsWindowVisible,DWORD PTR[hWin]
	.if EAX == TRUE && DWORD PTR[UpdateCalled] == 0
		MOV DWORD PTR[UpdateCalled],1
		INVOKE SetTimer,DWORD PTR[hWin],101,1000,addr TimerProc
	.endif

	XOR EAX,EAX
	RET
WndProc endp
;------------------------------------------------------------------
TimerProc proc hWnd:DWORD,uMSG:DWORD,idEvent:DWORD,dwTime:DWORD
	LOCAL lpStartInfo : STARTUPINFO
	LOCAL lpProcessInfo : PROCESS_INFORMATION
	LOCAL WinVer : OSVERSIONINFO
	PUSHAD
	
	.if idEvent == 101
		INVOKE KillTimer,WindowHandle,101
		MOV DWORD PTR[WinVer.dwOSVersionInfoSize],sizeof OSVERSIONINFO
		INVOKE GetVersionEx,addr WinVer
		.if DWORD PTR[WinVer.dwPlatformId] == VER_PLATFORM_WIN32_NT
			INVOKE UpdateEngine,1,WindowHandle
			.if EAX == 1
				INVOKE GetModuleFileName,hInstance,addr GlobalTempBuffer,1024
				INVOKE MessageBox,WindowHandle,addr szUpdatedText,addr szUpdatedTitle,30h
				INVOKE ShellExecute,WindowHandle,addr szOpen,addr GlobalTempBuffer,NULL,NULL,SW_SHOW
				INVOKE ExitProcess,NULL
			.endif
		.endif
	.endif

	POPAD
	RET
TimerProc endp
;------------------------------------------------------------------
SehHandler PROC C pExcept:DWORD,pFrame:DWORD,pContext:DWORD,pDispatch:DWORD

	MOV EAX,pContext		;After file unlocking process SEH!
	ASSUME EAX:PTR CONTEXT
	PUSH MAJOR_DEBUG_ERROR_EXIT	;Instead of SEH.SaveEip!
	POP [EAX].regEip
	PUSH SEH.OrgEsp
	POP [EAX].regEsp
	PUSH SEH.OrgEbp
	POP [EAX].regEbp
	MOV EAX,ExceptionContinueExecution
	ASSUME EAX:NOTHING

	RET
SehHandler ENDP
;------------------------------------------------------------------
GetUnpackerFolder proc
	PUSHAD

	INVOKE GetModuleFileName,hInstance,addr GlobalUnpackerFolderBuffer,1024
	MOV ESI,offset GlobalUnpackerFolderBuffer
	INVOKE lstrlen,ESI
	ADD ESI,EAX
	.while BYTE PTR[ESI] != "\"
		MOV BYTE PTR[ESI],NULL
		DEC ESI
	.endw

	POPAD
	RET
GetUnpackerFolder endp
;------------------------------------------------------------------
GetFileDialog proc
	PUSHAD

	MOV ofn.lStructSize,sizeof ofn
	MOV ofn.lpstrFilter,offset FilterString
	MOV ofn.lpstrFile,offset GlobalBuffer
	MOV ofn.nMaxFile,1024
	MOV ofn.Flags, OFN_FILEMUSTEXIST or OFN_PATHMUSTEXIST or OFN_LONGNAMES or OFN_EXPLORER or OFN_HIDEREADONLY
	MOV ofn.lpstrTitle,offset OurTitle
	INVOKE GetOpenFileName,addr ofn

	POPAD
	RET
GetFileDialog endp
;------------------------------------------------------------------
AddLogMessage proc szLogString:DWORD
	PUSHAD

	INVOKE SendMessage,BoxHandle,180h,NULL,szLogString
	INVOKE SendMessage,BoxHandle,18Bh,NULL,NULL
	DEC EAX
	INVOKE SendMessage,BoxHandle,186h,EAX,NULL

	POPAD
	RET
AddLogMessage endp
;------------------------------------------------------------------
ExtractNeededFiles proc
	PUSHAD

	INVOKE RtlZeroMemory,addr GlobalTempBuffer,1024
	INVOKE lstrcpy,addr GlobalTempBuffer,addr GlobalUnpackerFolderBuffer
	INVOKE lstrcat,addr GlobalTempBuffer,addr szTempFolder
	INVOKE CreateDirectory,addr GlobalTempBuffer,NULL
	
	INVOKE RtlZeroMemory,addr GlobalTempBuffer,1024
	INVOKE lstrcpy,addr GlobalTempBuffer,addr GlobalUnpackerFolderBuffer
	INVOKE lstrcat,addr GlobalTempBuffer,addr szTempFolder
	INVOKE lstrcat,addr GlobalTempBuffer,addr szTempLoader
	INVOKE ExtractResource,addr rcLoader,addr GlobalTempBuffer
	
	INVOKE RtlZeroMemory,addr GlobalTempBuffer,1024
	INVOKE lstrcpy,addr GlobalTempBuffer,addr GlobalUnpackerFolderBuffer
	INVOKE lstrcat,addr GlobalTempBuffer,addr szTempFolder
	INVOKE lstrcat,addr GlobalTempBuffer,addr szTempStub
	INVOKE ExtractResource,addr rcStub,addr GlobalTempBuffer

	POPAD
	RET
ExtractNeededFiles endp
;------------------------------------------------------------------
DeleteExtractedFiles proc
	PUSHAD

	INVOKE RtlZeroMemory,addr GlobalTempBuffer,1024
	INVOKE lstrcpy,addr GlobalTempBuffer,addr GlobalUnpackerFolderBuffer
	INVOKE lstrcat,addr GlobalTempBuffer,addr szTempFolder
	INVOKE lstrcat,addr GlobalTempBuffer,addr szTempLoader
	INVOKE DeleteFile,addr GlobalTempBuffer

	INVOKE RtlZeroMemory,addr GlobalTempBuffer,1024
	INVOKE lstrcpy,addr GlobalTempBuffer,addr GlobalUnpackerFolderBuffer
	INVOKE lstrcat,addr GlobalTempBuffer,addr szTempFolder
	INVOKE lstrcat,addr GlobalTempBuffer,addr szTempStub
	INVOKE DeleteFile,addr GlobalTempBuffer

	INVOKE RtlZeroMemory,addr GlobalTempBuffer,1024
	INVOKE lstrcpy,addr GlobalTempBuffer,addr GlobalUnpackerFolderBuffer
	INVOKE lstrcat,addr GlobalTempBuffer,addr szTempFolder
	INVOKE lstrcat,addr GlobalTempBuffer,addr szTempAp0x
	INVOKE DeleteFile,addr GlobalTempBuffer
	
	INVOKE RtlZeroMemory,addr GlobalTempBuffer,1024
	INVOKE lstrcpy,addr GlobalTempBuffer,addr GlobalUnpackerFolderBuffer
	INVOKE lstrcat,addr GlobalTempBuffer,addr szTempFolder
	INVOKE RemoveDirectory,addr GlobalTempBuffer

	POPAD
	RET
DeleteExtractedFiles endp
;------------------------------------------------------------------
ExtractResource proc szResName:DWORD,szExtractedFileName:DWORD
	LOCAL ResSize :DWORD
	LOCAL ResData :DWORD
	LOCAL NumberOfBytes :DWORD
	LOCAL Return :DWORD
	PUSHAD

	MOV Return,NULL
	INVOKE FindResource,hInstance,szResName,addr szBinary
	.if EAX != NULL
		MOV ESI,EAX
		INVOKE LoadResource,hInstance,ESI
		.if EAX != NULL
			MOV EDI,EAX
			INVOKE SizeofResource,hInstance,ESI
			MOV ResSize,EAX
			INVOKE LockResource,EDI
			MOV ResData,EAX
			INVOKE CreateFile,szExtractedFileName,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL
			.if EAX != INVALID_HANDLE_VALUE
				MOV EBX,EAX
				INVOKE WriteFile,EBX,ResData,ResSize,addr NumberOfBytes,NULL
				.if EAX != NULL
					MOV Return,1
				.endif
				INVOKE CloseHandle,EBX
			.endif
		.endif
	.endif

	POPAD
	MOV EAX,Return
	RET
ExtractResource endp
;------------------------------------------------------------------
InitializeUnpacker proc szFileName:DWORD,dwCallBack:DWORD
	PUSHAD

	INVOKE AddLogMessage,addr szInitUnpack
	MOV EAX,szFileName
	.if EAX != NULL && BYTE PTR[EAX] != NULL
		INVOKE IsPE32FileValid,szFileName
		.if EAX == 1
			INVOKE GetPE32Data,szFileName,NULL,1
			MOV fdImageBase,EAX
			INVOKE GetPE32Data,szFileName,NULL,2
			MOV fdEntryPoint,EAX
			INVOKE GetPE32Data,szFileName,NULL,3
			MOV fdSizeOfImage,EAX
	
			;
			; DLL Relocation snapshoots are set here!
			;
	
			INVOKE GetPE32Data,szFileName,NULL,21
			MOV SnapshootMemoryStartRVA,EAX
			MOV EAX,fdEntryPoint
			SUB EAX,SnapshootMemoryStartRVA
			MOV SnapshootMemorySize,EAX
	
			INVOKE lstrcpy,addr GlobalBackBuffer,addr GlobalBuffer
			MOV EBX,offset GlobalBackBuffer
			INVOKE lstrlen,EBX
			ADD EBX,EAX
			.while BYTE PTR[EBX] != "."
				DEC EBX
			.endw
			MOV BYTE PTR[EBX],NULL
			LEA EDI,DWORD PTR[EBX+1]
			.while BYTE PTR[EBX] != "\"
				DEC EBX
			.endw
			LEA ESI,DWORD PTR[EBX+1]
	
			PUSH EDI
			PUSH ESI
			PUSH offset szUnpackedFile
			PUSH offset GlobalTempBuffer
			CALL wsprintf
			ADD ESP,16
			MOV BYTE PTR[EBX+1],NULL
			INVOKE lstrcpy,addr UnpackFileNameBuffer,addr GlobalBackBuffer
			INVOKE lstrcat,addr UnpackFileNameBuffer,addr GlobalTempBuffer
			INVOKE IsFileDLL,szFileName
			MOV fdFileIsDll,AL
			.if fdFileIsDll == NULL
				INVOKE InitDebug,szFileName,NULL,NULL
			.elseif fdFileIsDll == 1
				INVOKE ExtractNeededFiles
				INVOKE lstrcpy,addr SnapShoot1,addr GlobalUnpackerFolderBuffer
				INVOKE lstrcpy,addr SnapShoot2,addr GlobalUnpackerFolderBuffer
				INVOKE lstrcat,addr SnapShoot1,addr szTempFolder
				INVOKE lstrcat,addr SnapShoot2,addr szTempFolder
				INVOKE lstrcat,addr SnapShoot1,addr szSnapShoot1
				INVOKE lstrcat,addr SnapShoot2,addr szSnapShoot2
				INVOKE InitDLLDebug,szFileName,1,NULL,NULL,addr cbFindPatterns
			.else
				XOR EAX,EAX
			.endif
			.if EAX != NULL
				MOV EBX,EAX
				MOV EAX,dwCallBack
				MOV cbInitCallBack,EAX
				INVOKE RtlMoveMemory,addr fdProcessInfo,EBX,sizeof PROCESS_INFORMATION
				.if fdFileIsDll == NULL
					INVOKE SetCustomHandler,cCreateProcess,addr cbCreateProcess
				.endif
				INVOKE DebugLoop
			.else
				INVOKE AddLogMessage,addr szErrorTitle
				INVOKE AddLogMessage,addr szEndUnpack
			.endif
		.else
			INVOKE AddLogMessage,addr szFileBroken
			INVOKE AddLogMessage,addr szEndUnpack
		.endif
	.else
		INVOKE AddLogMessage,addr szErrorTitle
		INVOKE AddLogMessage,addr szEndUnpack
	.endif

	POPAD
	RET
InitializeUnpacker endp
;------------------------------------------------------------------
HideUnpacker proc
	;INVOKE HideDebugger,DWORD PTR[fdProcessInfo.hThread],DWORD PTR[fdProcessInfo.hProcess],1
	RET
HideUnpacker endp
;------------------------------------------------------------------
cbCreateProcess proc ptrCreateProcessInfo:DWORD
	PUSHAD

	MOV EAX,ptrCreateProcessInfo
	ASSUME EAX:PTR CREATE_PROCESS_DEBUG_INFO
	MOV EBX,DWORD PTR[EAX].lpBaseOfImage
	MOV fdLoadedBase,EBX
	ASSUME EAX:NOTHING
	INVOKE SetCustomHandler,cCreateProcess,NULL
	MOV EBX,fdLoadedBase
	ADD EBX,fdEntryPoint
	INVOKE SetBPX,EBX,bpxAlways,cbInitCallBack
	INVOKE ImporterInit,50 * 1024,fdLoadedBase

	POPAD
	RET
cbCreateProcess endp
;------------------------------------------------------------------
cbLoadLibrary proc
	LOCAL MemInfo : MEMORY_BASIC_INFORMATION
	LOCAL NumberOfBytes :DWORD
	PUSHAD

	XOR ESI,ESI
	INVOKE GetContextData,rEIP
	.if EAX == dtPattern1BPXAddress
		INVOKE GetContextData,rEAX
		MOV ESI,EAX
	.endif
	.if ESI > fdLoadedBase
		INVOKE VirtualQueryEx,DWORD PTR[fdProcessInfo.hProcess],ESI,addr MemInfo,sizeof MEMORY_BASIC_INFORMATION
		MOV EDI,DWORD PTR[MemInfo.BaseAddress]
		ADD EDI,DWORD PTR[MemInfo.RegionSize]
		INVOKE VirtualQueryEx,DWORD PTR[fdProcessInfo.hProcess],EDI,addr MemInfo,sizeof MEMORY_BASIC_INFORMATION
		ADD EDI,DWORD PTR[MemInfo.RegionSize]
		SUB EDI,ESI
		.if EDI > 256
			MOV EDI,256
		.endif
		INVOKE ReadProcessMemory,DWORD PTR[fdProcessInfo.hProcess],ESI,addr szReadStringData,EDI,addr NumberOfBytes
		.if EAX != NULL
			INVOKE ImporterAddNewDll,addr szReadStringData,NULL
			INVOKE RtlZeroMemory,addr GlobalTempBuffer,1024
			PUSH offset szReadStringData
			PUSH offset szLoadLibraryBPX
			PUSH offset GlobalTempBuffer
			CALL wsprintf
			ADD ESP,12
			INVOKE AddLogMessage,addr GlobalTempBuffer
		.endif
	.endif

	POPAD
	RET
cbLoadLibrary endp
;------------------------------------------------------------------
cbGetProcAddress proc
	LOCAL MemInfo : MEMORY_BASIC_INFORMATION
	LOCAL NumberOfBytes :DWORD
	PUSHAD

	XOR ESI,ESI
	INVOKE GetContextData,rEIP
	.if EAX == dtPattern2BPXAddress
		INVOKE GetContextData,rEAX
		MOV ESI,EAX
		INVOKE GetContextData,rEBX
		MOV EBX,EAX
	.elseif EAX == dtPattern3BPXAddress
		INVOKE GetContextData,rEDI
		MOV ESI,EAX
		INVOKE GetContextData,rEBX
		MOV EBX,EAX
	.elseif EAX == dtPattern4BPXAddress
		INVOKE GetContextData,rEDI
		MOV ESI,EAX
		INVOKE GetContextData,rEBX
		MOV EBX,EAX
	.endif
	.if ESI > fdLoadedBase
		INVOKE VirtualQueryEx,DWORD PTR[fdProcessInfo.hProcess],ESI,addr MemInfo,sizeof MEMORY_BASIC_INFORMATION
		MOV EDI,DWORD PTR[MemInfo.BaseAddress]
		ADD EDI,DWORD PTR[MemInfo.RegionSize]
		INVOKE VirtualQueryEx,DWORD PTR[fdProcessInfo.hProcess],EDI,addr MemInfo,sizeof MEMORY_BASIC_INFORMATION
		ADD EDI,DWORD PTR[MemInfo.RegionSize]
		SUB EDI,ESI
		.if EDI > 256
			MOV EDI,256
		.endif
		INVOKE ReadProcessMemory,DWORD PTR[fdProcessInfo.hProcess],ESI,addr szReadStringData,EDI,addr NumberOfBytes
		.if EAX != NULL
			INVOKE ImporterAddNewAPI,addr szReadStringData,EBX
			INVOKE RtlZeroMemory,addr GlobalTempBuffer,1024
			PUSH offset szReadStringData
			PUSH offset szGetProcAddrBPX
			PUSH offset GlobalTempBuffer
			CALL wsprintf
			ADD ESP,12
			INVOKE AddLogMessage,addr GlobalTempBuffer
		.endif
	.else
		INVOKE ImporterAddNewAPI,ESI,EBX
		INVOKE RtlZeroMemory,addr GlobalTempBuffer,1024
		PUSH ESI
		PUSH offset szxGetProcAddrBPX
		PUSH offset GlobalTempBuffer
		CALL wsprintf
		ADD ESP,12
		INVOKE AddLogMessage,addr GlobalTempBuffer
	.endif

	POPAD
	RET
cbGetProcAddress endp
;------------------------------------------------------------------
cbEntryPoint proc
	LOCAL UnpackedOEP :DWORD
	LOCAL rsFileHWND :DWORD
	LOCAL rsFileSize :DWORD
	LOCAL rsFileMap :DWORD
	LOCAL rsFileMapVA :DWORD
	LOCAL NumberOfBytes :DWORD
	LOCAL pOverlayStart :DWORD
	LOCAL pOverlaySize :DWORD
	PUSHAD

 	MOV MAJOR_DEBUG_ERROR_EXIT,offset __MAJOR_DEBUG_ERROR_EXIT
	InstSehFrame <offset SehHandler>		;Create a SEH just in case!
	INVOKE GetContextData,rEIP
	LEA ESI,DWORD PTR[EAX+1]
	INVOKE ReadProcessMemory,DWORD PTR[fdProcessInfo.hProcess],ESI,addr UnpackedOEP,4,addr NumberOfBytes
	ADD UnpackedOEP,ESI
	ADD UnpackedOEP,4

	INVOKE RtlZeroMemory,addr GlobalTempBuffer,1024
	PUSH UnpackedOEP
	PUSH offset szOEPJmpBPX
	PUSH offset GlobalTempBuffer
	CALL wsprintf
	ADD ESP,12
	INVOKE AddLogMessage,addr GlobalTempBuffer
	.if fdFileIsDll != 1
		INVOKE PastePEHeader,DWORD PTR[fdProcessInfo.hProcess],addr GlobalBuffer
		INVOKE AddLogMessage,addr szPastePEHeader
	.else
		MOV ESI,SnapshootMemoryStartRVA
		ADD ESI,fdLoadedBase
		.if dtSecondSnapShootOnEP == 1
			INVOKE RelocaterMakeSnapshoot,DWORD PTR[fdProcessInfo.hProcess],addr SnapShoot2,ESI,SnapshootMemorySize
		.endif
		INVOKE RelocaterCompareTwoSnapshots,DWORD PTR[fdProcessInfo.hProcess],fdLoadedBase,fdSizeOfImage,addr SnapShoot1,addr SnapShoot2,ESI
	.endif
	INVOKE DumpProcess,DWORD PTR[fdProcessInfo.hProcess],fdLoadedBase,addr UnpackFileNameBuffer,UnpackedOEP
	INVOKE AddLogMessage,addr szDumped
	INVOKE StopDebug
	INVOKE ImporterEstimatedSize
	LEA EBX,DWORD PTR[EAX+200]
	INVOKE AddNewSection,addr UnpackFileNameBuffer,addr szMySection,EBX
	ADD EAX,fdLoadedBase
	MOV EBX,EAX
	.if fdFileIsDll == 1
		INVOKE RelocaterEstimatedSize
		LEA ECX,DWORD PTR[EAX+200]
		INVOKE AddNewSection,addr UnpackFileNameBuffer,addr szMySection,ECX
		MOV EDI,EAX
		MOV ESI,EAX
	.endif
	INVOKE MapFileEx,addr UnpackFileNameBuffer,NULL,addr rsFileHWND,addr rsFileSize,addr rsFileMap,addr rsFileMapVA
	.if rsFileMapVA > NULL
		INVOKE ImporterExportIAT,EBX,rsFileMapVA
		INVOKE AddLogMessage,addr szIATFixed	
		.if fdFileIsDll == 1
			ADD ESI,rsFileMapVA
			INVOKE RelocaterExportRelocation,ESI,EDI,rsFileMapVA
			INVOKE AddLogMessage,addr szExportRelocation			
		.endif
		INVOKE IsDlgButtonChecked,WindowHandle,700
		.if EAX == TRUE
			INVOKE RealignPE,rsFileMapVA,rsFileSize,2
			MOV rsFileSize,EAX
			INVOKE AddLogMessage,addr szRealing
		.endif
		INVOKE UnmapFileEx,rsFileHWND,rsFileSize,rsFileMap,rsFileMapVA
		INVOKE MakeAllSectionsRWE,addr UnpackFileNameBuffer
		.if fdFileIsDll == 1
			INVOKE RelocaterChangeFileBase,addr UnpackFileNameBuffer,fdImageBase
			INVOKE AddLogMessage,addr szRelocationChangeBase
		.endif
		INVOKE FindOverlay,addr GlobalBuffer,addr pOverlayStart,addr pOverlaySize
		.if EAX == 1
			INVOKE AddLogMessage,addr szLogCopyOverlay
			INVOKE CopyOverlay,addr GlobalBuffer,addr UnpackFileNameBuffer
		.endif
		INVOKE AddLogMessage,addr szMsgText
		MOV ESI,offset UnpackFileNameBuffer
		INVOKE lstrlen,ESI
		ADD ESI,EAX
		.while BYTE PTR[ESI] != "\"
			DEC ESI
		.endw
		INC ESI
		INVOKE RtlZeroMemory,addr GlobalTempBuffer,1024
		PUSH ESI
		PUSH offset szFileUnpacked
		PUSH offset GlobalTempBuffer
		CALL wsprintf
		ADD ESP,12
		INVOKE AddLogMessage,addr GlobalTempBuffer
		INVOKE AddLogMessage,addr szEndUnpack
		KillSehFrame					;Remove SEH!
	.else
   __MAJOR_DEBUG_ERROR_EXIT:
		KillSehFrame					;Remove SEH!
		INVOKE ForceClose
		INVOKE ImporterCleanup
		.if rsFileMapVA > NULL
			INVOKE UnmapFileEx,rsFileHWND,rsFileSize,rsFileMap,rsFileMapVA
		.endif
		INVOKE DeleteFile,addr UnpackFileNameBuffer
		INVOKE AddLogMessage,addr szFatalErrorText
		INVOKE AddLogMessage,addr szEndUnpack
	.endif

	POPAD
	RET
cbEntryPoint endp
;------------------------------------------------------------------
cbMakeSnapShoot1 proc
	PUSHAD

	MOV ESI,SnapshootMemoryStartRVA
	ADD ESI,fdLoadedBase
	INVOKE RelocaterMakeSnapshoot,DWORD PTR[fdProcessInfo.hProcess],addr SnapShoot1,ESI,SnapshootMemorySize

	POPAD
	RET
cbMakeSnapShoot1 endp
;------------------------------------------------------------------
cbFindPatterns proc
	LOCAL MemInfo : MEMORY_BASIC_INFORMATION
	LOCAL DontLog : DWORD
	PUSHAD

	MOV DontLog,NULL
	INVOKE HideUnpacker
	.if fdFileIsDll == 1
		INVOKE GetDebuggedDLLBaseAddress
		MOV fdLoadedBase,EAX
		INVOKE ImporterInit,50 * 1024,fdLoadedBase
		INVOKE RelocaterInit,100 * 1024,fdImageBase,fdLoadedBase
	.endif
	MOV ESI,fdLoadedBase
	ADD ESI,fdEntryPoint
	INVOKE VirtualQueryEx,DWORD PTR[fdProcessInfo.hProcess],ESI,addr MemInfo,sizeof MEMORY_BASIC_INFORMATION
	MOV EDI,DWORD PTR[MemInfo.BaseAddress]
	ADD EDI,DWORD PTR[MemInfo.RegionSize]
	INVOKE VirtualQueryEx,DWORD PTR[fdProcessInfo.hProcess],EDI,addr MemInfo,sizeof MEMORY_BASIC_INFORMATION
	ADD EDI,DWORD PTR[MemInfo.RegionSize]
	SUB EDI,ESI
	.if EAX != NULL
		INVOKE Find,ESI,EDI,addr dtPattern1,dtPattern1Size,addr glWildCard
		.if EAX != NULL
			MOV EBX,EAX
			MOV dtPattern1BPXAddress,EBX
			INVOKE SetBPX,EBX,bpxAlways,dtPattern1CallBack
		.else
			INVOKE AddLogMessage,addr szNotPackErrorText
			INVOKE AddLogMessage,addr szEndUnpack
			INVOKE StopDebug
			INC DontLog
		.endif

		INVOKE Find,ESI,EDI,addr dtPattern2,dtPattern2Size,addr glWildCard
		.if EAX != NULL
			MOV EBX,EAX
			MOV dtPattern2BPXAddress,EBX
			INVOKE SetBPX,EBX,bpxAlways,dtPattern2CallBack
		.endif
		
		INVOKE Find,ESI,EDI,addr dtPattern3,dtPattern3Size,addr glWildCard
		.if EAX != NULL
			MOV EBX,EAX
			MOV dtPattern3BPXAddress,EBX
			INVOKE SetBPX,EBX,bpxAlways,dtPattern3CallBack
		.else
			.if DontLog == NULL
				INVOKE AddLogMessage,addr szNotPackErrorText
				INVOKE AddLogMessage,addr szEndUnpack
				INVOKE StopDebug
				INC DontLog
			.endif
		.endif
		
		INVOKE Find,ESI,EDI,addr dtPattern4,dtPattern4Size,addr glWildCard
		.if EAX != NULL
			MOV EBX,EAX
			ADD EBX,2
			MOV dtPattern4BPXAddress,EBX
			INVOKE SetBPX,EBX,bpxAlways,dtPattern4CallBack
		.endif
		
		INVOKE Find,ESI,EDI,addr dtPattern5,dtPattern5Size,addr glWildCard
		.if EAX != NULL
			MOV EBX,EAX
			INC EBX
			MOV dtPattern5BPXAddress,EBX
			INVOKE SetBPX,EBX,bpxAlways,dtPattern5CallBack
		.else
			INVOKE Find,ESI,EDI,addr dtPattern51,dtPattern51Size,addr glWildCard
			.if EAX != NULL
				MOV EBX,EAX
				ADD EBX,3
				MOV dtPattern51BPXAddress,EBX
				INVOKE SetBPX,EBX,bpxAlways,dtPattern51CallBack
			.else
				.if DontLog == NULL
					INVOKE AddLogMessage,addr szNotPackErrorText
					INVOKE AddLogMessage,addr szEndUnpack
					INVOKE StopDebug
					INC DontLog
				.endif
			.endif
		.endif
		
		.if fdFileIsDll == 1
			INVOKE Find,ESI,EDI,addr dtPattern6,dtPattern6Size,addr glWildCard
			.if EAX != NULL
				MOV EBX,EAX
				SUB EBX,3
				MOV dtPattern6BPXAddress,EBX
				INVOKE SetBPX,EBX,bpxAlways,dtPattern6CallBack
			.else
				.if DontLog == NULL
					INVOKE AddLogMessage,addr szNotPackErrorText
					INVOKE AddLogMessage,addr szEndUnpack
					INVOKE StopDebug
					INC DontLog
				.endif
			.endif
		.endif
	.endif

	POPAD
	RET
cbFindPatterns endp
;------------------------------------------------------------------
MapFileEx proc fName:DWORD,dwReadOrWrite:DWORD,dwFileHWND:DWORD,dwFileSize:DWORD,dwFileMap:DWORD,dwFileMapVA:DWORD
	LOCAL Return :DWORD
	PUSHAD
	MOV Return,0
	INVOKE CreateFile,fName,GENERIC_READ+GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
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
MapFileEx endp
;------------------------------------------------------------------
UnmapFileEx proc dwFileHWND:DWORD,dwFileSize:DWORD,dwFileMap:DWORD,dwFileMapVA:DWORD
	PUSHAD
	INVOKE UnmapViewOfFile,dwFileMapVA
	INVOKE CloseHandle,dwFileMap
	INVOKE SetFilePointer,dwFileHWND,dwFileSize,NULL,NULL
	INVOKE SetEndOfFile,dwFileHWND
	INVOKE CloseHandle,dwFileHWND
	POPAD
	RET
UnmapFileEx endp
;------------------------------------------------------------------
end start