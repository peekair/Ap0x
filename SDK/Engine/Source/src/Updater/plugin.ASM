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
    include \masm32\include\user32.inc
    include \masm32\include\kernel32.inc
    include \masm32\include\urlmon.inc
    include \masm32\include\advapi32.inc
    include ..\..\Updater.inc

    includelib \masm32\lib\user32.lib
    includelib \masm32\lib\kernel32.lib
    includelib \masm32\lib\urlmon.lib
    includelib \masm32\lib\advapi32.lib
;------------------------------------------------------------------
    return MACRO arg
      mov eax, arg
      ret
    ENDM
;------------------------------------------------------------------
 .data
	szServer db "http://www.reversinglabs.com/updates/ue/15/",0h
	szVerIni db "ver.ini",0h
	szDebuggerEngine db "Debugger.dll",0h
	szImporterEngine db "Importer.dll",0h
	szDumperEngine db "Dumper.dll",0h
	szHiderEngine db "HideDebugger.dll",0h
	szRealignerEngine db "Realigner.dll",0h
	szTracerEngine db "Tracer.dll",0h
	szRelocaterEngine db "Relocater.dll",0h
	szGetModuleVersion db "GetModuleVersion",0h

	szErrorTitle db "[Error]",0h
	szErrorText db "[Error] Error while loading engine .dll(s)! Dll not found!",0h
	szErrorText2 db "[Error] Could not get version of engine`s .dll(s)!",0h
	szErrorText3 db "[Error] New engine .dll(s) could not be downloaded from Internet!",0h
	szUpdate db "Please wait, engine update in progress...",0h
	szUpdateDebugger db "Downloading Debugger.dll...",0h
	szUpdateImporter db "Downloading Importer.dll...",0h
	szUpdateDumper db "Downloading Dumper.dll...",0h
	szUpdateHider db "Downloading HideDebugger.dll...",0h
	szUpdateRealigner db "Downloading Realigner.dll...",0h
	szUpdateTracer db "Downloading Tracer.dll...",0h
	szUpdateRelocater db "Downloading Relocater.dll...",0h
	szKey db "Software\Unpacking Engine 1.5\Updater",0h
	szREGSZ db "REG_BINARY",0
 .data?
	hDebugger dd ?
	hImporter dd ?
	hDumper dd ?
	hHider dd ?
	hRealigner dd ?
	hTracer dd ?
	hRelocater dd ?
	vDebugger dd ?
	vImporter dd ?
	vDumper dd ?
	vHider dd ?
	vRealigner dd ?
	vTracer dd ?
	vRelocater dd ?
	uDebugger dd ?
	uImporter dd ?
	uDumper dd ?
	uHider dd ?
	uRealigner dd ?
	uTracer dd ?
	uRelocater dd ?
	hFile dd ?
	zCriticalError dd ?

	BackTitle db 1024 dup(?)
	WebBuffer db 256 dup(?)
	ReadBuffer db 100 dup(?)
	pNumOfBytes dd ?
	
	CurrentTime SYSTEMTIME <?>
	lpcbData dd  ?
	hKey dd  ?
	szBuff db 256h dup(?)
	szIsKey db ?
	Update dd ?
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
UpdateEngine proc UpdateWin:DWORD, WinHwnd:DWORD
	LOCAL Return :DWORD
	PUSHAD

	MOV Return,0
	MOV Update,0
	INVOKE GetSystemTime,addr CurrentTime

	MOV lpcbData,256h
	INVOKE RegOpenKeyEx,HKEY_CURRENT_USER,addr szKey,NULL,KEY_WRITE or KEY_READ,addr hKey
	.if hKey != 0
		INVOKE RegQueryValueEx,hKey,addr szIsKey,NULL,addr szREGSZ,addr szBuff,addr lpcbData
		MOV EAX,DWORD PTR[szBuff]
		MOV EBX,DWORD PTR[szBuff+4]
		.if AX == WORD PTR[CurrentTime.wDay] && BX == WORD PTR[CurrentTime.wMonth]
			MOV Update,-1
		.else
		        MOVZX EAX,WORD PTR[CurrentTime.wDay]
		        MOV DWORD PTR[szBuff],EAX
		        MOVZX EAX,WORD PTR[CurrentTime.wMonth]
		        MOV DWORD PTR[szBuff+4],EAX
			INVOKE RegSetValueEx,hKey,NULL,NULL,REG_BINARY,addr szBuff,8
		.endif
	.else
		INVOKE RegCreateKey,HKEY_CURRENT_USER,addr szKey,addr hKey
	        MOVZX EAX,WORD PTR[CurrentTime.wDay]
	        MOV DWORD PTR[szBuff],EAX
	        MOVZX EAX,WORD PTR[CurrentTime.wMonth]
	        MOV DWORD PTR[szBuff+4],EAX
		INVOKE RegSetValueEx,hKey,NULL,NULL,REG_BINARY,addr szBuff,8
	.endif

	.if Update == 0
		.if DWORD PTR[UpdateWin] == 1
			INVOKE GetWindowTextLength,DWORD PTR[WinHwnd]
			INC EAX
			INVOKE GetWindowText,DWORD PTR[WinHwnd],addr BackTitle,EAX
			INVOKE SetWindowText,DWORD PTR[WinHwnd],addr szUpdate
			INVOKE Sleep,1000
		.endif
	
		MOV DWORD PTR[zCriticalError],0
		INVOKE GetModuleHandle,addr szDebuggerEngine
		.if EAX == 0
			INVOKE LoadLibrary,addr szDebuggerEngine
			.if EAX == 0
				MOV DWORD PTR[zCriticalError],1
			.else
				MOV DWORD PTR[hDebugger],EAX
			.endif
		.else
			MOV DWORD PTR[hDebugger],EAX
		.endif
		INVOKE GetModuleHandle,addr szImporterEngine
		.if EAX == 0
			INVOKE LoadLibrary,addr szImporterEngine
			.if EAX == 0
				MOV DWORD PTR[zCriticalError],1
			.else
				MOV DWORD PTR[hImporter],EAX
			.endif
		.else
			MOV DWORD PTR[hImporter],EAX
		.endif
		INVOKE GetModuleHandle,addr szDumperEngine
		.if EAX == 0
			INVOKE LoadLibrary,addr szDumperEngine
			.if EAX == 0
				MOV DWORD PTR[zCriticalError],1
			.else
				MOV DWORD PTR[hDumper],EAX
			.endif
		.else
			MOV DWORD PTR[hDumper],EAX
		.endif
		INVOKE GetModuleHandle,addr szHiderEngine
		.if EAX == 0
			INVOKE LoadLibrary,addr szHiderEngine
			.if EAX != 0
				MOV DWORD PTR[hHider],EAX
			.endif
		.else
			MOV DWORD PTR[hHider],EAX
		.endif
		INVOKE GetModuleHandle,addr szRealignerEngine
		.if EAX == 0
			INVOKE LoadLibrary,addr szRealignerEngine
			.if EAX != 0
				MOV DWORD PTR[hRealigner],EAX
			.endif
		.else
			MOV DWORD PTR[hRealigner],EAX
		.endif
		INVOKE GetModuleHandle,addr szTracerEngine
		.if EAX == 0
			INVOKE LoadLibrary,addr szTracerEngine
			.if EAX != 0
				MOV DWORD PTR[hTracer],EAX
			.endif
		.else
			MOV DWORD PTR[hTracer],EAX
		.endif
		INVOKE GetModuleHandle,addr szRelocaterEngine
		.if EAX == 0
			INVOKE LoadLibrary,addr szRelocaterEngine
			.if EAX != 0
				MOV DWORD PTR[hRelocater],EAX
			.endif
		.else
			MOV DWORD PTR[hRelocater],EAX
		.endif
	
		.if DWORD PTR[zCriticalError] == 0
			INVOKE GetProcAddress,DWORD PTR[hDebugger],addr szGetModuleVersion
			.if EAX == 0
				MOV DWORD PTR[zCriticalError],1
			.else
				CALL EAX
				MOV DWORD PTR[vDebugger],EAX
			.endif
			INVOKE GetProcAddress,DWORD PTR[hImporter],addr szGetModuleVersion
			.if EAX == 0
				MOV DWORD PTR[zCriticalError],1
			.else
				CALL EAX
				MOV DWORD PTR[vImporter],EAX
			.endif
			INVOKE GetProcAddress,DWORD PTR[hDumper],addr szGetModuleVersion
			.if EAX == 0
				MOV DWORD PTR[zCriticalError],1
			.else
				CALL EAX
				MOV DWORD PTR[vDumper],EAX
			.endif
			.if DWORD PTR[hHider] != 0
				INVOKE GetProcAddress,DWORD PTR[hHider],addr szGetModuleVersion
				.if EAX == 0
					MOV DWORD PTR[zCriticalError],1
				.else
					CALL EAX
					MOV DWORD PTR[vHider],EAX
				.endif
			.endif
			.if DWORD PTR[hRealigner] != 0
				INVOKE GetProcAddress,DWORD PTR[hRealigner],addr szGetModuleVersion
				.if EAX == 0
					MOV DWORD PTR[zCriticalError],1
				.else
					CALL EAX
					MOV DWORD PTR[vRealigner],EAX
				.endif
			.endif
			.if DWORD PTR[hTracer] != 0
				INVOKE GetProcAddress,DWORD PTR[hTracer],addr szGetModuleVersion
				.if EAX == 0
					MOV DWORD PTR[zCriticalError],1
				.else
					CALL EAX
					MOV DWORD PTR[vTracer],EAX
				.endif
			.endif
			.if DWORD PTR[hRelocater] != 0
				INVOKE GetProcAddress,DWORD PTR[hRelocater],addr szGetModuleVersion
				.if EAX == 0
					MOV DWORD PTR[zCriticalError],1
				.else
					CALL EAX
					MOV DWORD PTR[vRelocater],EAX
				.endif
			.endif

			.if DWORD PTR[zCriticalError] == 0
				INVOKE lstrcpy,addr WebBuffer,addr szServer
				INVOKE lstrcat,addr WebBuffer,addr szVerIni
				INVOKE URLDownloadToFile,NULL,addr WebBuffer,addr szVerIni,NULL,NULL
				.if EAX == 0
					INVOKE CreateFile,addr szVerIni,GENERIC_READ,NULL,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
					.if EAX != -1
						MOV DWORD PTR[hFile],EAX
						INVOKE ReadFile,DWORD PTR[hFile],addr ReadBuffer,100,addr pNumOfBytes,NULL
						.if EAX == 1
							MOV EAX,DWORD PTR[ReadBuffer]		;Debugger
							SUB EAX,30303030h
							BSWAP EAX
							.if EAX > DWORD PTR[vDebugger]
								MOV DWORD PTR[uDebugger],1
							.else
								MOV DWORD PTR[uDebugger],0
							.endif
							MOV EAX,DWORD PTR[ReadBuffer+6]		;Importer
							SUB EAX,30303030h
							BSWAP EAX
							.if EAX > DWORD PTR[vImporter]
								MOV DWORD PTR[uImporter],1
							.else
								MOV DWORD PTR[uImporter],0
							.endif
							MOV EAX,DWORD PTR[ReadBuffer+12]	;Dumper
							SUB EAX,30303030h
							BSWAP EAX
							.if EAX > DWORD PTR[vDumper]
								MOV DWORD PTR[uDumper],1
							.else
								MOV DWORD PTR[uDumper],0
							.endif
							MOV EAX,DWORD PTR[ReadBuffer+18]	;Hider
							.if EAX != 0
								SUB EAX,30303030h
								BSWAP EAX
								.if EAX > DWORD PTR[vHider]
									MOV DWORD PTR[uHider],1
								.else
									MOV DWORD PTR[uHider],0
								.endif
							.else
								MOV DWORD PTR[uHider],0
							.endif
							MOV EAX,DWORD PTR[ReadBuffer+24]	;Realigner
							.if EAX != 0
								SUB EAX,30303030h
								BSWAP EAX
								.if EAX > DWORD PTR[vRealigner]
									MOV DWORD PTR[uRealigner],1
								.else
									MOV DWORD PTR[uRealigner],0
								.endif
							.else
								MOV DWORD PTR[uRealigner],0
							.endif
							MOV EAX,DWORD PTR[ReadBuffer+30]	;Tracer
							.if EAX != 0
								SUB EAX,30303030h
								BSWAP EAX
								.if EAX > DWORD PTR[vTracer]
									MOV DWORD PTR[uTracer],1
								.else
									MOV DWORD PTR[uTracer],0
								.endif
							.else
								MOV DWORD PTR[uTracer],0
							.endif
							MOV EAX,DWORD PTR[ReadBuffer+36]	;Relocater
							.if EAX != 0
								SUB EAX,30303030h
								BSWAP EAX
								.if EAX > DWORD PTR[vRelocater]
									MOV DWORD PTR[uRelocater],1
								.else
									MOV DWORD PTR[uRelocater],0
								.endif
							.else
								MOV DWORD PTR[uRelocater],0
							.endif
	
							.if DWORD PTR[uDebugger] == 1
								INVOKE FreeLibrary,DWORD PTR[hDebugger]
								INVOKE lstrcpy,addr WebBuffer,addr szServer
								INVOKE lstrcat,addr WebBuffer,addr szDebuggerEngine
								.if DWORD PTR[UpdateWin] == 1
									INVOKE SetWindowText,DWORD PTR[WinHwnd],addr szUpdateDebugger
									INVOKE Sleep,100h
								.endif
								INVOKE URLDownloadToFile,NULL,addr WebBuffer,addr szDebuggerEngine,NULL,NULL
								.if EAX != 0
									MOV DWORD PTR[zCriticalError],1
								.else
									MOV Return,1
								.endif
							.endif
							.if DWORD PTR[uImporter] == 1
								INVOKE FreeLibrary,DWORD PTR[hImporter]
								INVOKE lstrcpy,addr WebBuffer,addr szServer
								INVOKE lstrcat,addr WebBuffer,addr szImporterEngine
								.if DWORD PTR[UpdateWin] == 1
									INVOKE SetWindowText,DWORD PTR[WinHwnd],addr szUpdateImporter
									INVOKE Sleep,100h
								.endif
								INVOKE URLDownloadToFile,NULL,addr WebBuffer,addr szImporterEngine,NULL,NULL
								.if EAX != 0
									MOV DWORD PTR[zCriticalError],1
								.else
									MOV Return,1
								.endif
							.endif
							.if DWORD PTR[uDumper] == 1
								INVOKE FreeLibrary,DWORD PTR[hDumper]
								INVOKE lstrcpy,addr WebBuffer,addr szServer
								INVOKE lstrcat,addr WebBuffer,addr szDumperEngine
								.if DWORD PTR[UpdateWin] == 1
									INVOKE SetWindowText,DWORD PTR[WinHwnd],addr szUpdateDumper
									INVOKE Sleep,100h
								.endif
								INVOKE URLDownloadToFile,NULL,addr WebBuffer,addr szDumperEngine,NULL,NULL
								.if EAX != 0
									MOV DWORD PTR[zCriticalError],1
								.else
									MOV Return,1
								.endif
							.endif
							.if DWORD PTR[uHider] == 1
								INVOKE FreeLibrary,DWORD PTR[hHider]
								INVOKE lstrcpy,addr WebBuffer,addr szServer
								INVOKE lstrcat,addr WebBuffer,addr szHiderEngine
								.if DWORD PTR[UpdateWin] == 1
									INVOKE SetWindowText,DWORD PTR[WinHwnd],addr szUpdateHider
									INVOKE Sleep,100h
								.endif
								INVOKE URLDownloadToFile,NULL,addr WebBuffer,addr szHiderEngine,NULL,NULL
								.if EAX != 0
									MOV DWORD PTR[zCriticalError],1
								.else
									MOV Return,1
								.endif
							.endif
							.if DWORD PTR[uRealigner] == 1
								INVOKE FreeLibrary,DWORD PTR[hRealigner]
								INVOKE lstrcpy,addr WebBuffer,addr szServer
								INVOKE lstrcat,addr WebBuffer,addr szRealignerEngine
								.if DWORD PTR[UpdateWin] == 1
									INVOKE SetWindowText,DWORD PTR[WinHwnd],addr szUpdateRealigner
									INVOKE Sleep,100h
								.endif
								INVOKE URLDownloadToFile,NULL,addr WebBuffer,addr szRealignerEngine,NULL,NULL
								.if EAX != 0
									MOV DWORD PTR[zCriticalError],1  
								.else
									MOV Return,1
								.endif
							.endif
							.if DWORD PTR[uTracer] == 1
								INVOKE FreeLibrary,DWORD PTR[hTracer]
								INVOKE lstrcpy,addr WebBuffer,addr szServer
								INVOKE lstrcat,addr WebBuffer,addr szTracerEngine
								.if DWORD PTR[UpdateWin] == 1
									INVOKE SetWindowText,DWORD PTR[WinHwnd],addr szUpdateTracer
									INVOKE Sleep,100h
								.endif
								INVOKE URLDownloadToFile,NULL,addr WebBuffer,addr szTracerEngine,NULL,NULL
								.if EAX != 0
									MOV DWORD PTR[zCriticalError],1
								.else
									MOV Return,1
								.endif
							.endif
							.if DWORD PTR[uRelocater] == 1
								INVOKE FreeLibrary,DWORD PTR[hRelocater]
								INVOKE lstrcpy,addr WebBuffer,addr szServer
								INVOKE lstrcat,addr WebBuffer,addr szRelocaterEngine
								.if DWORD PTR[UpdateWin] == 1
									INVOKE SetWindowText,DWORD PTR[WinHwnd],addr szUpdateRelocater
									INVOKE Sleep,100h
								.endif
								INVOKE URLDownloadToFile,NULL,addr WebBuffer,addr szRelocaterEngine,NULL,NULL
								.if EAX != 0
									MOV DWORD PTR[zCriticalError],1
								.else
									MOV Return,1
								.endif
							.endif
						.endif
						INVOKE CloseHandle,DWORD PTR[hFile]
						.if DWORD PTR[zCriticalError] == 1
							INVOKE MessageBox,NULL,addr szErrorText3,addr szErrorTitle,30h
						.endif
					.endif
				.endif
			.else
				INVOKE MessageBox,NULL,addr szErrorText2,addr szErrorTitle,30h
			.endif
		.else
			INVOKE MessageBox,NULL,addr szErrorText,addr szErrorTitle,30h
		.endif
	
		INVOKE DeleteFile,addr szVerIni
	
		.if DWORD PTR[UpdateWin] == 1
			INVOKE SetWindowText,DWORD PTR[WinHwnd],addr BackTitle
		.endif
	.endif

	POPAD
	MOV EAX,Return
	RET
UpdateEngine endp
;------------------------------------------------------------------
End LibMain