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

    includelib \masm32\lib\user32.lib
    includelib \masm32\lib\kernel32.lib
    includelib \masm32\lib\psapi.lib

;------------------------------------------------------------------

	HideDebugger PROTO :DWORD,:DWORD,:DWORD

    return MACRO arg
      mov eax, arg
      ret
    ENDM

    .data
	dwNOP_Patch_0 dd 40484048h		;CheckRemoteDebuggerPresent
	dwEAX_Patch_1 dd 08C2C033h
	dwEAX_Patch_2 dd 90909000h
	dwNOP_Patch_1 dd 40484048h		;GetTickCount
	dwEAX_Patch_3 dd 90C3C033h
	retPatch db 068h,0,0,0,0,0C3h
	OLDProtect dd PAGE_EXECUTE_READ
	Nulled dd NULL
	szKernel32 db "kernel32.dll",0h
	szCheckRemoteDebuggerPresent db "CheckRemoteDebuggerPresent",0h
	szGetTickCount db "GetTickCount",0h
	szNTDLL db "ntdll.dll",0h
	szZwQueryInformationProcess db "ZwQueryInformationProcess",0h
	szZwSetInformationThread db "ZwSetInformationThread",0h
	szZwQueryObject db "ZwQueryObject",0h
	szZwQuerySystemInformation db "ZwQuerySystemInformation",0h
	
	szImporter db "Importer.dll",0h
	szImporterGetRemoteAPIAddress db "ImporterGetRemoteAPIAddress",0h
    .data?
	victimContext CONTEXT <?>
	sel LDT_ENTRY <?>
 	WinVer OSVERSIONINFOEX <?>
	FSBase dd ?
	PEBRva dd ?
	ProcessHeap dd ?
	APIAddress dd ?
	NumberOrBytesRead dd ?
	ReadBuffer dd ?
	
	hImporter dd ?
	cImporterGetRemoteAPIAddress dd ?
    .code

;------------------------------------------------------------------
LibMain proc hInstDLL:DWORD, reason:DWORD, unused:DWORD

        .if reason == DLL_PROCESS_ATTACH
		INVOKE GetModuleHandle,addr szImporter
		.if EAX == NULL
			INVOKE LoadLibrary,addr szImporter
		.endif
		.if EAX != NULL
			MOV hImporter,EAX
			INVOKE GetProcAddress,hImporter,addr szImporterGetRemoteAPIAddress
			MOV cImporterGetRemoteAPIAddress,EAX
		.endif
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
	MOV EAX,0101h
	RET
GetModuleVersion endp
;------------------------------------------------------------------
HideDebugger proc hThread:DWORD,hProcess:DWORD,dwPatchAPI:DWORD

	PUSHAD

	MOV DWORD PTR[victimContext.ContextFlags],CONTEXT_SEGMENTS
	INVOKE GetThreadContext,hThread,addr victimContext
	.if EAX == FALSE
		JMP _error_exit
	.endif
	
	INVOKE GetThreadSelectorEntry,hThread,victimContext.regFs,addr sel
	.if EAX == FALSE
		JMP _error_exit
	.endif
	MOVZX EAX,BYTE PTR[sel.HighWord1.Bytes.BaseHi]
	ROL EAX,8
	MOV AL,BYTE PTR[sel.HighWord1.Bytes.BaseMid]
	ROL EAX,16
        MOV AX,WORD PTR[sel.BaseLow]
        MOV FSBase,EAX

	ADD EAX,30h
        INVOKE ReadProcessMemory,hProcess,EAX,addr PEBRva,4,addr NumberOrBytesRead
        .if NumberOrBytesRead != 4
		JMP _error_exit
        .endif
;	//////////////////////////////////////////////////////////////////////////
;	//PEB.BeingDebugged patch
	MOV EAX,PEBRva
	ADD EAX,2h
        INVOKE WriteProcessMemory,hProcess,EAX,addr Nulled,2,addr NumberOrBytesRead
        .if NumberOrBytesRead != 2
		JMP _error_exit
        .endif
;	//////////////////////////////////////////////////////////////////////////
;	//NtGlobalFlag patch
	MOV EAX,PEBRva
	ADD EAX,68h
        INVOKE WriteProcessMemory,hProcess,EAX,addr Nulled,4,addr NumberOrBytesRead
        .if NumberOrBytesRead != 4
		JMP _error_exit
        .endif
;	//////////////////////////////////////////////////////////////////////////
;	// ProcessHeap
	MOV EAX,PEBRva
	ADD EAX,18h
        INVOKE ReadProcessMemory,hProcess,EAX,addr ProcessHeap,4,addr NumberOrBytesRead
        .if NumberOrBytesRead != 4
		JMP _error_exit
        .endif
	MOV EAX,ProcessHeap
	ADD EAX,10h
        INVOKE WriteProcessMemory,hProcess,EAX,addr Nulled,4,addr NumberOrBytesRead
        .if NumberOrBytesRead != 4
		JMP _error_exit
        .endif
        
	.if dwPatchAPI >= 1
;	//////////////////////////////////////////////////////////////////////////
;	// CheckRemoteDebuggerPresent
		INVOKE GetModuleHandle,addr szKernel32
		INVOKE GetProcAddress,EAX,addr szCheckRemoteDebuggerPresent
		MOV APIAddress,EAX
		.if cImporterGetRemoteAPIAddress != NULL
			PUSH APIAddress
			PUSH hProcess
			CALL DWORD PTR[cImporterGetRemoteAPIAddress]
			MOV APIAddress,EAX
		.endif
		.if APIAddress != 0
			INVOKE VirtualProtectEx,hProcess,APIAddress,8,PAGE_EXECUTE_READWRITE,addr OLDProtect
			.if EAX != 1
				JMP _error_exit
			.endif
		        INVOKE WriteProcessMemory,hProcess,APIAddress,addr dwNOP_Patch_0,12,addr NumberOrBytesRead
		        .if NumberOrBytesRead != 12
				JMP _error_exit
		        .endif
		.endif
;	//////////////////////////////////////////////////////////////////////////
;	// GetTickCount
		INVOKE GetModuleHandle,addr szKernel32
		INVOKE GetProcAddress,EAX,addr szGetTickCount
		MOV APIAddress,EAX
		.if cImporterGetRemoteAPIAddress != NULL
			PUSH APIAddress
			PUSH hProcess
			CALL DWORD PTR[cImporterGetRemoteAPIAddress]
			MOV APIAddress,EAX
		.endif
		.if APIAddress != 0
			INVOKE VirtualProtectEx,hProcess,APIAddress,8,PAGE_EXECUTE_READWRITE,addr OLDProtect
			.if EAX != 1
				JMP _error_exit
			.endif
		        INVOKE WriteProcessMemory,hProcess,APIAddress,addr dwNOP_Patch_1,8,addr NumberOrBytesRead
		        .if NumberOrBytesRead != 8
				JMP _error_exit
		        .endif
		.endif
	.if dwPatchAPI >= 2
;	//////////////////////////////////////////////////////////////////////////
;	// ZwQueryInformationProcess
		MOV DWORD PTR[WinVer.dwOSVersionInfoSize],sizeof OSVERSIONINFOEX
		INVOKE GetVersionEx,addr WinVer
		.if DWORD PTR[WinVer.dwPlatformId] == VER_PLATFORM_WIN32_NT
                        .if DWORD PTR[WinVer.dwMajorVersion] == 5 && DWORD PTR[WinVer.dwMinorVersion] == 1
                        	.if DWORD PTR[WinVer.wServicePackMajor] < 2
					JMP _success_exit
                        	.endif
                       	.elseif DWORD PTR[WinVer.dwMajorVersion] < 5
				JMP _success_exit
                        .endif
			INVOKE GetModuleHandle,addr szNTDLL
			INVOKE GetProcAddress,EAX,addr szZwQueryInformationProcess
			MOV APIAddress,EAX
			.if cImporterGetRemoteAPIAddress != NULL
				PUSH APIAddress
				PUSH hProcess
				CALL DWORD PTR[cImporterGetRemoteAPIAddress]
				MOV APIAddress,EAX
			.endif
			.if APIAddress != 0
				INVOKE VirtualProtectEx,hProcess,APIAddress,6,PAGE_EXECUTE_READWRITE,addr OLDProtect
				.if EAX != 1
					JMP _error_exit
				.endif
				INVOKE VirtualAllocEx,hProcess,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
				MOV DWORD PTR[retPatch+1],EAX
			        INVOKE WriteProcessMemory,hProcess,APIAddress,addr retPatch,6,addr NumberOrBytesRead
			        .if NumberOrBytesRead != 6
					JMP _error_exit
			        .endif
				PUSH offset NumberOrBytesRead
				PUSH (offset _ZW_QIP_patch_END - offset _ZW_QIP_patch_START)
				PUSH offset _ZW_QIP_patch_START
				PUSH DWORD PTR[retPatch+1]
				PUSH hProcess
			        CALL WriteProcessMemory
				MOV EAX,APIAddress
				ADD EAX,6
			        INVOKE ReadProcessMemory,hProcess,EAX,addr ReadBuffer,4,addr NumberOrBytesRead
			        .if NumberOrBytesRead != 4
					JMP _error_exit
			        .endif
				MOV EAX,DWORD PTR[retPatch+1]
				ADD EAX,(offset _ZW_QIP_patch_PATCH - offset _ZW_QIP_patch_START + 1)
			        INVOKE WriteProcessMemory,hProcess,EAX,addr ReadBuffer,4,addr NumberOrBytesRead
			.endif
		.endif
;	//////////////////////////////////////////////////////////////////////////
;	// ZwSetInformationThread
;		MOV DWORD PTR[WinVer.dwOSVersionInfoSize],sizeof OSVERSIONINFO
;		INVOKE GetVersionEx,addr WinVer
		.if DWORD PTR[WinVer.dwPlatformId] == VER_PLATFORM_WIN32_NT
			INVOKE GetModuleHandle,addr szNTDLL
			INVOKE GetProcAddress,EAX,addr szZwSetInformationThread
			MOV APIAddress,EAX
			.if cImporterGetRemoteAPIAddress != NULL
				PUSH APIAddress
				PUSH hProcess
				CALL DWORD PTR[cImporterGetRemoteAPIAddress]
				MOV APIAddress,EAX
			.endif
			.if APIAddress != 0
				INVOKE VirtualProtectEx,hProcess,APIAddress,6,PAGE_EXECUTE_READWRITE,addr OLDProtect
				.if EAX != 1
					JMP _error_exit
				.endif
				INVOKE VirtualAllocEx,hProcess,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
				MOV DWORD PTR[retPatch+1],EAX
			        INVOKE WriteProcessMemory,hProcess,APIAddress,addr retPatch,6,addr NumberOrBytesRead
			        .if NumberOrBytesRead != 6
					JMP _error_exit
			        .endif
				PUSH offset NumberOrBytesRead
				PUSH (offset _ZW_SIT_patch_END - offset _ZW_SIT_patch_START)
				PUSH offset _ZW_SIT_patch_START
				PUSH DWORD PTR[retPatch+1]
				PUSH hProcess
			        CALL WriteProcessMemory
				MOV EAX,APIAddress
				ADD EAX,6
			        INVOKE ReadProcessMemory,hProcess,EAX,addr ReadBuffer,4,addr NumberOrBytesRead
			        .if NumberOrBytesRead != 4
					JMP _error_exit
			        .endif
				MOV EAX,DWORD PTR[retPatch+1]
				ADD EAX,(offset _ZW_SIT_patch_PATCH - offset _ZW_SIT_patch_START + 1)
			        INVOKE WriteProcessMemory,hProcess,EAX,addr ReadBuffer,4,addr NumberOrBytesRead
			.endif
		.endif
;	//////////////////////////////////////////////////////////////////////////
;	// ZwQueryObject
;		MOV DWORD PTR[WinVer.dwOSVersionInfoSize],sizeof OSVERSIONINFO
;		INVOKE GetVersionEx,addr WinVer
		.if DWORD PTR[WinVer.dwPlatformId] == VER_PLATFORM_WIN32_NT
			INVOKE GetModuleHandle,addr szNTDLL
			INVOKE GetProcAddress,EAX,addr szZwQueryObject
			MOV APIAddress,EAX
			.if cImporterGetRemoteAPIAddress != NULL
				PUSH APIAddress
				PUSH hProcess
				CALL DWORD PTR[cImporterGetRemoteAPIAddress]
				MOV APIAddress,EAX
			.endif
			.if APIAddress != 0
				INVOKE VirtualProtectEx,hProcess,APIAddress,6,PAGE_EXECUTE_READWRITE,addr OLDProtect
				.if EAX != 1
					JMP _error_exit
				.endif
				INVOKE VirtualAllocEx,hProcess,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
				MOV DWORD PTR[retPatch+1],EAX
				MOV EAX,APIAddress
				ADD EAX,0Ch
			        INVOKE WriteProcessMemory,hProcess,EAX,addr retPatch,6,addr NumberOrBytesRead
			        .if NumberOrBytesRead != 6
					JMP _error_exit
			        .endif
				PUSH offset NumberOrBytesRead
				PUSH (offset _ZW_QO_patch_END - offset _ZW_QO_patch_START)
				PUSH offset _ZW_QO_patch_START
				PUSH DWORD PTR[retPatch+1]
				PUSH hProcess
			        CALL WriteProcessMemory
			.endif
		.endif
;	//////////////////////////////////////////////////////////////////////////
;	// ZwQuerySystemInformation
;		MOV DWORD PTR[WinVer.dwOSVersionInfoSize],sizeof OSVERSIONINFO
;		INVOKE GetVersionEx,addr WinVer
		.if DWORD PTR[WinVer.dwPlatformId] == VER_PLATFORM_WIN32_NT
			INVOKE GetModuleHandle,addr szNTDLL
			INVOKE GetProcAddress,EAX,addr szZwQuerySystemInformation
			MOV APIAddress,EAX
			.if cImporterGetRemoteAPIAddress != NULL
				PUSH APIAddress
				PUSH hProcess
				CALL DWORD PTR[cImporterGetRemoteAPIAddress]
				MOV APIAddress,EAX
			.endif
			.if APIAddress != 0
				INVOKE VirtualProtectEx,hProcess,APIAddress,6,PAGE_EXECUTE_READWRITE,addr OLDProtect
				.if EAX != 1
					JMP _error_exit
				.endif
				INVOKE VirtualAllocEx,hProcess,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
				MOV DWORD PTR[retPatch+1],EAX
				MOV EAX,APIAddress
				ADD EAX,0Ch
			        INVOKE WriteProcessMemory,hProcess,EAX,addr retPatch,6,addr NumberOrBytesRead
			        .if NumberOrBytesRead != 6
					JMP _error_exit
			        .endif
				PUSH offset NumberOrBytesRead
				PUSH (offset _ZW_QSI_patch_END - offset _ZW_QSI_patch_START)
				PUSH offset _ZW_QSI_patch_START
				PUSH DWORD PTR[retPatch+1]
				PUSH hProcess
			        CALL WriteProcessMemory
			.endif
		.endif
;	//////////////////////////////////////////////////////////////////////////
	.endif	;Patch ntdll.dll
	.endif	;Patch kernel32.dll

 _success_exit:
	POPAD
	XOR EAX,EAX		;Success
	RET

 _error_exit:
	POPAD
	MOV EAX,-1		;Error exit!
	RET

HideDebugger endp
;------------------------------------------------------------------
		db "Thanks to SHub-Nigurrath for this code!",0h
 _ZW_QIP_patch_START:
			cmp dword ptr[esp+8], 7
			je short no_zwqueryinformationprocess
			;//executes the normal function as usual
			;//the code comes from the original implementation of the API
			mov eax,9Ah
 _ZW_QIP_patch_PATCH:
			mov edx,7FFE0300h
			call dword ptr[edx]
			retn 14h

		no_zwqueryinformationprocess:
			mov eax,dword ptr[esp+0ch]
			cmp eax,0			;//if eax==0 then exit hook without doing anything
			je exit_hook 
			mov dword ptr[eax],0
			push eax
			push ebx
			mov eax, dword ptr[esp+18h]	;//points to how many bytes your API should read
			mov ebx, dword ptr[esp+1Ch]	;//point to how many bytes the API read indeed
			cmp ebx, 0			;//if the last parameter is null, just skip it.
							;//Otherwise emulate the function
			je exit_hook
			mov dword ptr[ebx],eax		;//these two values must be the same to behave like original

		exit_hook:
			pop ebx
			pop eax
			mov eax,0			;//eax must be set to 0 meaning that all went fine
			ret 14h
 _ZW_QIP_patch_END:
;------------------------------------------------------------------
		db "Thanks to Markus TH-DJM for this code!",0h
 _ZW_SIT_patch_START:
			CMP DWORD PTR SS:[ESP+8],11h
			jne short _ZwSetInformationThread
			retn 10h
			;//executes the normal function as usual
			;//the code comes from the original implementation of the API
 _ZwSetInformationThread:
			mov eax,0E5h
 _ZW_SIT_patch_PATCH:
			mov edx,7FFE0300h
			call dword ptr[edx]
			retn 10h
 _ZW_SIT_patch_END:
;------------------------------------------------------------------
		db "Thanks to Markus TH-DJM for this code!",0h
 _ZW_QO_patch_START:
			PUSHAD
			CMP DWORD PTR SS:[ESP+28h],3
			JNZ _exit_QO
			MOV EDI,DWORD PTR SS:[ESP+2Ch]
			MOV ECX,DWORD PTR SS:[ESP+30h]
			XOR EAX,EAX
			REP STOS BYTE PTR ES:[EDI]
			POPAD
	_exit_QO:
			RET 14h
 _ZW_QO_patch_END:
;------------------------------------------------------------------
		db "Thanks to Markus TH-DJM for this code!",0h
 _ZW_QSI_patch_START:
			CMP DWORD PTR SS:[ESP+4],23h
			JNZ _exit_QSI
			PUSHAD
			MOV EDI,DWORD PTR SS:[ESP+28h]
			MOV ECX,DWORD PTR SS:[ESP+2Ch]
			XOR EAX,EAX
			REP STOS BYTE PTR ES:[EDI]
			POPAD
			XOR EAX,EAX
	_exit_QSI:
			RET 10h
 _ZW_QSI_patch_END:
;------------------------------------------------------------------
;------------------------------------------------------------------
End LibMain