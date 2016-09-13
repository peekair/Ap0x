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
    include ..\..\Tracer.inc

    includelib \masm32\lib\user32.lib
    includelib \masm32\lib\kernel32.lib
    includelib \masm32\lib\psapi.lib

    ZombieHashMemory PROTO :DWORD,:DWORD
;------------------------------------------------------------------

    return MACRO arg
      mov eax, arg
      ret
    ENDM

    .data
    	szSectionName db "UEv15",0h
	szDumper db "Dumper.dll",0h
	szGetPE32Data db "GetPE32Data",0h
	szAddNewSection db "AddNewSection",0h
	szDumpProcess db "DumpProcess",0h
	szImporter db "Importer.dll",0h
	szImporterInit db "ImporterInit",0h
	szImporterAddNewDll db "ImporterAddNewDll",0h
	szImporterAddNewAPI db "ImporterAddNewAPI",0h
	szImporterExportIAT db "ImporterExportIAT",0h
	szImporterEstimatedSize db "ImporterEstimatedSize",0h
	szImporterGetDLLIndexEx db "ImporterGetDLLIndexEx",0h
	szImporterGetAPINameEx db "ImporterGetAPINameEx",0h
	szImporterSetAutoFixOptions db "ImporterSetAutoFixOptions",0h
	szImporterGetAPINameFromDebugee db "ImporterGetAPINameFromDebugee",0h
	szImporterFindAPIWriteLocation db "ImporterFindAPIWriteLocation",0h
	szImporterGetRemoteAPIAddress db "ImporterGetRemoteAPIAddress",0h
 ;
 ; Forwarded APIs
 ;
	szNTDLL_1 db "ntdll.dll",0h
	szNTDLL_2 db "NTDLL.dll",0h
	szNTDLL_3 db "NTDLL.DLL",0h
	szKERNEL32 db "kernel32.dll",0h
	szUSER32 db "user32.dll",0h
	szGetCommandLineA db "GetCommandLineA",0h
	szGetCommandLineW db "GetCommandLineW",0h
	szExitProcess db "ExitProcess",0h
	szRestoreLastError db "RestoreLastError",0h	;RestoreLastError
	szSetLastError db "SetLastError",0h
	szMessageBoxA db "MessageBoxA",0h
	szGetModuleHandleA db "GetModuleHandleA",0h
	szGetVersionExA db "GetVersionExA",0h
	szGetVersion db "GetVersion",0h
	szGetCurrentProcess db "GetCurrentProcess",0h
    .data?
	NumOfBytesRW dd ?
	MemStatus MEMORY_BASIC_INFORMATION <?>
	MemInfo MEMORY_BASIC_INFORMATION <?>
 ;
 ; Mapiranje fajla
 ;
	FileHWND dd ?
	FileSize dd ?
	FileMap dd ?
	FileMapVA dd ?
 ;
 ; Misc variables
 ;
	Converted dd ?
	NeededSpace dd ?
	dwListType dd ?
	APINameBuffer db 256 dup(?)
 ;
 ; Importer stuff
 ;
	hImporter dd ?
	cImporterInit dd ?
	cImporterAddNewDll dd ?
	cImporterAddNewAPI dd ?
	cImporterExportIAT dd ?
	cImporterEstimatedSize dd ?
	cImporterGetDLLIndexEx dd ?
	cImporterGetAPINameEx dd ?
	cImporterSetAutoFixOptions dd ?
	cImporterGetAPINameFromDebugee dd ?
	cImporterFindAPIWriteLocation dd ?
	cImporterGetRemoteAPIAddress dd ?
 ;
 ; Dumper stuff
 ;
	hDumper dd ?
	cGetPE32Data dd ?
	cAddNewSection dd ?
	cDumpProcess dd ?
    .code

;------------------------------------------------------------------
LibMain proc hInstDLL:DWORD, reason:DWORD, unused:DWORD

        .if reason == DLL_PROCESS_ATTACH
		CALL TracerInit
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
TracerFix_ACProtect proc hProcess:DWORD,dwAddressToScan:DWORD
	LOCAL Return :DWORD
	LOCAL BaseAlloc :DWORD
	PUSHAD

	INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
	MOV BaseAlloc,EAX
	INVOKE ReadProcessMemory,hProcess,dwAddressToScan,BaseAlloc,100,addr NumOfBytesRW
	MOV ESI,BaseAlloc
	MOV EAX,DWORD PTR[ESI+1]
	.if WORD PTR[ESI+5] == 2C81h
		SUB EAX,DWORD PTR[ESI+8]
	.elseif WORD PTR[ESI+5] == 3481h
		XOR EAX,DWORD PTR[ESI+8]
	.elseif WORD PTR[ESI+5] == 0481h
		ADD EAX,DWORD PTR[ESI+8]
	.endif
	MOV Return,EAX

	INVOKE VirtualFree,BaseAlloc,1000h,MEM_DECOMMIT
	INVOKE VirtualFree,BaseAlloc,NULL,MEM_RELEASE

	POPAD
	MOV EAX,Return
	RET
TracerFix_ACProtect endp
;------------------------------------------------------------------
TracerFix_tELock_varA proc hProcess:DWORD,dwAddressToScan:DWORD
	LOCAL Return :DWORD
	LOCAL BaseAlloc :DWORD
	PUSHAD

	INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
	MOV BaseAlloc,EAX
	INVOKE ReadProcessMemory,hProcess,dwAddressToScan,BaseAlloc,100,addr NumOfBytesRW
	MOV ESI,BaseAlloc
	MOV EAX,DWORD PTR[ESI+2]
	INVOKE ReadProcessMemory,hProcess,EAX,BaseAlloc,100,addr NumOfBytesRW
	MOV EAX,DWORD PTR[BaseAlloc]
	MOV EAX,DWORD PTR[EAX]
	MOV Return,EAX

	INVOKE VirtualFree,BaseAlloc,1000h,MEM_DECOMMIT
	INVOKE VirtualFree,BaseAlloc,NULL,MEM_RELEASE

	POPAD
	MOV EAX,Return
	RET
TracerFix_tELock_varA endp
;------------------------------------------------------------------
TracerFix_tELock_varB proc hProcess:DWORD,dwAddressToScan:DWORD
	LOCAL Return :DWORD
	LOCAL BaseAlloc :DWORD
	PUSHAD

	INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
	MOV BaseAlloc,EAX
	INVOKE ReadProcessMemory,hProcess,dwAddressToScan,BaseAlloc,100,addr NumOfBytesRW
	MOV ESI,BaseAlloc
	.if WORD PTR[ESI] == 35FFh
		MOV EAX,DWORD PTR[ESI+2]
	.else
		MOV EAX,DWORD PTR[ESI+3]
	.endif
	INVOKE ReadProcessMemory,hProcess,EAX,BaseAlloc,100,addr NumOfBytesRW
	MOV EAX,DWORD PTR[BaseAlloc]
	MOV EAX,DWORD PTR[EAX]
	MOV Return,EAX

	INVOKE VirtualFree,BaseAlloc,1000h,MEM_DECOMMIT
	INVOKE VirtualFree,BaseAlloc,NULL,MEM_RELEASE

	POPAD
	MOV EAX,Return
	RET
TracerFix_tELock_varB endp
;------------------------------------------------------------------
TracerFix_tELock_varC proc hProcess:DWORD,dwAddressToScan:DWORD
	LOCAL Return :DWORD
	LOCAL BaseAlloc :DWORD
	PUSHAD

	INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
	MOV BaseAlloc,EAX
	INVOKE ReadProcessMemory,hProcess,dwAddressToScan,BaseAlloc,100,addr NumOfBytesRW
	MOV ECX,100
	MOV ESI,BaseAlloc
	.while ECX > 0 && (WORD PTR[ESI] != 030FFh && WORD PTR[ESI] != 020FFh)
		INC ESI
		DEC ECX
	.endw
	.if ECX != 0 && WORD PTR[ESI] == 020FFh
		.if BYTE PTR[ESI+2] != 090h
			INC ESI
			.while ECX > 0 && (WORD PTR[ESI] != 030FFh && WORD PTR[ESI] != 020FFh)
				INC ESI
				DEC ECX
			.endw
		.endif
	.endif
	.if ECX != 0 && WORD PTR[ESI] == 030FFh
		.if BYTE PTR[ESI-6] == 0B8h
			MOV EAX,DWORD PTR[ESI-5]
			.if BYTE PTR[ESI-1] == 40h
				INC EAX
			.endif
		.else
			MOV EAX,DWORD PTR[ESI-4]
		.endif
		INVOKE ReadProcessMemory,hProcess,EAX,BaseAlloc,100,addr NumOfBytesRW
		MOV EAX,DWORD PTR[BaseAlloc]
		MOV EAX,DWORD PTR[EAX]
	.elseif ECX != 0 && WORD PTR[ESI] == 020FFh
		MOV EAX,DWORD PTR[ESI-4]
		INVOKE ReadProcessMemory,hProcess,EAX,BaseAlloc,100,addr NumOfBytesRW
		MOV EAX,DWORD PTR[BaseAlloc]
		MOV EAX,DWORD PTR[EAX]
	.else
		XOR EAX,EAX
	.endif
	MOV Return,EAX

	INVOKE VirtualFree,BaseAlloc,1000h,MEM_DECOMMIT
	INVOKE VirtualFree,BaseAlloc,NULL,MEM_RELEASE

	POPAD
	MOV EAX,Return
	RET
TracerFix_tELock_varC endp
;------------------------------------------------------------------
TracerFix_tELock_varD proc hProcess:DWORD,dwAddressToScan:DWORD
	LOCAL Return :DWORD
	LOCAL BaseAlloc :DWORD
	PUSHAD

	INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
	MOV BaseAlloc,EAX
	INVOKE ReadProcessMemory,hProcess,dwAddressToScan,BaseAlloc,100,addr NumOfBytesRW
	MOV ECX,100
	MOV ESI,BaseAlloc
	.while ECX > 0 && WORD PTR[ESI] != 0C350h
		INC ESI
		DEC ECX
	.endw
	.if ECX != 0 && WORD PTR[ESI] == 0C350h
		MOV EAX,DWORD PTR[ESI-16h]
		ADD EAX,18h
		MOV EDI,DWORD PTR[ESI-6h]
		INVOKE ReadProcessMemory,hProcess,EAX,BaseAlloc,100,addr NumOfBytesRW
		MOV EAX,DWORD PTR[BaseAlloc]
		MOV EAX,DWORD PTR[EAX]
		XOR EAX,EDI
	.else
		XOR EAX,EAX
	.endif
	MOV Return,EAX

	INVOKE VirtualFree,BaseAlloc,1000h,MEM_DECOMMIT
	INVOKE VirtualFree,BaseAlloc,NULL,MEM_RELEASE

	POPAD
	MOV EAX,Return
	RET
TracerFix_tELock_varD endp
;------------------------------------------------------------------
TracerFix_ReCrypt proc hProcess:DWORD,dwAddressToScan:DWORD
	LOCAL Return :DWORD
	LOCAL BaseAlloc :DWORD
	PUSHAD

	INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
	MOV BaseAlloc,EAX
	INVOKE ReadProcessMemory,hProcess,dwAddressToScan,BaseAlloc,100,addr NumOfBytesRW
	MOV ESI,BaseAlloc
	MOV EAX,DWORD PTR[ESI+1]
	MOV Return,EAX

	INVOKE VirtualFree,BaseAlloc,1000h,MEM_DECOMMIT
	INVOKE VirtualFree,BaseAlloc,NULL,MEM_RELEASE

	POPAD
	MOV EAX,Return
	RET
TracerFix_ReCrypt endp
;------------------------------------------------------------------
TracerFix_Orien proc hProcess:DWORD,dwAddressToScan:DWORD
	LOCAL Return :DWORD
	LOCAL BaseAlloc :DWORD
	PUSHAD

	INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
	MOV BaseAlloc,EAX
	INVOKE ReadProcessMemory,hProcess,dwAddressToScan,BaseAlloc,100,addr NumOfBytesRW
	MOV ESI,BaseAlloc
	MOVZX EAX,BYTE PTR[ESI]
	.if AL == 0E8h
		MOV EAX,DWORD PTR[ESI+15h]
		.if EAX == 55F0h
			INVOKE GetModuleHandle,addr szKERNEL32
			INVOKE GetProcAddress,EAX,addr szGetCommandLineA
		.else
			INVOKE GetModuleHandle,addr szKERNEL32
			INVOKE GetProcAddress,EAX,addr szGetCommandLineW
		.endif
	.elseif AL == 0C8h
		INVOKE GetModuleHandle,addr szKERNEL32
		INVOKE GetProcAddress,EAX,addr szExitProcess
	.else
		XOR EAX,EAX
	.endif
	MOV Return,EAX

	INVOKE VirtualFree,BaseAlloc,1000h,MEM_DECOMMIT
	INVOKE VirtualFree,BaseAlloc,NULL,MEM_RELEASE

	POPAD
	MOV EAX,Return
	RET
TracerFix_Orien endp
;------------------------------------------------------------------
TracerFix_AlexProtector proc hProcess:DWORD,dwAddressToScan:DWORD
	LOCAL Return :DWORD
	LOCAL BaseAlloc :DWORD
	PUSHAD

	INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
	MOV BaseAlloc,EAX
	INVOKE ReadProcessMemory,hProcess,dwAddressToScan,BaseAlloc,100,addr NumOfBytesRW
	MOV ESI,BaseAlloc
	MOV EAX,DWORD PTR[ESI+34h]
	MOV Return,EAX

	INVOKE VirtualFree,BaseAlloc,1000h,MEM_DECOMMIT
	INVOKE VirtualFree,BaseAlloc,NULL,MEM_RELEASE

	POPAD
	MOV EAX,Return
	RET
TracerFix_AlexProtector endp
;------------------------------------------------------------------
TracerDetectRedirection proc hProcess:DWORD,dwAddressToScan:DWORD
	LOCAL Return :DWORD
	LOCAL BaseAlloc :DWORD
	LOCAL DoHashCheck :DWORD
	PUSHAD

	MOV DoHashCheck,0
	INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
	MOV BaseAlloc,EAX
	INVOKE VirtualQueryEx,hProcess,dwAddressToScan,addr MemInfo,sizeof MemInfo
	MOV EAX,MemInfo.BaseAddress
	ADD EAX,MemInfo.RegionSize
	SUB EAX,dwAddressToScan
	.if EAX < 256
		MOV EBX,EAX
		INVOKE ReadProcessMemory,hProcess,dwAddressToScan,BaseAlloc,EBX,addr NumOfBytesRW
	.else
		INC DoHashCheck
		INVOKE ReadProcessMemory,hProcess,dwAddressToScan,BaseAlloc,256,addr NumOfBytesRW
	.endif

	XOR EAX,EAX
	MOV ESI,BaseAlloc
	.if WORD PTR[ESI] == 001EBh && ((BYTE PTR[ESI+3] >= 50h && BYTE PTR[ESI+3] <= 5Fh) || BYTE PTR[ESI+3] == 6Ah || BYTE PTR[ESI+3] == 68h)
		XOR EAX,EAX	; PeX 0.99 fail safe!
	.elseif BYTE PTR[ESI] == 068h && BYTE PTR[ESI+5] == 081h && BYTE PTR[ESI+0Ch] == 0C3h
		MOV EAX,1	; RLP 0.7.4 & CryptoPeProtector 0.9.x & ACProtect
				;$ ==>    >  68 904B4013     PUSH 13404B90
				;$+5      >  812C24 0A9E589B SUB DWORD PTR SS:[ESP],9B589E0A
				;$+C      >  C3              RET
				;$+D      >  68 E21554DF     PUSH DF5415E2
				;$+12     >  813424 B6DCB2A8 XOR DWORD PTR SS:[ESP],A8B2DCB6
				;$+19     >  C3              RET
				;$+1A     >  68 34B2C6B1     PUSH B1C6B234
				;$+1F     >  810424 4A2C21C6 ADD DWORD PTR SS:[ESP],C6212C4A
				;$+26     >  C3              RET
	.elseif WORD PTR[ESI] == 025FFh
		MOV EAX,2	; tELock 0.80 - 0.85
				;$ ==>    >- FF25 48018E00   JMP NEAR DWORD PTR DS:[8E0148]
	.elseif (WORD PTR[ESI] == 035FFh || WORD PTR[ESI+1] == 035FFh) && (BYTE PTR[ESI+09h] == 0C3h || BYTE PTR[ESI+08h] == 0C3h)
		MOV EAX,3	; tELock 0.90 - 0.95
				;$ ==>    >  FF35 AE018E00   PUSH DWORD PTR DS:[8E01AE]               ; kernel32.InitializeCriticalSection
				;$+6      >  A8 C3           TEST AL,0C3
				;$+8      >  C3              RET
				;$+9      >  F9              STC
				;$+A      >  FF35 B2018E00   PUSH DWORD PTR DS:[8E01B2]               ; kernel32.VirtualFree
				;$+10     >  80FA C3         CMP DL,0C3
				;$+13     >  C3              RET
	.elseif (DWORD PTR[ESI] == 060C901EBh && WORD PTR[ESI+4] == 0310Fh)
		MOV EAX,8	; AlexProtector 1.x
				;$ ==>    > /EB 01           JMP SHORT 008413F9
				;$+2      > |C9              LEAVE
				;$+3      > \60              PUSHAD
				;$+4      >  0F31            RDTSC
				;$+6      >  EB 01           JMP SHORT 008413FF
				;$+8      >  C9              LEAVE
				;$+9      >  8BD8            MOV EBX,EAX
				;$+B      >  EB 01           JMP SHORT 00841404
				;...
				;$+33     >  68 E9B9D477     PUSH USER32.PostQuitMessage
				;$+38     >  EB 01           JMP SHORT 00841431
				;$+3A     >- E9 C3EB01E9     JMP E985FFF8
	.elseif (WORD PTR[ESI] == 0C50Bh) || (BYTE PTR[ESI] == 05h && BYTE PTR[ESI+5] == 0B8h && WORD PTR[ESI+0Ah] == 002EBh) || (WORD PTR[ESI] == 0C413h && BYTE PTR[ESI+2] == 0E8h) || (BYTE PTR[ESI] == 083h && BYTE PTR[ESI+3] == 0E8h)
		MOV EAX,5	; tELock 0.99 - 1.0 Private!
				;008E0122    05 F9DEBE71     ADD EAX,71BEDEF9
				;008E0127    B8 28018E00     MOV EAX,8E0128
				;008E012C    EB 02           JMP SHORT 008E0130
				;008E012E    CD 20           INT 20
				;008E0130    05 18000000     ADD EAX,18
				;008E0135    8B00            MOV EAX,DWORD PTR DS:[EAX]
				;008E0137    35 22018E00     XOR EAX,8E0122
				;008E013C    90              NOP
				;008E013D    90              NOP
				;008E013E    50              PUSH EAX
				;008E013F    C3              RET
				;
				;00850036    13C4            ADC EAX,ESP
				;00850038    E8 0A000000     CALL 00850047
				;0085003D    90              NOP
				;0085003E    1BC2            SBB EAX,EDX
				;00850040    E9 09000000     JMP 0085004E
				;00850045    1BC3            SBB EAX,EBX
				;00850047    83F8 74         CMP EAX,74
				;0085004A    C3              RET
				;0085004B    98              CWDE
				;0085004C    33C7            XOR EAX,EDI
				;0085004E    D6              SALC
				;0085004F    B8 50008500     MOV EAX,850050
				;00850054    EB 02           JMP SHORT 00850058
				;00850056    CD 20           INT 20
				;00850058    05 18000000     ADD EAX,18
				;0085005D    8B00            MOV EAX,DWORD PTR DS:[EAX]
				;0085005F    35 36008500     XOR EAX,850036
				;00850064    90              NOP
				;00850065    90              NOP
				;00850066    50              PUSH EAX
				;00850067    C3              RET
				;
	.elseif ((BYTE PTR[ESI] == 0B8h || BYTE PTR[ESI] == 01Dh || BYTE PTR[ESI] == 00Dh || BYTE PTR[ESI] == 02Dh) && BYTE PTR[ESI+5] == 0B8h && WORD PTR[ESI+10] == 002EBh) || DWORD PTR[ESI] == 0E8F9C40Bh || WORD PTR[ESI] == 0E848h
		MOV EAX,5	; tELock 0.99 - 1.0 Private!
				;011F0000    B8 2107F205     MOV EAX,5F20721
				;011F0005    B8 06008D00     MOV EAX,8D0006
				;011F000A    EB 02           JMP SHORT 011F000E
				;011F000C    CD 20           INT 20
				;011F000E    05 18000000     ADD EAX,18
				;011F0013    8B00            MOV EAX,DWORD PTR DS:[EAX]
				;011F0015    35 00008D00     XOR EAX,8D0000
				;011F001A    90              NOP
				;011F001B    90              NOP
				;011F001C    50              PUSH EAX
				;011F001D    C3              RET
				;
				;01360000    1D A508F205     SBB EAX,5F208A5
				;01360005    B8 28008D00     MOV EAX,8D0028
				;0136000A    EB 02           JMP SHORT 0136000E
				;0136000C    CD 20           INT 20
				;0136000E    05 18000000     ADD EAX,18
				;01360013    8B00            MOV EAX,DWORD PTR DS:[EAX]
				;01360015    35 22008D00     XOR EAX,8D0022
				;0136001A    90              NOP
				;0136001B    90              NOP
				;0136001C    50              PUSH EAX
				;0136001D    C3              RET
				;
				;014B0000    0D F918F205     OR EAX,5F218F9
				;014B0005    B8 4A008D00     MOV EAX,8D004A
				;014B000A    EB 02           JMP SHORT 014B000E
				;014B000C    CD 20           INT 20
				;014B000E    05 18000000     ADD EAX,18
				;014B0013    8B00            MOV EAX,DWORD PTR DS:[EAX]
				;014B0015    35 44008D00     XOR EAX,8D0044
				;014B001A    90              NOP
				;014B001B    90              NOP
				;014B001C    50              PUSH EAX
				;014B001D    C3              RET
				;
				;01750000    2D 0B37F205     SUB EAX,5F2370B
				;01750005    B8 8E008D00     MOV EAX,8D008E
				;0175000A    EB 02           JMP SHORT 0175000E
				;0175000C    CD 20           INT 20
				;0175000E    05 18000000     ADD EAX,18
				;01750013    8B00            MOV EAX,DWORD PTR DS:[EAX]
				;01750015    35 88008D00     XOR EAX,8D0088
				;0175001A    90              NOP
				;0175001B    90              NOP
				;0175001C    50              PUSH EAX
				;0175001D    C3              RET
				;
				;019F0000    0BC4            OR EAX,ESP
				;019F0002    F9              STC
				;019F0003    E8 0B000000     CALL 019F0013
				;019F0008    90              NOP
				;019F0009    13C4            ADC EAX,ESP
				;019F000B    E9 0A000000     JMP 019F001A
				;019F0010    F9              STC
				;019F0011    13C3            ADC EAX,EBX
				;019F0013    98              CWDE
				;019F0014    03C2            ADD EAX,EDX
				;019F0016    C3              RET
				;
				;01B40000    48              DEC EAX
				;01B40001    E8 0D000000     CALL 01B40013
				;01B40006    03C5            ADD EAX,EBP
				;01B40008    FC              CLD
				;01B40009    E9 0A000000     JMP 01B40018
				;01B4000E    35 D82FF205     XOR EAX,5F22FD8
				;01B40013    C1C8 9A         ROR EAX,9A
				;01B40016    C3              RET
				;
	.elseif (BYTE PTR[ESI] == 0B8h && BYTE PTR[ESI+5] == 0E8h && WORD PTR[ESI+10] == 0E9F9h) || (DWORD PTR[ESI] == 008E8C21Bh && DWORD PTR[ESI+7] == 00009E940h) || (WORD PTR[ESI] == 00BE8h && WORD PTR[ESI+10] == 005E9h && WORD PTR[ESI+15] == 0C390h)
		MOV EAX,5	; tELock 0.99 - 1.0 Private!
				;01C90000    B8 B853F205     MOV EAX,5F253B8
				;01C90005    E8 07000000     CALL 01C90011
				;01C9000A    F9              STC
				;01C9000B    E9 07000000     JMP 01C90017
				;01C90010    90              NOP
				;01C90011    23C3            AND EAX,EBX
				;01C90013    C3              RET
				;
				;00A40022    1BC2            SBB EAX,EDX
				;00A40024    E8 08000000     CALL 00A40031
				;00A40029    40              INC EAX
				;00A4002A    E9 09000000     JMP 00A40038
				;00A4002F    33C7            XOR EAX,EDI
				;00A40031    C1E8 92         SHR EAX,92
				;00A40034    C3              RET
				;00A40035    83E0 25         AND EAX,25
				;00A40038    25 E5AE65DD     AND EAX,DD65AEE5
				;00A4003D    B8 3E00A400     MOV EAX,0A4003E
				;00A40042    EB 02           JMP SHORT 00A40046
				;00A40044    CD 20           INT 20
				;00A40046    05 18000000     ADD EAX,18
				;00A4004B    8B00            MOV EAX,DWORD PTR DS:[EAX]
				;00A4004D    35 2200A400     XOR EAX,0A40022
				;00A40052    90              NOP
				;00A40053    90              NOP
				;00A40054    50              PUSH EAX
				;00A40055    C3              RET
				;
				;00A4005A    E8 0B000000     CALL 00A4006A
				;00A4005F    15 06F265DD     ADC EAX,DD65F206
				;00A40064    E9 05000000     JMP 00A4006E
				;00A40069    90              NOP
				;00A4006A    C3              RET
				;00A4006B    1BC5            SBB EAX,EBP
				;00A4006D    40              INC EAX
				;00A4006E    1BC0            SBB EAX,EAX
				;00A40070    F9              STC
				;00A40071    B8 7200A400     MOV EAX,0A40072
				;00A40076    EB 02           JMP SHORT 00A4007A
				;00A40078    CD 20           INT 20
				;00A4007A    05 18000000     ADD EAX,18
				;00A4007F    8B00            MOV EAX,DWORD PTR DS:[EAX]
				;00A40081    35 5A00A400     XOR EAX,0A4005A
				;00A40086    90              NOP
				;00A40087    90              NOP
				;00A40088    50              PUSH EAX
				;00A40089    C3              RET
				;
	.elseif BYTE PTR[ESI] == 068h && BYTE PTR[ESI+5] == 0E9h
		MOV ECX,DWORD PTR[ESI+1]
		.if ECX > dwAddressToScan
			MOV EAX,6	; ReCrypt 0.74
					;001739F1    68 E9D9D477     PUSH User32.EndDialog
					;001739F6  ^ E9 FDFEFFFF     JMP 001738F8
		.endif
	.elseif (BYTE PTR[ESI] == 0E8h && BYTE PTR[ESI+5] == 058h && WORD PTR[ESI+6] == 01EBh) || (BYTE PTR[ESI] == 0C8h && BYTE PTR[ESI+4] == 0E8h && BYTE PTR[ESI+9] == 05Bh)
		MOV EAX,7	; Orien 2.1x
				;GetCommandLineA
				;$ ==>    >/$  E8 00000000     CALL crackme_.0040DF8F
				;$+5      >|$  58              POP EAX
				;$+6      >|.  EB 01           JMP SHORT crackme_.0040DF93
				;$+8      >|   B8              DB B8
				;$+9      >|>  85DB            TEST EBX,EBX
				;$+B      >|.  2D 8F1F0000     SUB EAX,1F8F
				;$+10     >|.  EB 01           JMP SHORT crackme_.0040DF9D
				;$+12     >|   A8              DB A8
				;$+13     >|>  8D80 F0550000   LEA EAX,DWORD PTR DS:[EAX+55F0]
				;$+19     >\.  C3              RET
				;GetCommandLineW
				;$ ==>    > .  E8 00000000     CALL crackme_.0040DFA9
				;$+5      >/$  58              POP EAX
				;$+6      >|.  EB 01           JMP SHORT crackme_.0040DFAD
				;$+8      >|   B8              DB B8
				;$+9      >|>  85DB            TEST EBX,EBX
				;$+B      >|.  2D A91F0000     SUB EAX,1FA9
				;$+10     >|.  EB 01           JMP SHORT crackme_.0040DFB7
				;$+12     >|   A8              DB A8
				;$+13     >|>  8D80 F4560000   LEA EAX,DWORD PTR DS:[EAX+56F4]
				;$+19     >\.  C3              RET
				;ExitProcess
				;$ ==>    > $  C8 000000       ENTER 0,0
				;$+4      > .  E8 00000000     CALL crackme_.0040DF2A
				;$+9      > $  5B              POP EBX
				;$+A      > .  EB 01           JMP SHORT crackme_.0040DF2E
				;$+C      >    B8              DB B8
				;$+D      > >  85DB            TEST EBX,EBX
				;$+F      > .  81EB 2A1F0000   SUB EBX,1F2A
				;$+15     > .  EB 01           JMP SHORT crackme_.0040DF39
				;$+17     >    A8              DB A8
				;$+18     > >  8D83 4D310000   LEA EAX,DWORD PTR DS:[EBX+314D]
				;$+1E     > .  8038 00         CMP BYTE PTR DS:[EAX],0
				;$+21     > .  74 29           JE SHORT crackme_.0040DF6D
				;$+23     > .  EB 01           JMP SHORT crackme_.0040DF47
				;$+25     >    A8              DB A8
				;$+26     > >  8D93 55380000   LEA EDX,DWORD PTR DS:[EBX+3855]
				;$+2C     > .  E8 01000000     CALL crackme_.0040DF53
				;$+31     >    E9              DB E9
				;$+32     > $  83EC FC         SUB ESP,-4
				;$+35     > .  6A 00           PUSH 0
				;$+37     > .  52              PUSH EDX
				;$+38     > .  50              PUSH EAX
				;$+39     > .  6A 00           PUSH 0
				;$+3B     > .  E8 05000000     CALL crackme_.0040DF66
				;$+40     > .  EB 0A           JMP SHORT crackme_.0040DF6D
				;$+42     >    88              DB 88
				;$+43     >    FC              DB FC
				;$+44     >    B6              DB B6
				;$+45     > $  FFA3 FF3A0000   JMP NEAR DWORD PTR DS:[EBX+3AFF]
				;$+4B     >    CD              DB CD
				;$+4C     > >  E8 01000000     CALL crackme_.0040DF73
				;$+51     >    E9              DB E9
				;$+52     > $  83EC FC         SUB ESP,-4
				;$+55     > .  FF75 08         PUSH DWORD PTR SS:[EBP+8]
				;$+58     > .  E8 05000000     CALL crackme_.0040DF83
				;$+5D     > .  EB 0A           JMP SHORT crackme_.0040DF8A
				;$+5F     >    88              DB 88
				;$+60     >    FC              DB FC
				;$+61     >    B6              DB B6
				;$+62     > $  FFA3 BF3A0000   JMP NEAR DWORD PTR DS:[EBX+3ABF]
	.elseif DoHashCheck == 1
		.if BYTE PTR[ESI] == 09Ch || BYTE PTR[ESI] == 0EBh
			INVOKE ZombieHashMemory,BaseAlloc,192
			.if EAX == 05AF7E209h
				MOV EAX,9
			.elseif EAX == 0EB480CACh
				MOV EAX,9
			.elseif EAX == 086218561h
				MOV EAX,9
			.elseif EAX == 0CA9ABD85h
				MOV EAX,9
			.elseif EAX == 0F1F84A98h
				MOV EAX,9
			.elseif EAX == 091823290h
				MOV EAX,9
			.elseif EAX == 0BEE6BAA0h
				MOV EAX,9
			.elseif EAX == 079603232h
				MOV EAX,9
			.else
				XOR EAX,EAX
			.endif
		.endif
	.elseif (DWORD PTR[ESI] == 1B6601EBh || DWORD PTR[ESI] == 20CD02EBh || DWORD PTR[ESI] == 0EBB801EBh || DWORD PTR[ESI] == 0EBFF03EBh || DWORD PTR[ESI] == 05B801EBh || DWORD PTR[ESI] == 20FF02EBh) || (BYTE PTR[ESI] == 0F9h || BYTE PTR[ESI] == 0F8h || BYTE PTR[ESI] == 0EBh || WORD PTR[ESI] == 0E40Bh || WORD PTR[ESI] == 0E485h)
		MOV EAX,4	; tELock 0.96 - 0.98
				;(BYTE PTR[ESI] == 0EBh && (BYTE PTR[ESI+3] == 0EBh || BYTE PTR[ESI+2] == 0EBh))
				;017B0000    0BE4            OR ESP,ESP
				;017B0002    75 01           JNZ SHORT 017B0005
				;
				;15940000    85E4            TEST ESP,ESP
				;15940002    79 03           JNS SHORT 15940007
				;
				;008E0359    B8 8DE44500     MOV EAX,45E48D
				;008E035E    90              NOP
				;008E035F    FF30            PUSH DWORD PTR DS:[EAX]
				;008E0361    C3              RET
				;
				;008F0033    B8 AF008F00     MOV EAX,8F00AF
				;008F0038    40              INC EAX
				;008F0039    FF30            PUSH DWORD PTR DS:[EAX]
				;008F003B    C3              RET
				;
				;008E02F7    B8 20078E00     MOV EAX,8E0720
				;008E02FC    FF20            JMP NEAR DWORD PTR DS:[EAX]
	.endif
	MOV Return,EAX
	
	INVOKE VirtualFree,BaseAlloc,1000h,MEM_DECOMMIT
	INVOKE VirtualFree,BaseAlloc,NULL,MEM_RELEASE

	POPAD
	MOV EAX,Return
	RET
TracerDetectRedirection endp
;------------------------------------------------------------------
TracerFixKnownRedirection proc dwRedirectionId:DWORD,hProcess:DWORD,dwAddressToScan:DWORD
	LOCAL Return :DWORD
	LOCAL BaseAlloc :DWORD
	LOCAL DoHashCheck :DWORD
	PUSHAD
	MOV Return,0
	MOV EAX,dwRedirectionId
	MOV EDX,dwAddressToScan
	.if EAX == 1
		PUSH EDX
		PUSH hProcess
		CALL TracerFix_ACProtect
		MOV Return,EAX
	.elseif EAX == 2
		PUSH EDX
		PUSH hProcess
		CALL TracerFix_tELock_varA
		MOV Return,EAX
	.elseif EAX == 3
		PUSH EDX
		PUSH hProcess
		CALL TracerFix_tELock_varB
		MOV Return,EAX
	.elseif EAX == 4
		PUSH EDX
		PUSH hProcess
		CALL TracerFix_tELock_varC
		MOV Return,EAX
	.elseif EAX == 5
		PUSH EDX
		PUSH hProcess
		CALL TracerFix_tELock_varD
		MOV Return,EAX
	.elseif EAX == 6
		PUSH EDX
		PUSH hProcess
		CALL TracerFix_ReCrypt
		MOV Return,EAX
	.elseif EAX == 7
		PUSH EDX
		PUSH hProcess
		CALL TracerFix_Orien
		MOV Return,EAX
	.elseif EAX == 8
		PUSH EDX
		PUSH hProcess
		CALL TracerFix_AlexProtector
		MOV Return,EAX
	.elseif EAX == 9
		MOV DoHashCheck,0
		INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
		MOV BaseAlloc,EAX
		INVOKE VirtualQueryEx,hProcess,dwAddressToScan,addr MemInfo,sizeof MemInfo
		MOV EAX,MemInfo.BaseAddress
		ADD EAX,MemInfo.RegionSize
		SUB EAX,dwAddressToScan
		.if EAX < 256
			MOV EBX,EAX
			INVOKE ReadProcessMemory,hProcess,dwAddressToScan,BaseAlloc,EBX,addr NumOfBytesRW
		.else
			INC DoHashCheck
			INVOKE ReadProcessMemory,hProcess,dwAddressToScan,BaseAlloc,256,addr NumOfBytesRW
		.endif

		.if DoHashCheck == 1
			INVOKE ZombieHashMemory,BaseAlloc,192
			.if EAX == 05AF7E209h		;GetCommandLineA
				INVOKE GetModuleHandle,addr szKERNEL32
				MOV EBX,EAX
				INVOKE GetProcAddress,EBX,addr szGetCommandLineA
				
				PUSH EAX
				PUSH hProcess
				CALL DWORD PTR[cImporterGetRemoteAPIAddress]
			.elseif EAX == 0EB480CACh	;ExitProcess
				INVOKE GetModuleHandle,addr szKERNEL32
				MOV EBX,EAX
				INVOKE GetProcAddress,EBX,addr szExitProcess
				
				PUSH EAX
				PUSH hProcess
				CALL DWORD PTR[cImporterGetRemoteAPIAddress]
			.elseif EAX == 086218561h	;GetCurrentProcess
				INVOKE GetModuleHandle,addr szKERNEL32
				MOV EBX,EAX
				INVOKE GetProcAddress,EBX,addr szGetCurrentProcess
				
				PUSH EAX
				PUSH hProcess
				CALL DWORD PTR[cImporterGetRemoteAPIAddress]
			.elseif EAX == 0CA9ABD85h	;GetVersion
				INVOKE GetModuleHandle,addr szKERNEL32
				MOV EBX,EAX
				INVOKE GetProcAddress,EBX,addr szGetVersion
				
				PUSH EAX
				PUSH hProcess
				CALL DWORD PTR[cImporterGetRemoteAPIAddress]
			.elseif EAX == 0F1F84A98h	;GetVersionExA
				INVOKE GetModuleHandle,addr szKERNEL32
				MOV EBX,EAX
				INVOKE GetProcAddress,EBX,addr szGetVersionExA
				
				PUSH EAX
				PUSH hProcess
				CALL DWORD PTR[cImporterGetRemoteAPIAddress]
			.elseif EAX == 091823290h	;GetModuleHandleA
				INVOKE GetModuleHandle,addr szKERNEL32
				MOV EBX,EAX
				INVOKE GetProcAddress,EBX,addr szGetModuleHandleA
				
				PUSH EAX
				PUSH hProcess
				CALL DWORD PTR[cImporterGetRemoteAPIAddress]
			.elseif EAX == 0BEE6BAA0h	;MessageBoxA
				INVOKE GetModuleHandle,addr szUSER32
				MOV EBX,EAX
				INVOKE GetProcAddress,EBX,addr szMessageBoxA
				
				PUSH EAX
				PUSH hProcess
				CALL DWORD PTR[cImporterGetRemoteAPIAddress]
			.elseif EAX == 079603232h	;GetModuleHandleA
				INVOKE GetModuleHandle,addr szKERNEL32
				MOV EBX,EAX
				INVOKE GetProcAddress,EBX,addr szGetModuleHandleA
				
				PUSH EAX
				PUSH hProcess
				CALL DWORD PTR[cImporterGetRemoteAPIAddress]
			.else
				XOR EAX,EAX
			.endif
		.else
			XOR EAX,EAX
		.endif
		MOV Return,EAX

		INVOKE VirtualFree,BaseAlloc,1000h,MEM_DECOMMIT
		INVOKE VirtualFree,BaseAlloc,NULL,MEM_RELEASE
	.endif
	POPAD
	MOV EAX,Return
	RET
TracerFixKnownRedirection endp
;------------------------------------------------------------------
TracerInit proc
	LOCAL Return:DWORD

	PUSHAD
	MOV Return,0
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
		INVOKE GetProcAddress,DWORD PTR[hImporter],addr szImporterGetDLLIndexEx
		MOV DWORD PTR[cImporterGetDLLIndexEx],EAX
		INVOKE GetProcAddress,DWORD PTR[hImporter],addr szImporterGetAPINameEx
		MOV DWORD PTR[cImporterGetAPINameEx],EAX
		INVOKE GetProcAddress,DWORD PTR[hImporter],addr szImporterSetAutoFixOptions
		MOV DWORD PTR[cImporterSetAutoFixOptions],EAX
		INVOKE GetProcAddress,DWORD PTR[hImporter],addr szImporterGetAPINameFromDebugee
		MOV DWORD PTR[cImporterGetAPINameFromDebugee],EAX
		INVOKE GetProcAddress,DWORD PTR[hImporter],addr szImporterFindAPIWriteLocation
		MOV DWORD PTR[cImporterFindAPIWriteLocation],EAX
		INVOKE GetProcAddress,DWORD PTR[hImporter],addr szImporterGetRemoteAPIAddress
		MOV DWORD PTR[cImporterGetRemoteAPIAddress],EAX
		MOV Return,1
	.endif
	INVOKE LoadLibrary,addr szDumper
	MOV DWORD PTR[hDumper],EAX
	.if DWORD PTR[hDumper] != 0
		INVOKE GetProcAddress,DWORD PTR[hDumper],addr szGetPE32Data
		MOV DWORD PTR[cGetPE32Data],EAX
		INVOKE GetProcAddress,DWORD PTR[hDumper],addr szAddNewSection
		MOV DWORD PTR[cAddNewSection],EAX
		INVOKE GetProcAddress,DWORD PTR[hDumper],addr szDumpProcess
		MOV DWORD PTR[cDumpProcess],EAX
		MOV Return,1
	.endif
	POPAD
	MOV EAX,Return
	RET
TracerInit endp
;------------------------------------------------------------------
TracerLevel1 proc hProcess:DWORD,dwAddressToTrace:DWORD
	LOCAL Return:DWORD
	LOCAL BaseAlloc:DWORD
	LOCAL StartAddress:DWORD
	LOCAL NumberOfInstructions :DWORD
	LOCAL CurrentNumberOfInstructions :DWORD
	LOCAL dwTestData :DWORD
	LOCAL dwLastPush :DWORD

	PUSHAD

	MOV NumberOfInstructions,0
	MOV CurrentNumberOfInstructions,0
	MOV dwLastPush,0
	INVOKE VirtualQueryEx,hProcess,dwAddressToTrace,addr MemStatus,sizeof MemStatus
	MOV EAX,DWORD PTR[MemStatus.RegionSize]
	.if EAX > 0
		INVOKE VirtualAlloc,NULL,EAX,MEM_COMMIT,PAGE_READWRITE
		MOV BaseAlloc,EAX
		INVOKE ReadProcessMemory,hProcess,DWORD PTR[MemStatus.BaseAddress],BaseAlloc,DWORD PTR[MemStatus.RegionSize],addr NumOfBytesRW
		.if EAX == 1
			MOV EDX,dwAddressToTrace
			SUB EDX,DWORD PTR[MemStatus.BaseAddress]
			ADD EDX,BaseAlloc
			MOV StartAddress,EDX
			XOR ESI,ESI
;
; Traceing starts here!!!
;
			.while CurrentNumberOfInstructions < 1000
				XOR EDI,EDI

				PUSH EDX
				CALL ldex86
			        INC CurrentNumberOfInstructions
				.if BYTE PTR[EDX] == 0E9h && EAX == 5					;Long jump
					MOV EDI,EDX
					ADD EDX,DWORD PTR[EDX+1]
					ADD EDX,EAX
					SUB EDX,BaseAlloc
					ADD EDX,DWORD PTR[MemStatus.BaseAddress]
					MOV ECX,DWORD PTR[MemStatus.BaseAddress]
					ADD ECX,DWORD PTR[MemStatus.RegionSize]
					.if EDX >= DWORD PTR[MemStatus.BaseAddress] && EDX <= ECX
						SUB EDX,DWORD PTR[MemStatus.BaseAddress]
						ADD EDX,BaseAlloc
					.else
						.if ESI == 0
							SUB EDX,ESI
							MOV EAX,EDX
							.break
						.endif
						MOV EBX,EAX
						PUSH EDX
						PUSH hProcess
						CALL DWORD PTR[cImporterGetAPINameFromDebugee]
						.if EAX == NULL
							SUB EDX,ESI
							PUSH EDX
							PUSH hProcess
							CALL DWORD PTR[cImporterGetAPINameFromDebugee]
							.if EAX == NULL
								MOV EAX,EBX
								MOV EDX,EDI
								XOR EDI,EDI
							.else
								MOV EAX,EDX
								.break
							.endif
						.else
							MOV EAX,EBX
							MOV EDX,EDI
							XOR EDI,EDI
						.endif
					.endif
				.elseif WORD PTR[EDX] == 025FFh && EAX == 6				;Near jump
					MOV dwTestData,NULL
					MOV EDI,EDX
					MOV EDX,DWORD PTR[EDX+2]
					PUSHAD
					INVOKE ReadProcessMemory,hProcess,EDX,addr dwTestData,4,addr NumOfBytesRW
					POPAD
					.if NumOfBytesRW == 4 && dwTestData != NULL
						MOV EDX,dwTestData
						MOV ECX,DWORD PTR[MemStatus.BaseAddress]
						ADD ECX,DWORD PTR[MemStatus.RegionSize]
						.if EDX >= DWORD PTR[MemStatus.BaseAddress] && EDX <= ECX
							SUB EDX,DWORD PTR[MemStatus.BaseAddress]
							ADD EDX,BaseAlloc
						.else
							.if ESI == 0
								SUB EDX,ESI
								MOV EAX,EDX
								.break
							.endif
							MOV EBX,EAX
							PUSH EDX
							PUSH hProcess
							CALL DWORD PTR[cImporterGetAPINameFromDebugee]
							.if EAX == NULL
								SUB EDX,ESI
								PUSH EDX
								PUSH hProcess
								CALL DWORD PTR[cImporterGetAPINameFromDebugee]
								.if EAX == NULL
									MOV EAX,EBX
									MOV EDX,EDI
									XOR EDI,EDI
								.else
									MOV EAX,EDX
									.break
								.endif
							.else
								MOV EAX,EBX
								MOV EDX,EDI
								XOR EDI,EDI
							.endif
						.endif
					.else
						MOV EDX,EDI
						XOR EDI,EDI
					.endif
				.elseif BYTE PTR[EDX] == 068h && BYTE PTR[EDX+5] == 0C3h && EAX == 5	;PUSH then RET
					MOV EAX,DWORD PTR[EDX+1]
					MOV ECX,DWORD PTR[MemStatus.BaseAddress]
					ADD ECX,DWORD PTR[MemStatus.RegionSize]
					.if EAX >= DWORD PTR[MemStatus.BaseAddress] && EAX <= ECX
						PUSH EDX
						MOV EDX,EAX
						SUB EDX,DWORD PTR[MemStatus.BaseAddress]
						ADD EDX,BaseAlloc
						PUSHAD
						INVOKE IsBadReadPtr,EDX,4
						.if EAX == 0
							MOV DWORD PTR[ESP+1Ch],0
						.else
							MOV DWORD PTR[ESP+1Ch],-1
						.endif
						POPAD
						.if EAX == -1
							POP EDX
							MOV EAX,5
						.else
							ADD ESP,4
							MOV EAX,1
						.endif
					.else
						SUB EAX,ESI
						.break
					.endif
				.elseif BYTE PTR[EDX] == 068h && EAX == 5				;PUSH
					PUSH EAX
					MOV EAX,DWORD PTR[EDX+1]
					MOV dwLastPush,EAX
					POP EAX
				.elseif WORD PTR[EDX] == 000h && EAX == 2				;End of page
					XOR EAX,EAX
					.break
				.elseif BYTE PTR[EDX] == 0C3h && EAX == 1				;Ret
					INC NumberOfInstructions
					MOV EAX,NumberOfInstructions 					;Suggest level2
					.break
				.elseif BYTE PTR[EDX] == 0C2h && EAX == 3				;Ret 0Ch, etc.
					INC NumberOfInstructions
					MOV EAX,NumberOfInstructions 					;Suggest level2
					.break
				.elseif BYTE PTR[EDX] == 0EBh && EAX == 2				;Short jump
					PUSH EAX
					MOVZX EAX,BYTE PTR[EDX+1]
					ADD EDX,EAX
					MOV EDI,1
					POP EAX
				.elseif BYTE PTR[EDX] == 0F8h && EAX == 1				;CLC
					MOV EDI,1
				.elseif BYTE PTR[EDX] == 0F9h && EAX == 1				;STC
					MOV EDI,1
				.elseif BYTE PTR[EDX] == 090h && EAX == 1				;NOP
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0D0D9h && EAX == 2				;FNOP
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0C88Bh && EAX == 2				;MOV EAX,EAX
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0C98Bh && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0DB8Bh && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0D28Bh && EAX == 2 && EDX != StartAddress	;MOV EDX,EDX
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0ED8Bh && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0F68Bh && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0E48Bh && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0FF8Bh && EAX == 2 && EDX != StartAddress	;MOV EDI,EDI
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0C08Ah && EAX == 2				;MOV AL,AL
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0DB8Ah && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0C98Ah && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0D28Ah && EAX == 2				;MOV DL,CL
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0E48Ah && EAX == 2				;MOV AH,AH
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0ED8Ah && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0FF8Ah && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0F68Ah && EAX == 2				;MOV DH,CH
					MOV EDI,1
				.elseif WORD PTR[EDX+1] == 0C08Bh && EAX == 3				;MOV AX,AX
					MOV EDI,1
				.elseif WORD PTR[EDX+1] == 0DB8Bh && EAX == 3
					MOV EDI,1
				.elseif WORD PTR[EDX+1] == 0C98Bh && EAX == 3
					MOV EDI,1
				.elseif WORD PTR[EDX+1] == 0D28Bh && EAX == 3				;MOV DX,DX
					MOV EDI,1
				.elseif WORD PTR[EDX+1] == 0FF8Bh && EAX == 3				;MOV SI,SI
					MOV EDI,1
				.elseif WORD PTR[EDX+1] == 0F68Bh && EAX == 3
					MOV EDI,1
				.elseif WORD PTR[EDX+1] == 0ED8Bh && EAX == 3				;MOV BP,BP
					MOV EDI,1
				.elseif BYTE PTR[EDX] == 0C1h && EAX == 3				;SHL EAX,0 - SHL EDI,0
					.if BYTE PTR[EDX+1] >= 0E0h && BYTE PTR[EDX+1] <= 0EFh		;SHR EAX,0 - SHR EDI,0
						.if BYTE PTR[EDX+2] == 0
							MOV EDI,1
						.endif
					.endif
				.elseif BYTE PTR[EDX] == 08Dh && EAX == 2				;LEA EAX,DWORD PTR[EAX]
					.if BYTE PTR[EDX+1] == 0h || BYTE PTR[EDX+1] == 09h || BYTE PTR[EDX+1] == 1Bh || BYTE PTR[EDX+1] == 12h
						MOV EDI,1
					.endif
					.if BYTE PTR[EDX+1] == 36h || BYTE PTR[EDX+1] == 3Fh
						MOV EDI,1
					.endif
					.if BYTE PTR[EDX+1] == 6Dh && BYTE PTR[EDX+2] == 00h
						MOV EDI,1
					.endif								;LEA EDI,DWORD PTR[EDI]
				.elseif BYTE PTR[EDX] == 0C1h && EAX == 3				;ROR EAX,0 - ROR EDI,0
					.if BYTE PTR[EDX+1] >= 0C0h && BYTE PTR[EDX+1] <= 0CFh		;ROL EAX,0 - ROL EDI,0
						.if BYTE PTR[EDX+2] == 0
							MOV EDI,1
						.endif
					.endif
				.elseif WORD PTR[EDX] == 0310Fh && EAX == 2				;RDTSC
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0A20Fh && EAX == 2				;CPUID
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0C087h && EAX == 2				;XCHG EAX,EAX
					MOV EDI,1
				.endif

				.if EDI == 0
					ADD ESI,EAX
					INC NumberOfInstructions
				.endif

				ADD EDX,EAX
			.endw
			.if EAX < 1000h && dwLastPush != 0
				.if CurrentNumberOfInstructions < 1000
					PUSHAD
					MOV EAX,dwLastPush
					SUB EAX,ESI
					ADD EAX,5
					MOV EDI,EAX
					PUSH EDI
					PUSH hProcess
					CALL DWORD PTR[cImporterGetAPINameFromDebugee]
					.if EAX != NULL
						MOV DWORD PTR[ESP+1Ch],EDI
					.endif
					POPAD
				.endif
			.endif
		.endif
;
; Cleanup and end!
;
		MOV Return,EAX
		INVOKE VirtualFree,BaseAlloc,DWORD PTR[MemStatus.RegionSize],MEM_DECOMMIT
		INVOKE VirtualFree,BaseAlloc,NULL,MEM_RELEASE
	.endif

	POPAD
	MOV EAX,Return
	RET
TracerLevel1 endp
;------------------------------------------------------------------
HashTracerLevel1 proc dwProcess:DWORD,dwAPIAddress:DWORD,dwNumOfInstructions:DWORD
	LOCAL aDLLBases :DWORD
	LOCAL aMiscBuffer :DWORD
	LOCAL aDLLSortedBases :DWORD
	LOCAL dummy :DWORD
	LOCAL UsedLoadLibrary :DWORD
	LOCAL ReturnInfo :DWORD
	LOCAL BaseAlloc:DWORD
	LOCAL dwHash :DWORD
	LOCAL NumOfInstructions :DWORD
	LOCAL StartAddress :DWORD
	LOCAL dwCurrentLibrary :DWORD

	PUSHAD
	MOV EAX,dwNumOfInstructions
	MOV NumOfInstructions,EAX
	MOV ReturnInfo,0	;Critical error
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_READWRITE
       	MOV aDLLBases,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_READWRITE
       	MOV aDLLSortedBases,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_READWRITE
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

	INVOKE VirtualQueryEx,dwProcess,dwAPIAddress,addr MemStatus,sizeof MemStatus
	MOV EAX,DWORD PTR[MemStatus.RegionSize]
	.if EAX > 0
		MOV dwHash,0
		INVOKE VirtualAlloc,NULL,EAX,MEM_COMMIT,PAGE_READWRITE
		MOV BaseAlloc,EAX
		INVOKE ReadProcessMemory,dwProcess,DWORD PTR[MemStatus.BaseAddress],BaseAlloc,DWORD PTR[MemStatus.RegionSize],addr NumOfBytesRW
		.if EAX == 1
			MOV EDX,dwAPIAddress
			SUB EDX,DWORD PTR[MemStatus.BaseAddress]
			ADD EDX,BaseAlloc
			MOV StartAddress,EDX
			XOR ESI,ESI
;
; Traceing starts here!!!
;
			.while NumOfInstructions > 0
				XOR EDI,EDI

				PUSH EDX
				CALL ldex86

				.if BYTE PTR[EDX] == 0E8h && EAX == 5					;CALL
					MOV EDI,EDX
					ADD EDI,DWORD PTR[EDX+1]
					ADD EDI,EAX
					SUB EDI,BaseAlloc
					ADD EDI,DWORD PTR[MemStatus.BaseAddress]
					MOV DWORD PTR[EDX],EDI
					MOV BYTE PTR[EDX+4],0h
					XOR EDI,EDI
				.elseif BYTE PTR[EDX] == 0EBh && EAX == 2				;Short jump
					MOV EDI,1
				.elseif BYTE PTR[EDX] == 0F8h && EAX == 1				;CLC
					MOV EDI,1
				.elseif BYTE PTR[EDX] == 0F9h && EAX == 1				;STC
					MOV EDI,1
				.elseif BYTE PTR[EDX] == 090h && EAX == 1				;NOP
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0D0D9h && EAX == 2				;FNOP
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0C88Bh && EAX == 2				;MOV EAX,EAX
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0C98Bh && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0DB8Bh && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0D28Bh && EAX == 2 && EDX != StartAddress	;MOV EDX,EDX
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0ED8Bh && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0F68Bh && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0E48Bh && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0FF8Bh && EAX == 2 && EDX != StartAddress	;MOV EDI,EDI
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0C08Ah && EAX == 2				;MOV AL,AL
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0DB8Ah && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0C98Ah && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0D28Ah && EAX == 2				;MOV DL,CL
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0E48Ah && EAX == 2				;MOV AH,AH
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0ED8Ah && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0FF8Ah && EAX == 2
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0F68Ah && EAX == 2				;MOV DH,CH
					MOV EDI,1
				.elseif WORD PTR[EDX+1] == 0C08Bh && EAX == 3				;MOV AX,AX
					MOV EDI,1
				.elseif WORD PTR[EDX+1] == 0DB8Bh && EAX == 3
					MOV EDI,1
				.elseif WORD PTR[EDX+1] == 0C98Bh && EAX == 3
					MOV EDI,1
				.elseif WORD PTR[EDX+1] == 0D28Bh && EAX == 3				;MOV DX,DX
					MOV EDI,1
				.elseif WORD PTR[EDX+1] == 0FF8Bh && EAX == 3				;MOV SI,SI
					MOV EDI,1
				.elseif WORD PTR[EDX+1] == 0F68Bh && EAX == 3
					MOV EDI,1
				.elseif WORD PTR[EDX+1] == 0ED8Bh && EAX == 3				;MOV BP,BP
					MOV EDI,1
				.elseif BYTE PTR[EDX] == 0C1h && EAX == 3				;SHL EAX,0 - SHL EDI,0
					.if BYTE PTR[EDX+1] >= 0E0h && BYTE PTR[EDX+1] <= 0EFh		;SHR EAX,0 - SHR EDI,0
						.if BYTE PTR[EDX+2] == 0
							MOV EDI,1
						.endif
					.endif
				.elseif BYTE PTR[EDX] == 08Dh && EAX == 2				;LEA EAX,DWORD PTR[EAX]
					.if BYTE PTR[EDX+1] == 0h || BYTE PTR[EDX+1] == 09h || BYTE PTR[EDX+1] == 1Bh || BYTE PTR[EDX+1] == 12h
						MOV EDI,1
					.endif
					.if BYTE PTR[EDX+1] == 36h || BYTE PTR[EDX+1] == 3Fh
						MOV EDI,1
					.endif
					.if BYTE PTR[EDX+1] == 6Dh && BYTE PTR[EDX+2] == 00h
						MOV EDI,1
					.endif								;LEA EDI,DWORD PTR[EDI]
				.elseif BYTE PTR[EDX] == 0C1h && EAX == 3				;ROR EAX,0 - ROR EDI,0
					.if BYTE PTR[EDX+1] >= 0C0h && BYTE PTR[EDX+1] <= 0CFh		;ROL EAX,0 - ROL EDI,0
						.if BYTE PTR[EDX+2] == 0
							MOV EDI,1
						.endif
					.endif
				.elseif WORD PTR[EDX] == 0310Fh && EAX == 2				;RDTSC
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0A20Fh && EAX == 2				;CPUID
					MOV EDI,1
				.elseif WORD PTR[EDX] == 0C087h && EAX == 2				;XCHG EAX,EAX
					MOV EDI,1
				.endif

				.if EDI == 0
					ADD ESI,EAX
					PUSHAD
					MOV ECX,EAX
					XOR EAX,EAX
					MOV EBX,dwHash
					.while ECX > 0
						MOVZX EAX,BYTE PTR[EDX]
						ROL EBX,7
						XOR BL,AL
						INC EDX
						DEC ECX
					.endw
					MOV dwHash,EBX
					POPAD
					DEC NumOfInstructions
				.endif

				ADD EDX,EAX
			.endw
		.endif
;
; Cleanup and end!
;
		INVOKE VirtualFree,BaseAlloc,DWORD PTR[MemStatus.RegionSize],MEM_DECOMMIT
		INVOKE VirtualFree,BaseAlloc,NULL,MEM_RELEASE
	.endif

	MOV EDI,aDLLSortedBases
	XOR EAX,EAX
	.while DWORD PTR[EDI] != 0 && EAX <= 0
		PUSH dwNumOfInstructions
		PUSH dwHash
		PUSH DWORD PTR[EDI+4]
		CALL TracerGetAPIAdressByHashing
		.if EAX > 0
			SUB EAX,DWORD PTR[EDI+4]
			ADD EAX,DWORD PTR[EDI]
		.endif
		ADD EDI,8
	.endw
	MOV ReturnInfo,EAX

 _error_exit_api_searcher:

	INVOKE VirtualFree,aMiscBuffer,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aMiscBuffer,NULL,MEM_RELEASE
       	INVOKE VirtualFree,aDLLSortedBases,2000h,MEM_DECOMMIT
       	INVOKE VirtualFree,aDLLSortedBases,NULL,MEM_RELEASE

	MOV ESI,aDLLBases			;Free all loaded libraries
	.while DWORD PTR[ESI] != 0
		.if DWORD PTR[ESI] != -1
			INVOKE FreeLibrary,DWORD PTR[ESI]
		.endif
		ADD ESI,4
	.endw

	INVOKE VirtualFree,aDLLBases,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aDLLBases,NULL,MEM_RELEASE

	POPAD
	MOV EAX,ReturnInfo
	RET
HashTracerLevel1 endp
;------------------------------------------------------------------
TracerGetAPIAdressByHashing proc dwDLLBases:DWORD,dwHash:DWORD,dwNumOfInstructions:DWORD
	LOCAL OrdinalBase : DWORD
	LOCAL EATEnteries : DWORD
	LOCAL NameEnteries :DWORD
	LOCAL ExportTable :DWORD
	LOCAL ExportTableSize :DWORD
	LOCAL Found : DWORD
	LOCAL Forwarder :DWORD
	LOCAL ForwarderHandle :DWORD
	LOCAL CurrentOrdinal :DWORD
	LOCAL Hash :DWORD
	LOCAL dwBuffer1 :DWORD
	LOCAL dwBuffer2 :DWORD
	PUSHAD

       	INVOKE VirtualAlloc,NULL,1000h,MEM_COMMIT,PAGE_READWRITE
       	MOV Forwarder,EAX

	MOV Found,-1
	MOV ESI,dwDLLBases
	MOV EDI,dwHash
	INVOKE IsBadReadPtr,ESI,1000h
	.if EAX == NULL
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
			PUSHAD
			MOV EAX,EBX
			MOV ECX,dwNumOfInstructions
			XOR EBX,EBX
			.while ECX > 0
				PUSH ECX
				PUSH EAX
				PUSH EAX
				CALL ldex86
				MOV ECX,EAX
				POP EAX
				.if BYTE PTR[EAX] == 0E8h && ECX == 5
					PUSH EAX
					MOV DWORD PTR[dwBuffer1],0
					MOV DWORD PTR[dwBuffer2],0
					ADD EAX,DWORD PTR[EAX+1]
					ADD EAX,5
					MOV DWORD PTR[dwBuffer2],EAX
					LEA EAX,DWORD PTR[dwBuffer2]
					CDQ
					.while ECX > 0
						MOV DL,BYTE PTR[EAX]
						ROL EBX,7
						XOR BL,DL
						INC EAX
						DEC ECX
					.endw
					POP EAX
					ADD EAX,5
				.else
					CDQ
					.while ECX > 0
						MOV DL,BYTE PTR[EAX]
						ROL EBX,7
						XOR BL,DL
						INC EAX
						DEC ECX
					.endw
				.endif
				POP ECX
				DEC ECX
			.endw
			MOV Hash,EBX
			POPAD
			.if EDI == Hash
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
				MOV EAX,Forwarder
				.while BYTE PTR[EAX] != '.'
					INC EAX
				.endw
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
					PUSHAD
					MOV EAX,EBX
					MOV ECX,dwNumOfInstructions
					XOR EBX,EBX
					.while ECX > 0
						PUSH ECX
						PUSH EAX
						PUSH EAX
						CALL ldex86
						MOV ECX,EAX
						POP EAX
						CDQ
						.while ECX > 0
							MOV DL,BYTE PTR[EAX]
							ROL EBX,7
							XOR BL,DL
							INC EAX
							DEC ECX
						.endw
						POP ECX
						DEC ECX
					.endw
					MOV Hash,EBX
					POPAD
					.if EDI == Hash
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
					PUSHAD
					MOV EAX,EBX
					MOV ECX,dwNumOfInstructions
					XOR EBX,EBX
					.while ECX > 0
						PUSH ECX
						PUSH EAX
						PUSH EAX
						CALL ldex86
						MOV ECX,EAX
						POP EAX
						CDQ
						.while ECX > 0
							MOV DL,BYTE PTR[EAX]
							ROL EBX,7
							XOR BL,DL
							INC EAX
							DEC ECX
						.endw
						POP ECX
						DEC ECX
					.endw
					MOV Hash,EBX
					POPAD
					.if EDI == Hash
						MOV ECX,CurrentOrdinal
						MOV Found,ECX
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
	.else
		MOV Found,-1
	.endif

	INVOKE VirtualFree,Forwarder,1000h,MEM_DECOMMIT
	INVOKE VirtualFree,Forwarder,NULL,MEM_RELEASE

	MOV EAX,Found
	.if EAX != -1
		INVOKE GetProcAddress,dwDLLBases,EAX
	.endif
	MOV Found,EAX

	POPAD
	MOV EAX,Found
	.if EAX == -1
		INC EAX
	.endif
	RET
TracerGetAPIAdressByHashing endp
;------------------------------------------------------------------
TracerAutoFixIAT proc hProcess:DWORD,szDumpFileName:DWORD,inImageBase:DWORD,SearchStart:DWORD,SearchSize:DWORD,SearchStep:DWORD
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
	LOCAL ReturnInfo :DWORD
	LOCAL dwCurrentLibrary :DWORD
	PUSHAD

	MOV ReturnInfo,0	;Critical error
	MOV LastDllId,-1
	MOV APIFoundNumber,0
	
	PUSH 1
	CALL DWORD PTR[cImporterSetAutoFixOptions]
	MOV dwListType,1

	MOV dwTrueAPIAddress,0

	.if SearchStep == 0
		MOV SearchStep,1
	.endif

	PUSH inImageBase
	PUSH 51200		;50kb per .dll
	CALL DWORD PTR[cImporterInit]

       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_READWRITE
       	MOV LastDllName,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_READWRITE
       	MOV aDLLBases,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_READWRITE
       	MOV aDLLSortedBases,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_READWRITE
       	MOV aMiscBuffer,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_READWRITE
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

       	INVOKE VirtualAlloc,NULL,SearchSize,MEM_COMMIT,PAGE_READWRITE
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
				CALL DWORD PTR[cImporterGetDLLIndexEx]
				.if EAX == -1
					PUSH EDX
					PUSH hProcess
					CALL TracerDetectRedirection
					.if EAX == 0
						PUSH EDX
						PUSH hProcess
						CALL TracerLevel1
						PUSH 1
						CALL DWORD PTR[cImporterSetAutoFixOptions]
						.if EAX > 0 && EAX < 1000h
							PUSH EAX
							PUSH EDX
							PUSH hProcess
							CALL HashTracerLevel1
							.if EAX > 1000h
								MOV EDX,EAX
								PUSH aDLLSortedBases
								PUSH EDX
								CALL DWORD PTR[cImporterGetDLLIndexEx]
							.else
								MOV EAX,-1
							.endif
						.else
							MOV EDX,EAX
							PUSH aDLLSortedBases
							PUSH EDX
							CALL DWORD PTR[cImporterGetDLLIndexEx]
						.endif
					.else
						.if EAX == 1
							PUSH EDX
							PUSH hProcess
							CALL TracerFix_ACProtect
						.elseif EAX == 2
							PUSH EDX
							PUSH hProcess
							CALL TracerFix_tELock_varA
						.elseif EAX == 3
							PUSH EDX
							PUSH hProcess
							CALL TracerFix_tELock_varB
						.elseif EAX == 4
							PUSH EDX
							PUSH hProcess
							CALL TracerFix_tELock_varC
						.elseif EAX == 5
							PUSH EDX
							PUSH hProcess
							CALL TracerFix_tELock_varD
						.elseif EAX == 6
							PUSH EDX
							PUSH hProcess
							CALL TracerFix_ReCrypt
						.elseif EAX == 7
							PUSH EDX
							PUSH hProcess
							CALL TracerFix_Orien
						.elseif EAX == 8
							PUSH EDX
							PUSH hProcess
							CALL TracerFix_AlexProtector
						.endif
						.if EAX > 1000h
							MOV EDX,EAX
							PUSH aDLLSortedBases
							PUSH EDX
							CALL DWORD PTR[cImporterGetDLLIndexEx]
						.else
							MOV EAX,-1
						.endif
					.endif
				.endif
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
							CALL DWORD PTR[cImporterAddNewDll]
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
					CALL DWORD PTR[cImporterGetAPINameEx]

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
						CALL DWORD PTR[cImporterAddNewAPI]
						INC APIFoundNumber
					.endif
				.endif
			.endif
			ADD EDI,SearchStep
			ADD EBX,SearchStep
			DEC ECX
		.endw
		.if APIFoundNumber > 0
			CALL DWORD PTR[cImporterEstimatedSize]

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
			CALL DWORD PTR[cImporterExportIAT]
			
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
	INVOKE VirtualFree,aDLLSortedBases,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aMiscBuffer,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aSearchMemory,SearchSize,MEM_DECOMMIT
	INVOKE VirtualFree,aExeFilePath,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,LastDllName,2000h,MEM_DECOMMIT
	
	INVOKE VirtualFree,aDLLBases,NULL,MEM_RELEASE
	INVOKE VirtualFree,aDLLSortedBases,NULL,MEM_RELEASE
	INVOKE VirtualFree,aMiscBuffer,NULL,MEM_RELEASE
	INVOKE VirtualFree,aSearchMemory,NULL,MEM_RELEASE
	INVOKE VirtualFree,aExeFilePath,NULL,MEM_RELEASE
	INVOKE VirtualFree,LastDllName,NULL,MEM_RELEASE

	PUSH 0
	CALL DWORD PTR[cImporterSetAutoFixOptions]
	MOV dwListType,0

	POPAD
	MOV EAX,ReturnInfo
	RET
TracerAutoFixIAT endp
;------------------------------------------------------------------
TracerAutoFixImportElimination proc hProcess:DWORD,szDumpFileName:DWORD,inImageBase:DWORD,dwSizeOfImage:DWORD,UnpackedOEP:DWORD
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
	LOCAL ReturnInfo :DWORD
	LOCAL dwCurrentLibrary :DWORD
	LOCAL SearchStart :DWORD
	LOCAL SearchSize :DWORD
	LOCAL SearchStep :DWORD
	LOCAL dwCALLorJMP_NEAR :DWORD
	LOCAL EliminationType :DWORD
	LOCAL IATVirtualOffset :DWORD
	LOCAL dwFixASM_start :DWORD
	LOCAL dwFixASM_size :DWORD
	LOCAL dwMinIAT :DWORD
	LOCAL dwMaxIAT :DWORD
	PUSHAD

	MOV ReturnInfo,0	;Critical error
	MOV LastDllId,-1
	MOV APIFoundNumber,0
	MOV SearchStep,1
	MOV dwFixASM_start,0
	MOV dwFixASM_size,0
	MOV dwMinIAT,0
	MOV dwMaxIAT,0
	MOV EAX,inImageBase
	ADD dwSizeOfImage,EAX
	
	PUSH 1
	CALL DWORD PTR[cImporterSetAutoFixOptions]
	MOV dwListType,1

	PUSH 21
	PUSH 0
	PUSH szDumpFileName
	CALL DWORD PTR[cGetPE32Data]
	ADD EAX,inImageBase
	MOV SearchStart,EAX

	PUSH 22
	PUSH 0
	PUSH szDumpFileName
	CALL DWORD PTR[cGetPE32Data]
	MOV SearchSize,EAX

	MOV dwTrueAPIAddress,0

	.if SearchStep == 0
		MOV SearchStep,1
	.endif

	PUSH szDumpFileName	;Calculate virtual new section virtual offset
	CALL _map_file
	PUSH 1000h
	PUSH FileMapVA
	CALL _calculate_needed_space
	CALL _unmap_file
	MOV EAX,DWORD PTR[Converted]
	MOV DWORD PTR[NeededSpace],EAX
	ADD EAX,inImageBase
	MOV IATVirtualOffset,EAX          

	PUSH inImageBase
	PUSH 51200		;50kb per .dll
	CALL DWORD PTR[cImporterInit]

       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_READWRITE
       	MOV LastDllName,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_READWRITE
       	MOV aDLLBases,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_READWRITE
       	MOV aDLLSortedBases,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_READWRITE
       	MOV aMiscBuffer,EAX
       	INVOKE VirtualAlloc,NULL,2000h,MEM_COMMIT,PAGE_READWRITE
       	MOV aExeFilePath,EAX

	INVOKE EnumProcessModules,hProcess,aDLLBases,800h,addr dummy
	MOV ESI,aDLLBases
	MOV EDI,aDLLSortedBases
	.if EAX == 0
		MOV ReturnInfo,401h	;Error, process terminated!
 		JMP _error_exit_iat_elimination_fixer
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

       	INVOKE VirtualAlloc,NULL,SearchSize,MEM_COMMIT,PAGE_READWRITE
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
		SUB ECX,4
		.while ECX > 0
			XOR EAX,EAX
			.if WORD PTR[EDI] == 15FFh || WORD PTR[EDI] == 25FFh
				MOV EDX,DWORD PTR[EDI+2]
				MOV DWORD PTR[dwCALLorJMP_NEAR],EDX
				PUSHAD
	                        INVOKE ReadProcessMemory,hProcess,EDX,addr dwTestRead,4,addr NumOfBytesWR
				MOV DWORD PTR[ESP+1Ch],EAX
				POPAD
				.if EAX != NULL
					MOV EDX,DWORD PTR[dwTestRead]
					PUSHAD
		                        INVOKE ReadProcessMemory,hProcess,EDX,addr dwTestRead,4,addr NumOfBytesWR
					MOV DWORD PTR[ESP+1Ch],EAX
					POPAD
					MOV DWORD PTR[dwTestRead],EDX
				.endif
				.if dwFixASM_start == 0 || dwMinIAT == 0
					PUSHAD
					.if dwFixASM_start == 0
						INVOKE VirtualQueryEx,hProcess,dwTestRead,addr MemStatus,sizeof MemStatus
						MOV EAX,DWORD PTR[MemStatus.BaseAddress]
						MOV ECX,DWORD PTR[MemStatus.RegionSize]
						MOV dwFixASM_start,EAX
						MOV dwFixASM_size,ECX
						ADD dwFixASM_size,EAX
					.endif

					INVOKE VirtualQueryEx,hProcess,dwCALLorJMP_NEAR,addr MemStatus,sizeof MemStatus
					MOV EAX,DWORD PTR[MemStatus.BaseAddress]
					.if EAX != dwFixASM_start
						MOV ECX,DWORD PTR[MemStatus.RegionSize]
						MOV dwMinIAT,EAX
						MOV dwMaxIAT,ECX
						ADD dwMaxIAT,EAX
					.endif
					POPAD
				.endif
			.endif
			.if EAX != NULL
;			.if EAX > 70000000h
				PUSH aDLLSortedBases
				PUSH DWORD PTR[dwCALLorJMP_NEAR]
				CALL DWORD PTR[cImporterGetDLLIndexEx]
				.if EAX == -1
					PUSH aDLLSortedBases
					PUSH DWORD PTR[dwTestRead]
					CALL DWORD PTR[cImporterGetDLLIndexEx]
					.if EAX == -1
						MOV EDX,DWORD PTR[dwTestRead]
						PUSH EDX
						PUSH hProcess
						CALL TracerDetectRedirection
						.if EAX == 0
							PUSH EDX
							PUSH hProcess
							CALL TracerLevel1
							PUSH 1
							CALL DWORD PTR[cImporterSetAutoFixOptions]
							.if EAX > 0 && EAX < 1000h
								PUSH EAX
								PUSH EDX
								PUSH hProcess
								CALL HashTracerLevel1
								.if EAX > 1000h
									MOV EDX,EAX
									PUSH aDLLSortedBases
									PUSH EDX
									CALL DWORD PTR[cImporterGetDLLIndexEx]
								.else
									MOV EAX,-1
								.endif
							.else
								MOV EDX,EAX
								PUSH aDLLSortedBases
								PUSH EDX
								CALL DWORD PTR[cImporterGetDLLIndexEx]
							.endif
						.else
							.if EAX == 1
								PUSH EDX
								PUSH hProcess
								CALL TracerFix_ACProtect
							.elseif EAX == 2
								PUSH EDX
								PUSH hProcess
								CALL TracerFix_tELock_varA
							.elseif EAX == 3
								PUSH EDX
								PUSH hProcess
								CALL TracerFix_tELock_varB
							.elseif EAX == 4
								PUSH EDX
								PUSH hProcess
								CALL TracerFix_tELock_varC
							.elseif EAX == 5
								PUSH EDX
								PUSH hProcess
								CALL TracerFix_tELock_varD
							.elseif EAX == 6
								PUSH EDX
								PUSH hProcess
								CALL TracerFix_ReCrypt
							.elseif EAX == 7
								PUSH EDX
								PUSH hProcess
								CALL TracerFix_Orien
							.elseif EAX == 8
								PUSH EDX
								PUSH hProcess
								CALL TracerFix_AlexProtector
							.endif
							.if EAX > 1000h
								MOV EDX,EAX
								PUSH aDLLSortedBases
								PUSH EDX
								CALL DWORD PTR[cImporterGetDLLIndexEx]
							.else
								MOV EAX,-1
							.endif
						.endif
					.endif
				.endif
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
							CALL DWORD PTR[cImporterAddNewDll]

							PUSH EAX	;Realign IAT in case of new .dll
							MOV EAX,IATVirtualOffset
							SUB EAX,NeededSpace
							.if EAX != inImageBase
								ADD IATVirtualOffset,4
							.endif
							POP EAX
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
					CALL DWORD PTR[cImporterGetAPINameEx]

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
						PUSH IATVirtualOffset	;EBX
						PUSH EAX
						CALL DWORD PTR[cImporterAddNewAPI]
						INC APIFoundNumber

						PUSHAD			;Write new API pointer
						SUB EDI,aSearchMemory
						ADD EDI,SearchStart
						ADD EDI,2
						INVOKE WriteProcessMemory,hProcess,EDI,addr IATVirtualOffset,4,addr NumOfBytesWR
						POPAD
						
						ADD IATVirtualOffset,4
					.endif
				.endif
			.endif
			ADD EDI,SearchStep
			ADD EBX,SearchStep
			DEC ECX
		.endw
		INVOKE ReadProcessMemory,hProcess,SearchStart,aSearchMemory,SearchSize,addr NumOfBytesWR
		MOV EDI,aSearchMemory
		MOV EBX,SearchStart
		MOV EAX,SearchSize
		MOV ECX,SearchStep
		CDQ
		DIV ECX
		MOV ECX,EAX
		SUB ECX,4
		.while ECX > 0
			MOV EAX,dwMinIAT
			MOV EBX,dwMaxIAT
			.if DWORD PTR[EDI] >= EAX && DWORD PTR[EDI] <= EBX
				MOV EDX,DWORD PTR[EDI]
				PUSHAD
	                        INVOKE ReadProcessMemory,hProcess,EDX,addr dwTestRead,4,addr NumOfBytesWR
				MOV DWORD PTR[ESP+1Ch],EAX
				POPAD
				.if EAX != NULL
					MOV EDX,DWORD PTR[dwTestRead]
					PUSHAD
		                        INVOKE ReadProcessMemory,hProcess,EDX,addr dwTestRead,4,addr NumOfBytesWR
					MOV DWORD PTR[ESP+1Ch],EAX
					POPAD
					MOV DWORD PTR[dwTestRead],EDX
				.endif
				.if EAX != 0
					MOV EAX,DWORD PTR[dwTestRead]
				.endif
			.else
				XOR EAX,EAX
			.endif
			.if EAX == 0
				MOV EAX,dwFixASM_start
				MOV EBX,dwFixASM_size
				.if DWORD PTR[EDI] >= EAX && DWORD PTR[EDI] <= EBX
					MOV EDX,DWORD PTR[EDI]
					PUSHAD
		                        INVOKE ReadProcessMemory,hProcess,EDX,addr dwTestRead,4,addr NumOfBytesWR
					MOV DWORD PTR[ESP+1Ch],EAX
					POPAD
					.if EAX != NULL
						MOV EDX,DWORD PTR[dwTestRead]
						PUSHAD
			                        INVOKE ReadProcessMemory,hProcess,EDX,addr dwTestRead,4,addr NumOfBytesWR
						MOV DWORD PTR[ESP+1Ch],EAX
						POPAD
						MOV DWORD PTR[dwTestRead],EDX
					.endif
					.if EAX != 0
						MOV EAX,DWORD PTR[dwTestRead]
					.endif
				.else
					XOR EAX,EAX
				.endif
			.endif
			.if EAX == 0
				MOV EAX,inImageBase
				MOV EBX,dwSizeOfImage
				.if DWORD PTR[EDI] >= EAX && DWORD PTR[EDI] <= EBX
					MOV EDX,DWORD PTR[EDI]
					PUSHAD
		                        INVOKE ReadProcessMemory,hProcess,EDX,addr dwTestRead,4,addr NumOfBytesWR
					MOV DWORD PTR[ESP+1Ch],EAX
					POPAD
					.if EAX != NULL
						MOV EDX,DWORD PTR[dwTestRead]
						PUSHAD
			                        INVOKE ReadProcessMemory,hProcess,EDX,addr dwTestRead,4,addr NumOfBytesWR
						MOV DWORD PTR[ESP+1Ch],EAX
						POPAD
						MOV DWORD PTR[dwTestRead],EDX
					.endif
					.if EAX != 0
						MOV EAX,DWORD PTR[dwTestRead]
					.endif
				.elseif BYTE PTR[EDI] == 0E9h ||  BYTE PTR[EDI] == 0E8h
					.if BYTE PTR[EDI] == 0E9h
						MOV EliminationType,1
					.else
						MOV EliminationType,2
					.endif
					MOV EAX,DWORD PTR[EDI+1]
					ADD EAX,EDI
					ADD EAX,5
					SUB EAX,aSearchMemory
					ADD EAX,inImageBase
					MOV EDX,EAX
					PUSH aDLLSortedBases
					PUSH EAX
					CALL DWORD PTR[cImporterGetAPINameEx]
					
					MOV EBX,EAX
					PUSH EAX
					CALL DWORD PTR[cImporterFindAPIWriteLocation]

					.if EAX != 0 && EAX != EBX
						MOV dummy,EAX
						PUSHAD			;Write new API pointer
						SUB EDI,aSearchMemory
						ADD EDI,SearchStart
						INVOKE WriteProcessMemory,hProcess,EDI,addr dummy,4,addr NumOfBytesWR
						POPAD
					.else
						.if EAX > 1000h
							PUSH aDLLSortedBases
							PUSH EDX
							CALL DWORD PTR[cImporterGetDLLIndexEx]
						.else
							MOV EAX,-1
						.endif
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
									CALL DWORD PTR[cImporterAddNewDll]
		
									PUSH EAX	;Realign IAT in case of new .dll
									MOV EAX,IATVirtualOffset
									SUB EAX,NeededSpace
									.if EAX != inImageBase
										ADD IATVirtualOffset,4
									.endif
									POP EAX
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
							CALL DWORD PTR[cImporterGetAPINameEx]
		
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
								PUSH IATVirtualOffset	;EBX
								PUSH EAX
								CALL DWORD PTR[cImporterAddNewAPI]
								INC APIFoundNumber

								ADD IATVirtualOffset,4
							.endif
						.endif
					.endif

					.if EAX != -1
						MOV EBX,EAX
						PUSH EAX
						CALL DWORD PTR[cImporterFindAPIWriteLocation]
	
						.if EAX != 0 && EAX != EBX
							MOV dummy,EAX
							PUSHAD			;Write new API pointer
							SUB EDI,aSearchMemory
							ADD EDI,SearchStart
							INVOKE WriteProcessMemory,hProcess,EDI,addr dummy,4,addr NumOfBytesWR
							POPAD
						.endif
					.endif
				.else
					XOR EAX,EAX
				.endif
			.endif
			.if EAX != NULL
				MOV EDX,DWORD PTR[dwTestRead]
				PUSH EDX
				PUSH hProcess
				CALL TracerDetectRedirection
				.if EAX == 0
					MOV EDX,DWORD PTR[dwTestRead]
					PUSHAD
		                        INVOKE ReadProcessMemory,hProcess,EDX,addr dummy,4,addr NumOfBytesWR
					MOV DWORD PTR[ESP+1Ch],EAX
					POPAD
					.if EAX != 0
						PUSH EDX
						PUSH hProcess
						CALL TracerLevel1
						PUSH 1
						CALL DWORD PTR[cImporterSetAutoFixOptions]
						.if EAX > 0 && EAX < 1000h
							PUSH EAX
							PUSH EDX
							PUSH hProcess
							CALL HashTracerLevel1
							.if EAX < 1000h
								XOR EAX,EAX
							.endif
						.endif
						.if EAX != 0
							PUSH EAX
							PUSHAD
							MOV EDI,EAX
				                        INVOKE ReadProcessMemory,hProcess,EDI,addr dummy,4,addr NumOfBytesWR
							MOV DWORD PTR[ESP+1Ch],EAX
							POPAD
							MOV EBX,EAX
							POP EAX
							.if EBX == 0
								XOR EAX,EAX
							.endif
						.endif
					.endif
				.else
					.if EAX == 1
						PUSH EDX
						PUSH hProcess
						CALL TracerFix_ACProtect
					.elseif EAX == 2
						PUSH EDX
						PUSH hProcess
						CALL TracerFix_tELock_varA
					.elseif EAX == 3
						PUSH EDX
						PUSH hProcess
						CALL TracerFix_tELock_varB
					.elseif EAX == 4
						PUSH EDX
						PUSH hProcess
						CALL TracerFix_tELock_varC
					.elseif EAX == 5
						PUSH EDX
						PUSH hProcess
						CALL TracerFix_tELock_varD
					.elseif EAX == 6
						PUSH EDX
						PUSH hProcess
						CALL TracerFix_ReCrypt
					.elseif EAX == 7
						PUSH EDX
						PUSH hProcess
						CALL TracerFix_Orien
					.elseif EAX == 8
						PUSH EDX
						PUSH hProcess
						CALL TracerFix_AlexProtector
					.endif
				.endif
				.if EAX != NULL
					MOV EDX,EAX
					PUSH aDLLSortedBases
					PUSH EAX
					CALL DWORD PTR[cImporterGetAPINameEx]
					
					MOV EBX,EAX
					PUSH EAX
					CALL DWORD PTR[cImporterFindAPIWriteLocation]

					.if EAX != 0 && EAX != EBX
						MOV dummy,EAX
						PUSHAD			;Write new API pointer
						SUB EDI,aSearchMemory
						ADD EDI,SearchStart
						INVOKE WriteProcessMemory,hProcess,EDI,addr dummy,4,addr NumOfBytesWR
						POPAD
					.else
						.if EAX > 1000h
							PUSH aDLLSortedBases
							PUSH EDX
							CALL DWORD PTR[cImporterGetDLLIndexEx]
						.else
							MOV EAX,-1
						.endif
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
									CALL DWORD PTR[cImporterAddNewDll]
		
									PUSH EAX	;Realign IAT in case of new .dll
									MOV EAX,IATVirtualOffset
									SUB EAX,NeededSpace
									.if EAX != inImageBase
										ADD IATVirtualOffset,4
									.endif
									POP EAX
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
							CALL DWORD PTR[cImporterGetAPINameEx]
		
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
								PUSH IATVirtualOffset	;EBX
								PUSH EAX
								CALL DWORD PTR[cImporterAddNewAPI]
								INC APIFoundNumber

								ADD IATVirtualOffset,4
							.endif
						.endif
					.endif

					.if EAX != -1
						MOV EBX,EAX
						PUSH EAX
						CALL DWORD PTR[cImporterFindAPIWriteLocation]
	
						.if EAX != 0 && EAX != EBX
							MOV dummy,EAX
							PUSHAD			;Write new API pointer
							SUB EDI,aSearchMemory
							ADD EDI,SearchStart
							ADD EDI,2
							INVOKE WriteProcessMemory,hProcess,EDI,addr dummy,4,addr NumOfBytesWR
							SUB EDI,2
							MOV dummy,0
							.if EliminationType == 1
								MOV BYTE PTR[dummy],0FFh
								MOV BYTE PTR[dummy+1],025h
							.else
								MOV BYTE PTR[dummy],0FFh
								MOV BYTE PTR[dummy+1],015h
							.endif
							INVOKE WriteProcessMemory,hProcess,EDI,addr dummy,2,addr NumOfBytesWR
							POPAD
						.endif
					.endif
				.endif
			.endif
			ADD EDI,SearchStep
			DEC ECX
		.endw
		.if APIFoundNumber > 0
			PUSH UnpackedOEP
			PUSH szDumpFileName
			PUSH inImageBase
			PUSH hProcess
			CALL DWORD PTR[cDumpProcess]

			MOV EBX,APIFoundNumber
			IMUL EBX,4
			ADD EBX,100
			PUSHAD
			MOV EAX,EBX
			CDQ
			MOV ECX,1000h
			DIV ECX
			.if EAX == 0
				INC EAX
			.endif
			IMUL EAX,1000h
			MOV DWORD PTR[ESP+1Ch],EAX
			POPAD
			MOV EBX,EAX

			PUSH EBX
			PUSH offset szSectionName
			PUSH szDumpFileName
			CALL DWORD PTR[cAddNewSection]

			CALL DWORD PTR[cImporterEstimatedSize]
			MOV EBX,APIFoundNumber
			IMUL EBX,4
			ADD EBX,100
			ADD EBX,EAX
			PUSHAD
			MOV EAX,EBX
			CDQ
			MOV ECX,1000h
			DIV ECX
			.if EAX == 0
				INC EAX
			.endif
			IMUL EAX,1000h
			MOV DWORD PTR[ESP+1Ch],EAX
			POPAD

			PUSH EAX
			PUSH offset szSectionName
			PUSH szDumpFileName
			CALL DWORD PTR[cAddNewSection]
			ADD EAX,inImageBase

			PUSH szDumpFileName
			CALL _map_file

			PUSH FileMapVA
			PUSH EAX
			CALL DWORD PTR[cImporterExportIAT]

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
 
 _error_exit_iat_elimination_fixer:

	INVOKE VirtualFree,aDLLBases,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aDLLSortedBases,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aMiscBuffer,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,aSearchMemory,SearchSize,MEM_DECOMMIT
	INVOKE VirtualFree,aExeFilePath,2000h,MEM_DECOMMIT
	INVOKE VirtualFree,LastDllName,2000h,MEM_DECOMMIT
	
	INVOKE VirtualFree,aDLLBases,NULL,MEM_RELEASE
	INVOKE VirtualFree,aDLLSortedBases,NULL,MEM_RELEASE
	INVOKE VirtualFree,aMiscBuffer,NULL,MEM_RELEASE
	INVOKE VirtualFree,aSearchMemory,NULL,MEM_RELEASE
	INVOKE VirtualFree,aExeFilePath,NULL,MEM_RELEASE
	INVOKE VirtualFree,LastDllName,NULL,MEM_RELEASE

	PUSH 0
	CALL DWORD PTR[cImporterSetAutoFixOptions]
	MOV dwListType,0

	POPAD
	MOV EAX,ReturnInfo
	RET
TracerAutoFixImportElimination endp
;------------------------------------------------------------------
ZombieHashMemory proc dwAddress:DWORD,dwLength:DWORD
	LOCAL Return :DWORD

	PUSHAD
	MOV EAX,dwAddress
	MOV ECX,dwLength
	XOR EBX,EBX
	CDQ
	.while ECX > 0
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
ZombieHashMemory endp
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
_resize_map_file:
	PUSH EBP
	MOV EBP,ESP
	PUSHAD
	INVOKE CreateFile,DWORD PTR[EBP+8],GENERIC_READ+GENERIC_WRITE,NULL,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL
	.if EAX == -1
		POPAD
		LEAVE
		RET 8
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
	include ..\..\ldex86bin.inc
;------------------------------------------------------------------
End LibMain