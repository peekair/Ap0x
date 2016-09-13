; ===========================================
; xInclude.inc by Reversing Labs
; ===========================================
;
; Unpack Engine SDK 1.5
; http://www.reversinglabs.com

;
; PE32_STRUCT
;

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

;
; Constants / Registers
;

rEAX			equ 1
rEBX			equ 2
rECX			equ 3
rEDX			equ 4
rEDI			equ 5
rESI			equ 6
rEBP			equ 7
rESP			equ 8
rEIP			equ 9
rEFLAGS			equ 10
rDR0			equ 11
rDR1			equ 12
rDR2			equ 13
rDR3			equ 14
rDR6			equ 15
rDR7			equ 16

;
; Custom handlers
;

cBreakPoint			equ 1
cSingleStep			equ 2
cAccessViolation		equ 3
cIllegalInstruction		equ 4
cNonContinuableException	equ 5
cArrayBoundsException		equ 6
cFloatDenormalOperand		equ 7
cFloatDevideByZero		equ 8
cIntegerDevideByZero		equ 9
cIntegerOverflow		equ 10
cPrivilegedInstruction		equ 11
cPageGuard			equ 12
cEverythingElse			equ 13
cCreateThread			equ 14
cExitThread			equ 15
cCreateProcess			equ 16
cExitProcess			equ 17
cLoadDll			equ 18
cUnloadDll			equ 19
cOutputDebugString		equ 20

;
; BPXes
;

bpxAlways		equ 0
bpxSingle		equ 1

;
; Imported functions
;

 include Debugger.inc
 include Importer.inc
 include Tracer.inc
 include Dumper.inc
 include Realigner.inc
 include Relocater.inc
 include HideDebugger.inc
 include Updater.inc

;
; (c) Ko radi taj i gresi, inc.
;