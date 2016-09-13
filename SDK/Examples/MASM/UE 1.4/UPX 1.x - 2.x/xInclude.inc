  ; ===========================================
  ; xInclude.inc by ap0x
  ; ===========================================

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

bpxAlways		equ 0
bpxSingle		equ 1
