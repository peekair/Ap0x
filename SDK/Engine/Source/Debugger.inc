;
; Debuger.dll functions
;

InitDebug PROTO :DWORD,:DWORD,:DWORD			;call fist
InitDLLDebug PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD	;call fist (dll)
StopDebug PROTO						;call last
DebugLoop PROTO						;start debugging
SetBPX PROTO :DWORD,:DWORD,:DWORD
DeleteBPX PROTO :DWORD
SetAPIBreakPoint PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DeleteAPIBreakPoint PROTO :DWORD,:DWORD,:DWORD
SetMemoryBPX PROTO :DWORD,:DWORD,:DWORD
RemoveMemoryBPX PROTO :DWORD,:DWORD
GetContextData PROTO :DWORD
SetContextData PROTO :DWORD,:DWORD
CurrentExceptionNumber PROTO
ClearExceptionNumber PROTO
SetCustomHandler PROTO :DWORD,:DWORD
LengthDisassemble PROTO :DWORD
LengthDisassembleEx PROTO :DWORD,:DWORD
Find PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ForceClose PROTO 
SehGoneWildProtection PROTO
GetTerminationData PROTO
GetDebugData PROTO
GetExitCode PROTO
AttachDebugger PROTO :DWORD,:DWORD,:DWORD,:DWORD
DetachDebugger PROTO :DWORD
DebugLoopEx PROTO :DWORD
GetDebuggedDLLBaseAddress PROTO
GetDebuggedFileBaseAddress PROTO

;
; (c) Ko radi taj i gresi, inc.
;