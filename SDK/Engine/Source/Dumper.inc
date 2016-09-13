;
; Dumper.dll functions
;

PastePEHeader PROTO :DWORD,:DWORD		;anti-antiDump
PastePEHeaderEx PROTO :DWORD,:DWORD,:DWORD	;anti-antiDump
DumpProcess PROTO :DWORD,:DWORD,:DWORD,:DWORD
DumpMemory PROTO :DWORD,:DWORD,:DWORD,:DWORD
ExtractOverlay PROTO :DWORD,:DWORD
FindOverlay PROTO :DWORD,:DWORD,:DWORD
AddOverlay PROTO :DWORD,:DWORD
CopyOverlay PROTO :DWORD,:DWORD
GetPE32Data PROTO :DWORD,:DWORD,:DWORD
GetPE32DataEx PROTO :DWORD,:DWORD
GetPE32DataFromMappedFile PROTO :DWORD,:DWORD,:DWORD
GetPE32DataFromMappedFileEx PROTO :DWORD,:DWORD
AddNewSection PROTO :DWORD,:DWORD,:DWORD
MakeAllSectionsRWE PROTO :DWORD
ConvertVAtoFileOffset PROTO :DWORD,:DWORD,:DWORD
ConvertFileOffsetToVA PROTO :DWORD,:DWORD,:DWORD
SetSharedOverlay PROTO :DWORD
GetSharedOverlay PROTO
StaticLengthDisassemble PROTO :DWORD
DeleteLastSection PROTO :DWORD
DumpProcessEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
IsFileDLL PROTO :DWORD

;
; (c) Ko radi taj i gresi, inc.
;