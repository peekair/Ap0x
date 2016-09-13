;
; Dumper.dll functions
;

TracerInit PROTO
TracerLevel1 PROTO :DWORD,:DWORD
HashTracerLevel1 PROTO :DWORD,:DWORD,:DWORD
TracerAutoFixIAT PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TracerGetAPIAdressByHashing PROTO :DWORD,:DWORD,:DWORD
TracerDetectRedirection PROTO :DWORD,:DWORD
TracerAutoFixImportElimination PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TracerFixKnownRedirection PROTO :DWORD,:DWORD,:DWORD

;
; (c) Ko radi taj i gresi, inc.
;