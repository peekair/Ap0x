;
; Relocater.dll functions
;

RelocaterInit PROTO :DWORD,:DWORD,:DWORD
RelocaterAddNewRelocation PROTO :DWORD,:DWORD,:DWORD
RelocaterEstimatedSize PROTO
RelocaterExportRelocation PROTO :DWORD,:DWORD,:DWORD
RelocaterChangeFileBase PROTO :DWORD,:DWORD
RelocaterGrabRelocationTable PROTO :DWORD,:DWORD,:DWORD
RelocaterGrabRelocationTableEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
RelocaterMakeSnapshoot PROTO :DWORD,:DWORD,:DWORD,:DWORD
RelocaterCompareTwoSnapshots PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

;
; (c) Ko radi taj i gresi, inc.
;