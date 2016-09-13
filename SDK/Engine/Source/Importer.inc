;
; Importer.dll functions
;

ImporterInit PROTO :DWORD,:DWORD		;call first
ImporterAddNewDll PROTO :DWORD,:DWORD
ImporterAddNewAPI PROTO :DWORD,:DWORD
ImporterExportIAT PROTO :DWORD,:DWORD		;call last
ImporterEstimatedSize PROTO
ImporterGetAPIName PROTO :DWORD
ImporterGetAPINameEx PROTO :DWORD,:DWORD
ImporterGetAPINameFromDebugee PROTO :DWORD,:DWORD
ImporterGetDLLNameFromDebugee PROTO :DWORD,:DWORD
ImporterGetDLLIndexEx PROTO :DWORD,:DWORD
ImporterGetRemoteAPIAddress PROTO :DWORD,:DWORD
ImporterAutoSearchIAT PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ImporterAutoSearchIATEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ImporterAutoFixIAT PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ImporterSetAutoFixOptions PROTO :DWORD
ImporterFindAPIWriteLocation PROTO :DWORD
ImporterRelocateWriteLocation PROTO :DWORD
ImporterGetAddedDllCount PROTO
ImporterGetAddedAPICount PROTO
ImporterMoveIAT PROTO
ImporterCleanup PROTO

;
; (c) Ko radi taj i gresi, inc.
;