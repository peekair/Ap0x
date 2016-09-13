// TODO: reference additional headers your program requires here

#pragma comment(lib, "sdk\\Debugger.lib")
#pragma comment(lib, "sdk\\Dumper.lib")
#pragma comment(lib, "sdk\\Hider.lib")
#pragma comment(lib, "sdk\\Importer.lib")
#pragma comment(lib, "sdk\\Realign.lib")
#pragma comment(lib, "sdk\\Relocater.lib")
#pragma comment(lib, "sdk\\Tracer.lib")
#pragma comment(lib, "sdk\\Updater.lib")

typedef struct{
	DWORD PE32Offset;
	DWORD ImageBase;
	DWORD OriginalEntryPoint;
	DWORD NtSizeOfImage;
	DWORD NtSizeOfHeaders;
	WORD SizeOfOptionalHeaders;
	DWORD FileAlignment;
	DWORD SectionAligment;
	DWORD ImportTableAddress;
	DWORD ImportTableSize;
	DWORD ResourceTableAddress;
	DWORD ResourceTableSize;
	DWORD ExportTableAddress;
	DWORD ExportTableSize;
	DWORD TLSTableAddress;
	DWORD TLSTableSize;
	DWORD RelocationTableAddress;
	DWORD RelocationTableSize;
	DWORD TimeDateStamp;
	WORD SectionNumber;
	DWORD CheckSum;
}PE32Struct, *PPE32Struct;

#define rEAX 1
#define rEBX 2
#define rECX 3
#define rEDX 4
#define rEDI 5
#define rESI 6
#define rEBP 7
#define rESP 8
#define rEIP 9
#define rEFLAGS 10
#define rDR0 11
#define rDR1 12
#define rDR2 13
#define rDR3 14
#define rDR6 15
#define rDR7 16

#define cBreakPoint 1
#define cSingleStep 2
#define cAccessViolation 3
#define cIllegalInstruction 4
#define cNonContinuableException 5
#define cArrayBoundsException 6
#define cFloatDenormalOperand 7
#define cFloatDevideByZero 8
#define cIntegerDevideByZero 9
#define cIntegerOverflow 10
#define cPrivilegedInstruction 11
#define cPageGuard 12
#define cEverythingElse 13
#define cCreateThread 14
#define cExitThread 15
#define cCreateProcess 16
#define cExitProcess 17
#define cLoadDll 18
#define cUnloadDll 19
#define cOutputDebugString 20

#define bpxAlways 0
#define bpxSingle 1

#ifdef __cplusplus
extern "C" {
#endif
// UnpackEngine.Dumper.functions:
__declspec(dllimport) bool __stdcall DumpProcess(HANDLE hProcess, void* ImageBase, char* szDumpFileName, long EntryPoint);
__declspec(dllimport) bool __stdcall DumpProcessEx(DWORD ProcessId, void* ImageBase, char* szDumpFileName, long EntryPoint, char* szOriginalFileName);
__declspec(dllimport) bool __stdcall DumpMemory(HANDLE hProcess, void* MemoryStart, long MemorySize, char* szDumpFileName);
__declspec(dllimport) bool __stdcall PastePEHeader(HANDLE hProcess, char* szDebuggedFileName);
__declspec(dllimport) bool __stdcall PastePEHeaderEx(HANDLE hProcess, void* LoadedImageBase, char* szDebuggedFileName);
__declspec(dllimport) bool __stdcall FindOverlay(char* szFileName, LPDWORD OverlayStart, LPDWORD OverlaySize);
__declspec(dllimport) bool __stdcall ExtractOverlay(char* szFileName, char* szExtactedFileName);
__declspec(dllimport) bool __stdcall AddOverlay(char* szFileName, char* szOverlayFileName);
__declspec(dllimport) bool __stdcall CopyOverlay(char* szInFileName, char* szOutFileName);
__declspec(dllimport) bool __stdcall MakeAllSectionsRWE(char* szFileName);
__declspec(dllimport) long __stdcall AddNewSection(char* szFileName, char* szSectionName, DWORD SectionSize);
__declspec(dllimport) void __stdcall SetSharedOverlay(char* szFileName);
__declspec(dllimport) char* __stdcall GetSharedOverlay();
__declspec(dllimport) bool __stdcall DeleteLastSection(char* szFileName);
__declspec(dllimport) long __stdcall GetPE32DataFromMappedFile(long FileMapVA, DWORD WhichSection, DWORD WhichData);
__declspec(dllimport) long __stdcall GetPE32Data(char* szFileName, DWORD WhichSection, DWORD WhichData);
__declspec(dllimport) bool __stdcall GetPE32DataFromMappedFileEx(long FileMapVA, void* DataStorage);
__declspec(dllimport) bool __stdcall GetPE32DataEx(char* szFileName, void* DataStorage);
__declspec(dllimport) long __stdcall ConvertVAtoFileOffset(long FileMapVA, long AddressToConvert, bool ReturnType);
__declspec(dllimport) long __stdcall ConvertFileOffsetToVA(long FileMapVA, long AddressToConvert, bool ReturnType);
__declspec(dllimport) long __stdcall StaticLengthDisassemble(long AddressToConvert);
__declspec(dllimport) bool __stdcall IsFileDLL(char* szFileName);
// UnpackEngine.Realigner.functions:
__declspec(dllimport) long __stdcall RealignPE(long FileMapVA, DWORD FileSize, DWORD RealingMode);
__declspec(dllimport) bool __stdcall IsPE32FileValid(char* szFileName);
// UnpackEngine.Hider.functions:
__declspec(dllimport) bool __stdcall HideDebugger(HANDLE hThread, HANDLE hProcess, DWORD PatchAPILevel);
// UnpackEngine.Relocater.functions:
__declspec(dllimport) void __stdcall RelocaterInit(DWORD MemorySize, long OldImageBase, long NewImageBase);
__declspec(dllimport) void __stdcall RelocaterAddNewRelocation(HANDLE hProcess, long RelocateAddress, DWORD RelocateState);
__declspec(dllimport) long __stdcall RelocaterEstimatedSize();
__declspec(dllimport) bool __stdcall RelocaterExportRelocation(long StorePlace, DWORD StorePlaceRVA, long FileMapVA);
__declspec(dllimport) bool __stdcall RelocaterGrabRelocationTable(HANDLE hProcess, long MemoryStart, DWORD MemorySize);
__declspec(dllimport) bool __stdcall RelocaterGrabRelocationTableEx(HANDLE hProcess, long MemoryStart, DWORD MemorySize, DWORD NtSizeOfImage);
__declspec(dllimport) bool __stdcall RelocaterMakeSnapshoot(HANDLE hProcess, char* szSaveFileName, void* MemoryStart, long MemorySize);
__declspec(dllimport) bool __stdcall RelocaterCompareTwoSnapshots(HANDLE hProcess, long LoadedImageBase, long NtSizeOfImage, char* szDumpFile1, char* szDumpFile2, long MemStart);
__declspec(dllimport) bool __stdcall RelocaterChangeFileBase(char* szFileName, long NewImageBase);
__declspec(dllimport) bool __stdcall RelocaterWipeRelocationTable(char* szFileName);
// UnpackEngine.Debugger.functions:
__declspec(dllimport) long __stdcall LengthDisassembleEx(HANDLE hProcess, void* DisassmAddress);
__declspec(dllimport) long __stdcall LengthDisassemble(void* DisassmAddress);
__declspec(dllimport) void* __stdcall InitDebug(char* szFileName, char* szCommandLine, char* szCurrentFolder);
__declspec(dllimport) void* __stdcall InitDLLDebug(char* szFileName, bool ReserveModuleBase, char* szCommandLine, char* szCurrentFolder, void* EntryCallBack);
__declspec(dllimport) bool __stdcall StopDebug();
__declspec(dllimport) bool __stdcall SetBPX(long bpxAddress, DWORD bpxType, void* bpxCallBack);
__declspec(dllimport) bool __stdcall DeleteBPX(long bpxAddress);
__declspec(dllimport) bool __stdcall SafeDeleteBPX(long bpxAddress);
__declspec(dllimport) bool __stdcall SetAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxType, DWORD bpxPlace, void* bpxCallBack);
__declspec(dllimport) bool __stdcall DeleteAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxPlace);
__declspec(dllimport) bool __stdcall SafeDeleteAPIBreakPoint(char* szDLLName, char* szAPIName, DWORD bpxPlace);
__declspec(dllimport) bool __stdcall SetMemoryBPX(long MemoryStart, DWORD SizeOfMemory, void* bpxCallBack);
__declspec(dllimport) bool __stdcall RemoveMemoryBPX(long MemoryStart, DWORD SizeOfMemory);
__declspec(dllimport) long __stdcall GetContextData(DWORD IndexOfRegister);
__declspec(dllimport) bool __stdcall SetContextData(DWORD IndexOfRegister, long NewRegisterValue);
__declspec(dllimport) void __stdcall ClearExceptionNumber();
__declspec(dllimport) long __stdcall CurrentExceptionNumber();
__declspec(dllimport) long __stdcall Find(void* MemoryStart, DWORD MemorySize, void* SearchPattern, DWORD PatternSize, LPBYTE WildCard);
__declspec(dllimport) void* __stdcall GetDebugData();
__declspec(dllimport) void* __stdcall GetTerminationData();
__declspec(dllimport) long __stdcall GetExitCode();
__declspec(dllimport) long GetDebuggedDLLBaseAddress();
__declspec(dllimport) long GetDebuggedFileBaseAddress();
__declspec(dllimport) void __stdcall SetCustomHandler(DWORD ExceptionId, void* CallBack);
__declspec(dllimport) void __stdcall ForceClose();
__declspec(dllimport) void __stdcall DebugLoop();
__declspec(dllimport) bool __stdcall AttachDebugger(DWORD ProcessId, bool KillOnExit, void* DebugInfo, void* CallBack);
__declspec(dllimport) bool __stdcall DetachDebugger(DWORD ProcessId);
__declspec(dllimport) void __stdcall DebugLoopEx(DWORD TimeOut);
// UnpackEngine.Importer.functions:
__declspec(dllimport) void __stdcall ImporterCleanup();
__declspec(dllimport) void __stdcall ImporterInit(DWORD MemorySize, long ImageBase);
__declspec(dllimport) void __stdcall ImporterAddNewDll(char* szDLLName, long FirstThunk);
__declspec(dllimport) void __stdcall ImporterAddNewAPI(char* szAPIName, long ThunkValue);
__declspec(dllimport) long __stdcall ImporterGetAddedDllCount();
__declspec(dllimport) long __stdcall ImporterGetAddedAPICount();
__declspec(dllimport) void __stdcall ImporterMoveIAT();
__declspec(dllimport) bool __stdcall ImporterExportIAT(long StorePlace, long FileMapVA);
__declspec(dllimport) long __stdcall ImporterEstimatedSize();
__declspec(dllimport) bool __stdcall ImporterExportIATEx(char* szExportFileName, char* szSectionName);
__declspec(dllimport) long __stdcall ImporterFindAPIWriteLocation(char* szAPIName);
__declspec(dllimport) void* __stdcall ImporterGetAPIName(long APIAddress);
__declspec(dllimport) void* __stdcall ImporterGetAPINameEx(long APIAddress, long DLLBasesList);
__declspec(dllimport) long __stdcall ImporterGetRemoteAPIAddress(HANDLE hProcess, long APIAddress);
__declspec(dllimport) void* __stdcall ImporterGetDLLNameFromDebugee(HANDLE hProcess, long APIAddress);
__declspec(dllimport) void* __stdcall ImporterGetAPINameFromDebugee(HANDLE hProcess, long APIAddress);
__declspec(dllimport) long __stdcall ImporterGetDLLIndexEx(long APIAddress, long DLLBasesList);
__declspec(dllimport) long __stdcall ImporterGetDLLIndex(HANDLE hProcess, long APIAddress, long DLLBasesList);
__declspec(dllimport) long __stdcall ImporterGetRemoteDLLBase(HANDLE hProcess, HMODULE LocalModuleBase);
__declspec(dllimport) bool __stdcall ImporterRelocateWriteLocation(long AddValue);
__declspec(dllimport) void __stdcall ImporterAutoSearchIAT(char* szFileName, long ImageBase, long SearchStart, DWORD SearchSize, void* pIATStart, void* pIATSize);
__declspec(dllimport) void __stdcall ImporterAutoSearchIATEx(HANDLE hProcess, long ImageBase, long SearchStart, DWORD SearchSize, void* pIATStart, void* pIATSize);
__declspec(dllimport) long __stdcall ImporterAutoFixIAT(HANDLE hProcess, char* szDumpedFile, long ImageBase, long SearchStart, DWORD SearchSize, DWORD SearchStep);
// Global.Engine.Tracer.functions:
__declspec(dllimport) void __stdcall TracerInit();
__declspec(dllimport) long __stdcall TracerLevel1(HANDLE hProcess, long AddressToTrace);
__declspec(dllimport) long __stdcall HashTracerLevel1(HANDLE hProcess, long AddressToTrace, DWORD InputNumberOfInstructions);
__declspec(dllimport) long __stdcall TracerDetectRedirection(HANDLE hProcess, long AddressToTrace);
__declspec(dllimport) long __stdcall TracerFixKnownRedirection(HANDLE hProcess, long AddressToTrace, DWORD RedirectionId);
__declspec(dllimport) long __stdcall TracerFixRedirectionViaModule(HMODULE hModuleHandle, HANDLE hProcess, long AddressToTrace, DWORD IdParameter);
__declspec(dllimport) long __stdcall TracerDetectRedirectionViaModule(HMODULE hModuleHandle, HANDLE hProcess, long AddressToTrace, PDWORD ReturnedId);
// Global.Engine.Updater.functions:
__declspec(dllimport) bool __stdcall UpdateEngine(bool UpdateWindow, HANDLE WindowHwnd);
#ifdef __cplusplus
}
#endif