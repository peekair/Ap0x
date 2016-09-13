// Import libraries
#pragma comment(lib, "Debugger.lib")
#pragma comment(lib, "Dumper.lib")
#pragma comment(lib, "Hider.lib")
#pragma comment(lib, "Importer.lib")
#pragma comment(lib, "Realign.lib")
#pragma comment(lib, "Relocater.lib")
#pragma comment(lib, "Tracer.lib")
#pragma comment(lib, "Updater.lib")

// PE32Struct
typedef struct PE32Struct{
	DWORD PE32Offset;
	DWORD ImageBase;
	DWORD OriginalEntryPoint;
	DWORD NtSizeOfImage;
	DWORD NtSizeOfHeaders;
	DWORD SizeOfOptionalHeaders;
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
	DWORD SectionNumber;
	DWORD CheckSum;
}PE32Struct, *PPE32Struct;

// Register values
enum RegisterId{rEAX = 1, rEBX, rECX, rEDX, rEDI, rESI, rEBP, rESP,
                rEIP, rEFLAGS, rDR0, rDR1, rDR2, rDR3, rDR6, rDR7};

// Exception handler values
enum CustomExceptionId{cBreakPoint = 1, cSingleStep, cAccessViolation, cIllegalInstruction, cNonContinuableException,
                       cArrayBoundsException, cFloatDenormalOperand, cFloatDevideByZero, cIntegerDevideByZero,
                       cIntegerOverflow, cPrivilegedInstruction, cPageGuard, cEverythingElse, cCreateThread,
                       cExitThread, cCreateProcess, cExitProcess, cLoadDll, cUnloadDll, cOutputDebugString};

// Breakpoint modes
enum BPXType{bpxAlways = 0, bpxSingle};
enum BPXPlace{bpxStart = 0, bpxEnd};

// Breakpoint and exception callback prototypes
typedef void (__stdcall* BPPROC)();
typedef void (__stdcall* EXCPROC)(DWORD Address);

#ifdef __cplusplus
extern "C" {
#endif

// UnpackEngine.Dumper.functions:
__declspec(dllimport) void  __stdcall PastePEHeader(HANDLE hProcess, char* ExePath);
__declspec(dllimport) void  __stdcall PastePEHeaderEx(HANDLE hProcess, DWORD ImageBase, char* ExePath); // !
__declspec(dllimport) void  __stdcall DumpProcess(HANDLE hProcess, DWORD ImageBase, char* ExePath, DWORD OEP);
__declspec(dllimport) void  __stdcall DumpProcessEx(DWORD ProcessId, DWORD ImageBase, char* szDumpFileName, DWORD EntryPoint, char* szOriginalFileName); // !
__declspec(dllimport) void  __stdcall DumpMemory(HANDLE hProcess, DWORD MemoryStart, DWORD MemorySize, char* ExePath);
__declspec(dllimport) DWORD __stdcall FindOverlay(char* szFname, DWORD* pOVLStart, DWORD* pOVLSize);
__declspec(dllimport) DWORD __stdcall ExtractOverlay(char* szFname, char* szSaveFileName);
__declspec(dllimport) BOOL  __stdcall AddOverlay(char* szFname, char* szOVLFileName);
__declspec(dllimport) BOOL  __stdcall CopyOverlay(char* inFile, char* outFile);
__declspec(dllimport) void  __stdcall SetSharedOverlay(char* fName);
__declspec(dllimport) char* __stdcall GetSharedOverlay();
__declspec(dllimport) DWORD __stdcall GetPE32Data(char* fName, DWORD WhichSection, DWORD WhichData);
__declspec(dllimport) DWORD __stdcall GetPE32DataEx(char* fName, PE32Struct* PEStruct);
__declspec(dllimport) DWORD __stdcall GetPE32DataFromMappedFile(void* fMap, DWORD WhichSection, DWORD WhichData);
__declspec(dllimport) DWORD __stdcall GetPE32DataFromMappedFileEx(void* fMap, PE32Struct* PEStruct);
__declspec(dllimport) DWORD __stdcall AddNewSection(char* fName, char* sectionName, DWORD sectionSize);
__declspec(dllimport) BOOL  __stdcall MakeAllSectionsRWE(char* fName);
__declspec(dllimport) BOOL  __stdcall DeleteLastSection(char* fName); // ?
__declspec(dllimport) long  __stdcall StaticLengthDisassemble(void* dwAddress);
__declspec(dllimport) DWORD __stdcall ConvertVAtoFileOffset(void* fMap, DWORD AddressToConvert, BOOL retnType);
__declspec(dllimport) DWORD __stdcall ConvertFileOffsetToVA(void* fMap, DWORD AddressToConvert, BOOL retnType);
__declspec(dllimport) BOOL  __stdcall IsFileDLL(char* fName);
// UnpackEngine.Realigner.functions:
__declspec(dllimport) DWORD __stdcall RealignPE(void* FileMapVA, DWORD FileSize, DWORD RealingMode);
__declspec(dllimport) BOOL  __stdcall IsPE32FileValid(char* szFileName);
// UnpackEngine.Hider.functions:
__declspec(dllimport) BOOL  __stdcall HideDebugger(HANDLE hThread, HANDLE hProcess, DWORD PatchAPI);
// UnpackEngine.Relocater.functions:
__declspec(dllimport) void  __stdcall RelocaterInit(DWORD MemorySize, DWORD OldImageBase, DWORD NewImageBase);
__declspec(dllimport) void  __stdcall RelocaterAddNewRelocation(HANDLE hProcess, DWORD RelocateAddress, DWORD RelocateState);
__declspec(dllimport) long  __stdcall RelocaterEstimatedSize();
__declspec(dllimport) void  __stdcall RelocaterExportRelocation(DWORD StorePlace, DWORD StorePlaceRVA, void* FileMapVA);
__declspec(dllimport) void  __stdcall RelocaterGrabRelocationTable(HANDLE hProcess, DWORD MemoryStart, DWORD MemorySize);
__declspec(dllimport) void  __stdcall RelocaterGrabRelocationTableEx(HANDLE hProcess, DWORD MemoryStart, DWORD MemorySize, DWORD NtSizeOfImage);
__declspec(dllimport) BOOL  __stdcall RelocaterMakeSnapshoot(HANDLE hProcess, char* szSaveFileName, DWORD MemoryStart, DWORD MemorySize);
__declspec(dllimport) BOOL  __stdcall RelocaterCompareTwoSnapshots(HANDLE hProcess, DWORD LoadedImageBase, DWORD NtSizeOfImage, char* szDumpFile1, char* szDumpFile2, DWORD MemStart);
__declspec(dllimport) long  __stdcall RelocaterChangeFileBase(char* szFileName, DWORD NewImageBase);
// UnpackEngine.Debugger.functions:
__declspec(dllimport) PROCESS_INFORMATION* __stdcall InitDebug(char* ExePath, char* CmdLine, char* CurDir);
__declspec(dllimport) PROCESS_INFORMATION* __stdcall InitDLLDebug(char* DLLPath, BOOL ReserveModuleBase, char* CmdLine, char* CurDir, BPPROC EntryCallback);
__declspec(dllimport) BOOL  __stdcall StopDebug();
__declspec(dllimport) void  __stdcall ForceClose();
__declspec(dllimport) void  __stdcall DebugLoop();
__declspec(dllimport) void  __stdcall DebugLoopEx(DWORD TimeOut);
__declspec(dllimport) void  __stdcall AttachDebugger(DWORD ProcessId, BOOL KillOnExit, PROCESS_INFORMATION* DebugInfo, BPPROC Callback);
__declspec(dllimport) BOOL  __stdcall DetachDebugger(DWORD ProcessId);
__declspec(dllimport) void  __stdcall SetBPX(DWORD bpxAddress, DWORD bpxType, BPPROC Callback);
__declspec(dllimport) void  __stdcall DeleteBPX(DWORD bpxAddress);
__declspec(dllimport) void  __stdcall SafeDeleteBPX(DWORD bpxAddress);
__declspec(dllimport) void  __stdcall SetAPIBreakPoint(char* dllName, char* apiName, DWORD bpxType, DWORD bpxPlace, BPPROC Callback);
__declspec(dllimport) void  __stdcall DeleteAPIBreakPoint(char* dllName, char* apiName, DWORD bpxPlace);
__declspec(dllimport) void  __stdcall SafeDeleteAPIBreakPoint(char* dllName, char* apiName, DWORD bpxPlace);
__declspec(dllimport) void  __stdcall SetMemoryBPX(DWORD MemoryStart, DWORD SizeOfMemory, BPPROC Callback);
__declspec(dllimport) void  __stdcall RemoveMemoryBPX(DWORD MemoryStart, DWORD SizeOfMemory);
__declspec(dllimport) DWORD __stdcall GetContextData(DWORD IndexOfRegister);
__declspec(dllimport) BOOL  __stdcall SetContextData(DWORD IndexOfRegister, DWORD NewRegisterValue);
__declspec(dllimport) long  __stdcall CurrentExceptionNumber();
__declspec(dllimport) void  __stdcall ClearExceptionNumber();
__declspec(dllimport) void  __stdcall SetCustomHandler(DWORD WhichException, EXCPROC Callback);
__declspec(dllimport) long  __stdcall LengthDisassemble(DWORD Address);
__declspec(dllimport) long  __stdcall LengthDisassembleEx(HANDLE hProcess, DWORD Address);
__declspec(dllimport) DEBUG_EVENT* __stdcall GetDebugData();
__declspec(dllimport) DEBUG_EVENT* __stdcall GetTerminationData();
__declspec(dllimport) DWORD __stdcall GetExitCode();
__declspec(dllimport) DWORD __stdcall GetDebuggedDLLBaseAddress();
__declspec(dllimport) DWORD __stdcall GetDebuggedFileBaseAddress();
__declspec(dllimport) DWORD __stdcall Find(DWORD MemStart, DWORD MemSize, BYTE* Pattern, DWORD PatternSize, BYTE* WildCard);
// UnpackEngine.Importer.functions:
__declspec(dllimport) void  __stdcall ImporterCleanup();
__declspec(dllimport) void  __stdcall ImporterInit(DWORD MemorySize, DWORD ImageBase);
__declspec(dllimport) void  __stdcall ImporterAddNewDll(char* DLLName, DWORD FirstThunk);
__declspec(dllimport) void  __stdcall ImporterAddNewAPI(char* APIName, DWORD ThunkValue);
__declspec(dllimport) long  __stdcall ImporterGetAddedDllCount();
__declspec(dllimport) long  __stdcall ImporterGetAddedAPICount();
__declspec(dllimport) long  __stdcall ImporterEstimatedSize();
__declspec(dllimport) void  __stdcall ImporterExportIAT(DWORD StorePlace, void* FileMap);
__declspec(dllimport) DWORD __stdcall ImporterFindAPIWriteLocation(char* APIName);
__declspec(dllimport) void  __stdcall ImporterMoveIAT();
__declspec(dllimport) char* __stdcall ImporterGetDLLNameFromDebugee(HANDLE hProcess, DWORD APIAddres);
__declspec(dllimport) char* __stdcall ImporterGetAPIName(DWORD APIAddress);
__declspec(dllimport) char* __stdcall ImporterGetAPINameEx(DWORD APIAddres, DWORD* pDLLBases);
__declspec(dllimport) char* __stdcall ImporterGetAPINameFromDebugee(HANDLE hProcess, DWORD APIAddres);
__declspec(dllimport) DWORD __stdcall ImporterGetRemoteAPIAddress(HANDLE hProcess, DWORD APIAddres);
__declspec(dllimport) long  __stdcall ImporterGetDLLIndexEx(DWORD APIAddres, DWORD* pDLLBases);
__declspec(dllimport) void  __stdcall ImporterRelocateWriteLocation(DWORD AddValue);
__declspec(dllimport) void  __stdcall ImporterAutoSearchIAT(char* pFileName, DWORD ImageBase, DWORD SearchStart, DWORD SearchSize, DWORD * pIATStart, DWORD * pIATSize);
__declspec(dllimport) void  __stdcall ImporterAutoSearchIATEx(HANDLE hProcess, DWORD ImageBase, DWORD SearchStart, DWORD SearchSize, DWORD * pIATStart, DWORD * pIATSize);
__declspec(dllimport) DWORD __stdcall ImporterAutoFixIAT(HANDLE hProcess, char* pFileName, DWORD ImageBase, DWORD SearchStart, DWORD SearchSize, DWORD SearchStep);
// Global.Engine.Tracer.functions:
__declspec(dllimport) void __stdcall TracerInit();
__declspec(dllimport) long __stdcall TracerLevel1(HANDLE hProcess, DWORD AddressToTrace);
__declspec(dllimport) long __stdcall HashTracerLevel1(HANDLE hProcess, DWORD AddressToTrace, long InputNumberOfInstructions);
__declspec(dllimport) long __stdcall TracerDetectRedirection(HANDLE hProcess, DWORD AddressToTrace);
__declspec(dllimport) long __stdcall TracerFixKnownRedirection(HANDLE hProcess, DWORD AddressToTrace, DWORD RedirectionId);
// Global.Engine.Updater.functions:
__declspec(dllimport) BOOL __stdcall UpdateEngine(BOOL ChangeTitle, HWND hWin);

#ifdef __cplusplus
}
#endif
