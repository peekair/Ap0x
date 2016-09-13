unit SDK;

interface

{ap0x Unpack Engine Delphi SDK 1.5}
{http://www.reversinglabs.com/}
{Types}
type
  PE32Structure = ^PE_32_STRUCT;
  PE_32_STRUCT = packed record
        PE32Offset : LongInt;
        ImageBase : LongInt;
        OriginalEntryPoint : LongInt;
        NtSizeOfImage : LongInt;
        NtSizeOfHeaders : LongInt;
        SizeOfOptionalHeaders : LongInt;
        SectionAligment : LongInt;
        ImportTableAddress : LongInt;
        ImportTableSize : LongInt;
        ResourceTableAddress : LongInt;
        ResourceTableSize : LongInt;
        ExportTableAddress : LongInt;
        ExportTableSize : LongInt;
        TLSTableAddress : LongInt;
        TLSTableSize : LongInt;
        RelocationTableAddress : LongInt;
        RelocationTableSize : LongInt;
        TimeDateStamp : LongInt;
        SectionNumber : LongInt;
        CheckSum : LongInt;
  end;
{Constants}
const
{Registers}
	rEAX = 1;
	rEBX = 2;
	rECX = 3;
	rEDX = 4;
	rEDI = 5;
	rESI = 6;
	rEBP = 7;
	rESP = 8;
	rEIP = 9;
	rEFLAGS = 10;
	rDR0 = 11;
	rDR1 = 12;
	rDR2 = 13;
	rDR3 = 14;
	rDR6 = 15;
	rDR7 = 16;
{Custom handlers}
	cBreakPoint = 1;
	cSingleStep = 2;
	cAccessViolation = 3;
	cIllegalInstruction = 4;
	cNonContinuableException = 5;
	cArrayBoundsException = 6;
	cFloatDenormalOperand = 7;
	cFloatDevideByZero = 8;
	cIntegerDevideByZero = 9;
	cIntegerOverflow = 10;
	cPrivilegedInstruction = 11;
	cPageGuard = 12;
	cEverythingElse = 13;
	cCreateThread = 14;
	cExitThread = 15;
	cCreateProcess = 16;
	cExitProcess = 17;
	cLoadDll = 18;
	cUnloadDll = 19;
	cOutputDebugString = 20;
{BPXes}
	bpxAlways = 0;
	bpxSingle = 1;
{Debuger.dll functions}
  function InitDebug(ExePath,CmdLine,CurDir:PChar): Pointer; stdcall; external 'Debugger.dll' name 'InitDebug';
  function StopDebug(): Boolean; stdcall; external 'Debugger.dll' name 'StopDebug';
  procedure ForceClose(); stdcall; external 'Debugger.dll' name 'ForceClose';
  function DebugLoop(): LongInt; stdcall; external 'Debugger.dll' name 'DebugLoop';
  procedure SetBPX(bpxAddress,bpxType:LongInt;CALLBACK:Pointer); stdcall; external 'Debugger.dll' name 'SetBPX';
  procedure DeleteBPX(bpxAddress:LongInt); stdcall; external 'Debugger.dll' name 'DeleteBPX';
  procedure SetAPIBreakPoint(dllName,apiName:PChar;bpxType,bpxPlace,CALLBACK:Pointer); stdcall; external 'Debugger.dll' name 'SetAPIBreakPoint';
  procedure DeleteAPIBreakPoint(dllName,apiName:PChar;bpxPlace:LongInt); stdcall; external 'Debugger.dll' name 'DeleteAPIBreakPoint';
  procedure SetMemoryBPX(MemoryStart:Pointer;SizeOfMemory:LongInt;CALLBACK:Pointer); stdcall; external 'Debugger.dll' name 'SetMemoryBPX';
  procedure RemoveMemoryBPX(MemoryStart:Pointer;SizeOfMemory:LongInt); stdcall; external 'Debugger.dll' name 'RemoveMemoryBPX';
  function GetContextData(IndexOfRegister:LongInt): LongInt; stdcall; external 'Debugger.dll' name 'GetContextData';
  procedure SetContextData(IndexOfRegister,NewRegisterValue:LongInt); stdcall; external 'Debugger.dll' name 'SetContextData';
  function CurrentExceptionNumber(): LongInt; stdcall; external 'Debugger.dll' name 'CurrentExceptionNumber';
  procedure ClearExceptionNumber(); stdcall; external 'Debugger.dll' name 'ClearExceptionNumber';
  procedure SetCustomHandler(WhichException:LongInt;CALLBACK:Pointer); stdcall; external 'Debugger.dll' name 'SetCustomHandler';
  function LengthDisassemble(Address:LongInt): LongInt; stdcall; external 'Debugger.dll' name 'LengthDisassemble';
  function LengthDisassembleEx(dwProcessHandle,Address:LongInt): LongInt; stdcall; external 'Debugger.dll' name 'LengthDisassembleEx';
  function Find(MemStart{Can be :Pointer},MemSize:LongInt;Pattern:Pointer;PatternSize:LongInt;WildCard:Pointer): LongInt; stdcall; external 'Debugger.dll' name 'Find';
  function GetDebugData(): Pointer; stdcall; external 'Debugger.dll' name 'GetDebugData';
  function GetTerminationData(): Pointer; stdcall; external 'Debugger.dll' name 'GetTerminationData';
  function AttachDebugger(ProcessId:LongInt;KillOnExit:Boolean;CALLBACK:Pointer): Pointer; stdcall; external 'Debugger.dll' name 'AttachDebugger';
  function DetachDebugger(ProcessId:LongInt): Pointer; stdcall; external 'Debugger.dll' name 'DetachDebugger';
  function DebugLoopEx(TimeOut:LongInt): LongInt; stdcall; external 'Debugger.dll' name 'DebugLoopEx';
  procedure GetExitCode(); stdcall; external 'Debugger.dll' name 'GetExitCode';
  function InitDLLDebug(ExePath:PChar;ReserveModuleBase:boolean;CmdLine,CurDir:PChar;CALLBACK:Pointer): Pointer; stdcall; external 'Debugger.dll' name 'InitDLLDebug';
  function GetDebuggedDLLBaseAddress(): LongInt; stdcall; external 'Debugger.dll' name 'GetDebuggedDLLBaseAddress';
  function GetDebuggedFileBaseAddress(): LongInt; stdcall; external 'Debugger.dll' name 'GetDebuggedFileBaseAddress';
{Dumper.dll functions}
  procedure PastePEHeader(hProcess:LongInt;ExePath:PChar); stdcall; external 'Dumper.dll' name 'PastePEHeader';
  procedure PastePEHeaderEx(hProcess,LoadedImageBase:LongInt;OriginalFile:PChar); stdcall; external 'Dumper.dll' name 'PastePEHeader';
  procedure DumpProcess(hProcess,ImageBase:LongInt;ExePath:PChar;OEP:LongInt); stdcall; external 'Dumper.dll' name 'DumpProcess';
  procedure DumpProcessEx(hProcess,ImageBase:LongInt;ExePath:PChar;OEP:LongInt;OriginalFile:PChar); stdcall; external 'Dumper.dll' name 'DumpProcessEx';
  procedure DumpMemory(hProcess,MemoryStart,MemorySize:LongInt;ExePath:PChar); stdcall; external 'Dumper.dll' name 'DumpMemory';
  function ExtractOverlay(FromFile,ToFile:PChar):LongInt; stdcall; external 'Dumper.dll' name 'ExtractOverlay';
  function FindOverlay(FileName:PChar;pOVLStart,pOVLSize:Pointer):LongInt; stdcall; external 'Dumper.dll' name 'FindOverlay';
  function AddOverlay(ToFile,OverlayFile:PChar):LongInt; stdcall; external 'Dumper.dll' name 'AddOverlay';
  function CopyOverlay(FromFile,ToFile:PChar):LongInt; stdcall; external 'Dumper.dll' name 'CopyOverlay';
  function GetPE32Data(FileName:PChar;WhichSection,WhichData:LongInt):LongInt; stdcall; external 'Dumper.dll' name 'GetPE32Data';
  function GetPE32DataEx(FileName:PChar;PE32Struct:Pointer):LongInt; stdcall; external 'Dumper.dll' name 'GetPE32DataEx';
  function GetPE32DataFromMappedFile(FileMapVA,WhichSection,WhichData:LongInt):LongInt; stdcall; external 'Dumper.dll' name 'GetPE32DataFromMappedFile';
  function GetPE32DataFromMappedFileEx(FileMapVA,PE32Struct:Pointer):LongInt; stdcall; external 'Dumper.dll' name 'GetPE32DataFromMappedFileEx';
  function AddNewSection(FileName,SectionName:PChar;SectionSize:LongInt):LongInt; stdcall; external 'Dumper.dll' name 'AddNewSection';
  function DeleteLastSection(FileName:PChar):Boolean; stdcall; external 'Dumper.dll' name 'DeleteLastSection';  
  function MakeAllSectionsRWE(FileName:PChar):LongInt; stdcall; external 'Dumper.dll' name 'MakeAllSectionsRWE';
  function ConvertVAtoFileOffset(FileMapVA,AddressToConvert,retnType:LongInt):LongInt; stdcall; external 'Dumper.dll' name 'ConvertVAtoFileOffset';
  function ConvertFileOffsetToVA(FileMapVA,AddressToConvert,retnType:LongInt):LongInt; stdcall; external 'Dumper.dll' name 'ConvertFileOffsetToVA';
  function SetSharedOverlay(FileName:PChar):LongInt; stdcall; external 'Dumper.dll' name 'SetSharedOverlay';
  function GetSharedOverlay():PChar; stdcall; external 'Dumper.dll' name 'GetSharedOverlay';
  function StaticLengthDisassemble(Address:LongInt): LongInt; stdcall; external 'Dumper.dll' name 'StaticLengthDisassemble';
  function IsFileDLL(FileName:PChar):boolean; stdcall; external 'Dumper.dll' name 'IsFileDLL';
{Importer.dll functions}
  procedure ImporterInit(MemorySize,ImageBase:LongInt); stdcall; external 'Importer.dll' name 'ImporterInit';
  procedure ImporterAddNewDll(DLLName:PChar;FirstThunk:LongInt); stdcall; external 'Importer.dll' name 'ImporterAddNewDll';
// This function takes APIName as PCHar
  procedure ImporterAddNewAPI(APIName:PChar;FirstThunk:LongInt); stdcall; external 'Importer.dll' name 'ImporterAddNewAPI';
// This function takes dwAPIName as LongInt but the procedure is the same as ImporterAddNewAPI and therefore is undocumented!
  procedure ImporterAddNewOrdinalAPI(dwAPIName,FirstThunk:LongInt); stdcall; external 'Importer.dll' name 'ImporterAddNewAPI';
  procedure ImporterExportIAT(StorePlace,FileMap:LongInt); stdcall; external 'Importer.dll' name 'ImporterExportIAT';
  function ImporterEstimatedSize(): LongInt; stdcall; external 'Importer.dll' name 'ImporterEstimatedSize';
  procedure ImporterCleanup() stdcall; external 'Importer.dll' name 'ImporterCleanup';
  procedure ImporterMoveIAT() stdcall; external 'Importer.dll' name 'ImporterMoveIAT';
  function ImporterGetAddedDllCount(): LongInt; stdcall; external 'Importer.dll' name 'ImporterGetAddedDllCount';
  function ImporterGetAddedAPICount(): LongInt; stdcall; external 'Importer.dll' name 'ImporterGetAddedAPICount';
  function ImporterGetAPIName(APIAddress:LongInt): PChar; stdcall; external 'Importer.dll' name 'ImporterGetAPIName';
  function ImporterFindAPIWriteLocation(APIName:PChar): PChar; stdcall; external 'Importer.dll' name 'ImporterFindAPIWriteLocation';
  function ImporterGetAPINameEx(APIAddress:LongInt;pDLLBases:Pointer): PChar; stdcall; external 'Importer.dll' name 'ImporterGetAPINameEx';
  function ImporterGetDLLIndexEx(APIAddress:LongInt;pDLLBases:Pointer): LongInt; stdcall; external 'Importer.dll' name 'ImporterGetDLLIndexEx';
  function ImporterGetAPINameFromDebugee(hProcess,APIAddress:LongInt): PChar; stdcall; external 'Importer.dll' name 'ImporterGetAPINameFromDebugee';
  function ImporterGetDLLNameFromDebugee(hProcess,APIAddress:LongInt): PChar; stdcall; external 'Importer.dll' name 'ImporterGetDLLNameFromDebugee';
  procedure ImporterAutoSearchIAT(pFileName:PChar;ImageBase,SearchStart,SearchSize:LongInt;pIATStart,pIATSize:Pointer); stdcall; external 'Importer.dll' name 'ImporterAutoSearchIAT';
  procedure ImporterAutoSearchIATEx(hProcess:LongInt;ImageBase,SearchStart,SearchSize:LongInt;pIATStart,pIATSize:Pointer); stdcall; external 'Importer.dll' name 'ImporterAutoSearchIATEx';
  procedure ImporterAutoFixIAT(hProcess:LongInt;pFileName:PChar;ImageBase,SearchStart,SearchSize,SearchStep:LongInt); stdcall; external 'Importer.dll' name 'ImporterAutoFixIAT';
  function ImporterGetRemoteAPIAddress(hProcess,APIAddress:LongInt): PChar; stdcall; external 'Importer.dll' name 'ImporterGetRemoteAPIAddress';
  procedure ImporterRelocateWriteLocation(AddValues:LongInt); stdcall; external 'Importer.dll' name 'ImporterRelocateWriteLocation';
{Updater.dll functions}
  function UpdateEngine(UpdateWin:boolean;WinHwnd:THandle):boolean; stdcall; external 'Updater.dll' name 'UpdateEngine';
{HideDebugger.dll functions}
  function HideDebugger(hThread,hProcess,PatchAPI:LongInt):LongInt; stdcall; external 'HideDebugger.dll' name 'HideDebugger';
{Tracer.dll functions}
  procedure TracerInit(); stdcall; external 'Importer.dll' name 'TracerInit';
  function TracerLevel1(hProcess,APIAddress:LongInt):LongInt; stdcall; external 'Tracer.dll' name 'TracerLevel1';
  function HashTracerLevel1(hProcess,APIAddress,NumberOfInstructions:LongInt):LongInt; stdcall; external 'Tracer.dll' name 'HashTracerLevel1';
  function TracerDetectRedirection(hProcess,APIAddress:LongInt):LongInt; stdcall; external 'Tracer.dll' name 'TracerDetectRedirection';
  function TracerFixKnownRedirection(RedirectionId,hProcess,APIAddress:LongInt):LongInt; stdcall; external 'Tracer.dll' name 'TracerFixKnownRedirection';
  function TracerGetAPIAdressByHashing(pDLLBases:Pointer;Hash,NumberOfInstructions:LongInt):LongInt; stdcall; external 'Tracer.dll' name 'TracerGetAPIAdressByHashing';
  procedure TracerAutoFixIAT(hProcess:LongInt;pFileName:PChar;ImageBase,SearchStart,SearchSize,SearchStep:LongInt); stdcall; external 'Tracer.dll' name 'TracerAutoFixIAT';
  procedure TracerAutoFixImportElimination(hProcess:LongInt;pFileName:PChar;ImageBase,SizeOfImage,UnpackedOEP:LongInt); stdcall; external 'Tracer.dll' name 'TracerAutoFixImportElimination';
{Tracer.dll functions}
  procedure RelocaterInit(MemorySize,OldImageBase,NewImageBase:LongInt); stdcall; external 'Relocater.dll' name 'RelocaterInit';
  procedure RelocaterAddNewRelocation(hProcess,RelocateAddress,RelocateState:LongInt); stdcall; external 'Relocater.dll' name 'RelocaterAddNewRelocation';
  function RelocaterEstimatedSize():LongInt; stdcall; external 'Relocater.dll' name 'RelocaterEstimatedSize';
  procedure RelocaterExportRelocation(MappedExportVA,ExportRVA,FileMapVA:LongInt); stdcall; external 'Relocater.dll' name 'RelocaterExportRelocation';
  function RelocaterChangeFileBase(pFileName:PChar;NewImageBase:LongInt):LongInt; stdcall; external 'Relocater.dll' name 'RelocaterChangeFileBase';
  function RelocaterGrabRelocationTable(hProcess,MemoryStart,MemorySize:LongInt):LongInt; stdcall; external 'Relocater.dll' name 'RelocaterGrabRelocationTable';
  function RelocaterGrabRelocationTableEx(hProcess,MemoryStart,MemorySize,SizeOfImage:LongInt):LongInt; stdcall; external 'Relocater.dll' name 'RelocaterGrabRelocationTableEx';
  function RelocaterMakeSnapshoot(hProcess:LongInt;SaveFileName:PChar;MemoryStart,MemorySize:LongInt):LongInt; stdcall; external 'Relocater.dll' name 'RelocaterMakeSnapshoot';
  function RelocaterCompareTwoSnapshots(hProcess,LoadedImageBase,SizeOfImage:LongInt;DumpFileName1,DumpFileName2:PChar;MemoryStart:LongInt):LongInt; stdcall; external 'Relocater.dll' name 'RelocaterCompareTwoSnapshots';
{Realigner.dll functions}
  function RealignPE(FileMapVA,FileSize,Two:LongInt):LongInt; stdcall; external 'Realign.dll' name 'RealignPE';
  function IsPE32FileValid(FileName:PChar):boolean; stdcall; external 'Realign.dll' name 'IsPE32FileValid';
implementation

end.
