unit Unpacker;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, XPMan, StdCtrls, Buttons, ExtCtrls, SDK;

type
  TmainForm = class(TForm)
    Image1: TImage;
    Label1: TLabel;
    Bevel1: TBevel;
    Label2: TLabel;
    browsedFile: TEdit;
    BitBtn1: TBitBtn;
    XPManifest1: TXPManifest;
    GroupBox1: TGroupBox;
    LogBox: TListBox;
    chkRealignFile: TCheckBox;
    Image2: TImage;
    BitBtn2: TBitBtn;
    BitBtn3: TBitBtn;
    BitBtn4: TBitBtn;
    OpenDialog1: TOpenDialog;
    procedure FormCreate(Sender: TObject);
    procedure BitBtn4Click(Sender: TObject);
    procedure BitBtn1Click(Sender: TObject);
    procedure BitBtn2Click(Sender: TObject);
    procedure BitBtn3Click(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  mainForm: TmainForm;
  hInstance : Cardinal;
  GlobalBuffer : string;
  cbInitCallBack : Pointer;
  UnpackFileNameBuffer : string;
  ReadStringData : array [0..256] of char;
  GlobalUnpackerFolderBuffer : array [0..1024] of char;
  fdImageBase,fdLoadedBase,fdSizeOfImage,fdEntryPoint : Cardinal;
  fdFileIsDll : boolean;
  UnpackerRunning : boolean;
  dtSecondSnapShootOnEP : boolean;
  ProcInfo : PProcessInformation;
  dtPatternBPXAddress : array [0..10] of Cardinal;
  SnapShoot1, SnapShoot2 : string;

  SnapshootMemoryStartRVA, SnapshootMemorySize : Cardinal;

implementation

{$R *.dfm}
{$R loader.res}
{$R stub.res}

function MapFileEx(fName:string; dwReadOrWrite: LongInt; dwFileHWND,dwFileSize,dwFileMap,dwFileMapVA:Pointer):boolean;
 var
 hFile : THandle;
 pVal : Pointer;
 cVal : Cardinal;
begin
 hFile := CreateFile(PAnsiChar(fName), GENERIC_READ+GENERIC_WRITE, FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
 if hFile <> INVALID_HANDLE_VALUE then begin
   asm
     PUSHAD
     MOV EAX,hFile
     MOV EBX,dwFileHWND
     MOV DWORD PTR[EBX],EAX
     POPAD
   end;
   cVal := GetFileSize(hFile, nil);
   asm
     PUSHAD
     MOV EAX,cVal
     MOV EBX,dwFileSize
     MOV DWORD PTR[EBX],EAX
     POPAD
   end;
   cVal := CreateFileMapping(hFile, nil, 4, 0, GetFileSize(hFile, nil), nil);
   asm
     PUSHAD
     MOV EAX,cVal
     MOV EBX,dwFileMap
     MOV DWORD PTR[EBX],EAX
     POPAD
   end;
   pVal := MapViewOfFile(cVal, 2, 0, 0, 0);
   asm
     PUSHAD
     MOV EAX,pVal
     MOV EBX,dwFileMapVA
     MOV DWORD PTR[EBX],EAX
     POPAD
   end;
   MapFileEx := true;
 end else begin
   MapFileEx := false;
 end;
end;

procedure UnmapFileEx(dwFileHWND,dwFileSize,dwFileMap,dwFileMapVA:Cardinal);
 var
 pVal : Pointer;
begin
 asm
  PUSHAD
  MOV EAX,dwFileMapVA
  MOV pVal,EAX
  POPAD
 end;
 UnmapViewOfFile(pVal);
 CloseHandle(dwFileMap);
 SetFilePointer(dwFileHWND, dwFileSize, nil, 0);
 SetEndOfFile(dwFileHWND);
 CloseHandle(dwFileHWND);
end;

procedure AddToLog(szLogString:string);
begin
  mainForm.LogBox.Items.Add(szLogString);
  mainForm.LogBox.Selected[mainForm.LogBox.Items.Count - 1] := true;
end;

function ExtractResource(ResourceName,ExtractedFileName:string):boolean;
var
  hRes,hResLoad,ResSize,hFile,lpNumberOfBytes : Cardinal;
  hResData : Pointer;
begin
  ExtractResource := false;
  hRes := FindResource(hInstance,PAnsiChar(ResourceName),PAnsiChar('Binary'));
  if hRes <> 0 then begin
    hResLoad := LoadResource(hInstance, hRes);
    if hResLoad <> 0 then begin
      ResSize := SizeofResource(hInstance, hRes);
      hResData := LockResource(hResLoad);
      hFile := CreateFile(PAnsiChar(ExtractedFileName),GENERIC_WRITE,FILE_SHARE_READ,nil,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
      if hFile <> INVALID_HANDLE_VALUE then begin
        if WriteFile(hFile, hResData^, ResSize, lpNumberOfBytes, nil) then begin
          CloseHandle(hFile);
          ExtractResource := true;
        end;
      end;
    end;
  end;
end;

procedure ExtractNeededFiles();
 var
 unpackFolder : string;
begin
  unpackFolder := GlobalUnpackerFolderBuffer;
  if CreateDirectory(PAnsiChar(unpackFolder + 'tmp\'),nil) then begin
    ExtractResource('#9000', unpackFolder + 'tmp\stub.exe');
    ExtractResource('#9001', unpackFolder + 'tmp\stub.dll');
  end;
end;

procedure DeleteExtractedFiles();
 var
 unpackFolder : string;
begin
  unpackFolder := GlobalUnpackerFolderBuffer;
  DeleteFile(unpackFolder + 'tmp\stub.exe');
  DeleteFile(unpackFolder + 'tmp\stub.dll');
  DeleteFile(unpackFolder + 'tmp\ap0x.dll');
  DeleteFile(SnapShoot1);
  DeleteFile(SnapShoot2);  
  RemoveDirectory(PAnsiChar(unpackFolder + 'tmp\'));
end;

procedure cbCreateProcess(ptrCreateProcessInfo:PCreateProcessDebugInfo); stdcall;
 var
 pLoadedBase : Pointer;
begin
  pLoadedBase := ptrCreateProcessInfo.lpBaseOfImage;
  asm
   PUSHAD
   MOV EAX,pLoadedBase
   MOV fdLoadedBase,EAX
   POPAD
  end;
  SetCustomHandler(cCreateProcess, nil);
  SetBPX(fdLoadedBase + fdEntryPoint, bpxAlways, cbInitCallBack);
  ImporterInit(50 * 1024,fdLoadedBase);
end;

procedure cbLoadLibrary();
 var
 cSize,NumberOfBytes,cPosition,wPosition : Cardinal;
 pPosition,rPosition : Pointer;
 MemInfo : MEMORY_BASIC_INFORMATION;
begin
 rPosition := nil;
 cPosition := GetContextData(rEIP);
 if cPosition = dtPatternBPXAddress[1] then begin
   cPosition := GetContextData(rEAX);
 end;
 if cPosition > fdLoadedBase then begin
   asm
    PUSHAD
    MOV EAX,cPosition
    MOV pPosition,EAX
    MOV rPosition,EAX    
    POPAD
   end; 
   VirtualQueryEx(ProcInfo.hProcess, pPosition, MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
   pPosition := MemInfo.BaseAddress;
   cSize := MemInfo.RegionSize;
   asm
     PUSHAD
     MOV EAX,pPosition
     ADD EAX,cSize
     MOV pPosition,EAX
     POPAD
   end;
   VirtualQueryEx(ProcInfo.hProcess, pPosition, MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
   cSize := MemInfo.RegionSize;
   asm
     PUSHAD
     MOV EAX,pPosition
     ADD EAX,cSize
     MOV wPosition,EAX
     POPAD
   end;
   wPosition := wPosition - cPosition;
   if wPosition > 256 then wPosition := 256;
   if ReadProcessMemory(ProcInfo.hProcess, rPosition, @ReadStringData[0], wPosition, NumberOfBytes) then begin
    ImporterAddNewDll(ReadStringData, 0);
    AddToLog('[x] LoadLibrary BPX -> ' + ReadStringData);
   end;
 end;
end;

procedure cbGetProcAddress();
 var
 cThunk : LongInt;
 cSize,NumberOfBytes,cPosition,wPosition : Cardinal;
 pPosition,rPosition : Pointer;
 MemInfo : MEMORY_BASIC_INFORMATION;
begin
 cThunk := 0;
 rPosition := nil;
 cPosition := GetContextData(rEIP);
 if cPosition = dtPatternBPXAddress[2] then begin
   cPosition := GetContextData(rEAX);
   cThunk := GetContextData(rEBX);
 end else if cPosition = dtPatternBPXAddress[3] then begin
   cPosition := GetContextData(rEDI);
   cThunk := GetContextData(rEBX);
 end else if cPosition = dtPatternBPXAddress[4] then begin
   cPosition := GetContextData(rEDI);
   cThunk := GetContextData(rEBX);
 end;
 if cPosition > fdLoadedBase then begin
   asm
    PUSHAD
    MOV EAX,cPosition
    MOV pPosition,EAX
    MOV rPosition,EAX
    POPAD
   end;
   VirtualQueryEx(ProcInfo.hProcess, pPosition, MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
   pPosition := MemInfo.BaseAddress;
   cSize := MemInfo.RegionSize;
   asm
     PUSHAD
     MOV EAX,pPosition
     ADD EAX,cSize
     MOV pPosition,EAX
     POPAD
   end;
   VirtualQueryEx(ProcInfo.hProcess, pPosition, MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
   cSize := MemInfo.RegionSize;
   asm
     PUSHAD
     MOV EAX,pPosition
     ADD EAX,cSize
     MOV wPosition,EAX
     POPAD
   end;
   wPosition := wPosition - cPosition;
   if wPosition > 256 then wPosition := 256;
   if ReadProcessMemory(ProcInfo.hProcess, rPosition, @ReadStringData[0], wPosition, NumberOfBytes) then begin
    ImporterAddNewAPI(ReadStringData, cThunk);
    AddToLog('[x] GetProcAddress BPX -> ' + ReadStringData);
   end;
 end else begin
    ImporterAddNewOrdinalAPI(cPosition, cThunk);
    AddToLog('[x] GetProcAddress BPX -> ' + IntToHex(cPosition,8));
 end;
end;

procedure cbMakeSnapShoot1();
begin
  RelocaterMakeSnapshoot(ProcInfo.hProcess, PAnsiChar(SnapShoot1), SnapshootMemoryStartRVA + fdLoadedBase, SnapshootMemorySize);
end;

procedure cbEntryPoint();
 var
 UnpackedOEP : LongInt;
 rPosition : Pointer;
 mImportTableOffset,mRelocTableOffset,pOverlayStart,pOverlaySize,NumberOfBytes : Cardinal;
 rsFileHWND,rsFileSize,rsFileMap,rsFileMapVA : Cardinal;
begin
  try
    UnpackedOEP := GetContextData(rEIP) + 1;
    asm
     PUSHAD
     MOV EAX,UnpackedOEP
     MOV rPosition,EAX
     POPAD
    end;
    if ReadProcessMemory(ProcInfo.hProcess, rPosition, @UnpackedOEP, 4, NumberOfBytes) then begin
      UnpackedOEP := UnpackedOEP + GetContextData(rEIP) + 5;
    end;
    if fdFileIsDll = false then begin
      PastePEHeader(ProcInfo.hProcess, PAnsiChar(GlobalBuffer));
      AddToLog('[x] Paste PE32 header!');
    end else begin
      if dtSecondSnapShootOnEP then begin
        RelocaterMakeSnapshoot(ProcInfo.hProcess, PAnsiChar(SnapShoot2), SnapshootMemoryStartRVA + fdLoadedBase, SnapshootMemorySize);
      end;
      RelocaterCompareTwoSnapshots(ProcInfo.hProcess, fdLoadedBase, fdSizeOfImage, PAnsiChar(SnapShoot1), PAnsiChar(SnapShoot2), SnapshootMemoryStartRVA + fdLoadedBase);
    end;
    AddToLog('[x] Entry Point at: ' + IntToHex(UnpackedOEP,8));
    DumpProcess(ProcInfo.hProcess, fdLoadedBase, PAnsiChar(UnpackFileNameBuffer), UnpackedOEP);
    AddToLog('[x] Process dumped!');
    StopDebug();
    mImportTableOffset := AddNewSection(PAnsiChar(UnpackFileNameBuffer), '.RLv15', ImporterEstimatedSize() + 200) + fdLoadedBase;
    if fdFileIsDll then begin
      mRelocTableOffset := AddNewSection(PAnsiChar(UnpackFileNameBuffer), '.RLv15', RelocaterEstimatedSize() + 200);
    end;
    if MapFileEx(PAnsiChar(UnpackFileNameBuffer), 0, @rsFileHWND, @rsFileSize, @rsFileMap, @rsFileMapVA) then begin
      if rsFileMapVA > 0 then begin
        ImporterExportIAT(mImportTableOffset, rsFileMapVA);
        AddToLog('[x] IAT has been fixed!');
        if fdFileIsDll then begin
          RelocaterExportRelocation(mRelocTableOffset + rsFileMapVA, mRelocTableOffset, rsFileMapVA);
          AddToLog('[x] Exporting relocations!');
        end;
        if mainForm.chkRealignFile.Checked then begin
          rsFileSize := RealignPE(rsFileMapVA, rsFileSize, 2);
        end;
        UnmapFileEx(rsFileHWND,rsFileSize,rsFileMap,rsFileMapVA);
        MakeAllSectionsRWE(PAnsiChar(UnpackFileNameBuffer));
        if fdFileIsDll then begin
          RelocaterChangeFileBase(PAnsiChar(UnpackFileNameBuffer), fdImageBase);
          AddToLog('[x] Rebase file image!');
        end;
        if FindOverlay(PAnsiChar(UnpackFileNameBuffer), @pOverlayStart, @pOverlaySize) = 1 then begin
          AddToLog('[x] Moving overlay to unpacked file!');
          CopyOverlay(PAnsiChar(GlobalBuffer), PAnsiChar(UnpackFileNameBuffer));
        end;
        AddToLog('[x] File has been unpacked to: ' + ExtractFileName(UnpackFileNameBuffer));
        AddToLog('-> Unpack ended...');
      end else begin
        AddToLog('[Fatal Unpacking Error] Please mail file you tried to unpack to Reversing Labs!');
        AddToLog('-> Unpack ended...');
      end;
    end else begin
      AddToLog('[Fatal Unpacking Error] Please mail file you tried to unpack to Reversing Labs!');
      AddToLog('-> Unpack ended...');
    end;
  except
    ForceClose();
    ImporterCleanup();
    if rsFileMapVA > 0 then begin
      UnmapFileEx(rsFileHWND,rsFileSize,rsFileMap,rsFileMapVA);
    end;
    DeleteFile(UnpackFileNameBuffer);
    AddToLog('[Fatal Unpacking Error] Please mail file you tried to unpack to Reversing Labs!');
    AddToLog('-> Unpack ended...');
  end;
end;

procedure cbFindPatterns();
 var
 DontLog : boolean;
 glWildCard : BYTE;
 cSize,cPosition,wPosition : Cardinal;
 pPosition : Pointer;
 MemInfo : MEMORY_BASIC_INFORMATION;
 dtPatternSize : LongInt;
 dtPattern : array[0..64] of BYTE;
begin
 dtSecondSnapShootOnEP := true;
 DontLog := false;
 glWildCard := $00;
 if fdFileIsDll then begin
   fdLoadedBase := GetDebuggedDLLBaseAddress();
   ImporterInit(50 * 1024, fdLoadedBase);
   RelocaterInit(100 * 1024, fdImageBase, fdLoadedBase);
 end; 
 cPosition := fdLoadedBase + fdEntryPoint;
 asm
  PUSHAD
  MOV EAX,cPosition
  MOV pPosition,EAX
  POPAD
 end;
 VirtualQueryEx(ProcInfo.hProcess, pPosition, MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
 pPosition := MemInfo.BaseAddress;
 cSize := MemInfo.RegionSize;
 asm
   PUSHAD
   MOV EAX,pPosition
   ADD EAX,cSize
   MOV pPosition,EAX
   POPAD
 end;
 VirtualQueryEx(ProcInfo.hProcess, pPosition, MemInfo, sizeof(MEMORY_BASIC_INFORMATION));
 cSize := MemInfo.RegionSize;
 asm
   PUSHAD
   MOV EAX,pPosition
   ADD EAX,cSize
   MOV wPosition,EAX
   POPAD
 end;
 cSize := wPosition - cPosition;

 dtPattern[0] := $50;
 dtPattern[1] := $83;
 dtPattern[2] := $C7;
 dtPattern[3] := $08;
 dtPattern[4] := $FF;
 dtPatternSize := 5;
 dtPatternBPXAddress[1] := Find(cPosition, cSize, @dtPattern[0], dtPatternSize, @glWildCard);
 if dtPatternBPXAddress[1] > 0 then begin
   SetBPX(dtPatternBPXAddress[1], bpxAlways, @cbLoadLibrary);
 end else begin
   if DontLog = false then begin
     AddToLog('[Error] File is not packed with UPX 1.x - 3.x');
     AddToLog('-> Unpack ended...');
     StopDebug();
     DontLog := true;
   end;
 end;

 dtPattern[0] := $50;
 dtPattern[1] := $47;
 dtPattern[2] := $00;
 dtPattern[3] := $57;
 dtPattern[4] := $48;
 dtPattern[5] := $F2;
 dtPattern[6] := $AE;
 dtPatternSize := 7;
 dtPatternBPXAddress[2] := Find(cPosition, cSize, @dtPattern[0], dtPatternSize, @glWildCard);
 if dtPatternBPXAddress[2] > 0 then begin
   SetBPX(dtPatternBPXAddress[2], bpxAlways, @cbGetProcAddress);
 end;

 dtPattern[0] := $57;
 dtPattern[1] := $48;
 dtPattern[2] := $F2;
 dtPattern[3] := $AE;
 dtPattern[4] := $00;
 dtPattern[5] := $FF;
 dtPatternSize := 6;
 dtPatternBPXAddress[3] := Find(cPosition, cSize, @dtPattern[0], dtPatternSize, @glWildCard);
 if dtPatternBPXAddress[3] > 0 then begin
   SetBPX(dtPatternBPXAddress[3], bpxAlways, @cbGetProcAddress);
 end else begin
   if DontLog = false then begin
     AddToLog('[Error] File is not packed with UPX 1.x - 3.x');
     AddToLog('-> Unpack ended...');
     StopDebug();
     DontLog := true;
   end;
 end;

 dtPattern[0] := $89;
 dtPattern[1] := $F9;
 dtPattern[2] := $57;
 dtPattern[3] := $48;
 dtPattern[4] := $F2;
 dtPattern[5] := $AE;
 dtPattern[6] := $52;
 dtPattern[7] := $FF;
 dtPatternSize := 8;
 dtPatternBPXAddress[4] := Find(cPosition, cSize, @dtPattern[0], dtPatternSize, @glWildCard);
 if dtPatternBPXAddress[4] > 0 then begin
   dtPatternBPXAddress[4] := dtPatternBPXAddress[4] + 2;
   SetBPX(dtPatternBPXAddress[4], bpxAlways, @cbGetProcAddress);
 end;

 dtPattern[0] := $61;
 dtPattern[1] := $E9;
 dtPatternSize := 2;
 dtPatternBPXAddress[5] := Find(cPosition, cSize, @dtPattern[0], dtPatternSize, @glWildCard);
 if dtPatternBPXAddress[5] > 0 then begin
   dtPatternBPXAddress[5] := dtPatternBPXAddress[5] + 1;
   SetBPX(dtPatternBPXAddress[5], bpxAlways, @cbEntryPoint);
 end else begin
   dtPattern[0] := $83;
   dtPattern[1] := $EC;
   dtPattern[2] := $00;
   dtPattern[3] := $E9;
   dtPatternSize := 4;
   dtPatternBPXAddress[5] := Find(cPosition, cSize, @dtPattern[0], dtPatternSize, @glWildCard);
   if dtPatternBPXAddress[5] > 0 then begin
     dtPatternBPXAddress[5] := dtPatternBPXAddress[5] + 3;
     SetBPX(dtPatternBPXAddress[5], bpxAlways, @cbEntryPoint);
   end else begin
     if DontLog = false then begin
       AddToLog('[Error] File is not packed with UPX 1.x - 3.x');
       AddToLog('-> Unpack ended...');
       StopDebug();
       DontLog := true;
     end;
   end;
 end;

 if fdFileIsDll then begin
   dtPattern[1] := $31;
   dtPattern[2] := $C0;
   dtPattern[3] := $8A;
   dtPattern[4] := $07;
   dtPattern[5] := $47;
   dtPattern[6] := $09;
   dtPattern[7] := $C0;
   dtPattern[8] := $74;
   dtPattern[9] := $22;
   dtPattern[10] := $3C;
   dtPattern[11] := $EF;
   dtPattern[12] := $77;
   dtPattern[13] := $11;
   dtPattern[14] := $01;
   dtPattern[15] := $C3;
   dtPattern[16] := $8B;
   dtPattern[17] := $03;
   dtPattern[18] := $86;
   dtPattern[19] := $C4;
   dtPattern[20] := $C1;
   dtPattern[21] := $C0;
   dtPattern[22] := $10;
   dtPattern[23] := $86;
   dtPattern[24] := $C4;
   dtPattern[25] := $01;
   dtPattern[26] := $F0;
   dtPattern[27] := $89;
   dtPattern[28] := $03;
   dtPattern[29] := $EB;
   dtPattern[30] := $E2;
   dtPattern[31] := $24;
   dtPattern[32] := $0F;
   dtPattern[33] := $C1;
   dtPattern[34] := $E0;
   dtPattern[35] := $10;
   dtPattern[36] := $66;
   dtPattern[37] := $8B;
   dtPattern[38] := $07;
   dtPattern[39] := $83;
   dtPattern[40] := $C7;
   dtPattern[41] := $02;
   dtPattern[42] := $EB;
   dtPattern[43] := $E2;
   dtPattern[44] := $2B;
   dtPatternSize := 43;
   dtPatternBPXAddress[6] := Find(cPosition, cSize, @dtPattern[1], dtPatternSize, @glWildCard);
   if dtPatternBPXAddress[6] > 0 then begin
     dtPatternBPXAddress[6] := dtPatternBPXAddress[6] - 3;
     SetBPX(dtPatternBPXAddress[6], bpxAlways, @cbMakeSnapShoot1);
   end else begin
     if DontLog = false then begin
       AddToLog('[Error] File is not packed with UPX 1.x - 3.x');
       AddToLog('-> Unpack ended...');
       StopDebug();
     end;
   end;
 end;

end;

procedure InitializeUnpacker(szFileName:string;CallBack:Pointer);
 var
 fileExten : string;
begin
 mainForm.LogBox.Clear;
 AddToLog('-> Unpack started...');
 if FileExists(szFileName) then begin
   if IsPE32FileValid(PAnsiChar(szFileName)) then begin
     cbInitCallBack := CallBack;
     fdImageBase := GetPE32Data(PAnsiChar(szFileName), 0, 1);
     fdEntryPoint := GetPE32Data(PAnsiChar(szFileName), 0, 2);
     fdSizeOfImage := GetPE32Data(PAnsiChar(szFileName), 0, 3);

     SnapshootMemoryStartRVA := GetPE32Data(PAnsiChar(szFileName), 0, 21);
     SnapshootMemorySize := fdEntryPoint - SnapshootMemoryStartRVA;

     UnpackFileNameBuffer := szFileName;
     fileExten := ExtractFileExt(szFileName);
     UnpackFileNameBuffer := ChangeFileExt(UnpackFileNameBuffer, '.unpacked' + fileExten);
     fdFileIsDll := IsFileDLL(PAnsiChar(szFileName));
     if fdFileIsDll = false then begin
        ProcInfo := InitDebug(PAnsiChar(szFileName),nil,nil);
     end else begin
        ExtractNeededFiles();
        SnapShoot1 := ExtractFilePath(UnpackFileNameBuffer) + 'tmp\snapshoot.1';
        SnapShoot2 := ExtractFilePath(UnpackFileNameBuffer) + 'tmp\snapshoot.2';
        ProcInfo := InitDLLDebug(PAnsiChar(szFileName),true,nil,nil,CallBack);
     end;
     if ProcInfo <> nil then begin
       if fdFileIsDll = false then begin
         SetCustomHandler(cCreateProcess, @cbCreateProcess);
       end;
       DebugLoop();
     end else begin
       AddToLog('[Error]');
       AddToLog('-> Unpack ended...');
     end;
   end else begin
     AddToLog('[Error] Selected file is not a valid PE32 file!');
     AddToLog('-> Unpack ended...');
   end;
 end;
end;

procedure TmainForm.FormCreate(Sender: TObject);
var
  j : integer;
begin
  hInstance := GetModuleHandle(nil);
  GetModuleFileName(0, GlobalUnpackerFolderBuffer, 1024);
  j := Length(GlobalUnpackerFolderBuffer);
  while GlobalUnpackerFolderBuffer[j] <> '\' do begin
    j := j - 1;
  end;
  GlobalUnpackerFolderBuffer[j+1] := #00;
end;

procedure TmainForm.BitBtn4Click(Sender: TObject);
begin
 GlobalBuffer := mainForm.browsedFile.Text;
 if UnpackerRunning = false then begin
   UnpackerRunning := true;
   InitializeUnpacker(GlobalBuffer, @cbFindPatterns);
   DeleteExtractedFiles();
   UnpackerRunning := false;
 end;
end;

procedure TmainForm.BitBtn1Click(Sender: TObject);
begin
  if OpenDialog1.Execute then begin
   mainForm.browsedFile.Text := OpenDialog1.FileName;
  end;
end;

procedure TmainForm.BitBtn2Click(Sender: TObject);
begin
  Application.Terminate;
end;

procedure TmainForm.BitBtn3Click(Sender: TObject);
begin
  messagedlg('RL!deUPX 1.x - 3.x unpacker'+ #13 + #10 + #13 + #10 + 'Visit Reversing Labs at http://www.reversinglabs.com'+ #13 + #10 + #13 + #10 + '  Minimum engine version needed:'+ #13 + #10 + '- DebuggerEngine 1.7 by RevLabs'+ #13 + #10 + '- DumperEngine 1.6 by RevLabs'+ #13 + #10 + '- ImporterEngine 1.6 by RevLabs'+ #13 + #10 + '- UpdaterEngine 1.2 by RevLabs'+ #13 + #10 + '- Realign 1.0 by RevLabs' + #13 + #10 + '- Relocater 1.0 by RevLabs' + #13 + #10 + #13 + #10 + 'Unpacker coded by Reversing Labs', mtInformation, [mbOk], 0);
end;

procedure TmainForm.FormShow(Sender: TObject);
begin
  if UpdateEngine(true, Application.Handle) then begin
    messagedlg('UnpackerEngine has been updated, press Ok to restart the program!', mtWarning, [mbOk], 0);
    WinExec(PAnsiChar(Application.ExeName), 1);
    Application.Terminate;
  end;
end;

end.
