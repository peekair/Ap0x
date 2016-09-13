unit Unpacker;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, XPMan, StdCtrls, Buttons, SDK, ExtCtrls;

type
  TForm1 = class(TForm)
    GroupBox1: TGroupBox;
    Label1: TLabel;
    Edit1: TEdit;
    BitBtn1: TBitBtn;
    XPManifest1: TXPManifest;
    GroupBox2: TGroupBox;
    ListBox1: TListBox;
    OpenDialog1: TOpenDialog;
    BitBtn2: TBitBtn;
    Image1: TImage;
    CheckBox1: TCheckBox;
    procedure BitBtn1Click(Sender: TObject);
    procedure BitBtn2Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;
  ProcessInfo: ^Integer;
  ImageBase,FirstSectionVA,NTSizeOfImage,PackedOEP:LongInt;

implementation

{$R *.dfm}
function ReadProcessMemoryFixed(hProcess: Integer; lpBaseAddress: Integer; lpBuffer: Pointer;
  nSize: DWORD;lpNumberOfBytesRead: Pointer): BOOL; stdcall;  external 'kernel32.dll' name 'ReadProcessMemory';
function RealignPE(FileMapVA,FileSize,Two:LongInt):Integer; stdcall;  external 'Realign.dll' name 'RealignPE';

procedure TForm1.BitBtn1Click(Sender: TObject);
begin
 if OpenDialog1.Execute then Edit1.Text := OpenDialog1.FileName;
end;

procedure OEP_JUMP;
 var
 DumpTo:string;
 hProcess,OEP,IATStart,IatSize,IatLoc:Integer;
 NumberOfBytesRead:Cardinal;
 buffer:LongInt;
 ReadOk:Boolean;
 SectionName:string;
 FileMapRVA,FileMap,FileSize,FileHWND:Cardinal;
 FileMapVA:Pointer;
begin
 SectionName := 'ap0x';
// Form1.ListBox1.Items.Add(' -> Breakpoint #3 reached!');
 DumpTo := ExtractFilePath(Form1.Edit1.Text) + 'unpacked.exe';
 Form1.ListBox1.Items.Add(' -> Reading OEP jump!');
 OEP := GetContextData(rEIP);
 OEP := OEP + $1;
 hProcess := ProcessInfo^;
 ReadOk := ReadProcessMemoryFixed(hProcess,OEP,@buffer,4,@NumberOfBytesRead);
 if ReadOk = True then begin
  OEP := buffer;
  Form1.ListBox1.Items.Add(' -> OEP is: ' + IntToHex(OEP,8));
  DumpProcess(hProcess,ImageBase,PChar(DumpTo),OEP);
  Form1.ListBox1.Items.Add(' -> Dumping process');
  ImporterAutoSearchIAT(PChar(DumpTo),ImageBase,FirstSectionVA,NTSizeOfImage,@IATStart,@IATSize);
  Form1.ListBox1.Items.Add(' -> Fixing IAT!');
  IatSize := ImporterEstimatedSize;
  Form1.ListBox1.Items.Add(' -> Adding New section!');
  IatLoc := AddNewSection(PChar(DumpTo),PChar(SectionName),IatSize);
  IatLoc := IatLoc + ImageBase;

  FileHWND := CreateFile(PChar(DumpTo),$0C0000000,2,0,3,$80,0);
  FileSize := GetFileSize(FileHWND,0);
  FileMap := CreateFileMapping(FileHWND,0,4,0,FileSize,0);
  FileMapVA := MapViewOfFile(FileMap,2,0,0,0);
  asm
   PUSHAD
   MOV EBX,FileMapVA
   MOV DWORD PTR[FileMapRVA],EBX
   POPAD
  end;

  ImporterExportIAT(IatLoc,FileMapRVA);
  if Form1.CheckBox1.Checked = True then begin
   Form1.ListBox1.Items.Add(' -> Realigning!');
   FileSize := RealignPE(FileMapRVA,FileSize,2);
  end;

  UnmapViewOfFile(FileMapVA);
  CloseHandle(FileMap);
  SetFilePointer(FileHWND,FileSize,0,0);
  SetEndOfFile(FileHWND);
  CloseHandle(FileHWND);

  StopDebug();
  Form1.ListBox1.Items.Add(' -> Unpacking finished!');
  Form1.ListBox1.Items.Add('Unpacking terminated...');
  MessageDlg('File has been unpacked to unpacked.exe!',mtInformation,[mbOk],0);
 end;
end;

procedure LOAD_LIBRARY;
 var
 hProcess,dEAX,dEDI,i:Integer;
 NumberOfBytesRead:Cardinal;
 buffer:array [0..256] of char;
 dllName:string;
 ReadOk:Boolean;
begin
// Form1.ListBox1.Items.Add(' -> Breakpoint #1 reached!');
 dEAX := GetContextData(rEAX);
 hProcess := ProcessInfo^;
 ZeroMemory(@buffer,256);
 ReadOk := ReadProcessMemoryFixed(hProcess,dEAX,@buffer,256,@NumberOfBytesRead);
 if ReadOk = False then ReadOk := ReadProcessMemoryFixed(hProcess,dEAX,@buffer,50,@NumberOfBytesRead);

 dllName := '';
 i := 0;
 while Ord(buffer[i]) <> 0 do begin
  dllName := dllName + buffer[i];
  i := i + 1;
 end;
 Form1.ListBox1.Items.Add(' -> DLL ' + dllName + ' loaded!');
 ImporterAddNewDll(PChar(dllName),0);
end;

procedure GET_PROCADDRESS;
 var
 hProcess,dEAX,dEDI,i:Integer;
 NumberOfBytesRead:Cardinal;
 buffer:array [0..256] of char;
 apiName:string;
 ReadOk:Boolean;
begin
// Form1.ListBox1.Items.Add(' -> Breakpoint #2 reached!');
 dEAX := GetContextData(rEBX);
 dEDI := GetContextData(rEDI);
 hProcess := ProcessInfo^;
 ZeroMemory(@buffer,256);
 if dEAX > ImageBase then begin
   ReadOk := ReadProcessMemoryFixed(hProcess,dEAX,@buffer,256,@NumberOfBytesRead);
   if ReadOk = False then ReadOk := ReadProcessMemoryFixed(hProcess,dEAX,@buffer,50,@NumberOfBytesRead);

   apiName := '';
   i := 0;
   while Ord(buffer[i]) <> 0 do begin
    apiName := apiName + buffer[i];
    i := i + 1;
   end;
   Form1.ListBox1.Items.Add(' -> API ' + apiName + ' loaded!');
   ImporterAddNewAPI(PChar(apiName),dEDI);
 end else begin
   Form1.ListBox1.Items.Add(' -> Ordinal ' + IntToHex(dEAX,8) + ' loaded!');
   ImporterAddNewOrdinalAPI(dEAX,dEDI);
 end;

end;

procedure TForm1.BitBtn2Click(Sender: TObject);
 var
 ASPackSignature1,ASPackSignature2,ASPackSignature3 :array[1..20] of BYTE;
 WildCard : Integer;
 FoundPattern:Integer;
 fname:string;
begin
 if FileExists(Edit1.Text) then begin
      fname := Edit1.Text;
      ImageBase := 0;
      FoundPattern := 0;
      WildCard := 0;
      ASPackSignature1[1] := $03;    //FSG 2.x LoadLibrary CALL
      ASPackSignature1[2] := $C2;
      ASPackSignature1[3] := $8B;
      ASPackSignature1[4] := $D8;
      ASPackSignature1[5] := $50;
      ASPackSignature1[6] := $FF;
      ASPackSignature1[7] := $95;
      ASPackSignature1[8] := $00;
      ASPackSignature1[9] := $00;
      ASPackSignature1[10] := $00;
      ASPackSignature1[11] := $00;
      ASPackSignature1[12] := $85;
      ASPackSignature1[13] := $C0;

      ASPackSignature2[1] := $53;    //FSG 2.x GetProcAddress CALL
      ASPackSignature2[2] := $81;
      ASPackSignature2[3] := $E3;
      ASPackSignature2[4] := $FF;
      ASPackSignature2[5] := $FF;
      ASPackSignature2[6] := $FF;
      ASPackSignature2[7] := $7F;
      ASPackSignature2[8] := $53;

      ASPackSignature3[1] := $C2;    //FSG 2.x OEP jump
      ASPackSignature3[2] := $0C;
      ASPackSignature3[3] := $00;
      ASPackSignature3[4] := $68;
      ASPackSignature3[5] := $00;
      ASPackSignature3[6] := $00;
      ASPackSignature3[7] := $00;
      ASPackSignature3[8] := $00;
      ASPackSignature3[9] := $C3;

      ListBox1.Clear;

      NTSizeOfImage := GetPE32Data(PChar(fname),0,3);
      ImageBase := GetPE32Data(PChar(fname),0,1);
      FirstSectionVA := ImageBase + GetPE32Data(PChar(fname),0,21);
      ListBox1.Items.Add('ImageBase is: ' + IntToHex(ImageBase,8));
      PackedOEP := ImageBase + GetPE32Data(PChar(fname),0,2);
      ListBox1.Items.Add('Packed OEP is: ' + IntToHex(PackedOEP,8));
      ProcessInfo := InitDebug(PChar(fname),'',PChar(ExtractFilePath(fname)));
      ListBox1.Items.Add('Creating process...');

      ListBox1.Items.Add('Searching for ASPack patterns...');
      FoundPattern := Find(PackedOEP,1000,@ASPackSignature1,13,@WildCard);
      if FoundPattern > 0 then begin
       FoundPattern := FoundPattern + 4;
       SetBpx(FoundPattern,bpxAlways,@LOAD_LIBRARY);
       ListBox1.Items.Add('Setting BPX #1 at: ' + IntToHex(FoundPattern,8));
       FoundPattern := Find(PackedOEP,1000,@ASPackSignature2,8,@WildCard);
       if FoundPattern > 0 then begin
        FoundPattern := FoundPattern + 7;
        SetBpx(FoundPattern,bpxAlways,@GET_PROCADDRESS);
        ListBox1.Items.Add('Setting BPX #2 at: ' + IntToHex(FoundPattern,8));
        FoundPattern := Find(PackedOEP,1000,@ASPackSignature3,9,@WildCard);
        if FoundPattern > 0 then begin
         FoundPattern := FoundPattern + 3;
         SetBpx(FoundPattern,bpxAlways,@OEP_JUMP);
         ListBox1.Items.Add('Setting BPX #3 at: ' + IntToHex(FoundPattern,8));
         ListBox1.Items.Add(' -> Unpacking ASPack 2.12');
         ImporterInit(50*1024,ImageBase);
         ImporterMoveIAT();
         DebugLoop();
        end;
      end;
      end else begin
       ListBox1.Items.Add('File is not packed with ASPack 2.12...');
       StopDebug();
       DebugLoop();
       ListBox1.Items.Add('Unpacking terminated...');
      end;
 end;
end;


end.
