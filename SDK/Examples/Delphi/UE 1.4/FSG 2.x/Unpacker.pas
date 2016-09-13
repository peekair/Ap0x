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
 SectionName := '.iat';
// Form1.ListBox1.Items.Add(' -> Breakpoint #3 reached!');
 DumpTo := ExtractFilePath(Form1.Edit1.Text) + 'unpacked.exe';
 Form1.ListBox1.Items.Add(' -> Reading OEP jump!');
 OEP := GetContextData(rEBX);
 OEP := OEP + $0C;
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
 dEDI := GetContextData(rEDI);
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
 ImporterAddNewDll(PChar(dllName),dEDI);
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
 dEAX := GetContextData(rEAX);
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
 FSGSignature1,FSGSignature2,FSGSignature3 :array[1..10] of BYTE;
 WildCard : Integer;
 FoundPattern:Integer;
begin
 if FileExists(Edit1.Text) then begin
      ImageBase := 0;
      FoundPattern := 0;
      WildCard := 0;
      FSGSignature1[1] := $50;    //FSG 2.x LoadLibrary CALL
      FSGSignature1[2] := $FF;
      FSGSignature1[3] := $53;
      FSGSignature1[4] := $10;

      FSGSignature2[1] := $50;    //FSG 2.x GetProcAddress CALL
      FSGSignature2[2] := $55;
      FSGSignature2[3] := $FF;
      FSGSignature2[4] := $53;
      FSGSignature2[5] := $14;

      FSGSignature3[1] := $FF;    //FSG 2.x OEP jump
      FSGSignature3[2] := $63;
      FSGSignature3[3] := $0C;

      ListBox1.Clear;

      NTSizeOfImage := GetPE32Data(PChar(Edit1.Text),0,3);
      ImageBase := GetPE32Data(PChar(Edit1.Text),0,1);
      FirstSectionVA := ImageBase + GetPE32Data(PChar(Edit1.Text),0,21);
      ListBox1.Items.Add('ImageBase is: ' + IntToHex(ImageBase,8));
      PackedOEP := ImageBase + GetPE32Data(PChar(Edit1.Text),0,2);
      ListBox1.Items.Add('Packed OEP is: ' + IntToHex(PackedOEP,8));
      ProcessInfo := InitDebug(PChar(Edit1.Text),'',PChar(ExtractFilePath(Edit1.Text)));
      ListBox1.Items.Add('Creating process...');
      ListBox1.Items.Add('Searching for FSG patterns...');
      FoundPattern := Find(PackedOEP,1000,@FSGSignature1,4,@WildCard);
      if FoundPattern > 0 then begin
       SetBpx(FoundPattern,bpxAlways,@LOAD_LIBRARY);
       ListBox1.Items.Add('Setting BPX #1 at: ' + IntToHex(FoundPattern,8));
       FoundPattern := Find(PackedOEP,1000,@FSGSignature2,5,@WildCard);
       if FoundPattern > 0 then begin
        SetBpx(FoundPattern,bpxAlways,@GET_PROCADDRESS);
        ListBox1.Items.Add('Setting BPX #2 at: ' + IntToHex(FoundPattern,8));
        FoundPattern := Find(PackedOEP,1000,@FSGSignature3,4,@WildCard);
        if FoundPattern > 0 then begin
         SetBpx(FoundPattern,bpxAlways,@OEP_JUMP);
         ListBox1.Items.Add('Setting BPX #3 at: ' + IntToHex(FoundPattern,8));
         ListBox1.Items.Add(' -> Unpacking FSG 2.x');
         ImporterInit(50*1024,ImageBase);
         DebugLoop();
        end;
      end;
      end else begin
       ListBox1.Items.Add('File is not packed with FSG 2.x...');
       StopDebug();
       DebugLoop();
       ListBox1.Items.Add('Unpacking terminated...');
      end;
 end;
end;


end.
