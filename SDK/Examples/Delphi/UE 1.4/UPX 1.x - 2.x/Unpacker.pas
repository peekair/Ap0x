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
 hProcess,OEP,IATStart,IATSize:Integer;
 NumberOfBytesRead:Cardinal;
 buffer:LongInt;
 ReadOk:Boolean;
 FileMapRVA,FileMap,FileSize,FileHWND:Cardinal;
 FileMapVA:Pointer;
begin
 Form1.ListBox1.Items.Add(' -> Breakpoint reached!');
 DumpTo := ExtractFilePath(Form1.Edit1.Text) + 'unpacked.exe';
 Form1.ListBox1.Items.Add(' -> Reading OEP jump!');
 OEP := GetContextData(rEIP);
 OEP := OEP + 1;
 hProcess := ProcessInfo^;
 ReadOk := ReadProcessMemoryFixed(hProcess,OEP,@buffer,4,@NumberOfBytesRead);
 if ReadOk = True then begin
  OEP := OEP + buffer + 4;
  Form1.ListBox1.Items.Add(' -> OEP is: ' + IntToHex(OEP,8));
  DumpProcess(hProcess,ImageBase,PChar(DumpTo),OEP);
  Form1.ListBox1.Items.Add(' -> Dumping process');
  ImporterAutoSearchIAT(PChar(DumpTo),ImageBase,FirstSectionVA,NTSizeOfImage,@IATStart,@IATSize);
  Form1.ListBox1.Items.Add(' -> Searching for IAT');
  ImporterAutoFixIAT(hProcess,PChar(DumpTo),ImageBase,IATStart,IATSize,1);
  Form1.ListBox1.Items.Add(' -> Fixing IAT');
  if Form1.CheckBox1.Checked = True then begin
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

   Form1.ListBox1.Items.Add(' -> Realigning!');
   FileSize := RealignPE(FileMapRVA,FileSize,2);

   UnmapViewOfFile(FileMapVA);
   CloseHandle(FileMap);
   SetFilePointer(FileHWND,FileSize,0,0);
   SetEndOfFile(FileHWND);
   CloseHandle(FileHWND);
  end;
  StopDebug();
  Form1.ListBox1.Items.Add(' -> Unpacking finished!');
  Form1.ListBox1.Items.Add('Unpacking terminated...');
  MessageDlg('File has been unpacked to unpacked.exe!',mtInformation,[mbOk],0);
 end;
end;

procedure TForm1.BitBtn2Click(Sender: TObject);
 var
 UPXSignature1,UPXSignature2 :array[1..10] of BYTE;
 WildCard : Integer;
 FoundPattern,SearchSize:Integer;
begin
 if FileExists(Edit1.Text) then begin
      ImageBase := 0;
      FoundPattern := 0;
      WildCard := 0;
      UPXSignature1[1] := $61;    //UPX 1.x signature
      UPXSignature1[2] := $E9;

      UPXSignature2[1] := $83;    //UPX 2.x signature
      UPXSignature2[2] := $EC;
      UPXSignature2[3] := $00;    // ??
      UPXSignature2[4] := $E9;

      ListBox1.Clear;

      NTSizeOfImage := GetPE32Data(PChar(Edit1.Text),0,3);
      ImageBase := GetPE32Data(PChar(Edit1.Text),0,1);
      FirstSectionVA := ImageBase + GetPE32Data(PChar(Edit1.Text),0,21);
      ListBox1.Items.Add('ImageBase is: ' + IntToHex(ImageBase,8));
      PackedOEP := ImageBase + GetPE32Data(PChar(Edit1.Text),0,2);
      SearchSize := PackedOEP - ImageBase - GetPE32Data(PChar(Edit1.Text),1,21);
      SearchSize := GetPE32Data(PChar(Edit1.Text),1,24) - SearchSize;
//      ListBox1.Items.Add('Search size is: ' + IntToHex(SearchSize,8));
      ListBox1.Items.Add('Packed OEP is: ' + IntToHex(PackedOEP,8));
      ProcessInfo := InitDebug(PChar(Edit1.Text),'',PChar(ExtractFilePath(Edit1.Text)));
      ListBox1.Items.Add('Creating process...');
      ListBox1.Items.Add('Searching for UPX pattern...');
      FoundPattern := Find(PackedOEP,SearchSize,@UPXSignature1,2,@WildCard);
      if FoundPattern > 0 then begin
         SetBpx(FoundPattern+1,bpxSingle,@OEP_JUMP);
         ListBox1.Items.Add('Setting BPX at: ' + IntToHex(FoundPattern+1,8));
         ListBox1.Items.Add(' -> Unpacking UPX 1.x');
         DebugLoop();
      end
        else begin
         FoundPattern := Find(PackedOEP,SearchSize,@UPXSignature2,4,@WildCard);
         if FoundPattern > 0 then begin
           SetBpx(FoundPattern+3,bpxSingle,@OEP_JUMP);
           ListBox1.Items.Add('Setting BPX at: ' + IntToHex(FoundPattern+1,8));
           ListBox1.Items.Add(' -> Unpacking UPX 2.x - 3.x');
           DebugLoop();
        end else begin
           ListBox1.Items.Add('File is not packed with UPX...');
           StopDebug();
           DebugLoop();
           ListBox1.Items.Add('Unpacking terminated...');
         end;
      end;
 end;
end;


end.
