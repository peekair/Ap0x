program unUPX;

uses
  Forms,
  Unpacker in 'Unpacker.pas' {Form1};

{$R *.res}                   

begin
  Application.Initialize;
  Application.Title := 'unFSG';
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
