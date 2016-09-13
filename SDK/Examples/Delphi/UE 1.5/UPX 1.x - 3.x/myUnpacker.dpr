program myUnpacker;

uses
  Forms,
  Unpacker in 'Unpacker.pas' {mainForm};

{$R *.res}

begin
  Application.Initialize;
  Application.Title := 'RevLab Unpacker';
  Application.CreateForm(TmainForm, mainForm);
  Application.Run;
end.
