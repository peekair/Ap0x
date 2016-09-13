if exist plugin.obj del plugin.obj
if exist plugin.dll del plugin.dll

call \masm32\bin\ml.exe /c /coff /Cp plugin.asm

call \masm32\bin\Link.exe /DLL /DEF:plugin.def /SUBSYSTEM:WINDOWS /LIBPATH:\masm32\lib plugin.obj