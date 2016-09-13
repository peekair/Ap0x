@echo off
echo ;
echo -------------------------------------
echo Building Debugger...
echo -------------------------------------
copy src\blddll.bat src\Debugger\build.bat
cd src\Debugger
call build
del *.exp
del *.obj
del *.bat
copy /y Debugger.dll ..\..\..\Debugger.dll
del *.dll
copy /y plugin.lib ..\..\..\Debugger.lib
del *.lib
cd..
cd..

echo ;
echo -------------------------------------
echo Building Dumper...
echo -------------------------------------
copy src\blddll.bat src\Dumper\build.bat
cd src\Dumper
call build
del *.exp
del *.obj
del *.bat
copy /y Dumper.dll ..\..\..\Dumper.dll
del *.dll
copy /y plugin.lib ..\..\..\Dumper.lib
del *.lib
cd..
cd..

echo ;
echo -------------------------------------
echo Building HideDebugger...
echo -------------------------------------
copy src\blddll.bat src\HideDebugger\build.bat
cd src\HideDebugger
call build
del *.exp
del *.obj
del *.bat
copy /y HideDebugger.dll ..\..\..\HideDebugger.dll
del *.dll
copy /y plugin.lib ..\..\..\HideDebugger.lib
del *.lib
cd..
cd..

echo ;
echo -------------------------------------
echo Building Importer...
echo -------------------------------------
copy src\blddll.bat src\Importer\build.bat
cd src\Importer
call build
del *.exp
del *.obj
del *.bat
copy /y Importer.dll ..\..\..\Importer.dll
del *.dll
copy /y plugin.lib ..\..\..\Importer.lib
del *.lib
cd..
cd..

echo ;
echo -------------------------------------
echo Building Realigner...
echo -------------------------------------
copy src\blddll.bat src\Realigner\build.bat
cd src\Realigner
call build
del *.exp
del *.obj
del *.bat
copy /y Realigner.dll ..\..\..\Realigner.dll
del *.dll
copy /y plugin.lib ..\..\..\Realigner.lib
del *.lib
cd..
cd..

echo .
echo -------------------------------------
echo Building Relocater...
echo -------------------------------------
copy src\blddll.bat src\Relocater\build.bat
cd src\Relocater
call build
del *.exp
del *.obj
del *.bat
copy /y Relocater.dll ..\..\..\Relocater.dll
del *.dll
copy /y plugin.lib ..\..\..\Relocater.lib
del *.lib
cd..
cd..

echo ;
echo -------------------------------------
echo Building Tracer...
echo -------------------------------------
copy src\blddll.bat src\Tracer\build.bat
cd src\Tracer
call build
del *.exp
del *.obj
del *.bat
copy /y Tracer.dll ..\..\..\Tracer.dll
del *.dll
copy /y plugin.lib ..\..\..\Tracer.lib
del *.lib
cd..
cd..

echo ;
echo -------------------------------------
echo Building Updater...
echo -------------------------------------
copy src\blddll.bat src\Updater\build.bat
cd src\Updater
call build
del *.exp
del *.obj
del *.bat
copy /y Updater.dll ..\..\..\Updater.dll
del *.dll
copy /y plugin.lib ..\..\..\Updater.lib
del *.lib
cd..
cd..

echo ;
echo -------------------------------------
echo RevLabs - Build complete!
echo -------------------------------------
@echo on
pause