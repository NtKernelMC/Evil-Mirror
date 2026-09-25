@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "LAUNCHER=%~dp0..\..\..\..\RE\tools\start_ragnarok_heap_dump.bat"
if not exist "%LAUNCHER%" (
    echo ERROR: heap dump launcher was not found at "%LAUNCHER%".
    exit /b 1
)
call "%LAUNCHER%" %*
exit /b %ERRORLEVEL%
