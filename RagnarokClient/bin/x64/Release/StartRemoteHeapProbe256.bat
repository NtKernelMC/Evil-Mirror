@echo off
call "%~dp0StartRemoteHeapDump.bat" %*
exit /b %ERRORLEVEL%
