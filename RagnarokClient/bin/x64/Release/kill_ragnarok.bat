@echo off
setlocal EnableExtensions

echo [kill-ragnarok] closing all Ragnarok.exe processes...
taskkill /F /T /IM Ragnarok.exe 2>nul

if errorlevel 1 (
	echo [kill-ragnarok] no Ragnarok.exe processes found
) else (
	echo [kill-ragnarok] done
)

pause
