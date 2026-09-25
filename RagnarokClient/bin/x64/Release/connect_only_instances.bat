@echo off
setlocal EnableExtensions

set "SERVER=%~1"
if "%SERVER%"=="" set "s1.radmirv.com:22005"
set "INSTANCES=%~2"
if "%INSTANCES%"=="" set "INSTANCES=300"

call "%~dp0split_crash_wave_shared_config.bat" "%SERVER%" "%INSTANCES%" nofuzz
