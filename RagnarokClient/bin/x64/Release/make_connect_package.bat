@echo off
setlocal EnableExtensions

set "RELEASE_DIR=%~dp0"
for %%I in ("%RELEASE_DIR%..\..\..") do set "CLIENT_ROOT=%%~fI"
set "BASE_OUT_ROOT=%USERPROFILE%\Desktop\RagnarokConnectInstances"
set "OUT_ROOT=%BASE_OUT_ROOT%"
set /A OUT_INDEX=1
:pick_output
if not exist "%OUT_ROOT%" goto output_ready
set /A OUT_INDEX+=1
set "OUT_ROOT=%BASE_OUT_ROOT%_%OUT_INDEX%"
goto pick_output

:output_ready
set "OUT_RELEASE=%OUT_ROOT%\bin\x64\Release"
set "OUT_TOOLS=%OUT_ROOT%\tools"

echo [package] target: %OUT_ROOT%
mkdir "%OUT_RELEASE%" || exit /b 1
mkdir "%OUT_TOOLS%" || exit /b 1

copy /Y "%RELEASE_DIR%Ragnarok.exe" "%OUT_RELEASE%\" >nul || exit /b 1
copy /Y "%RELEASE_DIR%Ragnarok.config" "%OUT_RELEASE%\" >nul || exit /b 1
copy /Y "%RELEASE_DIR%connect_only_instances.bat" "%OUT_RELEASE%\" >nul || exit /b 1
copy /Y "%RELEASE_DIR%split_crash_wave_shared_config.bat" "%OUT_RELEASE%\" >nul || exit /b 1
copy /Y "%RELEASE_DIR%kill_ragnarok.bat" "%OUT_RELEASE%\" >nul || exit /b 1
copy /Y "%CLIENT_ROOT%\tools\split_stress_runner.py" "%OUT_TOOLS%\" >nul || exit /b 1

echo [package] done
echo [package] folder: %OUT_ROOT%
pause
