@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "RELEASE=%~dp0"
set "BYTES=%~1"
set "INTERVAL_MS=%~2"
set "DUMP_DIR=%~3"
set "TARGET="

if "%BYTES%"=="" set "BYTES=65535"
if "%INTERVAL_MS%"=="" set "INTERVAL_MS=5000"
if "%DUMP_DIR%"=="" set "DUMP_DIR=%RELEASE%remote-heap-dumps"

if not exist "%RELEASE%Ragnarok.exe" (
    echo ERROR: Ragnarok.exe is missing from the Release folder.
    exit /b 1
)
if not exist "%RELEASE%Ragnarok.config" (
    echo ERROR: Ragnarok.config is missing from the Release folder.
    exit /b 1
)

for /f "usebackq tokens=1,* delims==" %%A in ("%RELEASE%Ragnarok.config") do (
    if /I "%%A"=="server" set "TARGET=%%B"
)
if "%TARGET%"=="" (
    echo ERROR: server= is missing from Ragnarok.config.
    exit /b 1
)

echo Target from Ragnarok.config: %TARGET%
echo Event: biz.order.add to biz.order.ans
echo Claim per packet: %BYTES% bytes; interval: %INTERVAL_MS% ms
echo Captures: "%DUMP_DIR%"
echo Press q or ESC in Ragnarok, or close its window, to stop.

"%RELEASE%Ragnarok.exe" "" biz_order_dump_remote "%BYTES%" "%INTERVAL_MS%" "%DUMP_DIR%"
exit /b %ERRORLEVEL%
