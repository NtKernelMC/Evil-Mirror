@echo off
setlocal EnableExtensions

set "RELEASE_DIR=%~dp0"
for %%I in ("%RELEASE_DIR%..\..\..") do set "CLIENT_ROOT=%%~fI"

set "RUNNER=%CLIENT_ROOT%\tools\split_stress_runner.py"
set "CLIENT_EXE=%RELEASE_DIR%Ragnarok.exe"
set "CONFIG=%RELEASE_DIR%Ragnarok.config"

set "SERVER=%~1"
if "%SERVER%"=="" for /f "tokens=1,* delims==" %%A in ('findstr /B /I "server=" "%CONFIG%" 2^>nul') do set "SERVER=%%B"
if "%SERVER%"=="" set "SERVER=s1.quant5.com.ua:22005"
set "INSTANCES=%~2"
if "%INSTANCES%"=="" set "INSTANCES=100"
set "MODE=%~3"
if "%MODE%"=="" set "MODE=stress"
set "DURATION=90000"
set "LAUNCH_GAP=0.05"
set "CONNECT_GATE=READY"
set "CONNECT_TIMEOUT=45"
set "CONNECT_RETRIES=5"
set "RETRY_DELAY=10"
set "PREALLOC_SETS=60000"
set "QUEUE_LIMIT=1024"
set "FREE_STOP_MIB=768"
set "REMOTE_ARGS="
set "FUZZER_ARGS="
set "FUZZER_STATE=on"

if /I not "%SERVER%"=="127.0.0.1:22005" set "REMOTE_ARGS=--no-server-monitor --stop-when-clients-exit --min-runtime 8"
if /I "%SERVER%"=="localhost:22005" set "REMOTE_ARGS="
if /I "%SERVER%"=="127.0.0.1:22005" set "REMOTE_ARGS="

if /I "%MODE%"=="nofuzz" set "FUZZER_STATE=off"
if /I "%MODE%"=="connect" set "FUZZER_STATE=off"
if /I "%MODE%"=="off" set "FUZZER_STATE=off"
if /I "%MODE%"=="0" set "FUZZER_STATE=off"

if /I "%FUZZER_STATE%"=="off" set "FUZZER_ARGS=--set split_stress=0 --set split_stress_duplicate_completion=0 --set split_stress_large_count_prealloc=0 --set split_stress_large_fragment_payload=0 --set split_stress_mixed_duplicate_missing=0 --set split_stress_many_split_id=0"

echo [split-crash] server=%SERVER%
echo [split-crash] instances=%INSTANCES%, prealloc_sets=%PREALLOC_SETS%, queue=%QUEUE_LIMIT%
echo [split-crash] mode=%MODE%, fuzzer=%FUZZER_STATE%
echo [split-crash] shared config hardlink source: %CONFIG%
if not "%REMOTE_ARGS%"=="" echo [split-crash] remote mode: local ragemp-server.exe monitor disabled
echo.

py -3 "%RUNNER%" ^
	--profile prealloc ^
	--duration %DURATION% ^
	--interval 0.2 ^
	--print-every 2 ^
	--instances %INSTANCES% ^
	--launch-gap %LAUNCH_GAP% ^
	--auto-reconnect ^
	--launch-confirm-event %CONNECT_GATE% ^
	--connect-timeout %CONNECT_TIMEOUT% ^
	--connect-retries %CONNECT_RETRIES% ^
	--retry-delay %RETRY_DELAY% ^
	--client-limit-mib 8192 ^
	--free-stop-mib %FREE_STOP_MIB% ^
	--server-missing-grace 10 ^
	--server %SERVER% ^
	--link-shared-config ^
	--watch-instance-logs ^
	--client-exe "%CLIENT_EXE%" ^
	--config "%CONFIG%" ^
	--set split_stress_prealloc_sets=%PREALLOC_SETS% ^
	--set split_stress_max_client_queue=%QUEUE_LIMIT% ^
	--set split_stress_sleep_every=0 ^
	--set split_stress_queue_wait_ms=0 ^
	%FUZZER_ARGS% ^
	%REMOTE_ARGS%

echo.
echo [split-crash] done, errorlevel=%ERRORLEVEL%
pause
