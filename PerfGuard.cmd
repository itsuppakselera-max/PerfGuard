@echo off
setlocal
rem %~dp0 MUST be captured before any shift: in batch, shift moves %0 as well,
rem so after shifting %~dp0 resolves against the argument instead of this file.
set "HERE=%~dp0"

set "MODE=%~1"
if "%MODE%"=="" set "MODE=status"
if not "%MODE%"=="" shift

set "REST="
:collect
if "%~1"=="" goto run
set "REST=%REST% %1"
shift
goto collect

:run
if not exist "%HERE%PerfGuard.ps1" (
  echo PerfGuard.ps1 tidak ditemukan di "%HERE%"
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%PerfGuard.ps1" -Mode %MODE%%REST%
endlocal
