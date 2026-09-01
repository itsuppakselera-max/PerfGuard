@echo off
title PerfGuard
cd /d "%~dp0"
rem %~dp0 must be captured before any shift: in batch, shift moves %0 too.
set "HERE=%~dp0"

rem Files copied from a USB stick or a network share carry Mark-of-the-Web,
rem which makes PowerShell refuse them. Clear it on THIS TOOL'S OWN FILES only.
rem Stripping it recursively would silently disarm SmartScreen and the Office
rem macro block for anything else that happens to be sitting in this folder.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Unblock-File -LiteralPath '%HERE%PerfGuard.ps1','%HERE%PerfGuard.cmd','%HERE%Start.cmd'" >nul 2>&1

:menu
cls
echo.
echo   PerfGuard - CPU 100%%, lag dan freeze
echo   ======================================================
echo.
echo    MENCARI PENYEBAB
echo     1   Status     siapa yang makan CPU dan RAM sekarang
echo     2   Watch      pantau + catat spike dan freeze (tidak mengubah apa pun)
echo     3   Report     rangkuman: siapa biang keroknya
echo     4   Export     laporan HTML + TXT untuk tiket
echo.
echo    MENGATASI
echo     5   Optimize   SEMUA SEKALIGUS: scan, perbaiki, jaga plafon 80%%
echo     6   Ceiling    tahan CPU dan RAM maksimal 80%%
echo     7   Guard      anti-lag: cegah macet sebelum terjadi
echo     8   Relieve    redakan sekarang, sekali jalan
echo     9   Auto       pantau + redakan otomatis + bersihkan RAM di 80%%
echo    10   MemClear   bersihkan RAM sekarang, manual (butuh admin)
echo    11   Restore    kembalikan semua proses ke normal
echo.
echo    PENGATURAN
echo    12   Tune       audit penyebab lag di level sistem
echo    13   Profile    scan ulang mesin ini
echo    14   Help
echo     0   Keluar
echo.
set "c="
set /p "c=  Pilih: "

if "%c%"=="1"  ( call :run status  & goto menu )
if "%c%"=="2"  ( goto watch )
if "%c%"=="3"  ( call :run report  & goto menu )
if "%c%"=="4"  ( goto export )
if "%c%"=="5"  ( call :run optimize & goto menu )
if "%c%"=="6"  ( call :run ceiling  & goto menu )
if "%c%"=="7"  ( goto guard )
if "%c%"=="8"  ( call :run relieve & goto menu )
if "%c%"=="9"  ( call :run auto    & goto menu )
if "%c%"=="10" ( goto memclear )
if "%c%"=="11" ( call :run restore & goto menu )
if "%c%"=="12" ( goto tune )
if "%c%"=="13" ( call :run profile & goto menu )
if "%c%"=="14" ( call :run help    & goto menu )
if "%c%"=="0"  ( exit /b 0 )
goto menu

:watch
cls
echo.
echo   Watch hanya memantau dan mencatat. Tidak ada yang diubah.
echo   Biarkan berjalan saat PC dipakai normal, lalu pilih Report atau Export.
echo.
set "d="
set /p "d=  Berapa menit? (kosongkan = sampai Ctrl+C): "
if "%d%"=="" ( call :run watch & goto menu )
set /a "s=%d%*60" 2>nul
if not defined s goto watch
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%PerfGuard.ps1" -Mode watch -Seconds %s%
echo.
pause
goto menu

:guard
cls
echo.
echo   GUARD - mode anti-lag.
echo.
echo   Bekerja mencegah, bukan bereaksi:
echo     - aplikasi yang sedang dipakai diprioritaskan otomatis
echo     - aplikasi background ditahan terus, bukan hanya saat CPU sudah penuh
echo     - bertindak di ambang lebih rendah, sebelum stutter terjadi
echo     - mencatat aplikasi yang berhenti merespons (freeze)
echo.
echo   Semua dikembalikan normal saat ditutup dengan Ctrl+C.
echo.
set "d="
set /p "d=  Berapa menit? (kosongkan = sampai Ctrl+C): "
if "%d%"=="" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%PerfGuard.ps1" -Mode guard
  echo.
  pause
  goto menu
)
set /a "s=%d%*60" 2>nul
if not defined s goto guard
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%PerfGuard.ps1" -Mode guard -Seconds %s%
echo.
pause
goto menu

:memclear
cls
echo.
echo   MEMCLEAR - setara menu Empty di RAMMap. BUTUH ADMINISTRATOR.
echo.
echo   Set standar (aman):
echo     - Empty Working Sets
echo     - Empty System Working Set
echo     - Empty Modified Page List
echo     - Empty Priority 0 Standby List
echo.
echo   Empty Standby List TIDAK termasuk: itu membuang seluruh cache disk
echo   mesin, jadi setiap baca berikutnya kembali ke disk. Pilih y di bawah
echo   hanya kalau standby list memang macet (mis. setelah copy file besar).
echo.
set "g="
set /p "g=  Sertakan Empty Standby List juga? (y/N): "
if /i "%g%"=="y" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%PerfGuard.ps1" -Mode memclear -Purge
) else (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%PerfGuard.ps1" -Mode memclear
)
echo.
pause
goto menu

:tune
cls
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%PerfGuard.ps1" -Mode tune
echo.
echo   ------------------------------------------------------
set "a="
set /p "a=  Terapkan perbaikan otomatis yang aman? (y/N): "
if /i "%a%"=="y" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%PerfGuard.ps1" -Mode tune -Apply
)
echo.
pause
goto menu

:export
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%PerfGuard.ps1" -Mode export
echo.
echo   Membuka folder laporan...
start "" "%HERE%logs"
echo.
pause
goto menu

:run
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%HERE%PerfGuard.ps1" -Mode %1
echo.
pause
exit /b 0
