@echo off
setlocal
cd /d "%~dp0"
app-divert.exe -check -config "%~dp0config.json"
if errorlevel 1 goto failed
powershell.exe -NoProfile -Command "Start-Process -FilePath (Join-Path (Get-Location) 'app-divert.exe') -Verb RunAs -WorkingDirectory (Get-Location)"
if errorlevel 1 goto failed
exit /b 0
:failed
echo Startup failed. Check configuration and administrator approval.
pause
exit /b 1
