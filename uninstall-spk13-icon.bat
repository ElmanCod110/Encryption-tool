@echo off
setlocal

set "SCRIPT=%~dp0platform\windows\file-association\unregister.ps1"

if not exist "%SCRIPT%" (
    echo ERROR: Could not find the SPK13 icon unregistration script.
    echo Expected: "%SCRIPT%"
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
set "RESULT=%ERRORLEVEL%"

if not "%RESULT%"=="0" (
    echo.
    echo ERROR: SPK13 icon unregistration failed with exit code %RESULT%.
)

pause
exit /b %RESULT%
