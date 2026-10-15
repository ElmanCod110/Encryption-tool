@echo off
setlocal

set "SCRIPT=%~dp0platform\windows\file-association\register.ps1"

if not exist "%SCRIPT%" (
    echo ERROR: Could not find the SPK13 icon registration script.
    echo Expected: "%SCRIPT%"
    pause
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
set "RESULT=%ERRORLEVEL%"

if not "%RESULT%"=="0" (
    echo.
    echo ERROR: SPK13 icon registration failed with exit code %RESULT%.
) else (
    echo.
    echo The SPK13 icon is registered for this Windows user.
    echo It applies to existing and newly created .spk13 files on this PC.
)

pause
exit /b %RESULT%
