@echo off
setlocal
set "SCRIPT=%~dp0platform\windows\file-association\install-from-package.ps1"
if not exist "%SCRIPT%" (
  echo ERROR: Embedded-icon installer was not found.
  pause
  exit /b 1
)
set "PACKAGE=%~1"
if "%PACKAGE%"=="" set /p "PACKAGE=Full path to a .spk13 package with embedded icon: "
if "%PACKAGE%"=="" (
  echo ERROR: No package path was provided.
  pause
  exit /b 2
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -PackagePath "%PACKAGE%"
set "RESULT=%ERRORLEVEL%"
if not "%RESULT%"=="0" (
  echo ERROR: Icon installation failed with exit code %RESULT%.
) else (
  echo Embedded icon registered for this Windows user.
  echo Repeat on each PC where Windows Explorer should show the icon.
)
pause
exit /b %RESULT%
