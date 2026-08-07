@echo off
setlocal
REM ============================================================================
REM  odd-scsi-probe GUI - Windows single-file executable build
REM  Produces: dist\odd-probe.exe  (GUI app, no console window)
REM  Requires: Python 3.8+ (python.org installer; "py launcher" recommended)
REM
REM  Usage:
REM    - double-click build.bat in Explorer, or run from cmd:  build.bat
REM    - from WSL (this repo lives on the Linux side):
REM        cmd.exe /c "pushd \\wsl.localhost\Ubuntu\...\odd-scsi-probe && build.bat"
REM      (CMD cannot start with a UNC path as its working directory, so we
REM       pushd to map it to a drive letter first. See README "Windows 編譯指南".)
REM ============================================================================

chcp 65001 >nul

if not exist odd_probe_gui.py (
  echo [ERROR] odd_probe_gui.py not found in the current directory.
  echo         Run this script from the odd-scsi-probe repo root.
  echo.
  echo         Note: CMD cannot start from a UNC path like \wsl.localhost\...
  echo         From WSL use:
  echo           cmd.exe /c "pushd \\wsl.localhost\Ubuntu\...\odd-scsi-probe ^&^& build.bat"
  echo         or copy the repo to a Windows drive and run build.bat there.
  exit /b 1
)

REM ---- locate Python: try py launcher, then python, then python3 ----
set "PY_CMD="
py -3 -c "import sys" >nul 2>&1 && set "PY_CMD=py -3"
if not defined PY_CMD (
  python -c "import sys" >nul 2>&1 && set "PY_CMD=python"
)
if not defined PY_CMD (
  python3 -c "import sys" >nul 2>&1 && set "PY_CMD=python3"
)
if not defined PY_CMD (
  echo [ERROR] Python 3.8+ not found.
  echo         Install it from https://www.python.org/downloads/ and tick
  echo         "Add python.exe to PATH" or install the py launcher.
  exit /b 1
)
for /f "delims=" %%v in ('%PY_CMD% -c "import sys;print(sys.version.split()[0])"') do set "PYVER=%%v"
echo [INFO] Python %PYVER% via: %PY_CMD%

REM ---- ensure PyInstaller ----
%PY_CMD% -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
  echo [INFO] PyInstaller not found - installing with pip...
  %PY_CMD% -m pip install pyinstaller
  if errorlevel 1 goto :error
)

REM ---- assemble PyInstaller arguments ----
set "ARGS=--onefile --windowed --name odd-probe --clean"
if exist version_info.txt set "ARGS=%ARGS% --version-file version_info.txt"
set "ICON="
for /f "delims=" %%i in ('dir /b *.ico 2^>nul') do set "ICON=%%i"
if defined ICON set "ARGS=%ARGS% --icon %ICON%"

echo [INFO] Running: %PY_CMD% -m PyInstaller %ARGS% odd_probe_gui.py
%PY_CMD% -m PyInstaller %ARGS% odd_probe_gui.py
if errorlevel 1 goto :error

if not exist dist\odd-probe.exe (
  echo [ERROR] dist\odd-probe.exe was not produced.
  exit /b 1
)
for %%f in (dist\odd-probe.exe) do set "SIZE=%%~zf"
echo.
echo ============================================================
echo  BUILD OK: %CD%\dist\odd-probe.exe  (%SIZE% bytes)
echo ============================================================
exit /b 0

:error
echo.
echo [ERROR] Build failed - see messages above.
exit /b 1
