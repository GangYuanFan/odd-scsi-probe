@echo off
REM odd-scsi-probe GUI — Windows executable build (requires Python 3.8+ on PATH)
REM Produces dist\odd-probe.exe (single file, no console window).
pip install pyinstaller || goto :error
pyinstaller --onefile --windowed --name odd-probe odd_probe_gui.py || goto :error
echo.
echo Build OK: dist\odd-probe.exe
exit /b 0
:error
echo Build failed.
exit /b 1
