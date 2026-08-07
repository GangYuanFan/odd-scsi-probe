#!/usr/bin/env bash
# odd-scsi-probe GUI - Linux executable build (requires Python 3.8+ and pip)
# Produces dist/odd-probe (single file). Mirrors build.bat arguments.
set -euo pipefail

# locate Python
if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi

# ensure PyInstaller
if ! "$PY" -m PyInstaller --version >/dev/null 2>&1; then
  echo "[INFO] PyInstaller not found - installing with pip..."
  "$PY" -m pip install pyinstaller
fi

# assemble arguments (keep in sync with build.bat)
ARGS=(--onefile --windowed --name odd-probe --clean)
if [ -f version_info.txt ]; then ARGS+=(--version-file version_info.txt); fi
for ico in *.ico; do
  if [ -e "$ico" ]; then ARGS+=(--icon "$ico"); break; fi
done

echo "[INFO] Running: $PY -m PyInstaller ${ARGS[*]} odd_probe_gui.py"
"$PY" -m PyInstaller "${ARGS[@]}" odd_probe_gui.py
echo "Build OK: dist/odd-probe"
