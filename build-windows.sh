#!/usr/bin/env bash
# odd-scsi-probe - build dist\odd-probe.exe on Windows from WSL (interop).
#
# Why a Windows-native temp dir? CMD/PyInstaller cannot reliably write into
# \\wsl.localhost (9P) mounts from Windows (permission mapping denies writes
# to WSL-owned files), so the build runs in %TEMP%\odd-build on the Windows
# side, then dist\odd-probe.exe is copied back into this repo's dist/.
#
# Requires: WSL interop enabled + a Windows Python 3.8+ (build.bat auto-detects).
# Usage: ./build-windows.sh   (run from the repo root)
set -euo pipefail

CMD=/mnt/c/Windows/System32/cmd.exe
[ -x "$CMD" ] || { echo "[ERROR] $CMD not found - WSL interop disabled?"; exit 1; }

# Resolve Windows %TEMP% (e.g. C:\Users\jerry\AppData\Local\Temp) and map it
# to a WSL mount path for copying files in/out.
WIN_TEMP=$("$CMD" /c "echo %TEMP%" 2>/dev/null | tr -d '\r' | tail -1)
[ -n "$WIN_TEMP" ] || { echo "[ERROR] could not resolve Windows %%TEMP%%"; exit 1; }
WIN_BUILD="$WIN_TEMP\\odd-build"
WSL_BUILD="$(printf '%s' "$WIN_TEMP" | sed 's|\\|/|g; s|^C:|/mnt/c|')/odd-build"

echo "[INFO] Windows build dir: $WIN_BUILD"

# 1. fresh Windows-side build dir (create/clear from the WSL side: writing
#    from WSL into /mnt/c works; the reverse 9P direction does not)
rm -rf "$WSL_BUILD"
mkdir -p "$WSL_BUILD"

# 2. copy repo (no .git / build artifacts) into it
tar -C "$PWD" \
  --exclude=.git --exclude=__pycache__ --exclude=build \
  --exclude=dist --exclude=.shots --exclude='*.spec' \
  -cf - . | tar -xf - -C "$WSL_BUILD"

# 3. run the Windows build (no inner quotes: WSL interop mangles embedded
#    quotes when rebuilding the Win32 command line; the path has no spaces)
"$CMD" /c "cd /d $WIN_BUILD && build.bat" || { echo "[ERROR] Windows build failed"; exit 1; }

# 4. copy the exe back into this repo
mkdir -p dist
cp "$WSL_BUILD/dist/odd-probe.exe" dist/odd-probe.exe
SIZE=$(stat -c %s dist/odd-probe.exe)
echo "[INFO] Copied back: $PWD/dist/odd-probe.exe ($SIZE bytes)"
