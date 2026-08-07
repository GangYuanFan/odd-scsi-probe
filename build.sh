#!/usr/bin/env bash
# odd-scsi-probe GUI — Linux executable build (requires Python 3.8+ and pip)
# Produces dist/odd-probe (single file).
set -euo pipefail
pip install pyinstaller
pyinstaller --onefile --windowed --name odd-probe odd_probe_gui.py
echo "Build OK: dist/odd-probe"
