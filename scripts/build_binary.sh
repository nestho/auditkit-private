#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."

echo "Cleaning old build artifacts..."
rm -rf build dist auditkit.spec cli_entry.spec

echo "Installing/upgrading PyInstaller..."
python3 -m pip install --upgrade pyinstaller

echo "Building standalone AuditKit binary..."
python3 -m PyInstaller \
  --clean \
  --onefile \
  --name auditkit \
  --paths . \
  --collect-all cryptography \
  --hidden-import=auditkit \
  --hidden-import=auditkit.cli \
  --hidden-import=auditkit.batch \
  --hidden-import=auditkit.models \
  --hidden-import=auditkit.report \
  --hidden-import=auditkit.report_batch \
  --hidden-import=auditkit.report_html \
  --hidden-import=auditkit.scoring \
  --hidden-import=auditkit.scanners \
  --hidden-import=auditkit.scanners.passive \
  --hidden-import=auditkit.scanners.http_metadata \
  --hidden-import=auditkit.license \
  --hidden-import=auditkit.license.offline \
  --hidden-import=auditkit.license.gate \
  cli_entry.py

echo ""
echo "Binary created:"
echo "  dist/auditkit"
