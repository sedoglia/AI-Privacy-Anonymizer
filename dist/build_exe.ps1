# Build standalone .exe via PyInstaller (Windows, PowerShell)
#
# Prerequisiti:
#   python -m pip install pyinstaller
#   python -m pip install -e ".[recommended]"
#
# Output: dist/privacy-anonymizer.exe

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Push-Location $root
try {
    Write-Host "Building privacy-anonymizer.exe ..."
    pyinstaller --clean --noconfirm packaging/privacy_anonymizer.spec
    Write-Host "Done. Binary at: dist/privacy-anonymizer.exe"
}
finally {
    Pop-Location
}
