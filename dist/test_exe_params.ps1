# Test a tappeto di tutti i parametri del progetto.
#
# Strategia:
#   FASE 1 – Python source  : testa TUTTA la logica CLI direttamente (< 1s/test, nessuna estrazione)
#   FASE 2 – Exe (3 test)   : verifica che le importazioni critiche non crashino nell'exe confezionato
#                              (richiede ~90-120s per la prima estrazione per ciascun test)
#
# Uso:
#   cd C:\Progetti\AI-Privacy-Anonymizer\dist
#   .\test_exe_params.ps1

$ErrorActionPreference = "Continue"
$root    = Split-Path -Parent $PSScriptRoot
$cli     = "$root\src\privacy_anonymizer\cli.py"
$exe     = "$PSScriptRoot\privacy-anonymizer.exe"
$python  = (Get-Command python -ErrorAction SilentlyContinue)?.Source
if (-not $python) { $python = "python" }

$sample  = "Mario Rossi abita a Roma, tel 02-12345678, email mario.rossi@example.com, CF MRIRSS80A01H501Z"
$results = [System.Collections.Generic.List[pscustomobject]]::new()
$tmpTxt  = "$env:TEMP\pa_input.txt"
$tmpVault= "$env:TEMP\pa_vault.json"
$tmpAnon = "$env:TEMP\pa_anon.txt"

Set-Content $tmpTxt  "Mario Rossi, via Roma 10, tel 02-123456, mario@example.com" -Encoding UTF8
Set-Content $tmpAnon "[PII_NAME_1] abita a [PII_ADDRESS_1]" -Encoding UTF8

# ── runner generici ───────────────────────────────────────────────────────────
function Invoke-PyTest {
    param([string]$Name, [string[]]$ArgList)
    $out  = & $python $cli @ArgList 2>&1
    $code = $LASTEXITCODE
    $text = $out -join "`n"

    $crashed = ($text -match "Traceback|Error:|Exception") -and ($code -ne 0 -and $code -ne 2)
    $status  = if ($crashed) { "FAIL" } else { "OK  " }
    $color   = if ($crashed) { "Red"  } else { "Green" }
    $errline = if ($crashed) {
        ($text -split "`n" | Where-Object { $_ -match "Error:|Exception" } | Select-Object -First 1).Trim()
    } else { "" }

    Write-Host "[$status] $Name" -ForegroundColor $color
    if ($errline) { Write-Host "       $errline" -ForegroundColor Yellow }

    $r = [PSCustomObject]@{ Mode="py"; Name=$Name; Status=$status.Trim(); Exit=$code; Error=$errline }
    $results.Add($r); return $r
}

function Invoke-ExeTest {
    param([string]$Name, [string[]]$ArgList, [int]$TimeoutSec = 200, [switch]$Server)

    $job = Start-Job -ScriptBlock {
        param($exePath, $argList)
        $out = & $exePath @argList 2>&1
        [PSCustomObject]@{ ExitCode = $LASTEXITCODE; Output = ($out -join "`n") }
    } -ArgumentList $exe, $ArgList

    $done = Wait-Job $job -Timeout $TimeoutSec
    if (-not $done) {
        Stop-Job $job; Remove-Job $job -Force
        if ($Server) {
            # Server processes (--webui, --api) never exit on their own: timeout = started OK
            Write-Host "[OK  ] $Name  (server running, killed after ${TimeoutSec}s)" -ForegroundColor Green
            $r = [PSCustomObject]@{ Mode="exe"; Name=$Name; Status="OK"; Exit=0; Error="" }
        } else {
            Write-Host "[TIMEOUT] $Name  (${TimeoutSec}s)" -ForegroundColor Yellow
            $r = [PSCustomObject]@{ Mode="exe"; Name=$Name; Status="TIMEOUT"; Exit=-999; Error="Timed out after ${TimeoutSec}s" }
        }
        $results.Add($r); return $r
    }

    $data   = Receive-Job $job; Remove-Job $job -Force
    $out    = if ($data) { $data.Output } else { "" }
    $code   = if ($data) { $data.ExitCode } else { -1 }

    $crashed = ($out -match "\[PYI-\d+:ERROR\]|FileNotFoundError|ModuleNotFoundError|ImportError")
    $status  = if ($crashed) { "FAIL" } else { "OK  " }
    $color   = if ($crashed) { "Red"  } else { "Green" }
    $errline = if ($crashed) {
        ($out -split "`n" | Where-Object { $_ -match "Error:|PYI-|FileNotFound|ModuleNotFound" } | Select-Object -First 1).Trim()
    } else { "" }

    Write-Host "[$status] $Name  (exit $code)" -ForegroundColor $color
    if ($errline) { Write-Host "       $errline" -ForegroundColor Yellow }

    $r = [PSCustomObject]@{ Mode="exe"; Name=$Name; Status=$status.Trim(); Exit=$code; Error=$errline }
    $results.Add($r); return $r
}

# ════════════════════════════════════════════════════════════════════════════
# FASE 1 — PYTHON SOURCE (logica, nessuna estrazione)
# ════════════════════════════════════════════════════════════════════════════
Write-Host "`n╔══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║  FASE 1: Python source (logica parametri)    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`n=== INFO / SETUP ===" -ForegroundColor Cyan
Invoke-PyTest "--supported-formats"   @("--supported-formats")   | Out-Null
Invoke-PyTest "--setup"               @("--setup")               | Out-Null
Invoke-PyTest "--download-models"     @("--download-models")     | Out-Null
Invoke-PyTest "--wipe-cache"          @("--wipe-cache")          | Out-Null

Write-Host "`n=== --text BASE ===" -ForegroundColor Cyan
Invoke-PyTest "--text pattern-only"        @("--text", $sample, "--pattern-only")               | Out-Null
Invoke-PyTest "--text --json"              @("--text", $sample, "--pattern-only", "--json")      | Out-Null
Invoke-PyTest "--text --show-map"          @("--text", $sample, "--pattern-only", "--show-map")  | Out-Null
Invoke-PyTest "--text --dry-run"           @("--text", $sample, "--pattern-only", "--dry-run")   | Out-Null

Write-Host "`n=== --mode ===" -ForegroundColor Cyan
Invoke-PyTest "--mode replace"  @("--text", $sample, "--pattern-only", "--mode", "replace") | Out-Null
Invoke-PyTest "--mode redact"   @("--text", $sample, "--pattern-only", "--mode", "redact")  | Out-Null
Invoke-PyTest "--mode hash"     @("--text", $sample, "--pattern-only", "--mode", "hash")    | Out-Null
Invoke-PyTest "--mode fake"     @("--text", $sample, "--pattern-only", "--mode", "fake")    | Out-Null

Write-Host "`n=== --recall-mode ===" -ForegroundColor Cyan
Invoke-PyTest "--recall-mode conservative" @("--text",$sample,"--pattern-only","--recall-mode","conservative") | Out-Null
Invoke-PyTest "--recall-mode balanced"     @("--text",$sample,"--pattern-only","--recall-mode","balanced")     | Out-Null
Invoke-PyTest "--recall-mode aggressive"   @("--text",$sample,"--pattern-only","--recall-mode","aggressive")   | Out-Null

Write-Host "`n=== --disable-layer ===" -ForegroundColor Cyan
Invoke-PyTest "--disable-layer opf+gliner" @("--text",$sample,"--disable-layer","opf","--disable-layer","gliner") | Out-Null
Invoke-PyTest "--disable-layer pattern"    @("--text",$sample,"--pattern-only","--disable-layer","pattern")         | Out-Null

Write-Host "`n=== FLAG ESECUZIONE ===" -ForegroundColor Cyan
Invoke-PyTest "--low-memory"       @("--text", $sample, "--pattern-only", "--low-memory")           | Out-Null
Invoke-PyTest "--no-parallel"      @("--text", $sample, "--pattern-only", "--no-parallel")          | Out-Null
Invoke-PyTest "--device cpu"       @("--text", $sample, "--pattern-only", "--device", "cpu")        | Out-Null
Invoke-PyTest "--log (auto path)"  @("--text", $sample, "--pattern-only", "--log")                  | Out-Null

Write-Host "`n=== CHUNKING ===" -ForegroundColor Cyan
Invoke-PyTest "--no-chunk-long-text" @("--text",$sample,"--pattern-only","--no-chunk-long-text")                           | Out-Null
Invoke-PyTest "--chunk-threshold"    @("--text",$sample,"--pattern-only","--chunk-threshold","100")                        | Out-Null
Invoke-PyTest "--chunk-size/overlap" @("--text",$sample,"--pattern-only","--chunk-size","500","--chunk-overlap","50")      | Out-Null
Invoke-PyTest "--chunk-max-workers"  @("--text",$sample,"--pattern-only","--chunk-max-workers","2")                        | Out-Null

Write-Host "`n=== ML SKIP ===" -ForegroundColor Cyan
Invoke-PyTest "--ml-skip-extensions" @("--text",$sample,"--pattern-only","--ml-skip-extensions",".txt") | Out-Null
Invoke-PyTest "--ml-skip-min-chars"  @("--text",$sample,"--pattern-only","--ml-skip-min-chars","100")   | Out-Null

Write-Host "`n=== FILE INPUT ===" -ForegroundColor Cyan
Invoke-PyTest "file (txt) --dry-run"     @($tmpTxt,"--pattern-only","--dry-run")                                                | Out-Null
Invoke-PyTest "file --output dir"        @($tmpTxt,"--pattern-only","--dry-run","--output",$env:TEMP)                           | Out-Null
Invoke-PyTest "file --keep-metadata"     @($tmpTxt,"--pattern-only","--dry-run","--keep-metadata")                              | Out-Null
Invoke-PyTest "file --show-map"          @($tmpTxt,"--pattern-only","--dry-run","--show-map")                                   | Out-Null
Invoke-PyTest "file --json"              @($tmpTxt,"--pattern-only","--json")                                                   | Out-Null
Invoke-PyTest "file --compliance-report" @($tmpTxt,"--pattern-only","--dry-run","--compliance-report","$env:TEMP\pa_comp.pdf") | Out-Null

Write-Host "`n=== VAULT / RESTORE ===" -ForegroundColor Cyan
Invoke-PyTest "--export-vault" @("--text",$sample,"--pattern-only","--mode","hash","--export-vault",$tmpVault) | Out-Null
if (Test-Path $tmpVault) {
    Invoke-PyTest "--restore" @($tmpAnon, "--restore", $tmpVault) | Out-Null
} else {
    Write-Host "  (vault non generato, skip restore)" -ForegroundColor DarkYellow
}

Write-Host "`n=== EVALUATION ===" -ForegroundColor Cyan
Invoke-PyTest "--generate-synthetic-dataset" @("--generate-synthetic-dataset","$env:TEMP\pa_synth.jsonl") | Out-Null
if (Test-Path "$env:TEMP\pa_synth.jsonl") {
    Invoke-PyTest "--evaluate" @("--evaluate","$env:TEMP\pa_synth.jsonl","--pattern-only") | Out-Null
} else {
    Write-Host "  (dataset non generato, skip evaluate)" -ForegroundColor DarkYellow
}

# ════════════════════════════════════════════════════════════════════════════
# FASE 2 — EXE (verifica importazioni critiche nell'eseguibile confezionato)
# Ogni test avvia l'exe che estrae ~2.7GB: atteso ~90-120s per estrazione.
# ════════════════════════════════════════════════════════════════════════════
Write-Host "`n╔══════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║  FASE 2: Exe – import crash test (200s/test) ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════════════╝" -ForegroundColor Magenta

Invoke-ExeTest "exe --supported-formats" @("--supported-formats")  | Out-Null
Invoke-ExeTest "exe --webui (gradio)"    @("--webui") -Server      | Out-Null
Invoke-ExeTest "exe --api (fastapi)"     @("--api")   -Server      | Out-Null

# ── Pulizia dir _pa_runtime residue ──────────────────────────────────────────
$paRuntime = "$PSScriptRoot\_pa_runtime"
if (Test-Path $paRuntime) {
    Write-Host "`nPulizia $paRuntime ..." -ForegroundColor DarkGray
    Remove-Item $paRuntime -Recurse -Force -ErrorAction SilentlyContinue
}

# ── Riepilogo ─────────────────────────────────────────────────────────────────
$failures = $results | Where-Object { $_.Status -in @("FAIL","TIMEOUT") }
$pass_n   = ($results | Where-Object { $_.Status -eq "OK" }).Count
$fail_n   = $failures.Count

Write-Host "`n════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  PASS: $pass_n    FAIL/TIMEOUT: $fail_n    TOTAL: $($results.Count)" -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan

if ($fail_n -gt 0) {
    Write-Host "`nDETTAGLIO FALLIMENTI:" -ForegroundColor Red
    foreach ($f in $failures) {
        Write-Host "  [$($f.Mode.ToUpper()) $($f.Status)] $($f.Name)  (exit $($f.Exit))" -ForegroundColor Red
        if ($f.Error) { Write-Host "    $($f.Error)" -ForegroundColor Yellow }
    }
}

$report = "$PSScriptRoot\test_exe_results.txt"
($results | Format-Table Mode, Name, Status, Exit, Error -AutoSize | Out-String).Trim() | Set-Content $report
Write-Host "`nReport: $report" -ForegroundColor Cyan
