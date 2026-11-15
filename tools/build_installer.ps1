# Rebuilds the browser web-installer artefacts in docs/ from a clean copy of
# the sources that uses src/secrets.example.h (placeholder credentials) - the
# maintainer's real WiFi/admin secrets must never end up in the public
# firmware.bin.
#
#   powershell -ExecutionPolicy Bypass -File tools/build_installer.ps1
#
# Produces/refreshes: docs/bootloader.bin, docs/partitions.bin,
# docs/boot_app0.bin, docs/firmware.bin, docs/littlefs.bin (partition table and
# offsets match docs/manifest.json - update both together if parts change).
param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$WorkDir     = (Join-Path $env:TEMP 'opencode\installer-build')
)
$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path $ProjectRoot).Path
$docs = Join-Path $ProjectRoot 'docs'
Write-Host "project : $ProjectRoot"
Write-Host "work dir: $WorkDir"

if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
New-Item -ItemType Directory -Path $WorkDir | Out-Null

# Copy the tree without build output, VCS metadata or local logs.
$rcArgs = @($ProjectRoot, $WorkDir, '/E', '/NFL', '/NDL', '/NJH', '/NJS', '/NP',
            '/XD', '.pio', '.git', '.vscode', '__pycache__', '/XF', 'build*.log')
& robocopy @rcArgs | Out-Null
if ($LASTEXITCODE -ge 8) { throw "robocopy failed ($LASTEXITCODE)" }

# Placeholder secrets: no real credentials may leak into the public image.
Copy-Item (Join-Path $WorkDir 'src\secrets.example.h') (Join-Path $WorkDir 'src\secrets.h') -Force
Write-Host 'secrets : using secrets.example.h placeholders'

$env:PYTHONIOENCODING = 'utf-8'
Push-Location $WorkDir
try {
    & pio run -t buildfs | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "buildfs failed ($LASTEXITCODE)" }
    & pio run | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }
} finally { Pop-Location }

$build = Join-Path $WorkDir '.pio\build\c3'
$bootApp0 = Join-Path $env:USERPROFILE '.platformio\packages\framework-arduinoespressif32\tools\partitions\boot_app0.bin'

Copy-Item (Join-Path $build 'bootloader.bin')  (Join-Path $docs 'bootloader.bin')  -Force
Copy-Item (Join-Path $build 'partitions.bin')  (Join-Path $docs 'partitions.bin')  -Force
Copy-Item (Join-Path $build 'firmware.bin')    (Join-Path $docs 'firmware.bin')    -Force
Copy-Item (Join-Path $build 'littlefs.bin')    (Join-Path $docs 'littlefs.bin')    -Force
if (Test-Path $bootApp0) {
    Copy-Item $bootApp0 (Join-Path $docs 'boot_app0.bin') -Force
} else {
    Write-Warning "boot_app0.bin not found at $bootApp0 - docs/ keeps the previous copy"
}

Get-ChildItem $docs -Filter *.bin | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
Write-Host 'installer artefacts refreshed in docs/'
