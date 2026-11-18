# Installs the latest mancar client on Windows (no administrator needed):
#
#   irm https://raw.githubusercontent.com/tinoimammp/mancar/main/scripts/install.ps1 | iex
#
# It checks the download against the release's SHA256SUMS, installs it to
# %LOCALAPPDATA%\Programs\mancar and adds that folder to your PATH.
$ErrorActionPreference = "Stop"
$base = "https://github.com/tinoimammp/mancar/releases/latest/download"
$dir  = Join-Path $env:LOCALAPPDATA "Programs\mancar"

$sums = (Invoke-WebRequest "$base/SHA256SUMS" -UseBasicParsing).Content
if ($sums -is [byte[]]) { $sums = [Text.Encoding]::ASCII.GetString($sums) }
$m = [regex]::Match($sums, '([0-9a-f]{64})\s+(mancar-v\S+-windows-amd64\.exe)')
if (-not $m.Success) { throw "the latest release has no Windows build" }
$file = $m.Groups[2].Value

Write-Host "Downloading $file ..."
New-Item -ItemType Directory -Force $dir | Out-Null
$tmp = Join-Path $dir "mancar.download"
Invoke-WebRequest "$base/$file" -OutFile $tmp -UseBasicParsing
if ((Get-FileHash $tmp -Algorithm SHA256).Hash.ToLower() -ne $m.Groups[1].Value) {
    Remove-Item $tmp
    throw "checksum mismatch; nothing was installed"
}
Move-Item -Force $tmp (Join-Path $dir "mancar.exe")

$path = [Environment]::GetEnvironmentVariable("Path", "User")
if (($path -split ";") -notcontains $dir) {
    [Environment]::SetEnvironmentVariable("Path", "$path;$dir", "User")
}
$env:Path = "$env:Path;$dir"   # this window too

Write-Host "Installed $dir\mancar.exe"
& (Join-Path $dir "mancar.exe") version
Write-Host "Next: mancar login https://YOUR_SERVER   (new windows find mancar on the PATH)"
