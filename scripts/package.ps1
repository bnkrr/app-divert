param(
  [string]$Output = (Join-Path $PSScriptRoot '../dist/windows-amd64')
)
$ErrorActionPreference = 'Stop'
$project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('app-divert-package-' + [guid]::NewGuid().ToString('N'))
$saved = @{}
foreach ($name in @('GOOS','GOARCH','CGO_ENABLED','GOWORK')) {
  $saved[$name] = [Environment]::GetEnvironmentVariable($name,'Process')
}
New-Item -ItemType Directory -Force $scratch | Out-Null
try {
  $env:GOOS = 'windows'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
  $env:GOWORK = 'off'
  $Output = [IO.Path]::GetFullPath($Output)
  New-Item -ItemType Directory -Force $Output | Out-Null
  Push-Location $project
  try {
    & go build -trimpath -o (Join-Path $Output 'app-divert.exe') ./cmd/app-divert
    if ($LASTEXITCODE -ne 0) { throw 'app-divert build failed' }
  } finally { Pop-Location }
  $archive = Join-Path $scratch 'WinDivert.zip'
  Invoke-WebRequest 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip' -OutFile $archive
  $expected = '63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15'
  if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
    throw 'Official WinDivert archive SHA-256 mismatch'
  }
  Expand-Archive $archive -DestinationPath $scratch
  $runtime = Join-Path $scratch 'WinDivert-2.2.2-A'
  $driver = Join-Path $runtime 'x64/WinDivert64.sys'
  if ((Get-AuthenticodeSignature $driver).Status -ne 'Valid') {
    throw 'WinDivert64.sys signature is not valid on this Windows machine'
  }
  Copy-Item (Join-Path $runtime 'x64/WinDivert.dll'),$driver -Destination $Output
  Copy-Item (Join-Path $runtime 'LICENSE') (Join-Path $Output 'WinDivert-LICENSE.txt')
  Copy-Item (Join-Path $runtime 'README') (Join-Path $Output 'WinDivert-README.txt')
  Copy-Item (Join-Path $project 'LICENSE') (Join-Path $Output 'LICENSE')
  Copy-Item (Join-Path $project 'THIRD_PARTY_NOTICES.md') (Join-Path $Output 'THIRD_PARTY_NOTICES.md')
  Copy-Item (Join-Path $project 'README.md') (Join-Path $Output 'README.md')
  New-Item -ItemType Directory -Force (Join-Path $Output 'docs') | Out-Null
  Copy-Item (Join-Path $project 'docs/library.md') (Join-Path $Output 'docs/library.md')
  Copy-Item (Join-Path $project 'configs/config.example.json') (Join-Path $Output 'config.example.json')
  $configTarget = Join-Path $Output 'config.json'
  if (!(Test-Path $configTarget)) { Copy-Item (Join-Path $Output 'config.example.json') $configTarget }
  Copy-Item (Join-Path $PSScriptRoot 'start-client.cmd') $Output
  Write-Host "Portable client ready: $Output"
} finally {
  foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name,$saved[$name],'Process') }
  Remove-Item -Recurse -Force $scratch
}
