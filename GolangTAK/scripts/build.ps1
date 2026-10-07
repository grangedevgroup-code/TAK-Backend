param(
    [string]$Version = 'dev',
    [string]$Out = 'dist',
    [string[]]$Targets = @(
        'linux/amd64', 'linux/arm64', 'linux/armv7', 'linux/armv6', 'linux/armv5', 'linux/386', 'linux/riscv64', 'linux/ppc64le',
        'linux/s390x', 'linux/loong64', 'linux/mips', 'linux/mipsle', 'linux/mips64', 'linux/mips64le', 'darwin/amd64', 'darwin/arm64',
        'windows/amd64', 'windows/arm64', 'windows/386', 'freebsd/amd64', 'freebsd/arm64', 'freebsd/386', 'freebsd/armv7',
        'openbsd/amd64', 'openbsd/arm64', 'netbsd/amd64', 'netbsd/arm64', 'android/arm64'
    )
)

$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
$Version = $Version -replace '^golangtak-', '' -replace '^v', ''
if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw 'Go is required: https://go.dev/dl/' }

if (Test-Path $Out) { Remove-Item -Recurse -Force $Out }
New-Item -ItemType Directory -Path $Out | Out-Null

$saved = @{}
foreach ($k in 'GOOS', 'GOARCH', 'GOARM', 'GOMIPS', 'GOMIPS64', 'CGO_ENABLED') { $saved[$k] = [Environment]::GetEnvironmentVariable($k) }
try {
    foreach ($target in $Targets) {
        $os, $arch = $target.Split('/')
        $goarch = $arch
        $goarm = ''
        switch ($arch) {
            'armv7' { $goarch = 'arm'; $goarm = '7' }
            'armv6' { $goarch = 'arm'; $goarm = '6' }
            'armv5' { $goarch = 'arm'; $goarm = '5' }
        }
        $ext = ''
        if ($os -eq 'windows') { $ext = '.exe' }
        $name = "golangtak-$os-$arch$ext"
        Write-Host "building $name"
        $env:GOOS = $os
        $env:GOARCH = $goarch
        $env:GOARM = $goarm
        $env:GOMIPS = 'softfloat'
        $env:GOMIPS64 = 'softfloat'
        $env:CGO_ENABLED = '0'
        & go build -trimpath -ldflags "-s -w -X main.version=$Version" -o (Join-Path $Out $name) ./cmd/golangtak
        if ($LASTEXITCODE -ne 0) { throw "build failed for $target" }
    }
} finally {
    foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
}

$lines = Get-ChildItem -Path $Out -Filter 'golangtak-*' | Sort-Object Name | ForEach-Object {
    (Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash.ToLower() + '  ' + $_.Name
}
[IO.File]::WriteAllText((Join-Path (Resolve-Path $Out) 'SHA256SUMS'), (($lines -join "`n") + "`n"))
Write-Host "done: $(Resolve-Path $Out)"
