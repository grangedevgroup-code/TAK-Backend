function Install-GolangTAKServer {
    param([string[]]$Arguments)

    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $repo = 'grangedevgroup-code/TAK-Backend'
    $tagPrefix = 'golangtakserver-v'
    $module = 'github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/cmd/golangtakserver'

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {
        Write-Verbose 'TLS 1.2 is already enabled'
    }

    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch ($arch) {
        'AMD64' { $arch = 'amd64' }
        'ARM64' { $arch = 'arm64' }
        'x86' { $arch = '386' }
        default { throw "unsupported processor: $arch" }
    }

    $work = Join-Path ([IO.Path]::GetTempPath()) ('golangtakserver-install-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $exe = Join-Path $work 'golangtakserver.exe'
    try {
        if ($env:GOLANGTAKSERVER_BINARY) {
            if (-not (Test-Path $env:GOLANGTAKSERVER_BINARY)) { throw "GOLANGTAKSERVER_BINARY does not exist: $env:GOLANGTAKSERVER_BINARY" }
            Copy-Item $env:GOLANGTAKSERVER_BINARY $exe
        } elseif ($env:GOLANGTAKSERVER_SOURCE -ne '1') {
            $tag = $null
            if ($env:GOLANGTAKSERVER_VERSION -and $env:GOLANGTAKSERVER_VERSION -ne 'latest') {
                $tag = $tagPrefix + $env:GOLANGTAKSERVER_VERSION.TrimStart('v')
            } else {
                try {
                    $releases = Invoke-RestMethod -UseBasicParsing -Uri "https://api.github.com/repos/$repo/releases?per_page=50" -Headers @{ 'User-Agent' = 'golangtakserver-installer' }
                    $tag = ($releases | Where-Object { $_.tag_name -like "$tagPrefix*" } | Select-Object -First 1).tag_name
                } catch {
                    Write-Host 'Could not look up the latest release.'
                }
            }
            if ($tag) {
                $asset = "golangtakserver-windows-$arch.exe"
                $base = "https://github.com/$repo/releases/download/$tag"
                Write-Host "Downloading GolangTAKServer $($tag.Substring($tagPrefix.Length)) for windows/$arch"
                try {
                    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $exe
                    $sumsFile = Join-Path $work 'SHA256SUMS'
                    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS" -OutFile $sumsFile
                    $line = Get-Content $sumsFile | Where-Object { $_ -match ('\s\*?' + [regex]::Escape($asset) + '\s*$') } | Select-Object -First 1
                    if (-not $line) { throw "no checksum published for $asset" }
                    $want = ($line -split '\s+')[0].ToLower()
                    $got = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash.ToLower()
                    if ($want -ne $got) { throw "checksum mismatch for $asset (expected $want, got $got)" }
                } catch {
                    Write-Host "Download failed: $($_.Exception.Message)"
                    Remove-Item -Force -ErrorAction SilentlyContinue $exe
                }
            }
        }

        if (-not (Test-Path $exe)) {
            if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
                throw "could not download GolangTAKServer. Install Go from https://go.dev/dl/ and run this again, or download a release from https://github.com/$repo/releases"
            }
            $ref = 'latest'
            if ($env:GOLANGTAKSERVER_VERSION -and $env:GOLANGTAKSERVER_VERSION -ne 'latest') { $ref = 'v' + $env:GOLANGTAKSERVER_VERSION.TrimStart('v') }
            Write-Host "Building GolangTAKServer from source with $(& go version)"
            $oldBin = $env:GOBIN
            $oldCgo = $env:CGO_ENABLED
            $env:GOBIN = $work
            $env:CGO_ENABLED = '0'
            & go install -trimpath -ldflags '-s -w' "$module@$ref" | Out-Host
            $env:GOBIN = $oldBin
            $env:CGO_ENABLED = $oldCgo
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exe)) { throw 'building from source failed' }
        }

        $previousEncoding = [Console]::OutputEncoding
        try {
            [Console]::OutputEncoding = [Text.Encoding]::UTF8
        } catch {
            Write-Verbose 'console encoding unchanged'
        }
        & $exe version | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'the downloaded program does not run on this system' }

        $installArgs = @('install') + @($Arguments | Where-Object { $_ })
        if ($env:GOLANGTAKSERVER_ZEROTIER) { $installArgs += @('--zerotier', $env:GOLANGTAKSERVER_ZEROTIER) }
        if ($env:GOLANGTAKSERVER_TAILSCALE) { $installArgs += @('--tailscale', $env:GOLANGTAKSERVER_TAILSCALE) }
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $isAdmin = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($isAdmin) {
            & $exe @installArgs | Out-Host
            $code = $LASTEXITCODE
            try {
                [Console]::OutputEncoding = $previousEncoding
            } catch {
                Write-Verbose 'console encoding unchanged'
            }
            return $code
        }
        Write-Host 'Administrator rights are required. Approve the Windows prompt; installation continues in a new window.'
        $quoted = @($installArgs + '--pause') | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }
        $p = Start-Process -FilePath $exe -ArgumentList $quoted -Verb RunAs -Wait -PassThru
        return $p.ExitCode
    } finally {
        Start-Sleep -Milliseconds 500
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $work
    }
}

$golangtakserverExit = 1
try {
    $golangtakserverExit = Install-GolangTAKServer -Arguments $args
} catch {
    Write-Host "golangtakserver installer: $($_.Exception.Message)" -ForegroundColor Red
}
if ($PSCommandPath) {
    exit $golangtakserverExit
}
$global:LASTEXITCODE = $golangtakserverExit
