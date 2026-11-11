# vio installer for Windows.
#
#   irm https://raw.githubusercontent.com/ThembinkosiThemba/vio/main/site/install.ps1 | iex
#
# Environment overrides:
#   VIO_VERSION      release tag to install (default: latest), e.g. v0.1.0
#   VIO_INSTALL_DIR  where to put vio.exe (default: %LOCALAPPDATA%\vio\bin)
#   VIO_DOWNLOAD_URL base URL for release assets (mirrors, testing)
#   VIO_NO_MODIFY_PATH=1  don't add the install dir to your user PATH
#
# Runs inside a script block so nothing leaks into your session, and throws
# instead of calling exit so a failure never closes your terminal.

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $repo = 'ThembinkosiThemba/vio'
    $version = if ($env:VIO_VERSION) { $env:VIO_VERSION } else { 'latest' }

    $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'amd64' }
        'ARM64' { 'arm64' }
        default { throw "vio: unsupported architecture '$env:PROCESSOR_ARCHITECTURE'" }
    }

    $base = if ($env:VIO_DOWNLOAD_URL) { $env:VIO_DOWNLOAD_URL }
            elseif ($version -eq 'latest') { "https://github.com/$repo/releases/latest/download" }
            else { "https://github.com/$repo/releases/download/$version" }

    $zip = "vio_windows_$arch.zip"
    $dir = if ($env:VIO_INSTALL_DIR) { $env:VIO_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'vio\bin' }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('vio-' + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $tmp | Out-Null

    try {
        Write-Host "Installing vio ($version, windows/$arch)" -ForegroundColor White
        Write-Host "  downloading $zip"
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$base/$zip" -OutFile (Join-Path $tmp $zip)
        }
        catch {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -eq 404) {
                throw "vio: no release found for $version ($base/$zip). If none has been published yet, build from source: go install github.com/$repo/cmd/vio@latest"
            }
            throw "vio: download failed: $base/$zip ($($_.Exception.Message))"
        }
        Invoke-WebRequest -UseBasicParsing -Uri "$base/checksums.txt" -OutFile (Join-Path $tmp 'checksums.txt')

        $line = Get-Content (Join-Path $tmp 'checksums.txt') | Where-Object { ($_ -split '\s+')[1] -eq $zip }
        if (-not $line) { throw "vio: no checksum for $zip in checksums.txt" }
        $expected = ($line -split '\s+')[0].ToLower()
        $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $zip)).Hash.ToLower()
        if ($expected -ne $actual) { throw "vio: checksum mismatch for $zip (expected $expected, got $actual)" }
        Write-Host '  checksum verified'

        Expand-Archive -Force -Path (Join-Path $tmp $zip) -DestinationPath $tmp
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Copy-Item -Force (Join-Path $tmp 'vio.exe') (Join-Path $dir 'vio.exe')
        Write-Host "  installed $dir\vio.exe"

        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if ($env:VIO_NO_MODIFY_PATH -ne '1' -and -not (($userPath -split ';') -contains $dir)) {
            $newPath = if ($userPath) { "$userPath;$dir" } else { $dir }
            [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
            $env:Path = "$env:Path;$dir"
            Write-Host "  added $dir to your PATH"
        }

        Write-Host ''
        Write-Host 'Done. Start chatting with your servers:' -ForegroundColor White
        Write-Host '  vio'
    }
    finally {
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    }
}
