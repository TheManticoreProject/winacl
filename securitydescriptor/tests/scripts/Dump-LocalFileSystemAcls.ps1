# =============================
# Dump-LocalFileSystemAcls.ps1
# =============================

function Convert-BytesToHex {
    param ([byte[]]$Bytes)
    ($Bytes | ForEach-Object { $_.ToString("X2") }) -join ""
}

# -----------------------------
# OS Identification
# -----------------------------
$os = Get-CimInstance Win32_OperatingSystem
$osKey = "$($os.Caption) - $($os.Version)"

$result = @{
    Metadata = @{
        Timestamp = $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        OS = @{
            OSVersion = $os.Version
            OSArchitecture = $os.OSArchitecture
            OSBuild = $os.BuildNumber
            OSVersionString = $os.VersionString
        }
    }
    LocalFileSystem = @()
}

# -----------------------------
# Filesystem enumeration
# -----------------------------
$roots = @("C:\")

foreach ($root in $roots) {
    Get-ChildItem -Path $root -Recurse -Force -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            Write-Host $_.FullName
            $acl = Get-Acl -LiteralPath $_.FullName
            $sdBytes = $acl.GetSecurityDescriptorBinaryForm()

            $result["LocalFileSystem"] += [PSCustomObject]@{
                name    = $_.FullName -replace "\\", "/"
                hexdata = (Convert-BytesToHex $sdBytes)
            }
        }
        catch {
            # Access denied, reparse points, transient errors → skip
        }
    }
}

# Deterministic ordering
$result["LocalFileSystem"] =
    $result["LocalFileSystem"] | Sort-Object name

# -----------------------------
# Output JSON
# -----------------------------
$dirPath = Join-Path -Path (Get-Location) -ChildPath $osKey
if (-not (Test-Path -Path $dirPath -PathType Container)) {
    New-Item -Path $dirPath -ItemType Directory | Out-Null
}

$jsonPath = Join-Path -Path $dirPath -ChildPath "LocalFileSystem.json"
$result | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
