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
    $osKey = @{
        LocalFileSystem = @()
    }
}

# -----------------------------
# Filesystem enumeration
# -----------------------------
$roots = @("C:\")

foreach ($root in $roots) {
    Get-ChildItem -Path $root -Recurse -Force -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            $acl = Get-Acl -LiteralPath $_.FullName
            $sdBytes = $acl.GetSecurityDescriptorBinaryForm()

            $result[$osKey]["LocalFileSystem"] += [PSCustomObject]@{
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
$result[$osKey]["LocalFileSystem"] =
    $result[$osKey]["LocalFileSystem"] | Sort-Object name

# -----------------------------
# Output JSON
# -----------------------------
$result | ConvertTo-Json -Depth 5
