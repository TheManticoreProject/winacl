# =============================
# Dump-ActiveDirectoryAcls.ps1
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
    ActiveDirectory = @()
}

# -----------------------------
# Active Directory enumeration
# -----------------------------
$rootDse = [ADSI]"LDAP://RootDSE"
$namingContexts = $rootDse.namingContexts

foreach ($nc in $namingContexts) {

    $entry = [ADSI]"LDAP://$nc"

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = $entry
    $searcher.Filter = "(nTSecurityDescriptor=*)"
    $searcher.PageSize = 1000

    $searcher.PropertiesToLoad.Clear()
    $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
    $searcher.PropertiesToLoad.Add("nTSecurityDescriptor") | Out-Null

    # Full SD (Owner, Group, DACL, SACL)
    $searcher.SecurityMasks =
        [System.DirectoryServices.SecurityMasks]::Owner `
        -bor [System.DirectoryServices.SecurityMasks]::Group `
        -bor [System.DirectoryServices.SecurityMasks]::Dacl `
        -bor [System.DirectoryServices.SecurityMasks]::Sacl

    foreach ($res in $searcher.FindAll()) {

        if ($res.Properties["nTSecurityDescriptor"].Count -eq 0) {
            continue
        }

        $dn = $res.Properties["distinguishedName"][0]
        Write-Host $dn
        $sdBytes = $res.Properties["nTSecurityDescriptor"][0]

        $result["ActiveDirectory"] += [PSCustomObject]@{
            name    = $dn
            hexdata = (Convert-BytesToHex $sdBytes)
        }
    }
}

# Deterministic ordering
$result["ActiveDirectory"] =
    $result["ActiveDirectory"] | Sort-Object name

# -----------------------------
# Output JSON
# -----------------------------

$dirPath = Join-Path -Path (Get-Location) -ChildPath $osKey
if (-not (Test-Path -Path $dirPath -PathType Container)) {
    New-Item -Path $dirPath -ItemType Directory | Out-Null
}

$jsonPath = Join-Path -Path $dirPath -ChildPath "ActiveDirectory.json"
$result | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
