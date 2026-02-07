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
    $osKey = @{
        ActiveDirectory = @()
    }
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
        $sdBytes = $res.Properties["nTSecurityDescriptor"][0]

        $result[$osKey]["ActiveDirectory"] += [PSCustomObject]@{
            name    = $dn
            hexdata = (Convert-BytesToHex $sdBytes)
        }
    }
}

# Deterministic ordering
$result[$osKey]["ActiveDirectory"] =
    $result[$osKey]["ActiveDirectory"] | Sort-Object name

# -----------------------------
# Output JSON
# -----------------------------
$result | ConvertTo-Json -Depth 5
