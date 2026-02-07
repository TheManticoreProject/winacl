# =============================
# Dump-ActiveDirectorySids.ps1
# =============================
# Enumerates all SIDs (objectSid) from Active Directory:
# users, groups, computers, and other security principals.

$component = "ActiveDirectorySids"

function Convert-ObjectSidBytesToSddl {
    param ([byte[]]$Bytes)
    if (-not $Bytes -or $Bytes.Length -eq 0) { return $null }
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($Bytes, 0)
        return $sid.Value
    } catch {
        return $null
    }
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
# Active Directory SID enumeration
# -----------------------------
$rootDse = [ADSI]"LDAP://RootDSE"
$namingContexts = $rootDse.namingContexts

foreach ($nc in $namingContexts) {

    $entry = [ADSI]"LDAP://$nc"

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot = $entry
    $searcher.Filter = "(objectSid=*)"
    $searcher.PageSize = 1000

    $searcher.PropertiesToLoad.Clear()
    $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
    $searcher.PropertiesToLoad.Add("objectSid") | Out-Null

    foreach ($res in $searcher.FindAll()) {

        if ($res.Properties["objectSid"].Count -eq 0) {
            continue
        }

        $dn = $res.Properties["distinguishedName"][0]
        $sidBytes = $res.Properties["objectSid"][0]
        $sidString = Convert-ObjectSidBytesToSddl $sidBytes

        if (-not $sidString) {
            continue
        }

        Write-Host $sidString "  " $dn
        $result[$component] += [PSCustomObject]@{
            name = $dn
            sid  = $sidString
        }
    }
}

# Deterministic ordering
$result[$component] =
    $result[$component] | Sort-Object name

# -----------------------------
# Output JSON
# -----------------------------

$dirPath = Join-Path -Path (Get-Location) -ChildPath $osKey
if (-not (Test-Path -Path $dirPath -PathType Container)) {
    New-Item -Path $dirPath -ItemType Directory | Out-Null
}

$jsonPath = Join-Path -Path $dirPath -ChildPath "ActiveDirectorySids.json"
$result | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
Write-Host "`nOutput: $jsonPath"
