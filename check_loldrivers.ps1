# check_loldrivers.ps1
# Downloads the LOLDrivers driver list and checks our drivers by hash

$hashesJson = Get-Content "$env:TEMP\new_driver_hashes.json" -Raw | ConvertFrom-Json

Write-Host "Fetching LOLDrivers driver list..."
$lolUrl = "https://www.loldrivers.io/api/drivers.json"
try {
    $lol = Invoke-RestMethod -Uri $lolUrl -TimeoutSec 60
} catch {
    Write-Host "ERROR fetching LOLDrivers: $_"
    exit 1
}
Write-Host "Loaded $($lol.Count) LOLDrivers entries."
Write-Host ""

# Build a hash lookup set (SHA256 + SHA1, lowercase)
$lolHashes = @{}
foreach ($entry in $lol) {
    $name = $entry.Tags -join ","
    if (-not $name) { $name = $entry.Id }

    foreach ($sample in $entry.KnownVulnerableSamples) {
        if ($sample.SHA256) { $lolHashes[$sample.SHA256.ToLower()] = $entry }
        if ($sample.SHA1)   { $lolHashes[$sample.SHA1.ToLower()]   = $entry }
        if ($sample.MD5)    { $lolHashes[$sample.MD5.ToLower()]    = $entry }
    }
}
Write-Host "Indexed $($lolHashes.Count) hashes from LOLDrivers."
Write-Host ""

# Check each driver
$allClear = $true
foreach ($drv in $hashesJson) {
    $hitSha256 = $lolHashes[$drv.SHA256]
    $hitSha1   = $lolHashes[$drv.SHA1]
    $hit = if ($hitSha256) { $hitSha256 } elseif ($hitSha1) { $hitSha1 } else { $null }

    if ($hit) {
        $allClear = $false
        Write-Host "[!] IN LOLDRIVERS: $($drv.Name)"
        Write-Host "    LOLDrivers entry: $($hit.Id)"
        Write-Host "    Tags: $($hit.Tags -join ', ')"
        Write-Host "    CVE: $($hit.CVE -join ', ')"
    } else {
        Write-Host "[+] NOT in LOLDrivers: $($drv.Name)"
    }
}

Write-Host ""
if ($allClear) {
    Write-Host "All drivers clear - none found in LOLDrivers."
} else {
    Write-Host "WARNING: Some drivers are already in LOLDrivers."
}
