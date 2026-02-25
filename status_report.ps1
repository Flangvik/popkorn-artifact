$r = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\evaluation\results_dp_drivers_raw_extended_sinks_only_timeout3600_qlkpud3d'

# Status distribution
$statuses = Get-ChildItem $r -Recurse -Filter 'status' | ForEach-Object { (Get-Content $_.FullName).Trim() }
Write-Host "=== Status Distribution ==="
$statuses | Group-Object | Sort-Object Count -Descending | ForEach-Object {
    Write-Host "  status=$($_.Name): $($_.Count) drivers"
}

# Vuln files
$vulns = Get-ChildItem $r -Recurse -Filter 'vuln'
Write-Host "`n=== Vulnerabilities: $($vulns.Count) ==="
foreach ($v in $vulns) {
    Write-Host "  $($v.Directory.Name)"
}

# Total
$total = (Get-ChildItem $r -Directory).Count
Write-Host "`nTotal result dirs: $total / 1143"
