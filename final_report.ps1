$r = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\evaluation\results_dp_drivers_raw_extended_sinks_only_timeout3600_qlkpud3d'
$total = (Get-ChildItem $r -Directory).Count
$vulns = Get-ChildItem $r -Recurse -Filter 'vuln'
$timeouts = (Get-ChildItem $r -Recurse -Filter 'returncode' | Where-Object { (Get-Content $_.FullName).Trim() -eq '-1' }).Count
$errors = (Get-ChildItem $r -Recurse -Filter 'returncode' | Where-Object { (Get-Content $_.FullName).Trim() -notin @('0','-1','1') }).Count

Write-Host "=== POPKORN Analysis Summary ==="
Write-Host "Drivers analyzed: $total / 1143"
Write-Host "Vulnerabilities found: $($vulns.Count)"
Write-Host "Timeouts (rc=-1): $timeouts"
if ($vulns.Count -gt 0) {
    Write-Host "`nVulnerable drivers:"
    $vulns | ForEach-Object { Write-Host "  $($_.Directory.Name)" }
}
