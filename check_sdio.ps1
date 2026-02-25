# check_sdio.ps1 — Monitor SDIO update analysis progress
$resultsDir = "C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\evaluation\results_dp_drivers_sdio_update_new_extended_sinks_signed_timeout1800_run0"
$total = 646

if (-not (Test-Path $resultsDir)) {
    Write-Host "Results dir not found yet."
    exit
}

$completed = (Get-ChildItem $resultsDir -Directory -ErrorAction SilentlyContinue).Count
$vulns = (Get-ChildItem $resultsDir -Filter "vuln" -Recurse -ErrorAction SilentlyContinue).Count
$pct = if ($total -gt 0) { [math]::Round($completed / $total * 100, 1) } else { 0 }

Write-Host "SDIO Update Analysis Progress"
Write-Host "  Completed : $completed / $total ($pct%)"
Write-Host "  VULNERABLE: $vulns"

if ($vulns -gt 0) {
    Write-Host ""
    Write-Host "Vulnerable drivers:"
    Get-ChildItem $resultsDir -Filter "vuln" -Recurse -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host "  $($_.Directory.Name)" }
}
