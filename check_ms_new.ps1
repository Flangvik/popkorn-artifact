$container = "popkorn-artifact-popkorn-1"
$resDir = "/home/popkorn/popkorn/evaluation/results_dp_drivers_ms_new_extended_sinks_signed_timeout1800_run2"

$done  = docker exec $container bash -c "ls $resDir 2>/dev/null | wc -l"
$vuln  = docker exec $container bash -c "ls $resDir/*/vulnerable 2>/dev/null | wc -l"
$vulns = docker exec $container bash -c "ls $resDir/*/vulnerable 2>/dev/null | sed 's|.*/\(.*\)/vulnerable|\1|'"

Write-Host "Progress: $done / 1410 done, $vuln vulnerable"
if ($vulns) {
    Write-Host "Vulnerable so far:"
    $vulns -split "`n" | Where-Object { $_ } | ForEach-Object { Write-Host "  $_" }
}
