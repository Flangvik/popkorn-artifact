$base = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\evaluation'
$run = Get-ChildItem $base -Directory -Filter 'results_dp_drivers_raw_missed*' | Select-Object -First 1
if ($run) {
    $done = (Get-ChildItem $run.FullName -Directory | Where-Object { Test-Path "$($_.FullName)\status" }).Count
    $vulns = (Get-ChildItem $run.FullName -Recurse -Filter 'vulnerable').Count
    Write-Host "Results dir: $($run.Name)"
    Write-Host "Completed: $done / 119"
    Write-Host "Vulnerabilities: $vulns"
    if ($vulns -gt 0) {
        Get-ChildItem $run.FullName -Recurse -Filter 'vulnerable' | ForEach-Object {
            Write-Host "  VULN: $($_.Directory.Name)"
        }
    }
} else {
    Write-Host "No results dir yet"
}
