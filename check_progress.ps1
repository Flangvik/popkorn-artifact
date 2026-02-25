$resultsBase = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\evaluation'
$runs = Get-ChildItem $resultsBase -Directory -Filter 'results_dp_drivers*'
if ($runs) {
    $run = $runs[0]
    Write-Host "Results dir: $($run.Name)"
    $completed = (Get-ChildItem $run.FullName -Directory).Count
    $vulns = (Get-ChildItem $run.FullName -Recurse -Filter 'vuln').Count
    Write-Host "Drivers completed: $completed / 1143"
    Write-Host "Vulnerabilities found so far: $vulns"
    Get-ChildItem $run.FullName -Recurse -Filter 'vuln' | Select-Object -First 20 | ForEach-Object {
        Write-Host "  VULN: $($_.Directory.Name)"
    }
} else {
    Write-Host 'No results directory yet - analysis may still be starting up'
}
