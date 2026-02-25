$resultsBase = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\evaluation'
$runs = Get-ChildItem $resultsBase -Directory -Filter 'results_dp_drivers*'
if ($runs) {
    $run = $runs[0]
    $completed = (Get-ChildItem $run.FullName -Directory).Count
    $vulns = (Get-ChildItem $run.FullName -Recurse -Filter 'vuln').Count
    Write-Host "Results dir: $($run.Name)"
    Write-Host "Drivers completed: $completed / 1143"
    Write-Host "Vulnerabilities found: $vulns"

    # Show the most recently modified driver result dirs (currently running)
    Write-Host "`nMost recently modified (currently running):"
    Get-ChildItem $run.FullName -Directory |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 8 |
        ForEach-Object {
            $rc = if (Test-Path "$($_.FullName)\returncode") { Get-Content "$($_.FullName)\returncode" } else { 'running' }
            Write-Host "  $($_.Name)  rc=$rc  modified=$($_.LastWriteTime.ToString('HH:mm:ss'))"
        }
} else {
    Write-Host 'No results directory yet'
}
