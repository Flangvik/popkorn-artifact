# check_pack.ps1 - monitor dp_drivers_pack analysis progress
$base = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\evaluation'
$run = Get-ChildItem $base -Directory -Filter 'results_dp_drivers_pack_extended_sinks_signed*' |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1

if ($run) {
    $done  = (Get-ChildItem $run.FullName -Directory | Where-Object { Test-Path "$($_.FullName)\status" }).Count
    $total = 4681
    $vulns = Get-ChildItem $run.FullName -Recurse -Filter 'vulnerable'
    Write-Host "Results dir : $($run.Name)"
    Write-Host "Completed   : $done / $total"
    Write-Host "Vulnerable  : $($vulns.Count)"
    foreach ($v in $vulns) {
        $boom = Get-Content "$($v.Directory.FullName)\stdout" -Raw -Encoding Byte |
                ForEach-Object { [System.Text.Encoding]::UTF8.GetString($_) } |
                Select-String -Pattern 'Boom!.*' -AllMatches |
                ForEach-Object { $_.Matches } | Select-Object -First 3 | ForEach-Object { "    " + $_.Value }
        Write-Host "  VULN: $($v.Directory.Name)"
        $boom | ForEach-Object { Write-Host $_ }
    }
} else {
    Write-Host "No results dir found for dp_drivers_pack analysis"
}
