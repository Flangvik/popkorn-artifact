$dataset = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\datasets\dp_drivers_raw_extended_sinks_only'
$results = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\evaluation\results_dp_drivers_raw_extended_sinks_only_timeout3600_qlkpud3d'
$missing_out = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\datasets\dp_drivers_raw_missed'

$analyzed = (Get-ChildItem $results -Directory).Name
$all = (Get-ChildItem $dataset -Filter '*.sys').Name

$missing = $all | Where-Object { $analyzed -notcontains $_ }

Write-Host "Total in dataset: $($all.Count)"
Write-Host "Already analyzed: $($analyzed.Count)"
Write-Host "Missing: $($missing.Count)"

# Create new dataset directory with missing drivers
New-Item -ItemType Directory -Force -Path $missing_out | Out-Null
foreach ($f in $missing) {
    Copy-Item "$dataset\$f" "$missing_out\$f" -Force
}
Write-Host "Copied $($missing.Count) drivers to $missing_out"
