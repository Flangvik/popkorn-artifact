$r = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\evaluation\results_dp_drivers_raw_extended_sinks_only_timeout3600_qlkpud3d'
$dirs = Get-ChildItem $r -Directory | Select-Object -First 3
foreach ($d in $dirs) {
    Write-Host "DIR: $($d.Name)"
    $files = Get-ChildItem $d.FullName
    foreach ($f in $files) {
        Write-Host "  $($f.Name) ($($f.Length) bytes)"
    }
}
