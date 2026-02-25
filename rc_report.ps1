$r = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\evaluation\results_dp_drivers_raw_extended_sinks_only_timeout3600_qlkpud3d'
$rcs = Get-ChildItem $r -Recurse -Filter 'returncode' | ForEach-Object { (Get-Content $_.FullName).Trim() }
Write-Host "Return code distribution:"
$rcs | Group-Object | Sort-Object Count -Descending | ForEach-Object {
    Write-Host "  rc=$($_.Name): $($_.Count) drivers"
}
