$r = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\evaluation\results_dp_drivers_raw_extended_sinks_only_timeout3600_qlkpud3d'
Write-Host "=== Searching for Boom! in all stdout files ==="
Get-ChildItem $r -Recurse -Filter 'stdout' | ForEach-Object {
    $content = Get-Content $_.FullName -Raw -Encoding Byte
    if ($content -match 'Boom!') {
        $driver = $_.Directory.Name
        Write-Host "`n[VULNERABLE] $driver"
        # Get matching lines
        Get-Content $_.FullName | Select-String 'Boom!' | ForEach-Object {
            Write-Host "  $_"
        }
    }
}
Write-Host "`nDone."
