$7z = 'C:\Program Files\7-Zip\7z.exe'
$src = 'C:\Users\Melvin\Documents\DriverFinder\Drivers'
$dst = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\datasets\dp_drivers_raw'

New-Item -ItemType Directory -Force -Path $dst | Out-Null

Get-ChildItem "$src\*.7z" | ForEach-Object {
    Write-Host "Extracting: $($_.Name)"
    & $7z e $_.FullName "-o$dst" -r -y "*.sys" 2>&1 | Where-Object { $_ -match 'Extracting|Error|Everything' }
}

$count = (Get-ChildItem $dst -Filter "*.sys" -Recurse).Count
Write-Host "Total .sys files: $count"
