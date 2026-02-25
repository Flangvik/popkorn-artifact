# extract_dp_pack.ps1
# Extracts all .sys files from every .7z archive in DriverPack\drivers,
# deduplicates by SHA-256 hash, and stores unique drivers in datasets\dp_drivers_pack\.
#
# Usage:  powershell -ExecutionPolicy Bypass -File extract_dp_pack.ps1

$7zip     = 'C:\Program Files\7-Zip\7z.exe'
$archives = Get-ChildItem 'C:\Users\Melvin\Downloads\DriverPack\drivers\*.7z'
$outDir   = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\datasets\dp_drivers_pack'
$baseTemp = Join-Path $env:TEMP 'dp_pack_extract'

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$seenHashes = @{}
$total      = 0
$skipped    = 0
$copied     = 0
$errors     = 0

Write-Host "Found $($archives.Count) archives to process."

foreach ($archive in $archives) {
    Write-Host "  Extracting $($archive.Name) ..."

    # Use a unique temp dir per archive so there are no cross-archive remnants
    $tmpDir = Join-Path $baseTemp $archive.BaseName
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

    # 'e' = extract without paths (flat), '*.sys' filter, -r recursive inside archive
    & $7zip e $archive.FullName "-o$tmpDir" '*.sys' -r -y 2>&1 | Out-Null

    # Force materialization of file list before processing
    $sysFiles = @(Get-ChildItem -LiteralPath $tmpDir -Filter '*.sys' -Recurse -ErrorAction SilentlyContinue)

    foreach ($f in $sysFiles) {
        $total++

        # Use -LiteralPath to avoid Resolve-Path failures on unusual filenames
        $hashResult = Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
        if ($null -eq $hashResult) {
            $errors++
            continue
        }
        $hash = $hashResult.Hash

        if ($seenHashes.ContainsKey($hash)) {
            $skipped++
            continue
        }
        $seenHashes[$hash] = $f.Name

        # Resolve name collision: append _1, _2, ... if needed
        $dest = Join-Path $outDir $f.Name
        $idx  = 1
        while (Test-Path -LiteralPath $dest) {
            $dest = Join-Path $outDir ($f.BaseName + "_$idx" + $f.Extension)
            $idx++
        }
        Copy-Item -LiteralPath $f.FullName -Destination $dest -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $dest) { $copied++ } else { $errors++ }
    }

    # Clean up this archive's temp dir
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Clean up base temp dir
Remove-Item $baseTemp -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done."
Write-Host "  Total .sys files found : $total"
Write-Host "  Duplicates skipped     : $skipped"
Write-Host "  Errors                 : $errors"
Write-Host "  Unique drivers copied  : $copied"
Write-Host "  Output directory       : $outDir"
