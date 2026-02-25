# extract_sdio_update_diff.ps1
# Extracts all .sys files from SDIO_Update\drivers archives,
# diffs against existing dp_drivers_pack (by SHA-256 hash),
# and stores ONLY NEW drivers in datasets\dp_drivers_sdio_update_new\.
#
# Usage:  powershell -ExecutionPolicy Bypass -File extract_sdio_update_diff.ps1

$7zip       = 'C:\Program Files\7-Zip\7z.exe'
$archives   = Get-ChildItem 'C:\Users\Melvin\Downloads\SDIO_Update\drivers\*.7z'
$existingDir = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\datasets\dp_drivers_pack'
$outDir     = 'C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\datasets\dp_drivers_sdio_update_new'
$baseTemp   = Join-Path $env:TEMP 'sdio_update_extract'

New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# --- Step 1: Build hash index of existing dp_drivers_pack ---
Write-Host "Building hash index of existing dp_drivers_pack ($existingDir)..."
$seenHashes = @{}
$existing = @(Get-ChildItem -LiteralPath $existingDir -Filter '*.sys' -ErrorAction SilentlyContinue)
$i = 0
foreach ($f in $existing) {
    $i++
    if ($i % 1000 -eq 0) { Write-Host "  Hashed $i / $($existing.Count)..." }
    $hashResult = Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
    if ($hashResult) { $seenHashes[$hashResult.Hash] = $f.Name }
}
Write-Host "  Indexed $($seenHashes.Count) existing unique drivers."
Write-Host ""

# --- Step 2: Extract SDIO archives and copy new drivers ---
Write-Host "Found $($archives.Count) SDIO archives to process."

$total   = 0
$skipped = 0
$copied  = 0
$errors  = 0

foreach ($archive in $archives) {
    Write-Host "  Extracting $($archive.Name) ..."

    $tmpDir = Join-Path $baseTemp $archive.BaseName
    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null

    & $7zip e $archive.FullName "-o$tmpDir" '*.sys' -r -y 2>&1 | Out-Null

    $sysFiles = @(Get-ChildItem -LiteralPath $tmpDir -Filter '*.sys' -Recurse -ErrorAction SilentlyContinue)

    foreach ($f in $sysFiles) {
        $total++

        $hashResult = Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
        if ($null -eq $hashResult) { $errors++; continue }
        $hash = $hashResult.Hash

        if ($seenHashes.ContainsKey($hash)) {
            $skipped++
            continue
        }
        # New driver — add to seen set and copy to output
        $seenHashes[$hash] = $f.Name

        $dest = Join-Path $outDir $f.Name
        $idx  = 1
        while (Test-Path -LiteralPath $dest) {
            $dest = Join-Path $outDir ($f.BaseName + "_$idx" + $f.Extension)
            $idx++
        }
        Copy-Item -LiteralPath $f.FullName -Destination $dest -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $dest) { $copied++ } else { $errors++ }
    }

    Remove-Item $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

Remove-Item $baseTemp -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Done."
Write-Host "  Total .sys found in SDIO    : $total"
Write-Host "  Already in dp_drivers_pack  : $skipped"
Write-Host "  Errors                      : $errors"
Write-Host "  NEW drivers copied          : $copied"
Write-Host "  Output directory            : $outDir"
