param(
    [string]$ZipPath     = "C:\Users\Melvin\Downloads\drivers.zip",
    [string]$ExistingDir = "C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\datasets\dp_drivers_pack",
    [string]$NewDir      = "C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\datasets\dp_drivers_ms_new"
)

Add-Type -Assembly 'System.IO.Compression.FileSystem'

# Step 1: Build SHA-256 index of all existing drivers (by hash, not filename)
Write-Host "[1] Hashing existing dp_drivers_pack ..."
$existingHashes = @{}
Get-ChildItem $ExistingDir -Filter '*.sys' | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    $existingHashes[$hash] = $true
}
Write-Host "    Unique hashes in existing dataset: $($existingHashes.Count)"

# Step 2: Open zip, iterate every .sys entry, deduplicate by SHA-256
Write-Host "[2] Scanning zip for new unique drivers ..."
if (Test-Path $NewDir) { Remove-Item $NewDir -Recurse -Force }
New-Item -ItemType Directory -Path $NewDir | Out-Null

$zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
$seenInZip = @{}      # SHA-256 -> true (dedup within zip itself)
$nameCounters = @{}   # basename -> counter for collision renaming
$newCount = 0
$dupExisting = 0
$dupZip = 0

foreach ($entry in $zip.Entries) {
    if ($entry.Name -notlike '*.sys') { continue }

    # Extract to temp buffer and hash
    $stream = $entry.Open()
    $ms = New-Object System.IO.MemoryStream
    $stream.CopyTo($ms)
    $stream.Dispose()
    $bytes = $ms.ToArray()
    $ms.Dispose()

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha.ComputeHash($bytes)
    $sha.Dispose()
    $hash = [BitConverter]::ToString($hashBytes) -replace '-', ''

    # Skip if already in existing dataset
    if ($existingHashes.ContainsKey($hash)) {
        $dupExisting++
        continue
    }

    # Skip if already seen in this zip
    if ($seenInZip.ContainsKey($hash)) {
        $dupZip++
        continue
    }
    $seenInZip[$hash] = $true

    # Resolve filename — add numeric suffix if collision in NewDir
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($entry.Name)
    $ext = [System.IO.Path]::GetExtension($entry.Name)
    if (-not $nameCounters.ContainsKey($entry.Name)) {
        $nameCounters[$entry.Name] = 0
        $destName = $entry.Name
    } else {
        $nameCounters[$entry.Name]++
        $destName = "${baseName}_$($nameCounters[$entry.Name])${ext}"
    }

    $destPath = Join-Path $NewDir $destName
    [System.IO.File]::WriteAllBytes($destPath, $bytes)
    $newCount++
}
$zip.Dispose()

Write-Host ""
Write-Host "Done."
Write-Host "  Duplicates of existing dp_drivers_pack: $dupExisting"
Write-Host "  Duplicates within the zip itself:       $dupZip"
Write-Host "  New unique drivers -> dp_drivers_ms_new: $newCount"
