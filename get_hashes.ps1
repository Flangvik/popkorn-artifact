$dataset = "C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\datasets\dp_drivers_pack_extended_sinks_signed"
$drivers = @(
    "amd_xata.sys",
    "behringer_fca1616_usb_x64_1.sys",
    "bypusb.sys",
    "CashdrawerSMBus32.sys",
    "jmcam.sys",
    "mbedSerial_x64.sys",
    "ptlser64.sys",
    "T5Usb64.sys"
)

$results = @()
foreach ($drv in $drivers) {
    $f = Get-ChildItem $dataset -Filter $drv -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($f) {
        $sha256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLower()
        $sha1   = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA1).Hash.ToLower()
        Write-Host "$drv"
        Write-Host "  SHA256: $sha256"
        Write-Host "  SHA1  : $sha1"
        $results += [PSCustomObject]@{ Name=$drv; SHA256=$sha256; SHA1=$sha1 }
    } else {
        Write-Host "$drv : NOT FOUND"
    }
}

# Export for later use
$results | ConvertTo-Json | Out-File "$env:TEMP\new_driver_hashes.json" -Encoding UTF8
Write-Host ""
Write-Host "Saved to $env:TEMP\new_driver_hashes.json"
