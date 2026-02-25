# get_new_cert_info.ps1 — cert + vuln info for new driver findings

$dataset    = "C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\datasets\dp_drivers_pack_extended_sinks_signed"
$resultsDir = "C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\evaluation\results_dp_drivers_pack_extended_sinks_signed_timeout300_run2"

$newDrivers = @(
    "amd_xata.sys",
    "behringer_fca1616_usb_x64_1.sys",
    "bypusb.sys",
    "CashdrawerSMBus32.sys",
    "jmcam.sys",
    "mbedSerial_x64.sys",
    "ptlser64.sys",
    "T5Usb64.sys"
)

foreach ($drv in $newDrivers) {
    $path = Get-ChildItem $dataset -Filter $drv -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $path) {
        # try base name without _N suffix
        $base = $drv -replace "_\d+\.sys$", ".sys"
        $path = Get-ChildItem $dataset -Filter $base -ErrorAction SilentlyContinue | Select-Object -First 1
    }
    if (-not $path) { Write-Host "$drv : NOT FOUND"; continue }

    $sig     = Get-AuthenticodeSignature $path.FullName
    $cert    = $sig.SignerCertificate
    $status  = $sig.Status
    $subject = if ($cert) { ($cert.Subject -replace "CN=([^,]+).*",'$1') } else { "NO CERT" }
    $issuer  = if ($cert) { ($cert.Issuer  -replace "CN=([^,]+).*",'$1') } else { "N/A" }
    $expiry  = if ($cert) { $cert.NotAfter.ToString("yyyy-MM") } else { "N/A" }

    # stdout from results dir uses driver base name (without _N suffix)
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($path.Name)
    $stdoutPath = Join-Path $resultsDir "$baseName\stdout"
    $booms = if (Test-Path $stdoutPath) {
        (Get-Content $stdoutPath | Select-String "Boom!" | ForEach-Object { "    " + $_.Line.Trim() }) -join "`n"
    } else { "    (no stdout yet)" }

    Write-Host "=== $($path.Name) ==="
    Write-Host "  SigStatus : $status"
    Write-Host "  Subject   : $subject"
    Write-Host "  Issuer    : $issuer"
    Write-Host "  Expiry    : $expiry"
    Write-Host "  Vulns:"
    Write-Host $booms
    Write-Host ""
}
