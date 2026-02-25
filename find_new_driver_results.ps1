$evalDir = "C:\Users\Melvin\Documents\DriverFinder\popkorn-artifact\evaluation"
$drivers = @("amd_xata","behringer_fca1616_usb_x64_1","bypusb","CashdrawerSMBus32","jmcam","mbedSerial_x64","ptlser64","T5Usb64")

$runs = Get-ChildItem $evalDir -Directory -Filter "results_dp_drivers_pack*" | Sort-Object Name

foreach ($drv in $drivers) {
    $found = $false
    foreach ($run in $runs) {
        $stdout = Join-Path $run.FullName "$drv\stdout"
        if (Test-Path $stdout) {
            $booms = (Get-Content $stdout | Select-String "Boom!" | ForEach-Object { $_.Line.Trim() }) -join " | "
            Write-Host "$drv [$($run.Name)]: $booms"
            $found = $true
            break
        }
    }
    if (-not $found) { Write-Host "$drv : no results yet" }
}
