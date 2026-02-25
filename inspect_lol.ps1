$r = Invoke-RestMethod -Uri "https://www.loldrivers.io/api/drivers.json" -TimeoutSec 60
Write-Host "Type:" $r.GetType().Name
Write-Host "Count:" $r.Count
if ($r -is [System.Array]) {
    Write-Host "First item keys:" (($r[0] | Get-Member -MemberType NoteProperty).Name -join ", ")
    Write-Host "First item sample:"
    $r[0] | ConvertTo-Json -Depth 2 | Select-Object -First 30
} elseif ($r -is [PSCustomObject]) {
    Write-Host "Top-level keys:" (($r | Get-Member -MemberType NoteProperty).Name -join ", ")
}
